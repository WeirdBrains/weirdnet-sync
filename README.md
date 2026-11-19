# weirdnet-sync

Linked-device sync for Weirdnet apps: a hybrid logical clock, an append-only per-node op log, last-writer-wins registers, OR-set merge, tombstone garbage collection, page sealing under a typed `SyncKey`, a device roster with self-issued node certificates and revocation, and the `weirdnet-sync/v1` pull protocol over [`weirdnet-net`](https://crates.io/crates/weirdnet-net).

Applications keep their own record types (Morph bookmarks, Muninn notes, and so on). This crate does not know those shapes. It also does not open a database: [`weirdnet-storage`](https://crates.io/crates/weirdnet-storage) has a separate SQL row change log (`sync` feature) with a three-way take/keep/conflict decision. That is useful for a local trigger log. It is not this protocol. Wrap it later if it grows to cover the HLC log, rather than forking it.

## Keys

Until the first rotation, `SyncKey(type)` is `HKDF-SHA256(seed, salt = user id, info = weirdnet-sync/v1/<type>)`, or `weirdnet-sync/v1/<type>/e<n>` after a bare revocation bumps the key epoch. `<type>` is an application string (`bookmarks`, `history`, `settings`, …). Pages on the wire are XChaCha20-Poly1305 sealed with that key; associated data binds the type, epoch and asking peer.

After a rotation the key comes from a random epoch key instead: `HKDF-SHA256(epoch key, salt = user id, info = weirdnet-sync/v1/<type>/e<n>/k<rotation id>)`, and the associated data also binds the rotation id. The envelope names the rotation in the clear (`key`); seed-sealed envelopes look exactly as in 0.2.

### Rotation

Every device holds the identity seed, so no key derived from it can shut a revoked device out. `SyncState::revoke` therefore revokes and rotates: it makes a fresh random epoch key and seals one copy to each remaining device (X25519 with an ephemeral key, then XChaCha20-Poly1305). The sealed copies travel in the roster's key chain (`Roster::chain`), next to the certs, in `Hello`, `HelloOk` and `Roster` messages.

- Each device publishes a `DeviceKey`: an X25519 public key derived from its node key and signed by that node key, so no other device, not even one holding the user key, can put its own key in another device's place. Nothing new needs storing.
- A `Rotation` is signed by its creator's node key. It counts when the creator has an active cert and was a member of the parent rotation (the first rotation has none). A revoked creator's rotations stop counting, with everything built on them. The head is the counting rotation with the highest epoch, then one without a revoked member, then the lowest id, so concurrent rotations settle on one head.
- Once a device holds a key from a first rotation it keeps that root (`KeyChain::root`, local). A later root, for example one started by a seed holder with a freshly certified node, is ignored.
- After a rotation only the head key carries data. Hellos and roster messages under an older or seed-derived key get the roster and chain back, so a device that missed a rotation catches up and retries; `Pull` under them is refused with `epoch-behind`. A peer that cannot open the head key answers `unknown-key`, and `pull_from` sends it the roster.
- A device restored from the recovery words gets a new node key and is not a member, so `pull_from` fails with `needs-admission` and `SyncState::key_status()` is `NeedsAdmission`. After the user approves it on a member device (as when linking; `DeviceKey::fingerprint` is a short code to compare on both screens), `SyncState::admit` seals the head key and the older keys it holds to the restored device's key. `SyncState::approve` does the same once the device key is known: an approved device is admitted by its first hello, and the roster reply to that hello already carries the admission, so it catches up in the same pull. Approved devices are also included in the next rotation. Old epochs stay readable; new writes use the head key.
- The first rotation starts itself while every device is still trusted: once at least two devices are linked and every active device has published its device key, the one with the lowest peer id rotates at the end of `pull_from` (`SyncState::auto_first_rotation`, on in `SyncState::new`; or call `rotate_if_first_due`). That covers both "right after the first link" and "once after upgrading from seed-only keys". Until a device has published its key, a rotation would leave it out; `SyncState::devices_without_key` lists such devices so apps can warn before a revoke.
- If the head still includes a revoked device (revoked on a device that could not rotate), the next `pull_from` on a member rotates again.

The epoch keys a device holds are in `SyncState::keys` (`EpochKeys`). They are secret: store them encrypted (`EpochKeys::export` / `import`). The chain is public and is stored with the roster.

This is not [`Profile::sync_key`](https://docs.rs/weirdnet-net): that derives one key from the Ed25519 secret with info `weirdnet/sync/v1/key`. Typed library pages use this crate.

The official WeirdBrains relay must not store sealed pages. Only a user-run node may keep them for catch-up, and that is an application choice, not something this crate enables on a relay.

## Large and sealed records

An entry's `op` is what every version reads. Since 0.4 an entry may also carry a `value` (`record::Value`); then `op` is only a fallback (empty, or a preview the application passes to `SyncState::write_with_fallback`) and the full value is in `value`. Older peers skip the field and keep the fallback. A peer before 0.4 that relays an entry keeps only the fallback, so a device that gets the entry through it sees the fallback too, not a corrupted value.

Configure a type once on every device, then write and read whole values:

```rust
state.configure("chat", RecordOptions::default())?;                        // chunk values over 32 KiB
state.configure("secrets", RecordOptions { sealed: true, ..Default::default() })?;
state.write(now_ms, "chat", "answer-1", &long_answer)?;
match state.read(&entry)? {
    RecordValue::Ready(bytes) => { /* apply */ }
    RecordValue::Pending { missing } => { /* pull_chunks(...) and read again */ }
}
```

### Chunks

A value larger than `Limits::inline_max` (after sealing) is split into `Limits::chunk_size` chunks, each an entry of the companion type `<typ>#chunks` whose record id is the BLAKE3 hash of its bytes. The entry of `<typ>` carries the manifest (`Blob`: length, whole hash, chunk hashes). A node reuses chunks it already wrote. `pull_from` pulls a type's chunks right after the type when an entry is still incomplete (`Limits::eager_chunks`, on by default); with it off, call `pull_chunks` when the value is needed. `SyncState::read` reassembles only when every chunk, the length and the whole hash match. A server serves a type's chunks wherever it serves the type; a 0.3 server refuses them and the pull carries on. Defaults: 32 KiB inline, 48 KiB chunks, 16 MiB per record; `Limits::check` keeps them inside a page.

### Sealed records

`RecordOptions::sealed` seals every value of the type under a key for that record: `HKDF-SHA256(epoch key, salt = user id, info = weirdnet-sync/v1/record/<type>/e<n>/k<rotation id>/<record id>)`, XChaCha20-Poly1305 with associated data binding the type, record id, epoch, rotation and writer node. Sealing happens before chunking, so chunks of a sealed value are ciphertext. The value stays sealed at rest in every log, not only on the wire.

- Only the head epoch key seals. Seed-derived keys are held by every seed holder, revoked or not, so a write before the first rotation fails with `no-epoch-key`.
- A device revoked before a write is not a member of the head rotation and cannot open the value, even holding the seed, every older key and the raw entries.
- Members keep older epoch keys and admitted devices receive them, so values sealed before a rotation stay readable. `SyncState::reseal_stale` re-seals the latest value of each record still under an older key; it is optional and is a new write of the same value, so run it after syncing. A revoked device keeps whatever it could read before; change the secret itself when that matters.
- `read` refuses an unsealed entry in a sealed type, so a seed holder cannot write around the seal. The fallback is never sealed.

## Protocol

`/weirdnet/sync/1`, length-prefixed CBOR, one request/reply at a time (the same style as `/weirdnet/link/1`). After the authenticated channel is up, payloads that carry records, cursors or certificates are sealed. Messages: `Hello` / `HelloOk` or `Refuse`, `Pull`, `Page`, `Ack`, `Roster`.

A session is accepted only if the peer presents a `NodeCert` for the same user that `WEIRDNET.verify_cert` accepts and that is not revoked.

A page carries at most `PAGE_BUDGET` bytes of ops (about a quarter of `PAGE_MAX`, because the sealed body is hex and the request-response codec sends bytes as an integer array), so it fits a 256 KiB reply cap on the wire. A node's log can mix record types. `Pull` asks for one type; pull positions are kept per (node, type) (`OpLog::cursor_for`), so pulling one type never skips another type's ops. `Page.to_seq` is the last seq the server walked, which may be past the last op it returned. A server answers only up to what it holds completely for that type: its own contiguous prefix of the node's log, or how far it has pulled that type itself. After a pull, `pull_from` moves the node's clock past the newest op it holds, so a later local write orders after everything it has seen. An `Ack` reports the puller's progress and never moves the server's own cursors.

A revocation bumps the roster epoch. A hello from an unrevoked device of the same user at an older epoch (or, after a rotation, under any key but the head's) gets the server's roster (user-signed certs and revocations, and the key chain) instead of a refusal; `pull_from` merges it and says hello again. When `pull_from` finds the server behind, it sends the server its roster. A revoked device is refused once a node holds the revocation. With seed-derived keys alone, a revoked device can still derive later keys, so exclusion rests on the session check; a rotation (see Keys) is what shuts it out of the data.

## Merge rules

- Field values are last-writer-wins by HLC.
- Sets (tags, and similar) are observed-remove: concurrent adds of different elements keep both; a remove is a per-element tombstone and LWW against adds of that element. Concurrent add vs remove: the add wins. A remove whose HLC is strictly later than the add wins.
- The same strictly-later rule applies to edit vs delete of a record.
- Tombstones may be garbage-collected after 90 days, and only once every known peer cursor is past that delete.
- Losing versions of a conflict may be kept for 30 days for the application's UI.

## Status

Published on crates.io; the current release is 0.4.0. It adds large records (values over
`Limits::inline_max` are split into BLAKE3-checked chunks) and sealed records (per-record keys
from the head epoch key, so a device revoked before a write cannot read it), budgets pages so a
full page fits the 256 KiB reply cap, adds `Roster::check_caller`, and moves to weirdnet-net 0.7.
Peers on 0.3 keep working and see the fallback value. Key rotation on revoke shipped in 0.3.0,
with two fixes in 0.3.1.
See `CHANGELOG.md`.
