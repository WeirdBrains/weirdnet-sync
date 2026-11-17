# weirdnet-sync

Linked-device sync for Weirdnet apps: a hybrid logical clock, an append-only per-node op log, last-writer-wins registers, OR-set merge, tombstone garbage collection, page sealing under a typed `SyncKey`, a device roster with self-issued node certificates and revocation, and the `weirdnet-sync/v1` pull protocol over [`weirdnet-net`](https://crates.io/crates/weirdnet-net).

Applications keep their own record types (Morph bookmarks, Muninn notes, and so on). This crate does not know those shapes. It also does not open a database: [`weirdnet-storage`](https://crates.io/crates/weirdnet-storage) has a separate SQL row change log (`sync` feature) with a three-way take/keep/conflict decision. That is useful for a local trigger log. It is not this protocol. Wrap it later if it grows to cover the HLC log, rather than forking it.

## Keys

`SyncKey(type)` is `HKDF-SHA256(seed, salt = user id, info = weirdnet-sync/v1/<type>)`, or `weirdnet-sync/v1/<type>/e<n>` after a revocation bumps the key epoch. `<type>` is an application string (`bookmarks`, `history`, `settings`, …). Pages on the wire are XChaCha20-Poly1305 sealed with that key; associated data binds the type, epoch and asking peer.

This is not [`Profile::sync_key`](https://docs.rs/weirdnet-net): that derives one key from the Ed25519 secret with info `weirdnet/sync/v1/key`. Typed library pages use this crate.

The official WeirdBrains relay must not store sealed pages. Only a user-run node may keep them for catch-up, and that is an application choice, not something this crate enables on a relay.

## Protocol

`/weirdnet/sync/1`, length-prefixed CBOR, one request/reply at a time (the same style as `/weirdnet/link/1`). After the authenticated channel is up, payloads that carry records, cursors or certificates are sealed. Messages: `Hello` / `HelloOk` or `Refuse`, `Pull`, `Page`, `Ack`, `Roster`.

A session is accepted only if the peer presents a `NodeCert` for the same user that `WEIRDNET.verify_cert` accepts and that is not revoked.

## Merge rules

- Field values are last-writer-wins by HLC.
- Sets (tags, and similar) are observed-remove: concurrent adds of different elements keep both; a remove is a per-element tombstone and LWW against adds of that element. Concurrent add vs remove: the add wins. A remove whose HLC is strictly later than the add wins.
- The same strictly-later rule applies to edit vs delete of a record.
- Tombstones may be garbage-collected after 90 days, and only once every known peer cursor is past that delete.
- Losing versions of a conflict may be kept for 30 days for the application's UI.

## Status

The crate is new and has not been published. Apps that pin crates.io versions (Morph releases included) cannot depend on it until `WeirdBrains/weirdnet-sync` exists and 0.1.0 is published.
