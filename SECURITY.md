# weirdnet-sync security notes

Not audited. Sealing and HKDF go through `weirdnet-keys` only (XChaCha20-Poly1305, HKDF-SHA256). This crate does not implement a cipher or a KDF.

- `SyncKey` is derived from the caller's seed and user id. The seed is never logged, stored, or put on the wire.
- Sealed page associated data binds `<type>`, the key epoch and the asking peer, so a page cannot be replayed under another type, epoch or peer.
- A sync session is accepted only when `WEIRDNET.verify_cert` accepts a `NodeCert` for the same user id and the cert is not revoked.
- A revoked device holds the seed, so it can derive every seed-based key. `SyncState::revoke` rotates to a random epoch key sealed only to the remaining devices' X25519 device keys; the revoked device can open pages from earlier epochs only. Pulls are served only under the head key.
- Device keys are signed by each device's node key. Rotations and admissions are signed by their creator's node key and count only while the creator is an active member; see the README for the rules.
- Every device can still sign with the user key. A revoked device can therefore certify new nodes and sign revocations of other devices (denial of service), but a new node gets no epoch key without an admission from a member, which the app must only make after the user approves it on a member device.
- Before the first rotation, all seed holders are equal. A device that has not yet synced the first rotation can be offered a rival root by a revoked seed holder. Rotating once while every device is trusted (for example right after linking) closes that window.
- Epoch keys (`EpochKeys`) are secret, zeroized on drop, and redacted from `Debug`. Store them encrypted.
- The official [WeirdBrains](https://weirdbrains.com) relay must not store sealed pages. This crate does not write pages to a relay.
