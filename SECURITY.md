# weirdnet-sync security notes

Not audited. Sealing and HKDF go through `weirdnet-keys` only (XChaCha20-Poly1305, HKDF-SHA256). This crate does not implement a cipher or a KDF.

- `SyncKey` is derived from the caller's seed and user id. The seed is never logged, stored, or put on the wire.
- Sealed page associated data binds `<type>`, the key epoch and the asking peer, so a page cannot be replayed under another type, epoch or peer.
- A sync session is accepted only when `WEIRDNET.verify_cert` accepts a `NodeCert` for the same user id and the cert is not revoked.
- A revoked device that kept an old `SyncKey` can open pages from earlier epochs only; later pages use `…/e<n>`.
- The official WeirdBrains relay must not store sealed pages. This crate does not write pages to a relay.
