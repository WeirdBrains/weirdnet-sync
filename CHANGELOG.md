# Changelog

All notable changes to weirdnet-sync are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.0] - 2026-11-20

Releases as 0.8.0 (breaking: `SyncState` gains a `voter` field, `Message` gains lease variants).

### Added

- `lease`: majority-vote leases with fencing terms. `Voters` (role grants or fixed peers), `LeaseConfig` (defaults 15 s, renew every 5 s, 1 % drift, 500 ms stagger), `Voter` with persistence and a restart grace, `Leases::acquire`/`renew`/`release`, `Elector`, `LeaseHandle`, `LeaseState`, `LeaseError`, `FenceGuard`, `LeaseRecord`. Messages `LeaseAsk`, `LeaseGrant`, `LeaseDeny`, `LeaseFree` on `/weirdnet/sync/2`.
- `plan`: signed, versioned plans ordered by `(term, version)` (`SyncState::publish_plan`, `current_plan`, `current_plan_where`).
- `jobs`: a job log with per-job claim leases, checkpoints, results, retries and re-claims (`Jobs`, `JobSpec`, `JobEvent`, `JobView`, `JobStatus`, `job_lease`, `Leases::claim_job`).
- `Identity::enable_voter`, `enable_voter_with`, `disable_voter` (terms kept in `voter.cbor`).

### Changed

- `SyncState` has a public `voter` field: code that builds `SyncState` with a struct literal adds `voter: None`.
- `Message` has `LeaseAsk`, `LeaseGrant`, `LeaseDeny` and `LeaseFree`: exhaustive matches need arms for them.
- Lease voters need 0.8 on every voting device; pulls between 0.7 and 0.8 devices are unchanged.

## [0.7.0] - 2026-11-20

Releases as 0.7.0 (breaking: `SyncState::seed` is an `Option`, `Roster` and `KeyStatus` grow, new messages).

### Added

- Service devices linked with a certificate only, never the seed: `SyncState::new_service`, `SyncState::service_bundle`, `LinkBundle`, `Identity::adopt_service`. They cannot admit, revoke, grant or rotate (`SyncError::NotPermitted`).
- Roster-only service devices (no data keys) that follow certs, revocations, grants and rotations through an unsealed roster swap (`Envelope::clear`, `KeyStatus::RosterOnly`).
- User-signed device grants with class, roles and sync types (`DeviceGrant`, `DeviceClass`, `Roster::grants`, `grant_of`, `roles_of`, `has_role`, `is_service`, `SyncState::grant`, `Identity::grant`).
- `SecretStore` and `FileSecrets`, with `Identity::create_with`, `adopt_with`, `adopt_service_with` and `open_with`; `Identity::user_keypair` and `Identity::service_bundle`.

### Changed

- `SyncState::seed` is `Option<Vec<u8>>` (`None` on a service device); `HelloOk` and `RosterMsg` carry grants; `Envelope` has a `clear` flag.
- Rotations and admissions signed by a service device are ignored; rotations keep service devices with sync types and never include roster-only ones.
- `Roster::check_caller` admits a service device by its grant without key-chain membership.

## [0.6.0] - 2026-11-19

### Added

- `identity::Identity` (re-exported with `LinkSettings` and `Tick`): the on-disk identity store apps with linked devices share (seed, node key and cert, epoch keys, roster), parameterised on the sync type. `create`, `adopt` (a device link), `open`, `approve`, `revoke`, `link_settings`, `roster_view`, and `tick`, a `pull_from_shared` pass against every linked device that reports devices reached, entries applied and per-device errors. Same files as Ymir's `membership` and Bragi's `identity`, which it replaces.

### Changed

- `SyncError` is `#[non_exhaustive]` and has `Io` and `Identity` variants (breaking for exhaustive matches).

## [0.5.2] - 2026-11-19

### Fixed

- A device linked on one device (no revocation or rotation, so no epoch change) now reaches the others in one pass. `HelloOk` lists every cert the answering node holds, not only the revoked ones (the field keeps its wire name `revocations`), and a puller whose peer lacks one of its certs sends it the roster. Before, a new cert spread only by luck of which device started the first rotation, so a pass could end without error and the new device stay unknown. Wire-compatible both ways: older nodes merge the extra certs as before, and a puller hands an older peer its roster on each pass (one small request).

## [0.5.1] - 2026-11-19

### Added

- `SyncState` is `Clone`, and `SyncState::snapshot` copies it to pull into without holding a shared lock.
- `SyncState::merge_back(&snapshot) -> MergeOutcome`: folds a pulled snapshot back without losing what the state learned or wrote meanwhile: the roster (revocations win; nothing is un-revoked), epoch keys and the adopted root (then keys the merged chain seals to this device), log entries through `OpLog::integrate`, peer and per-type cursors, and the clock.
- `pull_from_shared(&Mutex<SyncState>, ..)`: snapshot, pull, merge back, so the lock is never held across the network and two nodes can pull from each other at once.
- `PullOutcome { applied, error }` (non-exhaustive) and `pull_from_outcome`: the entries applied before a later page was refused, the network failed or the closing rotation failed. `pull_from` keeps its signature (and still keeps the applied pages on an error).

### Deprecated

- `SyncState::take_keys_from`: use `SyncState::merge_back`.

## [0.5.0] - 2026-11-19

### Changed

- Breaking: depends on weirdnet-net 0.8 (its types are in this crate's API, so apps move to 0.8 with it). Requests and replies now carry byte fields as CBOR byte strings, so the sync request-response protocol id is `/weirdnet/sync/2` (was `/1`) and a 0.4 node and a 0.5 node fail to negotiate rather than fail to decode. Upgrade every device together.
- `PAGE_BUDGET` is now `(PAGE_MAX - 16 KiB) / 2 - 8 KiB` (114,688 bytes; was about 60 KiB). A page is hex-sealed (2x) inside one CBOR byte string (1x), no longer four times the plaintext. A full page is about 225 KiB on the wire, under the 256 KiB `PAGE_MAX`; `CHUNK_MAX` grows with it. The test measures the real 0.8 encoding and keeps a 16 KiB margin.

### Compatibility

- Stored data is unchanged: op logs, records, chunks, sealed values and key chains read exactly as in 0.4. Only the network protocol moved.

## [0.4.0] - 2026-11-18

### Added

- Large records: `SyncState::write` splits a value over `Limits::inline_max` into BLAKE3 content-addressed chunks, stored as entries of the companion type `<typ>#chunks` and pulled right after their type (`Limits::eager_chunks`) or on demand (`pull_chunks`). `SyncState::read` reassembles a value only when every chunk, the length and the whole hash match, and reports `RecordValue::Pending` with the missing chunks otherwise. A type's chunks are served wherever the type is.
- Sealed records: a type configured with `RecordOptions { sealed: true, .. }` has every value sealed under a per-record key derived from the head epoch key (`record::record_key`; associated data binds type, record id, epoch, rotation and writer). A device revoked before a write cannot open it, even with the seed and every older key. Members keep older epoch keys and admitted devices receive them, so values sealed before a rotation stay readable; `SyncState::reseal_stale` optionally re-seals them under the head key. Nothing is sealed under seed-derived keys (`no-epoch-key`), and an unsealed entry in a sealed type is refused.
- `SyncState::configure`, `options`, `write`, `write_with_fallback`, `read`, `latest_entries`, `reseal_stale`; `record::{Limits, RecordOptions, Value, Blob, SealInfo, RecordRef, RecordValue}`, `chunk_type`, `seal_record` / `open_record`; `OpLog::append_value`, `chunk`, `pending_blobs`, `iter`; `PAGE_BUDGET`.
- `Roster::check_caller` and `CallerCheck`: whether the transport-authenticated caller of an app call or stream is one of the user's linked devices (an active, verified cert in this roster, in the key chain's head once there is one). A presented cert must match the peer and user and a revoked one is refused, but a cert the roster does not hold never admits a caller (a seed holder can mint one).

### Changed

- Breaking: depends on weirdnet-net 0.7 (its `NodeCert`, `NodeConfig`, `Keypair` and `Profile` are in this crate's API, so apps move to weirdnet-net 0.7 with it). The sync profile is unchanged: it never made links.
- `LogEntry` has an optional `value` (the full value when `op` is only a fallback). It is omitted when empty, so plain entries keep the 0.3 wire shape, and older peers skip it and keep the fallback. A `Value` newer than this crate reads is refused rather than misread.
- `SyncState` has a `records` field; `SyncState::local_op` returns the new seq.

### Fixed

- Pages are budgeted for what crosses the wire (`PAGE_BUDGET`, about a quarter of `PAGE_MAX`: the sealed body is hex, and the request-response codec sends bytes as an integer array), so a full page no longer exceeds the 256 KiB reply cap and stalls the stream.

## [0.3.1] - 2026-11-18

### Fixed

- Two devices that each started the first rotation before learning of the other (linking two devices before either synced) no longer split into two chains for good: the earliest root whose creator the followed chain trusts wins, and a device in both chains admits the devices it approved into both (`Roster::all_views`).
- Revoking the device that made the first rotation no longer drops the whole chain: a revoked device's rotations still count when an active device built on them, and `revoke` rotates on the head from before the revocation.

## [0.3.0] - 2026-11-18

### Added

- Key rotation on revoke: `SyncState::revoke` makes a random epoch key sealed to each remaining device, so a revoked device that holds the seed cannot read later ops.
- Re-admission: a device restored from the recovery words reports `needs-admission` until a member device admits it (`SyncState::admit`, or `approve` before its device key is known); it then gets the current and older epoch keys.
- Automatic first rotation after the first link and after upgrading from seed-only keys, once every device has a device key (`auto_first_rotation`, `first_rotation_due`, `rotate_if_first_due`), and `devices_without_key` for a pre-revoke warning.
- `DeviceKey`, `Rotation`, `Admission`, `KeyChain` (in `Roster::chain`), `EpochKeys`, `KeyStatus`, `SyncState::new`, `key_status`, `rotate`, `refresh_keys`, `approve`, `admit_approved` and `take_keys_from`.

### Changed

- `SyncState` has `device` and `keys` fields; `Hello`, `HelloOk` and `RosterMsg` carry the key chain; `Envelope` names the rotation key. Seed-sealed envelopes keep the 0.2 wire shape.
- After a rotation, pulls are served only under the head key.

## [0.2.0] - 2026-11-18

### Added

- Per-type pull cursors (`OpLog::cursor_for`, `set_cursor_for`, `type_cursors`), `OpLog::page_of_type`, `OpLog::contiguous`, `OpLog::newest_hlc` and `net::observe`.

### Fixed

- Pulling one record type no longer moves past another type's ops on the same node's log.
- `pull_from` advances the local clock past the ops it pulled.
- An `Ack` from a puller no longer overwrites the server's own cursor.
- A device that missed a revocation catches up: an older-epoch hello gets the roster and retries, and `pull_from` sends its roster to a server that is behind. Before, the other devices were refused with `epoch-behind` forever.

## [0.1.0] - 2026-11-17

### Added

- HLC, op log, LWW registers, OR-sets, tombstone GC, SyncKey page sealing, roster / self-cert / revocation, and the `weirdnet-sync/v1` protocol over `weirdnet-net` 0.6.0.

[Unreleased]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.1.0
