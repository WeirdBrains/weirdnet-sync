# Changelog

All notable changes to weirdnet-sync are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.1.0
