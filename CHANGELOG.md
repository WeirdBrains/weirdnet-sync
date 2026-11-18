# Changelog

All notable changes to weirdnet-sync are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Key rotation on revoke: `SyncState::revoke` makes a random epoch key sealed to each remaining device, so a revoked device that holds the seed cannot read later ops.
- Re-admission: a device restored from the recovery words reports `needs-admission` until a member device admits it with `SyncState::admit`; it then gets the current and older epoch keys.
- `DeviceKey`, `Rotation`, `Admission`, `KeyChain` (in `Roster::chain`), `EpochKeys`, `KeyStatus`, `SyncState::new`, `key_status`, `rotate`, `refresh_keys` and `take_keys_from`.

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

[Unreleased]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/WeirdBrains/weirdnet-sync/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.1.0
