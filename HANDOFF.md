# Handoff

Running log for [weirdnet-sync](https://github.com/WeirdBrains/weirdnet-sync), newest first. Shared rules: the collective `AGENTS.md` of [Weird Brains](https://weirdbrains.com) projects.

## 2026-11-26: released v0.8.5

What changed: [`8fc693e`](https://github.com/WeirdBrains/weirdnet-sync/commit/8fc693e06daeaeef1a7b1e43aa5fbfab64b24c4b) (`release: v0.8.5`, tag [`v0.8.5`](https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.8.5)), published as [weirdnet-sync 0.8.5](https://crates.io/crates/weirdnet-sync/0.8.5) ([docs.rs](https://docs.rs/weirdnet-sync/0.8.5)) with the shared release script (`--patch`).

Checks run: CI green on Linux, macOS and Windows for the change and the release commit; the release script's checks; `cargo semver-checks` against 0.8.4 (no breaking changes). docs.rs built 0.8.5. The site ([net.weirdbrains.com](https://net.weirdbrains.com/crates/sync)) shows 0.8.5.

Not tested: see the entry below.

Next: weirdnet-agent and Bragi can move their per-type pull loops onto `pull_types`.

## 2026-11-26: several types in one sync session (for 0.8.5)

What changed: [`fb83317`](https://github.com/WeirdBrains/weirdnet-sync/commit/fb8331750c85c29e6850d2f017c5d95726164103) (code), [`6c17f58`](https://github.com/WeirdBrains/weirdnet-sync/commit/6c17f58e722c9bd291482e6bbeab2931137335df) (tests), plus this commit (README, CHANGELOG). Asked for Bragi and Ymir, which pulled each record type in its own session.

- Each `pull_from` said `Hello` (and swapped rosters when the peer was behind) once per type. The server already answers every request on its own (no server-side session state), and weirdnet-net keeps the connection open between requests, so only the Hello and roster swap were repeated.
- `pull_session` is split into `open_session` (Hello and the roster and rotation catch-up, sealed under the first type), `pull_with` (one type and its pending chunks, under that type's own key) and `close_session` (clock and due rotations). `pull_from` runs all three for one type, as before.
- New `pull_types` / `pull_types_shared`: one session for several types, one `PullOutcome` per type in a `PullTypesOutcome` (`types`, `get`, `applied`, `is_ok`). A service device skips types outside its own grant (`type-not-granted`, no request sent); a type the peer refuses fails alone and the rest still pull; a Hello refused `type-not-granted` moves to the next type. No wire change, so it works against 0.7.1 and 0.8.0 to 0.8.4 peers.
- Servers now refuse a `Pull` sealed under another type than the one it asks for (`type-mismatch`); every released client seals each `Pull` under its own type.

Checks run: `cargo fmt --check`; `cargo clippy --all-targets` (default and `--all-features`) with `-D warnings`; `cargo test` default, `--all-features` and `--no-default-features` (110 tests: the 104 before plus 6 in `tests/multi_type.rs`, `compat_07`, `compat_082` and `sealed_scoped` included); `cargo doc --no-deps` with `-D warnings`; `cargo semver-checks` against 0.8.4 (no breaking changes).

Not tested: a real network (all tests use the in-memory transport); timings (the Hello saved per type was not measured); a service device linked by a pre-0.8.3 device that still holds epoch keys (the server-side `type-not-granted` path for Hello is covered only by the existing per-type tests).

What's left: release 0.8.5; weirdnet-agent and Bragi can move their per-type pull loops onto `pull_types`.

Next: release with the shared script once CI is green on Linux, macOS and Windows, then update the site.

## 2026-11-26: released v0.8.4

What changed: [`f02e130`](https://github.com/WeirdBrains/weirdnet-sync/commit/f02e130b31aa4847e90c956963e7c0b2b82772e9) (`release: v0.8.4`, tag [`v0.8.4`](https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.8.4)), published as [weirdnet-sync 0.8.4](https://crates.io/crates/weirdnet-sync/0.8.4) ([docs.rs](https://docs.rs/weirdnet-sync/0.8.4)) with the shared release script (`--patch`).

Checks run: CI green on Linux, macOS and Windows for the change and the release commit; the release script's checks. weirdnet-agent 0.5.6 (`jobs,pool,serve`, 124 tests) and weirdnet-backends 0.4.7 (`node`, 47 tests) pass on the published 0.8.4 and resolve with it to one weirdnet-sync. docs.rs built 0.8.4. The site ([net.weirdbrains.com](https://net.weirdbrains.com/crates/sync)) shows 0.8.4.

Not tested: see the entry below.

Next: nothing for this release.

## 2026-11-26: type-scoped record keys for service devices (for 0.8.4)

What changed: [`c757c60`](https://github.com/WeirdBrains/weirdnet-sync/commit/c757c604beb514d5c9d9e0286a27b8abbd4b2fb3) (code), [`05ccdce`](https://github.com/WeirdBrains/weirdnet-sync/commit/05ccdce24d7b1546b54ed8bcaeddc4f381747d9a) (tests), [`3f4f881`](https://github.com/WeirdBrains/weirdnet-sync/commit/3f4f881b1f77811e3ed774d37c0efb1294440d55) (README, CHANGELOG). Fixes a 0.8.3 regression reported for Ymir: a service device granted a sealed type (`ymir.context`, `RecordOptions { sealed: true }`) opened its pages but could not read or write its records, because record keys came only from the epoch key.

- New record-key scheme under the type's `SyncKey` of the rotation: `scoped_record_key` (`HKDF-SHA256(SyncKey(type), salt = user id, info = weirdnet-sync/v1/record-scoped/<type>/e<n>/k<id>/<record id>)`), `scoped_record_aad` (own label), `seal_record_scoped`, `open_record_scoped`. A service device holds that key for its granted types; a full device derives it from the epoch key (`EpochKeys::sync_key`).
- Sealing rule (`SyncState::seals_scoped`): a service device always seals type-scoped. A full device seals type-scoped while an active service device is granted the type (`Roster::service_granted`), and with the epoch key otherwise, so 0.7.1 to 0.8.3 devices keep reading records no service device shares (the 0.7.1 compatibility test stays byte-identical).
- No wire marker: `SealInfo` is unchanged (adding a field would break semver). A full device tries both keys, the one it would seal with first; a service device has only the type-scoped key and gets a `Crypto` error for a record under the epoch key.
- `reseal_stale` re-seals records under an older rotation and, new, records under the head that use the other scheme than a write would now. Run it on a full device after granting a service device a sealed type, so records written before the grant open there; after the last such service device is revoked it moves them back to the epoch key. A service device never re-seals records under the epoch key.

Checks run: `cargo fmt --check`; `cargo clippy --all-targets` (default and all features, `-D warnings`); `cargo test` (default, all and no default features: 104 tests each, including 3 new sealed-record tests and a new 0.8.2 record-seal compatibility test; the 0.7.1 and 0.8.2 compatibility tests pass); `cargo doc --no-deps` with `-D warnings`; `cargo semver-checks` against 0.8.3 (no semver update required). weirdnet-agent 0.5.6 (`jobs,pool,serve` and all features, 124 tests) and weirdnet-backends 0.4.7 (`node` and all features, 47 tests) pass against this tree, and a graph with both resolves to one weirdnet-sync.

Not tested: a real network or many devices; a full device on 0.8.3 or older can't open records sealed type-scoped (upgrade every full device that reads a type shared with a service device); a revoked service device that has not seen the rotation can still write under the rotation it held (peers refuse its sessions).

Next: release 0.8.4 once CI is green; Ymir runs `reseal_stale("ymir.context")` on a full device after linking an inference node.

## 2026-11-26: released v0.8.3

What changed: [`d0bfe9d`](https://github.com/WeirdBrains/weirdnet-sync/commit/d0bfe9dc32a22e0154d38b1a2e63a7c5e2e2cc3e) (`release: v0.8.3`, tag [`v0.8.3`](https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.8.3)), published as [weirdnet-sync 0.8.3](https://crates.io/crates/weirdnet-sync/0.8.3) ([docs.rs](https://docs.rs/weirdnet-sync/0.8.3)) with the shared release script. The first upload got a crates.io 500; `crates --tag v0.8.3` published it.

Checks run: CI green on Linux, macOS and Windows for the change and the release commit; the release script's checks. weirdnet-agent 0.5.6 (`jobs,pool,serve`) and weirdnet-backends 0.4.7 (`node`) pass their tests on the published 0.8.3, and resolve with it to one weirdnet-sync. The site ([net.weirdbrains.com](https://net.weirdbrains.com/crates/sync)) shows 0.8.3.

Not tested: see the entry below.

Next: nothing for this release.

## 2026-11-26: type-scoped keys for service devices (for 0.8.3)

What changed: [`94aa8f7`](https://github.com/WeirdBrains/weirdnet-sync/commit/94aa8f7ca0ae3c22dbd5e144d6d50f16f618b64e) (code), [`d28ce72`](https://github.com/WeirdBrains/weirdnet-sync/commit/d28ce72305c395934afd4f5029499915009581e8) (tests), [`9e20eb8`](https://github.com/WeirdBrains/weirdnet-sync/commit/9e20eb8bcfad44b34ad6db8e4811fdb0cb2b419d) (README, CHANGELOG). Requested for Ymir, so cert-only model nodes can run and vote on `ymir.train` jobs without being able to read `ymir.context`.

- `EpochKeys` also holds type-scoped keys by (rotation id, type), exported with an optional `typ` field (epoch-key entries encode as before). A service device with sync types gets only those: `service_bundle` sends the scoped keys of its granted types, their chunk types and `weirdnet.lease`; a rotation no longer seals the epoch key to it but admits it with the new rotation's scoped keys (the scoped key binds the rotation id, which exists only once the rotation is signed). A service device narrows any epoch key it loads (from an older device) to scoped keys.
- `seal_envelope`/`open_envelope` use the epoch key when held and the scoped key otherwise; the envelope is identical (`Envelope::seal_scoped`/`open_scoped`).
- `SyncState::handle` refuses a service peer's `Hello`/`Pull`/`Ack` outside its grant (also a pull of another type inside a granted type's envelope) and lease requests from roster-only devices, with `type-not-granted` (`Roster::may_sync`).
- `weirdnet.lease` is automatic for any service device with sync types (0.8.2's lease tests already relied on that); a grant of only `weirdnet.lease` is a lease-only voter.

Checks run: `cargo fmt --check`; `cargo clippy --all-targets` (default and all features, `-D warnings`); `cargo test` (default, all and no default features: 74 unit tests, 13 lease/job network tests, 5 service tests, 5 new scoped-key tests, the 0.7.1 and new 0.8.2 compatibility tests); `cargo doc --no-deps` with `-D warnings`; `cargo semver-checks` against 0.8.2 (no semver update required). weirdnet-agent 0.5.6 (`jobs,pool,serve`, 134 tests) and weirdnet-backends 0.4.7 (`node`, 61 tests) pass against this tree, and both build together with it in one graph (one weirdnet-sync).

Not tested: a real network or many devices; a fleet where a 0.8.2 full device rotates (it still seals the epoch key to service devices, which then narrow it on load; upgrade full devices first). A 0.8.2 service device can't use the scoped admissions and needs 0.8.3. Changing a service device's types takes effect for its keys at the next rotation; enforcement applies at once.

Next: release 0.8.3 once CI is green; Ymir grants its model nodes `ymir.train` and keeps that type unsealed.

## 2026-11-25: owner pause spares the attempt in progress (for 0.8.2)

What changed: [`e1b279e`](https://github.com/WeirdBrains/weirdnet-sync/commit/e1b279ecbe263011cb5b82f288939ac084e2e927). Voters refuse to renew a paused job's claim, so a busy holder could see the owner's pause only after its lease ran out; it then could not record its own pause and the fold counted its claim as an attempt. The fold now treats the owner's pause as ending the claim in progress without an attempt (unless that term already finished or failed). Found by weirdnet-agent's `jobs` tests on a loaded runner (Windows CI, and locally with six test runs in parallel).

Checks run: `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`, `cargo test --all-features` (new unit test `an_owner_pause_spares_only_the_attempt_in_progress`), `cargo doc -D warnings`; weirdnet-agent's six job tests against this tree, 18 runs six at a time, all passing (before: 6 of 18 failed).

Not tested: devices on 0.8.1 and 0.8.2 folding the same job can disagree on its attempt count after such a pause (status is the same); move job voters together.

What's left and next: release 0.8.2; weirdnet-agent 0.5.6 locks it.

## 2026-11-25: released 0.8.1

What changed: `release: v0.8.1` ([`cf8d275`](https://github.com/WeirdBrains/weirdnet-sync/commit/cf8d275e1bbb110f79a251b7a9613a273584b8a8)), annotated tag [`v0.8.1`](https://github.com/WeirdBrains/weirdnet-sync/releases/tag/v0.8.1), published to [crates.io](https://crates.io/crates/weirdnet-sync/0.8.1) with `scripts/weirdnet_release.py --patch` from weirdnet-project-helpers.

Checks run: CI on the release commit passed on Linux, macOS and Windows.

Not tested: as in the entry below.

What's left and next: [weirdnet-agent](https://github.com/WeirdBrains/weirdnet-agent) 0.5.6 builds its `jobs` feature on this release. Possible follow-up: `Cargo.lock` still resolves the yanked weirdnet-net 0.8.0 and weirdnet-keys 0.1.0 (a `cargo update` warning, no build change).

## 2026-11-25: job rules, pause and resume, voter limits (for 0.8.1)

What changed: additive job features for synced training jobs (requested for Ymir's resume-on-another-node work), in [`1be60da`](https://github.com/WeirdBrains/weirdnet-sync/commit/1be60daf8edfc40fc4a6dbddbd0bfd1c915b2855) and docs/CI in [`4e2b96c`](https://github.com/WeirdBrains/weirdnet-sync/commit/4e2b96c4dca1e2e63b73ea678a8179dee296f7fd).

- `JobRules` on `JobSpec`: candidates and a role (claims from anyone else are ignored when folding and refused by voters that have the job), a takeover wait after a lapsed claim (voter-side), and a retry backoff (`JobView::not_before_ms`, `LeaseError::NotYet`).
- `JobEvent::Paused` (holder or owner; not an attempt) and `JobEvent::Resumed`, `Jobs::pause`/`resume`, `JobStatus::Paused`.
- `JobEvent::Note`: last-writer-wins holder notes (progress, checkpoint copies).
- `Voter::with_limits` per lease-name prefix and job-derived limits (a job's own claim time up to one hour); a voter persists its longest grant and waits it out after a restart.
- `Leases::term_seen`.
- Jobs without rules fold exactly as in 0.8.0; specs without rules encode byte-identically; 0.8.0 devices skip the new events.
- CI also runs `cargo test --all-features` on macOS and Windows.

Checks run: `cargo fmt --check`; `cargo clippy --all-targets` (default and all features, `-D warnings`); `cargo test` (default, all and no default features: 73 unit tests, 13 lease/job network tests, 5 service tests, the 0.7.1 compatibility test); `cargo doc -D warnings`; `cargo semver-checks` against 0.8.0 (no semver update required).

Compatibility: `tests/compat_07.rs` links a published 0.7.1 device and this version over `/weirdnet/sync/2` (memory transport), shares a sealed record type both ways and compares the stored log entries byte for byte. Nothing migrates for records; apps that build `SyncState` with a struct literal still add `voter: None` (a 0.8.0 change).

Not tested: live nodes on real networks; mixed 0.8.0/0.8.1 voter sets beyond the encoding tests (a 0.8.0 voter ignores job rules and grants at most its own maximum).

What's left and next: release 0.8.1, then weirdnet-agent's `jobs` feature on top of it.
