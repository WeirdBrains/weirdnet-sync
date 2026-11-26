# Handoff

Running log for [weirdnet-sync](https://github.com/WeirdBrains/weirdnet-sync), newest first. Shared rules: the collective `AGENTS.md` of [Weird Brains](https://weirdbrains.com) projects.

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
