//! A job log (since 0.8): jobs posted to the op log, claimed under a per-job lease, with
//! checkpoints, results and re-claims after a failure.
//!
//! Claiming a job is acquiring the lease `<type>/<job id>` with the same voters as any lease
//! ([`Leases::claim_job`]); its term is the attempt's fencing token. The holder renews while it
//! works and writes [`JobEvent::Checkpoint`]s. If it dies, its claim lapses at the voters and
//! another eligible device acquires the next term and carries on from
//! [`JobView::resume_from`].
//!
//! Every event is signed by the writing device's node key and counts only while its signer is
//! active; folding is deterministic, so every device computes the same [`JobView`]. A holder
//! that lost its lease mid-write may still land a late event from a lower term: jobs must be
//! idempotent per item, and side effects that must happen once are fenced with
//! [`FenceGuard`](crate::lease::FenceGuard).
//!
//! Since 0.8.1 a job can carry [`JobRules`]: who may claim it (candidates and a role grant,
//! enforced in the fold and by voters), how long voters wait after a claim lapses before
//! granting it to another device, and a backoff after a retryable failure. Jobs can be
//! paused ([`JobEvent::Paused`], not counted as an attempt) and resumed
//! ([`JobEvent::Resumed`]), and holders can keep last-writer-wins [`JobEvent::Note`]s. Jobs
//! posted without rules fold exactly as in 0.8.0, and 0.8.0 devices skip the new events.
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SyncError};
use crate::hlc::Hlc;
use crate::lease::{LeaseConfig, LeaseError, LeaseHandle, LeaseLimits, LeaseName, Leases, Term};
use crate::net::SyncState;
use crate::protocol::{decode, encode};
use crate::roster::Roster;

const JOB_DOMAIN: &[u8] = b"weirdnet-sync/v1/job\n";
/// Longest job id.
pub const MAX_JOB_ID: usize = 128;
/// The longest claim a voter grants from a job's own [`JobSpec::claim_ms`] (one hour).
pub const MAX_JOB_CLAIM: Duration = Duration::from_secs(3_600);

/// Who may claim a job and how claims hand over (since 0.8.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobRules {
    /// After a claim lapses (its holder stopped renewing without letting go), voters refuse
    /// another device for this long (ms). A clean release (pause, failure, finish) has no wait.
    #[serde(default)]
    pub takeover_after_ms: u64,
    /// After a retryable failure the job can't be claimed for this long (ms), counted from
    /// the failure's HLC time.
    #[serde(default)]
    pub retry_backoff_ms: u64,
    /// Peer ids that may claim it; empty means any device (with [`role`](Self::role) if set).
    #[serde(default)]
    pub candidates: Vec<String>,
    /// The role grant a claimer must hold (`Roster::has_role`).
    #[serde(default)]
    pub role: Option<String>,
}

impl JobRules {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_takeover_after(mut self, wait: Duration) -> Self {
        self.takeover_after_ms = wait.as_millis() as u64;
        self
    }

    pub fn with_retry_backoff(mut self, wait: Duration) -> Self {
        self.retry_backoff_ms = wait.as_millis() as u64;
        self
    }

    pub fn with_candidates<S: Into<String>>(mut self, peers: impl IntoIterator<Item = S>) -> Self {
        self.candidates = peers.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn takeover_after(&self) -> Duration {
        Duration::from_millis(self.takeover_after_ms)
    }

    pub fn retry_backoff(&self) -> Duration {
        Duration::from_millis(self.retry_backoff_ms)
    }

    /// Whether `peer` may claim under these rules.
    pub fn allows(&self, roster: &Roster, peer: &str) -> bool {
        self.allows_with(peer, &|p, r| roster.has_role(p, r))
    }

    fn allows_with(&self, peer: &str, has_role: &dyn Fn(&str, &str) -> bool) -> bool {
        (self.candidates.is_empty() || self.candidates.iter().any(|c| c == peer)) && self.role.as_deref().is_none_or(|r| has_role(peer, r))
    }
}

/// A job as posted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobSpec {
    pub id: String,
    pub kind: String,
    #[serde(with = "crate::bytes")]
    pub body: Vec<u8>,
    pub priority: u8,
    /// Attempts before a retryable failure becomes final.
    pub max_attempts: u32,
    /// How long each claim's lease lasts (ms).
    pub claim_ms: u64,
    /// Claim rules (since 0.8.1); `None` folds as in 0.8.0. Left off the wire when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<JobRules>,
}

impl JobSpec {
    /// Three attempts, 15 s claims, priority 0, no rules.
    pub fn new(id: impl Into<String>, kind: impl Into<String>, body: Vec<u8>) -> Self {
        Self { id: id.into(), kind: kind.into(), body, priority: 0, max_attempts: 3, claim_ms: 15_000, rules: None }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n.max(1);
        self
    }

    pub fn with_claim(mut self, claim: Duration) -> Self {
        self.claim_ms = claim.as_millis() as u64;
        self
    }

    /// Claim rules (since 0.8.1).
    pub fn with_rules(mut self, rules: JobRules) -> Self {
        self.rules = Some(rules);
        self
    }

    pub fn claim(&self) -> Duration {
        Duration::from_millis(self.claim_ms)
    }
}

/// One log entry for a job (record id = job id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum JobEvent {
    Posted(JobSpec),
    Claimed {
        term: Term,
        by: String,
    },
    /// App-defined progress (for example the items done).
    Checkpoint {
        term: Term,
        seq: u64,
        #[serde(with = "crate::bytes")]
        data: Vec<u8>,
    },
    Finished {
        term: Term,
        #[serde(with = "crate::bytes")]
        result: Vec<u8>,
    },
    Failed {
        term: Term,
        reason: String,
        retry: bool,
    },
    Cancelled,
    /// The job stops without failing (since 0.8.1). With a term, its holder lets go and that
    /// claim is not counted as an attempt; without one, the owner holds the job and a running
    /// holder should pause. Either way it stays [`JobStatus::Paused`] until
    /// [`Resumed`](Self::Resumed).
    Paused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        term: Option<Term>,
    },
    /// The owner puts a paused job back up for claims (since 0.8.1).
    Resumed,
    /// A holder's last-writer-wins note under `key` (since 0.8.1): progress, or which devices
    /// hold a copy of a checkpoint, without writing a new checkpoint.
    Note {
        term: Term,
        key: String,
        #[serde(with = "crate::bytes")]
        data: Vec<u8>,
    },
}

impl JobEvent {
    fn term(&self) -> Option<Term> {
        match self {
            JobEvent::Claimed { term, .. }
            | JobEvent::Checkpoint { term, .. }
            | JobEvent::Finished { term, .. }
            | JobEvent::Failed { term, .. }
            | JobEvent::Note { term, .. } => Some(*term),
            JobEvent::Paused { term } => *term,
            JobEvent::Posted(_) | JobEvent::Cancelled | JobEvent::Resumed => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobStatus {
    Open,
    Claimed,
    Done,
    Failed,
    Cancelled,
    /// Paused by its holder or owner until resumed (since 0.8.1).
    Paused,
}

/// A job folded from its events.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JobView {
    pub spec: JobSpec,
    pub status: JobStatus,
    /// Distinct claimed terms, less the ones their holder paused.
    pub attempts: u32,
    /// The claim with the highest term: who and which term.
    pub claim: Option<(String, Term)>,
    /// Every checkpoint as `(term, seq, data)`, oldest first; merge them if the app's
    /// checkpoints are partial (a union of finished items).
    pub checkpoints: Vec<(Term, u64, Vec<u8>)>,
    /// The last checkpoint of the highest term.
    pub resume_from: Option<Vec<u8>>,
    pub result: Option<Vec<u8>>,
    /// The reason of the last failure.
    pub failure: Option<String>,
    /// The device that posted it (since 0.8.1).
    pub owner: String,
    /// When it was posted, as the post's HLC wall time in ms (since 0.8.1).
    pub posted_ms: u64,
    /// Not claimable before this wall time (ms), after a retryable failure under
    /// [`JobRules::retry_backoff_ms`] (since 0.8.1).
    pub not_before_ms: Option<u64>,
    /// HLC wall time (ms) of the newest event from the current claim's holder (since 0.8.1).
    pub last_seen_ms: Option<u64>,
    /// The newest note per key from a claim's holder, highest term first (since 0.8.1).
    pub notes: BTreeMap<String, (Term, Vec<u8>)>,
    /// When the status became what it is, as an HLC wall time in ms (since 0.8.1).
    pub changed_ms: u64,
}

impl JobView {
    /// Whether a device may try to claim it at wall time `now_ms`: open (or claimed, whose
    /// lease may have lapsed; the voters decide) and past any backoff.
    pub fn claimable_at(&self, now_ms: u64) -> bool {
        matches!(self.status, JobStatus::Open | JobStatus::Claimed) && self.not_before_ms.is_none_or(|t| now_ms >= t)
    }
}

fn check_id(id: &str) -> Result<()> {
    let ok = !id.is_empty() && id.len() <= MAX_JOB_ID && id.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:+#".contains(c));
    if ok { Ok(()) } else { Err(SyncError::Protocol(format!("bad job id {id:?}"))) }
}

/// The lease a job's claim is: `<typ>/<id>`.
pub fn job_lease(typ: &str, id: &str) -> Result<LeaseName> {
    check_id(id)?;
    LeaseName::new(format!("{typ}/{id}"))
}

/// The jobs under one record type (for example `ymir.jobs`).
pub struct Jobs<'a> {
    state: &'a mut SyncState,
    typ: String,
}

impl<'a> Jobs<'a> {
    pub fn new(state: &'a mut SyncState, typ: impl Into<String>) -> Self {
        Self { state, typ: typ.into() }
    }

    fn append(&mut self, now_ms: u64, id: &str, ev: &JobEvent) -> Result<()> {
        check_id(id)?;
        let doc = self.state.sign_doc(JOB_DOMAIN, &self.typ, id, encode(ev)?)?;
        self.state.write(now_ms, &self.typ, id, &encode(&doc)?)?;
        Ok(())
    }

    /// Post a job. Posting an id twice keeps the first spec.
    pub fn post(&mut self, now_ms: u64, spec: JobSpec) -> Result<()> {
        let id = spec.id.clone();
        self.append(now_ms, &id, &JobEvent::Posted(spec))
    }

    /// Record an event of the attempt `lease` holds: its term must be the lease's, and the
    /// lease must be this job's and still valid.
    pub fn record(&mut self, now_ms: u64, id: &str, lease: &LeaseHandle, ev: JobEvent) -> Result<()> {
        let want = job_lease(&self.typ, id)?;
        if lease.name() != &want || !lease.is_valid() || lease.holder() != self.state.our_cert.peer_id {
            return Err(SyncError::NotPermitted("not holding this job's claim".into()));
        }
        match (&ev, ev.term()) {
            (JobEvent::Claimed { by, .. }, _) if *by != self.state.our_cert.peer_id => {
                return Err(SyncError::NotPermitted("a claim names its writer".into()));
            }
            (_, Some(t)) if t != lease.term() => return Err(SyncError::NotPermitted("the event's term is not the lease's".into())),
            (_, None) => return Err(SyncError::Protocol("use post, pause, resume or cancel for that event".into())),
            _ => {}
        }
        self.append(now_ms, id, &ev)
    }

    /// Cancel a job. Under [`JobRules`] only its owner or a full (non-service) device of the
    /// user may (others' cancels are ignored by the fold).
    pub fn cancel(&mut self, now_ms: u64, id: &str) -> Result<()> {
        self.check_owner(id)?;
        self.append(now_ms, id, &JobEvent::Cancelled)
    }

    /// Hold a job as its owner (since 0.8.1): it stays paused until [`resume`](Self::resume),
    /// and a running holder should pause.
    pub fn pause(&mut self, now_ms: u64, id: &str) -> Result<()> {
        self.check_owner(id)?;
        self.append(now_ms, id, &JobEvent::Paused { term: None })
    }

    /// Put a paused job back up for claims (since 0.8.1).
    pub fn resume(&mut self, now_ms: u64, id: &str) -> Result<()> {
        self.check_owner(id)?;
        self.append(now_ms, id, &JobEvent::Resumed)
    }

    fn check_owner(&self, id: &str) -> Result<()> {
        let me = self.state.our_cert.peer_id.as_str();
        match view_in(self.state, &self.typ, id) {
            Some(v) if !owner_may(&v.spec, &v.owner, me, &|p| self.state.roster.is_service(p)) => {
                Err(SyncError::NotPermitted("only the job's owner or a full device may do that".into()))
            }
            _ => Ok(()),
        }
    }

    /// The job folded from its events, `None` if it was never posted.
    pub fn view(&self, id: &str) -> Option<JobView> {
        view_in(self.state, &self.typ, id)
    }

    /// Ids of every job posted under this type.
    pub fn ids(&self) -> Vec<String> {
        ids_in(self.state, &self.typ)
    }

    /// Jobs to (re)claim: open, or claimed and not finished (whether the claim is still alive
    /// is the lease's to say). Highest priority first.
    pub fn open(&self) -> Vec<JobView> {
        let mut v: Vec<JobView> =
            self.ids().iter().filter_map(|id| self.view(id)).filter(|j| matches!(j.status, JobStatus::Open | JobStatus::Claimed)).collect();
        v.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority).then_with(|| a.spec.id.cmp(&b.spec.id)));
        v
    }
}

fn ids_in(state: &SyncState, typ: &str) -> Vec<String> {
    let mut ids: Vec<String> = state.log.iter().filter(|e| e.typ == typ).map(|e| e.record_id.clone()).collect();
    ids.sort();
    ids.dedup();
    ids
}

fn events_in(state: &SyncState, typ: &str, id: &str) -> Vec<(JobEvent, String, Hlc)> {
    let mut evs: Vec<(JobEvent, String, Hlc)> = state
        .signed_docs(JOB_DOMAIN, typ, id)
        .into_iter()
        .filter_map(|(d, hlc)| decode::<JobEvent>(&d.body).ok().map(|e| (e, d.signer, hlc)))
        .collect();
    evs.sort_by(|a, b| a.2.cmp_total(&b.2));
    evs
}

fn view_in(state: &SyncState, typ: &str, id: &str) -> Option<JobView> {
    let roster = &state.roster;
    fold(events_in(state, typ, id), &|p, r| roster.has_role(p, r), &|p| roster.is_service(p))
}

/// Whether `signer` may pause, resume or cancel: anyone without rules (as in 0.8.0), else the
/// owner or a full device of the user.
fn owner_may(spec: &JobSpec, owner: &str, signer: &str, is_service: &dyn Fn(&str) -> bool) -> bool {
    spec.rules.is_none() || signer == owner || !is_service(signer)
}

type RoleCheck<'a> = &'a dyn Fn(&str, &str) -> bool;
type ServiceCheck<'a> = &'a dyn Fn(&str) -> bool;

fn fold(evs: Vec<(JobEvent, String, Hlc)>, has_role: RoleCheck, is_service: ServiceCheck) -> Option<JobView> {
    let (spec, owner, posted) =
        evs.iter().find_map(|(e, s, h)| if let JobEvent::Posted(sp) = e { Some((sp.clone(), s.clone(), h.clone())) } else { None })?;
    let may_claim = |signer: &str| spec.rules.as_ref().is_none_or(|r| r.allows_with(signer, has_role));
    let owner_op = |signer: &str| owner_may(&spec, &owner, signer, is_service);
    let mut claim: Option<(String, Term)> = None;
    let mut terms: Vec<Term> = Vec::new();
    let mut checkpoints = Vec::new();
    let mut finished: Option<(Term, Vec<u8>, Hlc)> = None;
    let mut failed: Option<(Term, String, bool, Hlc)> = None;
    let mut cancelled: Option<Hlc> = None;
    let mut notes: BTreeMap<String, (Term, Vec<u8>, Hlc)> = BTreeMap::new();
    let mut holder_paused: Vec<Term> = Vec::new();
    // Who claimed each term: a term's checkpoints, result and failure count only from it, and
    // under rules only claims from allowed devices count at all.
    let claimers: HashMap<Term, &str> = evs
        .iter()
        .filter_map(|(e, signer, _)| match e {
            JobEvent::Claimed { term, by } if by == signer && may_claim(signer) => Some((*term, signer.as_str())),
            _ => None,
        })
        .collect();
    let by_claimer = |term: &Term, signer: &str| claimers.get(term).is_some_and(|c| *c == signer);
    let top = claimers.keys().max().copied();
    // Paused or not, in HLC order; a holder's pause counts only for the highest term.
    let mut paused: Option<bool> = None;
    let mut paused_at = posted.clone();
    for (e, signer, hlc) in &evs {
        match e {
            // A claim counts only from the device it names (and, under rules, an allowed one).
            JobEvent::Claimed { term, by } if by == signer && by_claimer(term, signer) => {
                if !terms.contains(term) {
                    terms.push(*term);
                }
                if claim.as_ref().is_none_or(|(_, t)| term > t) {
                    claim = Some((by.clone(), *term));
                }
            }
            JobEvent::Checkpoint { term, seq, data } if by_claimer(term, signer) => checkpoints.push((*term, *seq, data.clone())),
            JobEvent::Finished { term, result } if by_claimer(term, signer) => {
                if finished.as_ref().is_none_or(|(t, _, _)| term > t) {
                    finished = Some((*term, result.clone(), hlc.clone()));
                }
            }
            JobEvent::Failed { term, reason, retry } if by_claimer(term, signer) => {
                if failed.as_ref().is_none_or(|(t, _, _, _)| term >= t) {
                    failed = Some((*term, reason.clone(), *retry, hlc.clone()));
                }
            }
            JobEvent::Note { term, key, data } if by_claimer(term, signer) => {
                let newer = notes.get(key).is_none_or(|(t, _, h)| term > t || (term == t && hlc.cmp_total(h).is_gt()));
                if newer {
                    notes.insert(key.clone(), (*term, data.clone(), hlc.clone()));
                }
            }
            JobEvent::Paused { term: Some(t) } if by_claimer(t, signer) => {
                if !holder_paused.contains(t) {
                    holder_paused.push(*t);
                }
                if Some(*t) == top {
                    paused = Some(true);
                    paused_at = hlc.clone();
                }
            }
            JobEvent::Paused { term: None } if owner_op(signer) => {
                // The owner's pause ends the attempt in progress without counting it, whether
                // or not its holder gets its own pause into the log before its lease runs out
                // (voters stop renewing a paused job's claim).
                if let Some((_, t)) = &claim {
                    let ended = finished.as_ref().is_some_and(|f| f.0 == *t) || failed.as_ref().is_some_and(|f| f.0 == *t);
                    if !ended && !holder_paused.contains(t) {
                        holder_paused.push(*t);
                    }
                }
                paused = Some(true);
                paused_at = hlc.clone();
            }
            JobEvent::Resumed if owner_op(signer) && paused == Some(true) => {
                paused = Some(false);
                paused_at = hlc.clone();
            }
            JobEvent::Cancelled if cancelled.is_none() && owner_op(signer) => cancelled = Some(hlc.clone()),
            _ => {}
        }
    }
    let attempts = terms.iter().filter(|t| !holder_paused.contains(t)).count() as u32;
    let finished_before_cancel = match (&finished, &cancelled) {
        (Some((_, _, f)), Some(c)) => f.cmp_total(c).is_lt(),
        _ => false,
    };
    let failure_state = match (&claim, &failed) {
        (Some((_, ct)), Some((ft, _, retry, _))) if ft >= ct => {
            Some(if *retry && attempts < spec.max_attempts { JobStatus::Open } else { JobStatus::Failed })
        }
        _ => None,
    };
    let holder_let_go = claim.as_ref().is_some_and(|(_, ct)| holder_paused.contains(ct));
    let mut changed = claim
        .as_ref()
        .and_then(|(by, t)| evs.iter().find(|(e, s, _)| matches!(e, JobEvent::Claimed { term, .. } if term == t) && s == by).map(|x| x.2.clone()))
        .unwrap_or_else(|| posted.clone());
    let status = if let Some(c) = cancelled.as_ref().filter(|_| !finished_before_cancel) {
        changed = c.clone();
        JobStatus::Cancelled
    } else if let Some((_, _, f)) = &finished {
        changed = f.clone();
        JobStatus::Done
    } else if failure_state == Some(JobStatus::Failed) {
        changed = failed.as_ref().map(|f| f.3.clone()).unwrap_or(changed);
        JobStatus::Failed
    } else if paused == Some(true) {
        changed = paused_at.clone();
        JobStatus::Paused
    } else if let Some(s) = failure_state {
        changed = failed.as_ref().map(|f| f.3.clone()).unwrap_or(changed);
        if paused == Some(false) && paused_at.cmp_total(&changed).is_gt() {
            changed = paused_at.clone();
        }
        s
    } else if holder_let_go || claim.is_none() {
        if paused == Some(false) {
            changed = paused_at.clone();
        }
        JobStatus::Open
    } else {
        JobStatus::Claimed
    };
    let not_before_ms = match (&failure_state, &failed, &spec.rules) {
        (Some(JobStatus::Open), Some((_, _, _, h)), Some(r)) if r.retry_backoff_ms > 0 => Some(h.physical_ms.saturating_add(r.retry_backoff_ms)),
        _ => None,
    };
    let last_seen_ms =
        claim.as_ref().and_then(|(by, t)| evs.iter().filter(|(e, s, _)| s == by && e.term() == Some(*t)).map(|(_, _, h)| h.physical_ms).max());
    let resume_from = checkpoints.iter().max_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1))).map(|c| c.2.clone());
    Some(JobView {
        spec,
        status,
        attempts,
        claim,
        checkpoints,
        resume_from,
        result: finished.map(|f| f.1),
        failure: failed.map(|f| f.1),
        owner,
        posted_ms: posted.physical_ms,
        not_before_ms,
        last_seen_ms,
        notes: notes.into_iter().map(|(k, (t, d, _))| (k, (t, d))).collect(),
        changed_ms: changed.physical_ms,
    })
}

impl SyncState {
    /// What a voter applies to an ask for lease `name` when it is a job's claim lease and
    /// this device has the job with [`JobRules`]: the job's claim time as the longest grant
    /// (up to [`MAX_JOB_CLAIM`]) and its takeover wait. `Err` carries why the asker can't
    /// have it (not a candidate, the job isn't claimable, or it is in its backoff).
    pub(crate) fn job_lease_limits(&self, name: &LeaseName, from: &str, renew: bool) -> std::result::Result<Option<LeaseLimits>, &'static str> {
        let Some((typ, id)) = name.as_str().rsplit_once('/') else { return Ok(None) };
        if check_id(id).is_err() {
            return Ok(None);
        }
        let Some(view) = view_in(self, typ, id) else { return Ok(None) };
        let Some(rules) = view.spec.rules.as_ref() else { return Ok(None) };
        if !rules.allows(&self.roster, from) {
            return Err("not-a-candidate");
        }
        if !matches!(view.status, JobStatus::Open | JobStatus::Claimed) {
            return Err("job-closed");
        }
        if !renew && view.not_before_ms.is_some_and(|t| wall_ms() < t) {
            return Err("job-backoff");
        }
        Ok(Some(LeaseLimits::new(view.spec.claim().min(MAX_JOB_CLAIM), rules.takeover_after())))
    }
}

impl Leases {
    /// Claim job `id` under `typ`: acquire its lease (the job's claim duration, `cfg`'s
    /// voters) and write `Claimed`. Fails with `LeaseError::Held` while another device works
    /// on it (or voters still wait out a lapsed claim's takeover time),
    /// `LeaseError::NotEligible` when the job's rules leave this device out, and
    /// `LeaseError::NotYet` during a retry backoff. Renew the handle with [`Leases::renew`]
    /// (with `cfg` set to the job's claim time, see [`LeaseConfig::with_duration`]) while
    /// working.
    pub fn claim_job(&self, typ: &str, id: &str, cfg: &LeaseConfig) -> std::result::Result<LeaseHandle, LeaseError> {
        let name = job_lease(typ, id)?;
        let spec = {
            let st = self.state().lock().map_err(|_| LeaseError::Sync("sync state lock poisoned".into()))?;
            let view = view_in(&st, typ, id).ok_or_else(|| LeaseError::Sync(format!("no job {id}")))?;
            if !matches!(view.status, JobStatus::Open | JobStatus::Claimed) {
                return Err(LeaseError::Sync(format!("job {id} is {:?}", view.status)));
            }
            if let Some(r) = &view.spec.rules
                && !r.allows(&st.roster, &st.our_cert.peer_id)
            {
                return Err(LeaseError::NotEligible);
            }
            let now = wall_ms();
            if let Some(t) = view.not_before_ms.filter(|t| now < *t) {
                return Err(LeaseError::NotYet { retry_in: Duration::from_millis(t - now) });
            }
            view.spec
        };
        let cfg = cfg.clone().with_duration(spec.claim());
        let handle = self.acquire(&name, &cfg)?;
        let mut st = self.state().lock().map_err(|_| LeaseError::Sync("sync state lock poisoned".into()))?;
        let me = st.our_cert.peer_id.clone();
        Jobs::new(&mut st, typ).record(wall_ms(), id, &handle, JobEvent::Claimed { term: handle.term(), by: me })?;
        Ok(handle)
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::NodeId;

    /// Folds with nobody holding a role and every signer a full device.
    fn fold(evs: Vec<(JobEvent, String, Hlc)>) -> Option<JobView> {
        super::fold(evs, &|_, _| false, &|_| false)
    }

    fn hlc(ms: u64) -> Hlc {
        Hlc { physical_ms: ms, counter: 0, node_id: NodeId("n".into()) }
    }

    fn evs(list: Vec<(JobEvent, &str, u64)>) -> Vec<(JobEvent, String, Hlc)> {
        list.into_iter().map(|(e, s, t)| (e, s.to_string(), hlc(t))).collect()
    }

    fn spec() -> JobSpec {
        JobSpec::new("j1", "batch", b"prompts".to_vec()).with_max_attempts(2)
    }

    #[test]
    fn folding_claims_checkpoints_and_results() {
        assert!(fold(evs(vec![(JobEvent::Cancelled, "a", 1)])).is_none(), "never posted");
        let v = fold(evs(vec![(JobEvent::Posted(spec()), "a", 1)])).unwrap();
        assert_eq!((v.status, v.attempts), (JobStatus::Open, 0));
        let base = vec![
            (JobEvent::Posted(spec()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Checkpoint { term: Term(1), seq: 1, data: b"10".to_vec() }, "a", 3),
        ];
        let v = fold(evs(base.clone())).unwrap();
        assert_eq!((v.status, v.claim.clone(), v.resume_from.clone()), (JobStatus::Claimed, Some(("a".into(), Term(1))), Some(b"10".to_vec())));
        // A claim written by someone else for "a" doesn't count.
        let mut forged = base.clone();
        forged.push((JobEvent::Claimed { term: Term(9), by: "a".into() }, "b", 4));
        assert_eq!(fold(evs(forged)).unwrap().claim, Some(("a".into(), Term(1))));
        // b re-claims at term 2 and resumes from a's checkpoint; a late a-checkpoint loses.
        let mut re = base.clone();
        re.push((JobEvent::Claimed { term: Term(2), by: "b".into() }, "b", 5));
        re.push((JobEvent::Checkpoint { term: Term(2), seq: 1, data: b"20".to_vec() }, "b", 6));
        re.push((JobEvent::Checkpoint { term: Term(1), seq: 2, data: b"11".to_vec() }, "a", 7));
        let v = fold(evs(re.clone())).unwrap();
        assert_eq!((v.attempts, v.resume_from.clone(), v.checkpoints.len()), (2, Some(b"20".to_vec()), 3));
        // Finished: the highest term wins.
        let mut done = re.clone();
        done.push((JobEvent::Finished { term: Term(1), result: b"late".to_vec() }, "a", 8));
        done.push((JobEvent::Finished { term: Term(2), result: b"ok".to_vec() }, "b", 9));
        let v = fold(evs(done.clone())).unwrap();
        assert_eq!((v.status, v.result.clone()), (JobStatus::Done, Some(b"ok".to_vec())));
        // A cancel after it finished doesn't undo it; one before does.
        let mut after = done.clone();
        after.push((JobEvent::Cancelled, "a", 10));
        assert_eq!(fold(evs(after)).unwrap().status, JobStatus::Done);
        let mut before = re.clone();
        before.push((JobEvent::Cancelled, "a", 8));
        before.push((JobEvent::Finished { term: Term(2), result: b"ok".to_vec() }, "b", 9));
        assert_eq!(fold(evs(before)).unwrap().status, JobStatus::Cancelled);
    }

    #[test]
    fn a_worker_whose_clock_runs_ahead_does_not_win_by_hlc() {
        // a's clock is a day ahead: its term-1 events sort after b's term-2 ones by HLC.
        let day = 86_400_000;
        let e = vec![
            (JobEvent::Posted(spec()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", day + 2),
            (JobEvent::Checkpoint { term: Term(1), seq: 7, data: b"a7".to_vec() }, "a", day + 3),
            (JobEvent::Claimed { term: Term(2), by: "b".into() }, "b", 10),
            (JobEvent::Checkpoint { term: Term(2), seq: 1, data: b"b1".to_vec() }, "b", 11),
            (JobEvent::Finished { term: Term(1), result: b"a-late".to_vec() }, "a", day + 9),
        ];
        let mut sorted = evs(e.clone());
        sorted.sort_by(|a, b| a.2.cmp_total(&b.2));
        let v = fold(sorted).unwrap();
        assert_eq!(v.claim, Some(("b".into(), Term(2))));
        assert_eq!(v.resume_from, Some(b"b1".to_vec()));
        // A lower term's late result still lands (jobs are idempotent per item), but the
        // higher term's result replaces it as soon as it is written.
        assert_eq!(v.result, Some(b"a-late".to_vec()));
        let mut e2 = e;
        e2.push((JobEvent::Finished { term: Term(2), result: b"b-ok".to_vec() }, "b", 12));
        let mut sorted = evs(e2);
        sorted.sort_by(|a, b| a.2.cmp_total(&b.2));
        assert_eq!(fold(sorted).unwrap().result, Some(b"b-ok".to_vec()));
    }

    #[test]
    fn only_the_claimer_of_a_term_writes_for_it() {
        let e = vec![
            (JobEvent::Posted(spec()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Checkpoint { term: Term(1), seq: 1, data: b"a1".to_vec() }, "a", 3),
            // c never claimed term 1 (or any term): its events don't count.
            (JobEvent::Checkpoint { term: Term(1), seq: 9, data: b"c".to_vec() }, "c", 4),
            (JobEvent::Finished { term: Term(5), result: b"forged".to_vec() }, "c", 5),
            (JobEvent::Failed { term: Term(1), reason: "x".into(), retry: false }, "c", 6),
        ];
        let v = fold(evs(e)).unwrap();
        assert_eq!((v.status, v.resume_from.clone(), v.result.clone(), v.checkpoints.len()), (JobStatus::Claimed, Some(b"a1".to_vec()), None, 1));
    }

    #[test]
    fn retryable_failures_reopen_until_the_attempts_run_out() {
        let mut e = vec![
            (JobEvent::Posted(spec()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Failed { term: Term(1), reason: "oom".into(), retry: true }, "a", 3),
        ];
        let v = fold(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.failure.as_deref()), (JobStatus::Open, Some("oom")));
        e.push((JobEvent::Claimed { term: Term(2), by: "b".into() }, "b", 4));
        assert_eq!(fold(evs(e.clone())).unwrap().status, JobStatus::Claimed);
        e.push((JobEvent::Failed { term: Term(2), reason: "oom".into(), retry: true }, "b", 5));
        assert_eq!(fold(evs(e.clone())).unwrap().status, JobStatus::Failed, "two attempts were allowed");
        let final_fail = vec![
            (JobEvent::Posted(spec()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Failed { term: Term(1), reason: "bad input".into(), retry: false }, "a", 3),
        ];
        assert_eq!(fold(evs(final_fail)).unwrap().status, JobStatus::Failed);
    }

    #[test]
    fn job_ids_make_lease_names() {
        assert_eq!(job_lease("ymir.jobs", "42").unwrap().as_str(), "ymir.jobs/42");
        assert!(job_lease("ymir.jobs", "a/b").is_err());
        assert!(job_lease("ymir.jobs", "").is_err());
    }

    fn ruled() -> JobSpec {
        JobSpec::new("j2", "train", b"t".to_vec())
            .with_max_attempts(2)
            .with_rules(JobRules::new().with_role("ymir.model").with_candidates(["a", "b", "c"]).with_retry_backoff(Duration::from_millis(100)))
    }

    /// `a`, `b` and `z` hold the role; `z` is not a candidate; `svc` is a service device.
    fn fold_r(evs: Vec<(JobEvent, String, Hlc)>) -> Option<JobView> {
        super::fold(evs, &|p, r| r == "ymir.model" && ["a", "b", "z"].contains(&p), &|p| p == "svc" || p == "b")
    }

    #[test]
    fn rules_leave_out_claims_from_outside_the_role_or_candidates() {
        let e = vec![
            (JobEvent::Posted(ruled()), "a", 1),
            // z holds the role but is not a candidate; c is a candidate without the role.
            (JobEvent::Claimed { term: Term(1), by: "z".into() }, "z", 2),
            (JobEvent::Claimed { term: Term(2), by: "c".into() }, "c", 3),
            (JobEvent::Checkpoint { term: Term(2), seq: 1, data: b"c".to_vec() }, "c", 4),
        ];
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.claim.clone(), v.attempts, v.resume_from.clone()), (JobStatus::Open, None, 0, None));
        // Without rules the same claims count, as in 0.8.0.
        let mut plain = e.clone();
        plain[0] = (JobEvent::Posted(spec()), "a", 1);
        assert_eq!(fold_r(evs(plain)).unwrap().attempts, 2);
        let mut ok = e;
        ok.push((JobEvent::Claimed { term: Term(3), by: "b".into() }, "b", 5));
        let v = fold_r(evs(ok)).unwrap();
        assert_eq!((v.status, v.claim, v.attempts, v.owner.as_str()), (JobStatus::Claimed, Some(("b".into(), Term(3))), 1, "a"));
    }

    #[test]
    fn a_holder_pause_is_not_an_attempt_and_resume_reopens() {
        let mut e = vec![
            (JobEvent::Posted(ruled()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Checkpoint { term: Term(1), seq: 1, data: b"s100".to_vec() }, "a", 3),
            (JobEvent::Paused { term: Some(Term(1)) }, "a", 4),
        ];
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts, v.changed_ms), (JobStatus::Paused, 0, 4));
        // A service device that is not the owner can't resume it.
        e.push((JobEvent::Resumed, "svc", 5));
        assert_eq!(fold_r(evs(e.clone())).unwrap().status, JobStatus::Paused);
        e.push((JobEvent::Resumed, "a", 6));
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts, v.resume_from.clone(), v.changed_ms), (JobStatus::Open, 0, Some(b"s100".to_vec()), 6));
        e.push((JobEvent::Claimed { term: Term(2), by: "b".into() }, "b", 7));
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts, v.resume_from.clone()), (JobStatus::Claimed, 1, Some(b"s100".to_vec())));
        // A late pause from the old term doesn't pause the new claim.
        e.push((JobEvent::Paused { term: Some(Term(1)) }, "a", 8));
        assert_eq!(fold_r(evs(e)).unwrap().status, JobStatus::Claimed);
    }

    #[test]
    fn the_owner_pauses_and_resumes_and_a_service_device_cannot() {
        let mut e = vec![(JobEvent::Posted(ruled()), "a", 1), (JobEvent::Claimed { term: Term(1), by: "b".into() }, "b", 2)];
        e.push((JobEvent::Paused { term: None }, "svc", 3));
        e.push((JobEvent::Cancelled, "svc", 4));
        assert_eq!(fold_r(evs(e.clone())).unwrap().status, JobStatus::Claimed, "a service device is not the owner");
        e.push((JobEvent::Paused { term: None }, "a", 5));
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts), (JobStatus::Paused, 0), "the owner's pause doesn't use an attempt");
        // The holder stops and lets go; its claim is not an attempt.
        e.push((JobEvent::Paused { term: Some(Term(1)) }, "b", 6));
        e.push((JobEvent::Resumed, "a", 7));
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts), (JobStatus::Open, 0));
        e.push((JobEvent::Cancelled, "a", 8));
        assert_eq!(fold_r(evs(e)).unwrap().status, JobStatus::Cancelled);
    }

    #[test]
    fn an_owner_pause_spares_only_the_attempt_in_progress() {
        let mut e = vec![
            (JobEvent::Posted(ruled()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Failed { term: Term(1), reason: "oom".into(), retry: true }, "a", 3),
            (JobEvent::Claimed { term: Term(2), by: "b".into() }, "b", 200),
            // The holder's lease ran out before it could write its own pause.
            (JobEvent::Paused { term: None }, "a", 300),
        ];
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts), (JobStatus::Paused, 1), "the failed attempt still counts");
        e.push((JobEvent::Resumed, "a", 400));
        e.push((JobEvent::Claimed { term: Term(3), by: "a".into() }, "a", 500));
        assert_eq!(fold_r(evs(e)).unwrap().attempts, 2);
    }

    #[test]
    fn a_retryable_failure_waits_out_the_backoff_and_attempts_run_out() {
        let mut e = vec![
            (JobEvent::Posted(ruled()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Failed { term: Term(1), reason: "oom".into(), retry: true }, "a", 1_000),
        ];
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.not_before_ms), (JobStatus::Open, Some(1_100)));
        assert!(!v.claimable_at(1_050) && v.claimable_at(1_100));
        // A lapsed claim (no event after it) counts as an attempt too.
        e.push((JobEvent::Claimed { term: Term(2), by: "b".into() }, "b", 1_200));
        let v = fold_r(evs(e.clone())).unwrap();
        assert_eq!((v.status, v.attempts, v.not_before_ms), (JobStatus::Claimed, 2, None));
        e.push((JobEvent::Failed { term: Term(2), reason: "oom".into(), retry: true }, "b", 1_300));
        assert_eq!(fold_r(evs(e)).unwrap().status, JobStatus::Failed, "max_attempts 2");
    }

    #[test]
    fn notes_keep_the_newest_per_key_from_the_holder() {
        let e = vec![
            (JobEvent::Posted(ruled()), "a", 1),
            (JobEvent::Claimed { term: Term(1), by: "a".into() }, "a", 2),
            (JobEvent::Note { term: Term(1), key: "progress".into(), data: b"1".to_vec() }, "a", 3),
            (JobEvent::Note { term: Term(1), key: "progress".into(), data: b"2".to_vec() }, "a", 4),
            (JobEvent::Note { term: Term(1), key: "progress".into(), data: b"forged".to_vec() }, "b", 5),
            (JobEvent::Note { term: Term(1), key: "holders".into(), data: b"a,b".to_vec() }, "a", 6),
        ];
        let v = fold_r(evs(e)).unwrap();
        assert_eq!(v.notes.get("progress"), Some(&(Term(1), b"2".to_vec())));
        assert_eq!(v.notes.get("holders"), Some(&(Term(1), b"a,b".to_vec())));
        assert_eq!(v.last_seen_ms, Some(6));
    }

    /// `JobSpec` and `JobEvent` as 0.8.0 published them.
    mod v080 {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct JobSpec {
            pub id: String,
            pub kind: String,
            #[serde(with = "crate::bytes")]
            pub body: Vec<u8>,
            pub priority: u8,
            pub max_attempts: u32,
            pub claim_ms: u64,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "ev", rename_all = "kebab-case")]
        pub enum JobEvent {
            Posted(JobSpec),
            Claimed { term: crate::lease::Term, by: String },
            Cancelled,
        }
    }

    #[test]
    fn events_stay_readable_both_ways_with_0_8_0() {
        let old = v080::JobEvent::Posted(v080::JobSpec {
            id: "j1".into(),
            kind: "batch".into(),
            body: b"prompts".to_vec(),
            priority: 0,
            max_attempts: 2,
            claim_ms: 15_000,
        });
        let new = JobEvent::Posted(spec());
        assert_eq!(encode(&old).unwrap(), encode(&new).unwrap(), "a spec without rules encodes as in 0.8.0");
        assert_eq!(decode::<JobEvent>(&encode(&old).unwrap()).unwrap(), new);
        // A 0.8.0 device reads a spec with rules (ignoring them) and skips the new events.
        let ruled_old: v080::JobEvent = decode(&encode(&JobEvent::Posted(ruled())).unwrap()).unwrap();
        assert!(matches!(ruled_old, v080::JobEvent::Posted(s) if s.id == "j2"));
        for ev in [JobEvent::Paused { term: Some(Term(1)) }, JobEvent::Paused { term: None }, JobEvent::Resumed] {
            assert!(decode::<v080::JobEvent>(&encode(&ev).unwrap()).is_err());
            assert_eq!(decode::<JobEvent>(&encode(&ev).unwrap()).unwrap(), ev);
        }
        let note = JobEvent::Note { term: Term(1), key: "k".into(), data: vec![1, 2] };
        assert_eq!(decode::<JobEvent>(&encode(&note).unwrap()).unwrap(), note);
    }
}
