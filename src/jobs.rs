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
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SyncError};
use crate::hlc::Hlc;
use crate::lease::{LeaseConfig, LeaseError, LeaseHandle, LeaseName, Leases, Term};
use crate::net::SyncState;
use crate::protocol::{decode, encode};

const JOB_DOMAIN: &[u8] = b"weirdnet-sync/v1/job\n";
/// Longest job id.
pub const MAX_JOB_ID: usize = 128;

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
}

impl JobSpec {
    /// Three attempts, 15 s claims, priority 0.
    pub fn new(id: impl Into<String>, kind: impl Into<String>, body: Vec<u8>) -> Self {
        Self { id: id.into(), kind: kind.into(), body, priority: 0, max_attempts: 3, claim_ms: 15_000 }
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
}

impl JobEvent {
    fn term(&self) -> Option<Term> {
        match self {
            JobEvent::Claimed { term, .. } | JobEvent::Checkpoint { term, .. } | JobEvent::Finished { term, .. } | JobEvent::Failed { term, .. } => {
                Some(*term)
            }
            JobEvent::Posted(_) | JobEvent::Cancelled => None,
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
}

/// A job folded from its events.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JobView {
    pub spec: JobSpec,
    pub status: JobStatus,
    /// Distinct claimed terms.
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
            (_, None) => return Err(SyncError::Protocol("use post or cancel for that event".into())),
            _ => {}
        }
        self.append(now_ms, id, &ev)
    }

    pub fn cancel(&mut self, now_ms: u64, id: &str) -> Result<()> {
        self.append(now_ms, id, &JobEvent::Cancelled)
    }

    fn events(&self, id: &str) -> Vec<(JobEvent, String, Hlc)> {
        let mut evs: Vec<(JobEvent, String, Hlc)> = self
            .state
            .signed_docs(JOB_DOMAIN, &self.typ, id)
            .into_iter()
            .filter_map(|(d, hlc)| decode::<JobEvent>(&d.body).ok().map(|e| (e, d.signer, hlc)))
            .collect();
        evs.sort_by(|a, b| a.2.cmp_total(&b.2));
        evs
    }

    /// The job folded from its events, `None` if it was never posted.
    pub fn view(&self, id: &str) -> Option<JobView> {
        fold(self.events(id))
    }

    /// Ids of every job posted under this type.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.state.log.iter().filter(|e| e.typ == self.typ).map(|e| e.record_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
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

fn fold(evs: Vec<(JobEvent, String, Hlc)>) -> Option<JobView> {
    let spec = evs.iter().find_map(|(e, _, _)| if let JobEvent::Posted(s) = e { Some(s.clone()) } else { None })?;
    let mut claim: Option<(String, Term)> = None;
    let mut terms: Vec<Term> = Vec::new();
    let mut checkpoints = Vec::new();
    let mut finished: Option<(Term, Vec<u8>, Hlc)> = None;
    let mut failed: Option<(Term, String, bool)> = None;
    let mut cancelled: Option<Hlc> = None;
    // Who claimed each term: a term's checkpoints, result and failure count only from it.
    let claimers: std::collections::HashMap<Term, &str> = evs
        .iter()
        .filter_map(|(e, signer, _)| match e {
            JobEvent::Claimed { term, by } if by == signer => Some((*term, signer.as_str())),
            _ => None,
        })
        .collect();
    let by_claimer = |term: &Term, signer: &str| claimers.get(term).is_some_and(|c| *c == signer);
    for (e, signer, hlc) in &evs {
        match e {
            // A claim counts only from the device it names.
            JobEvent::Claimed { term, by } if by == signer => {
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
                if failed.as_ref().is_none_or(|(t, _, _)| term >= t) {
                    failed = Some((*term, reason.clone(), *retry));
                }
            }
            JobEvent::Cancelled if cancelled.is_none() => cancelled = Some(hlc.clone()),
            _ => {}
        }
    }
    let attempts = terms.len() as u32;
    let finished_before_cancel = match (&finished, &cancelled) {
        (Some((_, _, f)), Some(c)) => f.cmp_total(c).is_lt(),
        _ => false,
    };
    let status = if cancelled.is_some() && !finished_before_cancel {
        JobStatus::Cancelled
    } else if finished.is_some() {
        JobStatus::Done
    } else {
        match (&claim, &failed) {
            (Some((_, ct)), Some((ft, _, retry))) if ft >= ct => {
                if *retry && attempts < spec.max_attempts {
                    JobStatus::Open
                } else {
                    JobStatus::Failed
                }
            }
            (Some(_), _) => JobStatus::Claimed,
            (None, _) => JobStatus::Open,
        }
    };
    let resume_from = checkpoints.iter().max_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1))).map(|c| c.2.clone());
    Some(JobView { spec, status, attempts, claim, checkpoints, resume_from, result: finished.map(|f| f.1), failure: failed.map(|f| f.1) })
}

impl Leases {
    /// Claim job `id` under `typ`: acquire its lease (the job's claim duration, `cfg`'s
    /// voters) and write `Claimed`. Fails with `LeaseError::Held` while another device works
    /// on it. Renew the handle with [`Leases::renew`] while working.
    pub fn claim_job(&self, typ: &str, id: &str, cfg: &LeaseConfig) -> std::result::Result<LeaseHandle, LeaseError> {
        let name = job_lease(typ, id)?;
        let spec = {
            let mut st = self.state().lock().map_err(|_| LeaseError::Sync("sync state lock poisoned".into()))?;
            let jobs = Jobs::new(&mut st, typ);
            let view = jobs.view(id).ok_or_else(|| LeaseError::Sync(format!("no job {id}")))?;
            if !matches!(view.status, JobStatus::Open | JobStatus::Claimed) {
                return Err(LeaseError::Sync(format!("job {id} is {:?}", view.status)));
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
}
