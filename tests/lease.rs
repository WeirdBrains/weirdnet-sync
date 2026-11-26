//! Majority-vote leases, plans and jobs between service devices over weirdnet-net (memory
//! transport), with the voters taken from `ymir.inference` role grants.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, Multiaddr, Node, WEIRDNET};
use weirdnet_sync::{
    DeviceClass, FenceGuard, Identity, JobEvent, JobRules, JobSpec, JobStatus, Jobs, LeaseConfig, LeaseError, LeaseHandle, LeaseName, Leases,
    LinkBundle, Roster, SyncState, Term, Voter, Voters, job_lease, node_config, pull_from, start_node,
};

const T: &str = "ymir.pool";
const ROLE: &str = "ymir.inference";
const SEED: [u8; 32] = *b"SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS";
/// Short leases keep the tests quick; the voters' maximum (and restart grace) matches.
const LEASE: Duration = Duration::from_millis(3_000);

type N = Node<Vec<u8>, Vec<u8>>;

fn user() -> Keypair {
    let mut s = SEED;
    Keypair::ed25519_from_bytes(&mut s).unwrap()
}

fn peer(k: &Keypair) -> String {
    k.public().to_peer_id().to_string()
}

fn cert(user: &Keypair, k: &Keypair, label: &str, at: i64) -> NodeCert {
    WEIRDNET.certify(user, &user::user_id(&user.public()), &peer(k), label, at).unwrap()
}

fn addrs(n: &N) -> Vec<Multiaddr> {
    n.reachable_addrs().into_iter().map(|s| s.parse().unwrap()).collect()
}

fn cfg() -> LeaseConfig {
    LeaseConfig::for_role(ROLE).with_duration(LEASE).with_stagger(Duration::from_millis(100))
}

fn name(s: &str) -> LeaseName {
    LeaseName::new(s).unwrap()
}

/// One voting inference node: its state, node and lease client.
struct Inf {
    k: Keypair,
    st: Arc<Mutex<SyncState>>,
    node: Arc<N>,
    leases: Leases,
}

/// A phone (full device, not a voter) and `n` inference service nodes holding the role.
struct Pool {
    phone: SyncState,
    nodes: Vec<Inf>,
    book: Arc<Mutex<HashMap<String, Vec<Multiaddr>>>>,
}

fn pool(n: usize) -> Pool {
    let u = user();
    let kp = Keypair::generate_ed25519();
    let mut phone = SyncState::new(SEED.to_vec(), u.public(), cert(&u, &kp, "phone", 1), Some(&kp), vec![T.into()]).unwrap();
    phone.auto_first_rotation = false;
    let mut linked = Vec::new();
    for i in 0..n {
        let k = Keypair::generate_ed25519();
        let bundle = phone.service_bundle(&peer(&k), &[ROLE.to_string()], &[T.to_string()], 10 + i as i64).unwrap();
        let bytes = bundle.to_bytes().unwrap();
        let c = cert(&u, &k, &format!("inference{i}"), 10);
        phone.approve(c.clone(), 10).unwrap();
        linked.push((k, c, bytes));
    }
    let book: Arc<Mutex<HashMap<String, Vec<Multiaddr>>>> = Arc::default();
    let mut nodes = Vec::new();
    for (k, c, bytes) in linked {
        let mut st = SyncState::new_service(u.public(), c, &k, vec![T.into()], &LinkBundle::from_bytes(&bytes).unwrap()).unwrap();
        // Every device has synced the roster (all certs and grants) by now.
        st.roster = phone.roster.clone();
        st.set_voter(Some(Voter::new(Voters::Role(ROLE.into())).with_max_duration(LEASE)));
        let st = Arc::new(Mutex::new(st));
        let node = Arc::new(start_node(k.clone(), node_config(true), st.clone()).unwrap());
        book.lock().unwrap().insert(peer(&k), addrs(&node));
        let b = book.clone();
        let leases = Leases::new(node.clone(), st.clone()).with_addrs(move |p| b.lock().unwrap().get(p).cloned().unwrap_or_default());
        nodes.push(Inf { k, st, node, leases });
    }
    // Connect every pair up front, as a running pool would be, so the first rounds don't pay
    // for dialling.
    for (i, a) in nodes.iter().enumerate() {
        for b in &nodes[i + 1..] {
            let _ = a.node.connect(b.node.peer_id(), &addrs(&b.node));
        }
    }
    // Wait out the voters' start-up grace.
    std::thread::sleep(LEASE + Duration::from_millis(100));
    Pool { phone, nodes, book }
}

/// A crash: the node leaves the network (its voter and its lease client go with it).
fn kill(p: &mut Pool, i: usize) -> Inf {
    let b = p.nodes.remove(i);
    p.book.lock().unwrap().remove(&peer(&b.k));
    b.node.halt();
    b
}

/// A lease that should be granted: retries only rounds where too few voters answered in
/// time (a slow, loaded machine), never a `Held` or any other answer.
fn got(mut f: impl FnMut() -> Result<LeaseHandle, LeaseError>) -> LeaseHandle {
    let end = Instant::now() + LEASE * 4;
    loop {
        match f() {
            Ok(h) => return h,
            Err(LeaseError::NoQuorum { .. }) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("expected a grant, got {e:?}"),
        }
    }
}

fn retry_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn a_majority_elects_one_holder_and_terms_fence_the_old_one() {
    let p = pool(3);
    let (a, b) = (&p.nodes[0], &p.nodes[1]);
    let n = name("ymir.scheduler");
    let mut h1 = got(|| a.leases.acquire(&n, &cfg()));
    let t1 = h1.term();
    assert!(t1 >= Term(1));
    assert!(h1.is_valid() && h1.remaining() <= LEASE);
    match b.leases.acquire(&n, &cfg()) {
        Err(LeaseError::Held { holder, term, retry_in }) => {
            assert_eq!((holder, term), (peer(&a.k), t1));
            assert!(retry_in <= LEASE);
        }
        other => panic!("expected Held, got {other:?}"),
    }
    // Renewing keeps it (same term); the second candidate still can't take it.
    retry_until(LEASE, || a.leases.renew(&mut h1, &cfg()).ok()).expect("renewed");
    assert_eq!(h1.term(), t1);
    assert!(matches!(b.leases.acquire(&n, &cfg()), Err(LeaseError::Held { .. })));
    // Releasing lets the next one in at once, with a higher term.
    let mut fence = FenceGuard::new();
    fence.check(&n, h1.term()).unwrap();
    a.leases.release(h1.clone(), &cfg());
    // (Release is best effort: on a loaded machine a voter may still see the old promise.)
    let h2 = retry_until(LEASE * 2, || b.leases.acquire(&n, &cfg()).ok()).expect("taken after the release");
    assert!(h2.term() > h1.term());
    fence.check(&n, h2.term()).unwrap();
    assert!(fence.check(&n, h1.term()).is_err(), "the old holder's commands are refused");
    // The old holder can't renew a term that has been superseded.
    assert!(a.leases.renew(&mut h1, &cfg()).is_err());
    // A device without the role (the phone) can't stand.
    assert!(cfg().voters.resolve(&p.phone.roster).len() == 3 && !cfg().voters.contains(&p.phone.roster, &p.phone.our_cert.peer_id));
}

#[test]
fn after_a_holder_crashes_the_next_term_comes_once_its_lease_lapses() {
    let mut p = pool(3);
    let n = name("ymir.scheduler");
    let h1 = got(|| p.nodes[0].leases.acquire(&n, &cfg()));
    let crashed = Instant::now();
    drop(kill(&mut p, 0));
    // While the promise lasts at the surviving voters nobody else gets it (checked only
    // while the old handle is still valid, which ends before the voters' promises do).
    if h1.remaining() > Duration::from_millis(300) {
        let r = p.nodes[0].leases.acquire(&n, &cfg());
        assert!(matches!(r, Err(LeaseError::Held { .. })), "{r:?}");
    }
    let h2 = retry_until(LEASE * 4, || p.nodes[0].leases.acquire(&n, &cfg()).ok()).expect("taken over");
    assert!(crashed.elapsed() >= LEASE.mul_f64(0.9), "never before the old lease ran out at the voters");
    assert!(h2.term() > h1.term(), "a newer term (terms a partial round used up are skipped)");
    assert!(!h1.is_valid());
}

#[test]
fn a_minority_cannot_elect() {
    let mut p = pool(3);
    let n = name("ymir.scheduler");
    drop(kill(&mut p, 2));
    drop(kill(&mut p, 1));
    match p.nodes[0].leases.acquire(&n, &cfg()) {
        // Its own voter grants (unless a loaded machine delays even that answer).
        Err(LeaseError::NoQuorum { reached, needed }) => assert!(needed == 2 && reached <= 1, "{reached} of {needed}"),
        other => panic!("expected NoQuorum, got {other:?}"),
    }
}

#[test]
fn a_holder_cut_off_from_the_majority_loses_its_lease_and_is_fenced_after_the_partition_heals() {
    let mut p = pool(3);
    let n = name("ymir.scheduler");
    let mut fence = FenceGuard::new();
    let mut h1 = got(|| p.nodes[0].leases.acquire(&n, &cfg()));
    fence.check(&n, h1.term()).unwrap();
    // Partition: the holder's network goes, its state (and its own voter) stay. Its renewals
    // reach only itself, and the handle runs out on its own, before the voters' promises do.
    let isolated = p.nodes.remove(0);
    p.book.lock().unwrap().remove(&peer(&isolated.k));
    isolated.node.halt();
    let lost = retry_until(LEASE * 3, || match isolated.leases.renew(&mut h1, &cfg()) {
        Err(LeaseError::Lost) => Some(Instant::now()),
        Err(LeaseError::NoQuorum { reached, .. }) => {
            assert!(reached <= 1, "only its own voter answers");
            None
        }
        other => panic!("cut off, yet {other:?}"),
    })
    .expect("lost");
    assert!(!h1.is_valid());
    // It can't get it back on its side either.
    assert!(matches!(isolated.leases.acquire(&n, &cfg()), Err(LeaseError::NoQuorum { reached: 1, needed: 2 })));
    // The majority side elects a newer term once the old promise lapses at its voters.
    let h2 = retry_until(LEASE * 4, || p.nodes[0].leases.acquire(&n, &cfg()).ok()).expect("majority side elects");
    assert!(h2.term() > h1.term());
    assert!(Instant::now() >= lost);
    fence.check(&n, h2.term()).unwrap();
    // The partition heals: the old holder is back on the network with the same key and state.
    let node = Arc::new(start_node(isolated.k.clone(), node_config(true), isolated.st.clone()).unwrap());
    p.book.lock().unwrap().insert(peer(&isolated.k), addrs(&node));
    let book = p.book.clone();
    let back = Leases::new(node.clone(), isolated.st.clone()).with_addrs(move |q| book.lock().unwrap().get(q).cloned().unwrap_or_default());
    // Its stale handle can't be renewed, its commands are refused, and it can't publish.
    assert!(back.renew(&mut h1, &cfg()).is_err());
    assert!(fence.check(&n, h1.term()).is_err());
    assert!(isolated.st.lock().unwrap().publish_plan(now_ms(), T, "placement", &h1, b"stale").is_err());
    // While the new holder lives it stays a follower, with the newer term.
    match back.acquire(&n, &cfg()) {
        Err(LeaseError::Held { holder, term, .. }) => assert_eq!((holder, term), (peer(&p.nodes[0].k), h2.term())),
        other => panic!("expected Held, got {other:?}"),
    }
}

#[test]
fn a_paused_holder_that_wakes_after_its_lease_ran_out_acts_no_more() {
    // A holder that stalls (GC pause, suspend) without noticing: its handle is invalid on
    // wake, the new holder has a higher term, and the fence refuses the old one.
    let p = pool(3);
    let n = name("ymir.scheduler");
    let mut h1 = got(|| p.nodes[0].leases.acquire(&n, &cfg()));
    std::thread::sleep(LEASE + Duration::from_millis(100));
    assert!(!h1.is_valid());
    let h2 = retry_until(LEASE * 3, || p.nodes[1].leases.acquire(&n, &cfg()).ok()).expect("taken over");
    assert!(h2.term() > h1.term(), "a newer term (terms a partial round used up are skipped)");
    assert!(matches!(p.nodes[0].leases.renew(&mut h1, &cfg()), Err(LeaseError::Lost)));
    let mut fence = FenceGuard::new();
    fence.check(&n, h2.term()).unwrap();
    assert!(fence.check(&n, h1.term()).is_err());
    let mut jobs_st = p.nodes[0].st.lock().unwrap();
    assert!(jobs_st.publish_plan(now_ms(), T, "placement", &h1, b"late").is_err());
    drop(jobs_st);
}

#[test]
fn electors_hold_one_lease_at_a_time_and_hand_over_on_release() {
    let p = pool(3);
    let n = name("ymir.scheduler");
    let electors: Vec<_> = p.nodes.iter().map(|b| b.leases.elect(n.clone(), cfg())).collect();
    let first = retry_until(LEASE * 4, || electors.iter().position(|e| e.handle().is_some())).expect("someone holds it");
    // Sample for a while: never two valid holders, and terms never go back. (A live holder
    // keeps its term; only a renewal starved for longer than the lease, as on a badly
    // overloaded machine, hands over to a higher one.)
    let mut term = electors[first].handle().map(|h| h.term()).unwrap_or_default();
    let end = Instant::now() + LEASE * 2;
    while Instant::now() < end {
        let held: Vec<_> = electors.iter().filter_map(|e| e.handle()).collect();
        assert!(held.len() <= 1, "two holders: {held:?}");
        if let Some(h) = held.first() {
            assert!(h.term() >= term, "terms only grow");
            term = h.term();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let holder = retry_until(LEASE * 4, || electors.iter().position(|e| e.handle().is_some())).expect("still held");
    let term = electors[holder].handle().map(|h| h.term()).unwrap_or(term);
    let others: Vec<_> = electors.iter().enumerate().filter(|(i, _)| *i != holder).map(|(_, e)| (e.state(), e.handle())).collect();
    assert!(others.iter().all(|(_, h)| h.is_none()), "{others:?}");
    let mut electors = electors;
    electors.remove(holder).release();
    let next = retry_until(LEASE * 4, || electors.iter().find_map(|e| e.handle())).expect("handed over");
    assert!(next.term() > term);
}

#[test]
fn electors_fail_over_when_the_holder_crashes() {
    let mut p = pool(3);
    let n = name("ymir.scheduler");
    let mut electors: Vec<_> = p.nodes.iter().map(|b| Some(b.leases.elect(n.clone(), cfg()))).collect();
    let first = retry_until(LEASE * 4, || electors.iter().position(|e| e.as_ref().unwrap().handle().is_some())).expect("someone holds it");
    let term = electors[first].as_ref().unwrap().handle().unwrap().term();
    // The holder crashes: its network goes and its elector stops without letting go.
    let crashed = kill(&mut p, first);
    let gone = electors[first].take().unwrap();
    std::mem::forget(gone);
    let at = Instant::now();
    let next = retry_until(LEASE * 10, || electors.iter().flatten().find_map(|e| e.handle())).expect("failed over");
    assert!(next.term() > term);
    assert!(at.elapsed() >= LEASE.mul_f64(0.5), "not before the promise lapsed at the voters");
    let held: Vec<_> = electors.iter().flatten().filter_map(|e| e.handle()).collect();
    assert_eq!(held.len(), 1);
    drop(crashed);
}

#[test]
fn a_candidate_with_a_stale_voter_set_cannot_win() {
    let mut p = pool(3);
    let n = name("ymir.scheduler");
    // The phone grants the role to a fourth node; only the first inference node has heard.
    let k4 = Keypair::generate_ed25519();
    let u = user();
    p.phone.approve(cert(&u, &k4, "inference3", 20), 20).unwrap();
    p.phone.grant(&peer(&k4), DeviceClass::Service, &[ROLE.into()], &[T.into()], 20).unwrap();
    p.nodes[0].st.lock().unwrap().roster = p.phone.roster.clone();
    match p.nodes[0].leases.acquire(&n, &cfg()) {
        Err(LeaseError::NoQuorum { reached, needed }) => assert!(needed == 3 && reached <= 1, "the others refuse a different voter set: {reached}"),
        other => panic!("expected NoQuorum, got {other:?}"),
    }
    // The others, still on three voters, elect among themselves; once the roster reaches
    // everyone the four agree again.
    let h = got(|| p.nodes[1].leases.acquire(&n, &cfg()));
    p.nodes[1].leases.release(h, &cfg());
    for b in &p.nodes {
        b.st.lock().unwrap().roster = p.phone.roster.clone();
    }
    // Three of four reachable: still a majority.
    assert!(retry_until(LEASE * 3, || p.nodes[2].leases.acquire(&n, &cfg()).ok()).is_some());
    drop(kill(&mut p, 0));
}

#[test]
fn revoked_devices_neither_vote_nor_stand() {
    let p = pool(3);
    let mut r: Roster = p.phone.roster.clone();
    let gone = peer(&p.nodes[2].k);
    r.revoke(&WEIRDNET, &user(), &gone, 30).unwrap();
    let v = Voters::Role(ROLE.into());
    assert_eq!(v.resolve(&r).len(), 2);
    assert!(!v.contains(&r, &gone));
    assert_ne!(v.digest(&r), v.digest(&p.phone.roster));
}

#[test]
fn plans_order_by_term_not_by_clock() {
    let p = pool(3);
    let n = name("ymir.scheduler");
    let h1 = got(|| p.nodes[0].leases.acquire(&n, &cfg()));
    // The first holder's clock runs a day ahead.
    let ahead = 86_400_000 + now_ms();
    let v1 = p.nodes[0].st.lock().unwrap().publish_plan(ahead, T, "placement", &h1, b"plan A1").unwrap();
    assert_eq!((v1.term, v1.version), (h1.term(), 1));
    let v2 = p.nodes[0].st.lock().unwrap().publish_plan(ahead + 1, T, "placement", &h1, b"plan A2").unwrap();
    assert_eq!(v2.version, 2);
    p.nodes[0].leases.release(h1.clone(), &cfg());
    let h2 = got(|| p.nodes[1].leases.acquire(&n, &cfg()));
    p.nodes[1].st.lock().unwrap().publish_plan(now_ms(), T, "placement", &h2, b"plan B1").unwrap();
    // Before syncing, the old holder still sees its own plan.
    assert_eq!(p.nodes[0].st.lock().unwrap().current_plan(T, "placement").unwrap().body, b"plan A2");
    // Everyone converges on the newer term's plan, whatever the HLC says.
    let (b_node, b_peer) = (p.nodes[1].node.clone(), p.nodes[1].node.peer_id());
    let b_addrs = addrs(&b_node);
    {
        let mut st = p.nodes[0].st.lock().unwrap();
        pull_from(&mut st, &p.nodes[0].node, b_peer, &b_addrs, T).unwrap();
        let cur = st.current_plan(T, "placement").unwrap();
        assert_eq!((cur.body.as_slice(), cur.term), (&b"plan B1"[..], h2.term()));
        // It can't publish under its old term any more.
        assert!(st.publish_plan(ahead + 3, T, "placement", &h1, b"no").is_err());
    }
    let a_peer = p.nodes[0].node.peer_id();
    let a_addrs = addrs(&p.nodes[0].node);
    {
        let mut st = p.nodes[1].st.lock().unwrap();
        pull_from(&mut st, &p.nodes[1].node, a_peer, &a_addrs, T).unwrap();
        assert_eq!(st.current_plan(T, "placement").unwrap().body, b"plan B1");
        // Only plans signed by a role holder, if the app asks.
        let roster = st.roster.clone();
        assert!(st.current_plan_where(T, "placement", |s| roster.has_role(s, ROLE)).is_some());
        assert!(st.current_plan_where(T, "placement", |_| false).is_none());
    }
}

#[test]
fn a_job_is_reclaimed_after_its_worker_dies_and_resumes_from_the_checkpoint() {
    let mut p = pool(3);
    let jcfg = cfg();
    let spec = JobSpec::new("batch-1", "prompts", b"100 prompts".to_vec()).with_claim(LEASE);
    {
        let mut st = p.nodes[0].st.lock().unwrap();
        Jobs::new(&mut st, T).post(now_ms(), spec).unwrap();
    }
    let h1 = got(|| p.nodes[0].leases.claim_job(T, "batch-1", &jcfg));
    {
        let mut st = p.nodes[0].st.lock().unwrap();
        let mut jobs = Jobs::new(&mut st, T);
        jobs.record(now_ms(), "batch-1", &h1, JobEvent::Checkpoint { term: h1.term(), seq: 1, data: b"done:40".to_vec() }).unwrap();
        // Events must carry the lease's term.
        assert!(jobs.record(now_ms(), "batch-1", &h1, JobEvent::Checkpoint { term: Term(99), seq: 2, data: vec![] }).is_err());
        assert_eq!(jobs.view("batch-1").unwrap().status, JobStatus::Claimed);
    }
    // The second node syncs the job log, then the worker dies.
    let a_peer = p.nodes[0].node.peer_id();
    let a_addrs = addrs(&p.nodes[0].node);
    {
        let mut st = p.nodes[1].st.lock().unwrap();
        pull_from(&mut st, &p.nodes[1].node, a_peer, &a_addrs, T).unwrap();
        assert_eq!(Jobs::new(&mut st, T).open().len(), 1);
    }
    drop(kill(&mut p, 0));
    if h1.remaining() > Duration::from_millis(300) {
        let r = p.nodes[0].leases.claim_job(T, "batch-1", &jcfg);
        assert!(matches!(r, Err(LeaseError::Held { .. })), "{r:?}");
    }
    let h2 = retry_until(LEASE * 4, || p.nodes[0].leases.claim_job(T, "batch-1", &jcfg).ok()).expect("re-claimed");
    assert!(h2.term() > h1.term(), "a newer term (terms a partial round used up are skipped)");
    let mut st = p.nodes[0].st.lock().unwrap();
    let mut jobs = Jobs::new(&mut st, T);
    let v = jobs.view("batch-1").unwrap();
    assert_eq!((v.attempts, v.resume_from.as_deref()), (2, Some(&b"done:40"[..])));
    jobs.record(now_ms(), "batch-1", &h2, JobEvent::Finished { term: h2.term(), result: b"ok".to_vec() }).unwrap();
    let v = jobs.view("batch-1").unwrap();
    assert_eq!((v.status, v.result.as_deref()), (JobStatus::Done, Some(&b"ok"[..])));
    assert!(jobs.open().is_empty());
    drop(st);
    assert!(p.nodes[0].leases.claim_job(T, "batch-1", &jcfg).is_err(), "a finished job is not claimed again");
}

/// Every node pulls node `from`'s job log.
fn spread(p: &Pool, from: usize) {
    let (peer_id, a) = (p.nodes[from].node.peer_id(), addrs(&p.nodes[from].node));
    for (i, n) in p.nodes.iter().enumerate() {
        if i != from {
            let mut st = n.st.lock().unwrap();
            pull_from(&mut st, &n.node, peer_id, &a, T).unwrap();
        }
    }
}

#[test]
fn job_rules_hold_voters_to_candidates_and_the_takeover_wait() {
    let mut p = pool(3);
    let wait = Duration::from_millis(2_000);
    let outsider = peer(&p.nodes[2].k);
    let rules = JobRules::new().with_candidates([peer(&p.nodes[0].k), peer(&p.nodes[1].k)]).with_takeover_after(wait);
    let spec = JobSpec::new("train-1", "ymir.train", b"{}".to_vec()).with_claim(LEASE).with_rules(rules);
    Jobs::new(&mut p.nodes[0].st.lock().unwrap(), T).post(now_ms(), spec).unwrap();
    spread(&p, 0);
    let jcfg = cfg();
    // The outsider is refused locally, and voters refuse its raw ask for the job's lease.
    assert!(matches!(p.nodes[2].leases.claim_job(T, "train-1", &jcfg), Err(LeaseError::NotEligible)));
    let lease = job_lease(T, "train-1").unwrap();
    let raw = p.nodes[2].leases.acquire(&lease, &jcfg.clone().with_duration(LEASE));
    assert!(matches!(raw, Err(LeaseError::NoQuorum { .. })), "{raw:?} from {outsider}");
    let h1 = got(|| p.nodes[0].leases.claim_job(T, "train-1", &jcfg));
    // Node 0 crashes without letting go: node 1 waits for the lapse plus the takeover wait.
    let at = Instant::now();
    let left = h1.remaining();
    drop(kill(&mut p, 0));
    let h2 = retry_until(LEASE * 4 + wait, || match p.nodes[0].leases.claim_job(T, "train-1", &jcfg) {
        Ok(h) => Some(h),
        Err(LeaseError::Held { .. } | LeaseError::NoQuorum { .. }) => None,
        Err(e) => panic!("{e:?}"),
    })
    .expect("taken over after the wait");
    assert!(at.elapsed() >= left + wait - Duration::from_millis(100), "{:?} < {:?} + {:?}", at.elapsed(), left, wait);
    assert!(h2.term() > h1.term());
    let me = peer(&p.nodes[0].k);
    let mut st = p.nodes[0].st.lock().unwrap();
    let v = Jobs::new(&mut st, T).view("train-1").unwrap();
    assert_eq!((v.status, v.claim), (JobStatus::Claimed, Some((me, h2.term()))));
}

#[test]
fn an_identity_voter_keeps_its_terms_across_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("v");
    let short = Duration::from_millis(100);
    let n = name("ymir.scheduler");
    let ask = |term: u64| weirdnet_sync::lease::LeaseAsk { name: n.clone(), term: Term(term), duration_ms: 100, renew: false, voters: String::new() };
    {
        let id = Identity::create(&dir, "phone", T).unwrap();
        id.enable_voter_with(Voter::new(Voters::Role(ROLE.into())).with_max_duration(short), Voters::Role(ROLE.into())).unwrap();
        std::thread::sleep(short * 2);
        let st = id.state();
        let mut st = st.lock().unwrap();
        let v = st.voter.as_mut().unwrap();
        assert!(matches!(v.on_ask("a", &ask(7), Instant::now()), weirdnet_sync::Message::LeaseGrant(_)));
    }
    assert!(dir.join("voter.cbor").is_file(), "written before the grant");
    let id = Identity::open(&dir, T).unwrap().unwrap();
    id.enable_voter_with(Voter::new(Voters::Role(ROLE.into())).with_max_duration(short), Voters::Role(ROLE.into())).unwrap();
    let st = id.state();
    let mut st = st.lock().unwrap();
    let v = st.voter.as_mut().unwrap();
    assert_eq!(v.max_term(&n), Term(7));
    std::thread::sleep(short * 2);
    assert!(matches!(v.on_ask("b", &ask(7), Instant::now()), weirdnet_sync::Message::LeaseDeny(_)), "a term is never granted twice");
    assert!(matches!(v.on_ask("b", &ask(8), Instant::now()), weirdnet_sync::Message::LeaseGrant(_)));
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}
