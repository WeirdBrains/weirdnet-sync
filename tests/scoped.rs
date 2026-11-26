//! Type-scoped keys for service devices (0.8.3): a service device granted `ymir.train`
//! syncs it, votes and claims jobs, and can neither be served nor open `ymir.context`.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, Multiaddr, Node, WEIRDNET};
use weirdnet_sync::lease::LeaseAsk;
use weirdnet_sync::{
    DeviceClass, Envelope, EpochKeys, Hello, Hlc, JobEvent, JobSpec, JobStatus, Jobs, KeyRef, LEASE_TYPE, LeaseConfig, LeaseError, LeaseHandle,
    LeaseName, Leases, LinkBundle, Message, NodeId, Pull, RecordOptions, SyncError, SyncState, Term, Voter, Voters, node_config, pull_from,
    rotated_sync_key, start_node,
};

const TRAIN: &str = "ymir.train";
const CONTEXT: &str = "ymir.context";
const ROLE: &str = "ymir.model";
const SEED: [u8; 32] = *b"QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
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

fn strs(r: &[&str]) -> Vec<String> {
    r.iter().map(|s| s.to_string()).collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// A full device syncing both types, with the role (so it votes) and `ymir.context`
/// sealed.
fn full(k: &Keypair) -> SyncState {
    let u = user();
    let mut st = SyncState::new(SEED.to_vec(), u.public(), cert(&u, k, "phone", 1), Some(k), strs(&[TRAIN, CONTEXT])).unwrap();
    st.auto_first_rotation = false;
    st.grant(&peer(k), DeviceClass::Full, &strs(&[ROLE]), &[], 2).unwrap();
    st.configure(CONTEXT, RecordOptions { sealed: true, ..RecordOptions::default() }).unwrap();
    st
}

/// Link `k` as a service device with `types`, returning its state and the bundle bytes.
fn link(a: &mut SyncState, k: &Keypair, types: &[&str], at: i64) -> (SyncState, Vec<u8>) {
    let u = user();
    let bundle = a.service_bundle(&peer(k), &strs(&[ROLE]), &strs(types), at).unwrap();
    let bytes = bundle.to_bytes().unwrap().to_vec();
    let c = cert(&u, k, "model", at);
    a.approve(c.clone(), at).unwrap();
    let st = SyncState::new_service(u.public(), c, k, strs(&[TRAIN]), &LinkBundle::from_bytes(&bytes).unwrap()).unwrap();
    (st, bytes)
}

/// No key `keys` holds is an epoch key of `a`, or derives `typ` under one.
fn holds_no_key_for(keys: &EpochKeys, a: &SyncState, typ: &str) {
    assert_eq!(keys.epoch_key_count(), 0, "no epoch key");
    for (id, epoch) in a.keys.ids() {
        let raw = a.keys.get(id).unwrap();
        let forbidden = rotated_sync_key(raw, &a.user_id, typ, epoch, id).unwrap();
        for t in keys.scoped_types(id) {
            let k = keys.get_scoped(id, t).unwrap();
            assert_ne!(k.0, raw.0, "an epoch key under {t}");
            assert_ne!(k.0, forbidden.0, "a {typ} key under {t}");
        }
        assert!(keys.get_scoped(id, typ).is_none());
    }
}

fn reason(m: Message) -> String {
    match m {
        Message::Refuse(r) => r.reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// One device on the network with its lease client.
struct Dev {
    k: Keypair,
    st: Arc<Mutex<SyncState>>,
    node: Arc<N>,
    leases: Leases,
}

fn up(k: &Keypair, mut st: SyncState, book: &Arc<Mutex<std::collections::HashMap<String, Vec<Multiaddr>>>>) -> Dev {
    st.set_voter(Some(Voter::new(Voters::Role(ROLE.into())).with_max_duration(LEASE)));
    let st = Arc::new(Mutex::new(st));
    let node = Arc::new(start_node(k.clone(), node_config(true), st.clone()).unwrap());
    book.lock().unwrap().insert(peer(k), addrs(&node));
    let b = book.clone();
    let leases = Leases::new(node.clone(), st.clone()).with_addrs(move |p| b.lock().unwrap().get(p).cloned().unwrap_or_default());
    Dev { k: k.clone(), st, node, leases }
}

fn pull(from: &Dev, to: &Dev, typ: &str) -> Result<usize, SyncError> {
    let mut st = to.st.lock().unwrap();
    pull_from(&mut st, &to.node, from.node.peer_id(), &addrs(&from.node), typ)
}

fn cfg() -> LeaseConfig {
    LeaseConfig::for_role(ROLE).with_duration(LEASE).with_stagger(Duration::from_millis(100))
}

/// A lease that should be granted (retrying rounds too few voters answered in time).
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

/// Post `id` on `poster`, sync it to `worker`, claim it there (both devices vote), renew,
/// checkpoint, and check the poster sees the claim and checkpoint.
fn claim_round(poster: &Dev, worker: &Dev, id: &str) {
    let spec = JobSpec::new(id, "train", b"adapter".to_vec()).with_claim(LEASE);
    Jobs::new(&mut poster.st.lock().unwrap(), TRAIN).post(now_ms(), spec).unwrap();
    assert!(pull(poster, worker, TRAIN).unwrap() >= 1);
    assert!(Jobs::new(&mut worker.st.lock().unwrap(), TRAIN).view(id).is_some(), "the job reached the worker");
    let mut h = got(|| worker.leases.claim_job(TRAIN, id, &cfg()));
    let deadline = Instant::now() + LEASE;
    while worker.leases.renew(&mut h, &cfg()).is_err() {
        assert!(Instant::now() < deadline, "renewed");
        std::thread::sleep(Duration::from_millis(50));
    }
    {
        let mut st = worker.st.lock().unwrap();
        Jobs::new(&mut st, TRAIN).record(now_ms(), id, &h, JobEvent::Checkpoint { term: h.term(), seq: 1, data: b"step:10".to_vec() }).unwrap();
    }
    pull(worker, poster, TRAIN).unwrap();
    let v = Jobs::new(&mut poster.st.lock().unwrap(), TRAIN).view(id).unwrap();
    assert_eq!((v.status, v.resume_from.as_deref()), (JobStatus::Claimed, Some(&b"step:10"[..])));
    worker.leases.release(h, &cfg());
}

#[test]
fn a_service_granted_ymir_train_syncs_votes_and_claims_and_keeps_up_with_rotations() {
    let (ka, ks, kc) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    let (s, bytes) = link(&mut a, &ks, &[TRAIN, LEASE_TYPE], 10);
    // The bundle and the service hold scoped keys only.
    let bundle = LinkBundle::from_bytes(&bytes).unwrap();
    let sent = EpochKeys::import(bundle.keys.as_deref().unwrap()).unwrap();
    assert!(sent.scoped_len() > 0);
    holds_no_key_for(&sent, &a, CONTEXT);
    holds_no_key_for(&s.keys, &a, CONTEXT);
    let head = a.roster.head_id().unwrap();
    assert!(s.keys.get_scoped(&head, TRAIN).is_some() && s.keys.get_scoped(&head, LEASE_TYPE).is_some());
    assert!(matches!(s.key_status(), weirdnet_sync::KeyStatus::Current { .. }));
    // Scoped keys persist.
    assert_eq!(EpochKeys::import(&s.keys.export()).unwrap(), s.keys);

    let book = Arc::default();
    let da = up(&ka, a, &book);
    let ds = up(&ks, s, &book);
    let _ = da.node.connect(ds.node.peer_id(), &addrs(&ds.node));
    std::thread::sleep(LEASE + Duration::from_millis(100));

    // The service claims a job the phone posted (the phone votes), and the phone takes a
    // lease (the service votes, opening the ask with its scoped lease key).
    claim_round(&da, &ds, "train-1");
    let n = LeaseName::new("ymir.scheduler").unwrap();
    let h = got(|| da.leases.acquire(&n, &cfg()));
    da.leases.release(h, &cfg());

    // A rotation (another device revoked): the service is admitted with new scoped keys.
    let before = da.st.lock().unwrap().roster.head_id();
    {
        let mut st = da.st.lock().unwrap();
        st.approve(cert(&user(), &kc, "old laptop", 20), 20).unwrap();
        st.revoke(&user(), &peer(&kc), 30).unwrap();
        assert_ne!(st.roster.head_id(), before);
        let head = st.roster.chain_view().head().cloned().unwrap();
        let r = st.roster.chain.rotations.iter().find(|r| r.id() == head.id).unwrap();
        assert!(r.recipients().all(|p| p != peer(&ks)), "the epoch key is not sealed to the service");
        assert!(head.members.contains(&peer(&ks)), "admitted with scoped keys instead");
    }
    std::thread::sleep(Duration::from_millis(200));
    claim_round(&da, &ds, "train-2");
    {
        let st = ds.st.lock().unwrap();
        let a = da.st.lock().unwrap();
        assert_eq!(st.roster.head_id(), a.roster.head_id());
        holds_no_key_for(&st.keys, &a, CONTEXT);
        assert!(st.keys.get_scoped(&a.roster.head_id().unwrap(), TRAIN).is_some());
    }
    let h = got(|| da.leases.acquire(&n, &cfg()));
    da.leases.release(h, &cfg());
    drop(ds.k);
}

#[test]
fn a_service_is_refused_ymir_context_and_cannot_open_it() {
    let (ka, ks) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    let (s, _) = link(&mut a, &ks, &[TRAIN], 10);
    let sp = peer(&ks);
    a.write(1_000, CONTEXT, "chat-1", b"conversation history").unwrap();
    a.write(1_001, TRAIN, "job-0", b"not secret").unwrap();
    let key = a.current_key();
    let id = key.id.clone().unwrap();
    let epoch_key = a.keys.get(&id).unwrap().clone();
    let uid = a.user_id.clone();

    // Protocol layer: even with the epoch key (a service linked by a 0.8.2 device holds
    // it), a service peer is refused ymir.context: hello, pull and ack.
    let hello = |types: &[&str]| {
        Message::Hello(Hello {
            cert: s.our_cert.clone(),
            user_id: uid.clone(),
            epoch: key.epoch,
            types: strs(types),
            our_cursors: vec![],
            our_hlc: Hlc::new(0, 0, NodeId(sp.clone())),
            chain: s.roster.chain.shared(),
        })
    };
    let ask = |typ: &str, m: &Message| Envelope::seal_keyed(&epoch_key, &id, &uid, typ, key.epoch, &sp, m).unwrap();
    let answer = |a: &mut SyncState, env: Envelope| a.handle(&sp, env).unwrap().open_keyed(&epoch_key, &uid, &sp).unwrap();
    let pull_ctx = Message::Pull(Pull { node_id: a.our_node.clone(), after_seq: 0, typ: CONTEXT.into(), limit: 10 });
    assert_eq!(reason(answer(&mut a, ask(CONTEXT, &hello(&[CONTEXT])))), "type-not-granted");
    assert_eq!(reason(answer(&mut a, ask(TRAIN, &hello(&[CONTEXT])))), "type-not-granted");
    assert_eq!(reason(answer(&mut a, ask(CONTEXT, &pull_ctx))), "type-not-granted");
    assert_eq!(reason(answer(&mut a, ask(TRAIN, &pull_ctx))), "type-not-granted", "a ymir.context pull inside a ymir.train envelope");
    let ack = Message::Ack(weirdnet_sync::Ack { node_id: a.our_node.clone(), last_seq: 1 });
    assert_eq!(reason(answer(&mut a, ask(CONTEXT, &ack))), "type-not-granted");
    // Its granted type is served; a hello offering both types counts only ymir.train.
    assert!(matches!(answer(&mut a, ask(TRAIN, &hello(&[TRAIN, CONTEXT]))), Message::HelloOk(_)));
    let pull_train = Message::Pull(Pull { node_id: a.our_node.clone(), after_seq: 0, typ: TRAIN.into(), limit: 10 });
    assert!(matches!(answer(&mut a, ask(TRAIN, &pull_train)), Message::Page(_)));
    // A full device is not limited.
    {
        let kf = Keypair::generate_ed25519();
        let fp = peer(&kf);
        a.approve(cert(&user(), &kf, "laptop", 11), 11).unwrap();
        let m = Envelope::seal_keyed(&epoch_key, &id, &uid, CONTEXT, key.epoch, &fp, &pull_ctx).unwrap();
        let reply = a.handle(&fp, m).unwrap().open_keyed(&epoch_key, &uid, &fp).unwrap();
        assert!(matches!(reply, Message::Page(ref p) if p.page.ops.iter().any(|e| e.record_id == "chat-1")), "{reply:?}");
    }

    // Crypto: the service cannot seal, open or read ymir.context.
    let real = a.seal_envelope(&key, CONTEXT, &sp, &pull_ctx).unwrap();
    assert!(s.open_envelope(&real, &sp).is_err(), "a real ymir.context envelope does not open");
    assert!(s.seal_envelope(&key, CONTEXT, &sp, &pull_ctx).is_err());
    let train_env = a.seal_envelope(&key, TRAIN, &sp, &pull_train).unwrap();
    assert_eq!(s.open_envelope(&train_env, &sp).unwrap(), pull_train, "its own type opens");
    let rec = a.log.iter().find(|e| e.record_id == "chat-1").unwrap().clone();
    assert!(rec.value.as_ref().and_then(|v| v.seal.as_ref()).is_some_and(|x| x.key == id), "sealed under the same rotation");
    let mut s = s;
    s.configure(CONTEXT, RecordOptions { sealed: true, ..RecordOptions::default() }).unwrap();
    assert!(s.read(&rec).is_err(), "a sealed ymir.context record does not open");
    assert_eq!(a.read(&rec).unwrap().ready().unwrap().as_slice(), b"conversation history");
    holds_no_key_for(&s.keys, &a, CONTEXT);
    // Asked to answer for ymir.context under the rotation it holds, it says so.
    let reply = s.handle(&peer(&ka), Envelope::seal_keyed(&epoch_key, &id, &uid, CONTEXT, key.epoch, &peer(&ka), &pull_ctx).unwrap()).unwrap();
    assert_eq!(reason(reply.open_clear().unwrap()), "type-not-granted");
}

#[test]
fn a_service_pulling_ymir_context_over_the_network_fails() {
    let (ka, ks) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    let (s, _) = link(&mut a, &ks, &[TRAIN], 10);
    a.write(1_000, CONTEXT, "chat-1", b"conversation history").unwrap();
    let book = Arc::default();
    let da = up(&ka, a, &book);
    let ds = up(&ks, s, &book);
    assert!(pull(&da, &ds, CONTEXT).is_err());
    assert_eq!(pull(&da, &ds, TRAIN).unwrap(), 0);
    let st = ds.st.lock().unwrap();
    assert!(st.log.iter().all(|e| e.typ != CONTEXT));
}

#[test]
fn leases_need_a_key_holding_grant_and_lease_only_devices_hold_only_leases() {
    let (ka, kl, kr) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    // A lease-only voter: weirdnet.lease and nothing else.
    let (l, _) = link(&mut a, &kl, &[LEASE_TYPE], 10);
    let head = a.roster.head_id().unwrap();
    assert_eq!(l.keys.scoped_types(&head).collect::<Vec<_>>(), vec![LEASE_TYPE]);
    holds_no_key_for(&l.keys, &a, TRAIN);
    // A roster-only device holds nothing and is refused leases even with a stolen key.
    let (r, _) = link(&mut a, &kr, &[], 11);
    assert!(r.keys.is_empty());
    let key = a.current_key();
    let id = key.id.clone().unwrap();
    let ek = a.keys.get(&id).unwrap().clone();
    let uid = a.user_id.clone();
    let lease_ask =
        Message::LeaseAsk(LeaseAsk { name: LeaseName::new("x").unwrap(), term: Term(1), duration_ms: 100, renew: false, voters: String::new() });
    for (k, want_refused) in [(&kr, true), (&kl, false)] {
        let p = peer(k);
        let env = Envelope::seal_keyed(&ek, &id, &uid, LEASE_TYPE, key.epoch, &p, &lease_ask).unwrap();
        let reply = a.handle(&p, env).unwrap().open_keyed(&ek, &uid, &p).unwrap();
        match reply {
            Message::Refuse(r) if r.reason == "type-not-granted" => assert!(want_refused, "{p} refused"),
            other => assert!(!want_refused, "expected type-not-granted, got {other:?}"),
        }
    }
    // The lease-only device opens lease envelopes and nothing else.
    let lp = peer(&kl);
    let env = a.seal_envelope(&key, LEASE_TYPE, &lp, &lease_ask).unwrap();
    assert_eq!(l.open_envelope(&env, &lp).unwrap(), lease_ask);
    let pull_train = Message::Pull(Pull { node_id: a.our_node.clone(), after_seq: 0, typ: TRAIN.into(), limit: 10 });
    assert!(l.open_envelope(&a.seal_envelope(&key, TRAIN, &lp, &pull_train).unwrap(), &lp).is_err());
    let env = Envelope::seal_keyed(&ek, &id, &uid, TRAIN, key.epoch, &lp, &pull_train).unwrap();
    assert_eq!(reason(a.handle(&lp, env).unwrap().open_keyed(&ek, &uid, &lp).unwrap()), "type-not-granted");
    let _ = KeyRef::seed(0);
}

#[test]
fn epoch_keys_from_an_older_link_are_narrowed_to_scoped_keys() {
    let (ka, ks) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    let u = user();
    // What a 0.8.2 device sends: the grant and its epoch keys.
    let mut bundle = a.service_bundle(&peer(&ks), &strs(&[ROLE]), &strs(&[TRAIN]), 10).unwrap();
    bundle.keys = Some(a.keys.export().to_vec());
    let c = cert(&u, &ks, "model", 10);
    a.approve(c.clone(), 10).unwrap();
    let s = SyncState::new_service(u.public(), c, &ks, strs(&[TRAIN]), &bundle).unwrap();
    holds_no_key_for(&s.keys, &a, CONTEXT);
    let key = a.current_key();
    let id = key.id.clone().unwrap();
    let sp = peer(&ks);
    let pull_train = Message::Pull(Pull { node_id: a.our_node.clone(), after_seq: 0, typ: TRAIN.into(), limit: 10 });
    assert_eq!(s.open_envelope(&a.seal_envelope(&key, TRAIN, &sp, &pull_train).unwrap(), &sp).unwrap(), pull_train);
    assert!(s.keys.get_scoped(&id, &weirdnet_sync::chunk_type(TRAIN)).is_some(), "chunk types come along");
}
