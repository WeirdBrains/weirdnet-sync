//! Several record types in one sync session (0.8.5): one Hello for all of them, each type's
//! pulls and acks sealed under its own key, a service device's ungranted types refused
//! without stopping the granted ones, and the same pass against 0.8.2 and 0.7.1 peers.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Handler, Keypair, Multiaddr, Node, PeerId, WEIRDNET};
use weirdnet_sync::{
    Envelope, LinkBundle, LogEntry, Message, Pull, RecordOptions, SYNC_PROFILE, SyncError, SyncHandler, SyncState, decode, node_config, pull_from,
    pull_types, pull_types_shared,
};
use weirdnet_sync_07 as old07;
use weirdnet_sync_082 as old082;

const POOL: &str = "ymir.pool";
const TRAIN: &str = "ymir.train";
const CONTEXT: &str = "ymir.context";
const ALL: [&str; 3] = [POOL, TRAIN, CONTEXT];
const SEED: [u8; 32] = *b"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM";

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

fn strs(r: &[&str]) -> Vec<String> {
    r.iter().map(|s| s.to_string()).collect()
}

fn sealed() -> RecordOptions {
    RecordOptions { sealed: true, ..RecordOptions::default() }
}

fn addrs(n: &N) -> Vec<Multiaddr> {
    n.reachable_addrs().into_iter().map(|s| s.parse().unwrap()).collect()
}

/// What a responder was asked, as `kind:envelope-type`, opened with its own keys.
type Seen = Arc<Mutex<Vec<String>>>;

/// A [`SyncHandler`] that records each request before answering it.
struct Counting {
    inner: SyncHandler,
    seen: Seen,
}

fn kind(m: &Message) -> String {
    let k = match m {
        Message::Hello(_) => "hello",
        Message::Pull(_) => "pull",
        Message::Ack(_) => "ack",
        Message::Roster(_) => "roster",
        _ => "other",
    };
    k.to_string()
}

impl Handler<Vec<u8>, Vec<u8>> for Counting {
    fn request(&self, from: &PeerId, req: Vec<u8>) -> Vec<u8> {
        if let Ok(env) = decode::<Envelope>(&req) {
            let opened = self.inner.state.lock().unwrap().open_envelope(&env, &from.to_string());
            let k = match opened {
                Ok(Message::Pull(p)) => format!("pull:{}:{}", env.typ, p.typ),
                Ok(m) => format!("{}:{}", kind(&m), env.typ),
                Err(_) => format!("unopened:{}", env.typ),
            };
            self.seen.lock().unwrap().push(k);
        }
        self.inner.request(from, req)
    }
}

/// The same for a 0.8.2 responder: counts the hellos it is sent.
struct Counting082 {
    inner: old082::SyncHandler,
    hellos: Arc<Mutex<usize>>,
}

impl Handler<Vec<u8>, Vec<u8>> for Counting082 {
    fn request(&self, from: &PeerId, req: Vec<u8>) -> Vec<u8> {
        if let Ok(env) = old082::decode::<old082::Envelope>(&req)
            && let Ok(old082::Message::Hello(_)) = self.inner.state.lock().unwrap().open_envelope(&env, &from.to_string())
        {
            *self.hellos.lock().unwrap() += 1;
        }
        self.inner.request(from, req)
    }
}

struct Dev {
    st: Arc<Mutex<SyncState>>,
    node: N,
    seen: Seen,
}

impl Dev {
    fn lock(&self) -> std::sync::MutexGuard<'_, SyncState> {
        self.st.lock().unwrap()
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }

    fn hellos(seen: &[String]) -> usize {
        seen.iter().filter(|s| s.starts_with("hello:")).count()
    }
}

fn up(k: &Keypair, st: SyncState) -> Dev {
    let st = Arc::new(Mutex::new(st));
    let seen = Seen::default();
    let h = Counting { inner: SyncHandler { state: st.clone() }, seen: seen.clone() };
    let node = Node::start(&SYNC_PROFILE, k.clone(), node_config(true), Arc::new(h)).unwrap();
    Dev { st, node, seen }
}

/// Two full devices of one user, both admitted to `a`'s first rotation, all three types
/// synced and `ymir.context` sealed.
fn full_pair() -> (Keypair, SyncState, Keypair, SyncState) {
    let u = user();
    let (ka, kb) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let (ca, cb) = (cert(&u, &ka, "phone", 1), cert(&u, &kb, "laptop", 1));
    let mut a = SyncState::new(SEED.to_vec(), u.public(), ca.clone(), Some(&ka), strs(&ALL)).unwrap();
    let mut b = SyncState::new(SEED.to_vec(), u.public(), cb.clone(), Some(&kb), strs(&ALL)).unwrap();
    for s in [&mut a, &mut b] {
        s.auto_first_rotation = false;
        s.configure(CONTEXT, sealed()).unwrap();
    }
    a.roster.chain.merge(&b.roster.chain.shared());
    b.roster.chain.merge(&a.roster.chain.shared());
    a.approve(cb, 2).unwrap();
    b.approve(ca, 2).unwrap();
    a.rotate(3).unwrap();
    (ka, a, kb, b)
}

/// Link `k` from `a` as a service device granted `granted`, configured for `types`.
fn link(a: &mut SyncState, k: &Keypair, granted: &[&str], types: &[&str], at: i64) -> SyncState {
    let u = user();
    let bundle = a.service_bundle(&peer(k), &strs(&["ymir.inference"]), &strs(granted), at).unwrap();
    let bytes = bundle.to_bytes().unwrap().to_vec();
    let c = cert(&u, k, "inference", at);
    a.approve(c.clone(), at).unwrap();
    let mut st = SyncState::new_service(u.public(), c, k, strs(types), &LinkBundle::from_bytes(&bytes).unwrap()).unwrap();
    st.configure(CONTEXT, sealed()).unwrap();
    st
}

fn values(st: &SyncState, typ: &str) -> BTreeMap<String, Vec<u8>> {
    st.latest_entries(typ).into_iter().filter_map(|e: &LogEntry| Some((e.record_id.clone(), st.read(e).ok()?.ready()?.to_vec()))).collect()
}

fn one(rid: &str, v: &[u8]) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(rid.to_string(), v.to_vec())])
}

/// `to` pulls from `from` until it holds `from`'s head key.
fn catch_up(from: &Dev, to: &Dev) {
    let head = from.lock().roster.head_id();
    let end = Instant::now() + Duration::from_secs(10);
    while to.lock().current_key().id != head {
        assert!(Instant::now() < end, "caught up with the rotation");
        let mut st = to.lock();
        let _ = pull_from(&mut st, &to.node, from.node.peer_id(), &addrs(&from.node), POOL);
        drop(st);
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn refused(o: Option<&weirdnet_sync::PullOutcome>) -> Option<String> {
    match o.and_then(|o| o.error.as_ref()) {
        Some(SyncError::Refused(r)) => Some(r.clone()),
        _ => None,
    }
}

#[test]
fn a_full_device_pulls_three_types_with_one_hello() {
    let (ka, a, kb, b) = full_pair();
    let (da, db) = (up(&ka, a), up(&kb, b));
    catch_up(&da, &db);
    {
        // Written after the catch-up pull, so each type has one new op.
        let mut a = da.lock();
        a.write(10, POOL, "node-1", b"pool").unwrap();
        a.write(11, TRAIN, "job-1", b"train").unwrap();
        a.write(12, CONTEXT, "chat-1", b"sealed chat").unwrap();
    }
    da.take();

    let out = {
        let mut st = db.lock();
        pull_types(&mut st, &db.node, da.node.peer_id(), &addrs(&da.node), &ALL)
    };
    assert!(out.is_ok(), "{out:?}");
    assert_eq!(out.types.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(), ALL, "one outcome per type, in order");
    assert_eq!(out.applied(), 3);
    assert!(ALL.iter().all(|t| out.get(t).unwrap().applied == 1));
    let seen = da.take();
    assert_eq!(Dev::hellos(&seen), 1, "one hello for three types: {seen:?}");
    assert!(seen.iter().all(|s| !s.starts_with("unopened")), "{seen:?}");
    // Every pull is sealed under the type it asks for, each type pulled.
    for t in ALL {
        assert!(seen.iter().any(|s| *s == format!("pull:{t}:{t}")), "{t} pulled: {seen:?}");
    }
    assert!(seen.iter().filter(|s| s.starts_with("pull:")).all(|s| {
        let p: Vec<&str> = s.split(':').collect();
        p[1] == p[2]
    }));
    let b = db.lock();
    assert_eq!(values(&b, POOL), one("node-1", b"pool"));
    assert_eq!(values(&b, TRAIN), one("job-1", b"train"));
    assert_eq!(values(&b, CONTEXT), one("chat-1", b"sealed chat"), "the sealed record opens");
    drop(b);

    // One type at a time costs a hello each.
    da.lock().write(20, POOL, "node-2", b"pool 2").unwrap();
    for t in ALL {
        let mut st = db.lock();
        pull_from(&mut st, &db.node, da.node.peer_id(), &addrs(&da.node), t).unwrap();
    }
    assert_eq!(Dev::hellos(&da.take()), 3);
    // Asking twice for a type pulls it once.
    da.lock().write(21, TRAIN, "job-2", b"train 2").unwrap();
    let out = pull_types_shared(&db.st, &db.node, da.node.peer_id(), &addrs(&da.node), &[TRAIN, TRAIN, POOL]);
    assert!(out.is_ok() && out.types.len() == 2 && out.applied() == 1, "{out:?}");
    assert_eq!(Dev::hellos(&da.take()), 1);
    assert_eq!(values(&db.lock(), TRAIN).len(), 2);
}

#[test]
fn a_service_device_pulls_its_granted_types_in_one_session_and_is_refused_the_rest() {
    let (ka, mut a, _, _) = full_pair();
    let ks = Keypair::generate_ed25519();
    // Granted pool and context; configured for train too, which it may not sync.
    let s = link(&mut a, &ks, &[POOL, CONTEXT], &ALL, 10);
    let (da, ds) = (up(&ka, a), up(&ks, s));
    catch_up(&da, &ds);
    {
        // Written after the catch-up pull, so each type has one new op.
        let mut a = da.lock();
        a.write(10, POOL, "node-1", b"pool").unwrap();
        a.write(11, TRAIN, "job-1", b"train").unwrap();
        a.write(12, CONTEXT, "chat-1", b"sealed chat").unwrap();
    }
    da.take();

    let out = pull_types_shared(&ds.st, &ds.node, da.node.peer_id(), &addrs(&da.node), &[TRAIN, POOL, CONTEXT]);
    assert_eq!(refused(out.get(TRAIN)).as_deref(), Some("type-not-granted"), "{out:?}");
    assert!(out.get(POOL).unwrap().is_ok() && out.get(CONTEXT).unwrap().is_ok(), "{out:?}");
    assert_eq!((out.get(POOL).unwrap().applied, out.get(CONTEXT).unwrap().applied), (1, 1));
    let seen = da.take();
    assert_eq!(Dev::hellos(&seen), 1, "{seen:?}");
    assert!(seen.iter().all(|s| !s.contains(TRAIN)), "nothing of ymir.train is asked for: {seen:?}");
    {
        let s = ds.lock();
        assert_eq!(values(&s, POOL), one("node-1", b"pool"));
        assert_eq!(values(&s, CONTEXT), one("chat-1", b"sealed chat"), "the scoped sealed record opens");
        assert!(s.latest_entries(TRAIN).is_empty(), "no ymir.train ops on the service device");
        // It holds no key for ymir.train at all.
        let key = s.current_key();
        let pull = Message::Pull(Pull { node_id: s.our_node.clone(), after_seq: 0, typ: TRAIN.into(), limit: 1 });
        assert!(s.seal_envelope(&key, TRAIN, "peer-x", &pull).is_err());
    }

    // The service device writes pool and sealed context; the full device pulls all three
    // from it: the service answers pool and context and refuses train.
    {
        let mut s = ds.lock();
        s.write(30, POOL, "node-s", b"from s").unwrap();
        s.write(31, CONTEXT, "chat-s", b"sealed from s").unwrap();
    }
    ds.take();
    let out = pull_types_shared(&da.st, &da.node, ds.node.peer_id(), &addrs(&ds.node), &ALL);
    assert_eq!(refused(out.get(TRAIN)).as_deref(), Some("type-not-granted"), "{out:?}");
    assert!(out.get(POOL).unwrap().is_ok() && out.get(CONTEXT).unwrap().is_ok(), "{out:?}");
    assert!(out.get(POOL).unwrap().applied >= 1 && out.get(CONTEXT).unwrap().applied >= 1, "{out:?}");
    let seen = ds.take();
    assert_eq!(Dev::hellos(&seen), 1, "{seen:?}");
    let a = da.lock();
    assert_eq!(values(&a, POOL).get("node-s").map(Vec::as_slice), Some(&b"from s"[..]));
    assert_eq!(values(&a, CONTEXT).get("chat-s").map(Vec::as_slice), Some(&b"sealed from s"[..]));
}

#[test]
fn a_pull_sealed_under_another_type_is_refused() {
    let (ka, a, kb, b) = full_pair();
    let (da, db) = (up(&ka, a), up(&kb, b));
    catch_up(&da, &db);
    let b = db.lock();
    let key = b.current_key();
    let pull = Message::Pull(Pull { node_id: b.our_node.clone(), after_seq: 0, typ: CONTEXT.into(), limit: 1 });
    let env = b.seal_envelope(&key, POOL, &peer(&kb), &pull).unwrap();
    let reply = da.lock().handle(&peer(&kb), env).unwrap();
    match b.open_envelope(&reply, &peer(&kb)).unwrap() {
        Message::Refuse(r) => assert_eq!(r.reason, "type-mismatch"),
        m => panic!("expected a refusal, got {m:?}"),
    }
}

#[test]
fn a_service_device_with_nothing_granted_of_the_asked_types_sends_nothing() {
    let (ka, mut a, _, _) = full_pair();
    let ks = Keypair::generate_ed25519();
    let s = link(&mut a, &ks, &[POOL], &ALL, 10);
    let (da, ds) = (up(&ka, a), up(&ks, s));
    catch_up(&da, &ds);
    da.take();
    let out = pull_types_shared(&ds.st, &ds.node, da.node.peer_id(), &addrs(&da.node), &[TRAIN, CONTEXT]);
    assert_eq!(refused(out.get(TRAIN)).as_deref(), Some("type-not-granted"));
    assert_eq!(refused(out.get(CONTEXT)).as_deref(), Some("type-not-granted"));
    assert!(da.take().is_empty(), "no request was sent");
    assert!(pull_types_shared(&ds.st, &ds.node, da.node.peer_id(), &addrs(&da.node), &[]).types.is_empty());
}

/// A 0.8.5 device pulls three types in one session from a 0.8.2 one, which knows only
/// one-type pulls: the wire is the same, so the older peer answers each request as before.
#[test]
fn several_types_in_one_session_from_a_0_8_2_peer() {
    let u = user();
    let (ka, kb) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let (ca, cb) = (cert(&u, &ka, "old", 1), cert(&u, &kb, "new", 1));
    let mut a = old082::SyncState::new(SEED.to_vec(), u.public(), ca.clone(), Some(&ka), strs(&ALL)).unwrap();
    let mut b = SyncState::new(SEED.to_vec(), u.public(), cb.clone(), Some(&kb), strs(&ALL)).unwrap();
    a.auto_first_rotation = false;
    b.auto_first_rotation = false;
    a.configure(CONTEXT, old082::RecordOptions { sealed: true, ..Default::default() }).unwrap();
    b.configure(CONTEXT, sealed()).unwrap();
    a.roster.chain.merge(&old082::decode(&weirdnet_sync::encode(&b.roster.chain.shared()).unwrap()).unwrap());
    a.approve(cb, 2).unwrap();
    b.approve(ca, 2).unwrap();
    a.rotate(3).unwrap();
    a.write(10, POOL, "node-1", b"pool").unwrap();
    a.write(11, TRAIN, "job-1", b"train").unwrap();
    a.write(12, CONTEXT, "chat-1", b"sealed chat").unwrap();
    let a = Arc::new(Mutex::new(a));
    let hellos = Arc::new(Mutex::new(0));
    let h = Counting082 { inner: old082::SyncHandler { state: a.clone() }, hellos: hellos.clone() };
    let na = Node::start(&old082::SYNC_PROFILE, ka.clone(), old082::node_config(true), Arc::new(h)).unwrap();
    let b = Arc::new(Mutex::new(b));
    let nb = weirdnet_sync::start_node(kb.clone(), node_config(true), b.clone()).unwrap();
    let aa = addrs(&na);
    let end = Instant::now() + Duration::from_secs(10);
    let out = loop {
        let out = pull_types_shared(&b, &nb, na.peer_id(), &aa, &ALL);
        if out.is_ok() || Instant::now() > end {
            break out;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(out.is_ok(), "{out:?}");
    // Caught up: the next pass of all three types is one hello on the old peer too.
    a.lock().unwrap().write(20, TRAIN, "job-2", b"train 2").unwrap();
    *hellos.lock().unwrap() = 0;
    let out = pull_types_shared(&b, &nb, na.peer_id(), &aa, &ALL);
    assert!(out.is_ok() && out.applied() == 1, "{out:?}");
    assert_eq!(*hellos.lock().unwrap(), 1);
    let b = b.lock().unwrap();
    assert_eq!(values(&b, POOL), one("node-1", b"pool"));
    assert_eq!(values(&b, TRAIN).len(), 2);
    assert_eq!(values(&b, CONTEXT), one("chat-1", b"sealed chat"));
    na.halt();
    nb.halt();
}

/// The same from a 0.7.1 peer.
#[test]
fn several_types_in_one_session_from_a_0_7_1_peer() {
    let u = user();
    let (ka, kb) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let (ca, cb) = (cert(&u, &ka, "old", 1), cert(&u, &kb, "new", 1));
    let mut a = old07::SyncState::new(SEED.to_vec(), u.public(), ca.clone(), Some(&ka), strs(&ALL)).unwrap();
    let mut b = SyncState::new(SEED.to_vec(), u.public(), cb.clone(), Some(&kb), strs(&ALL)).unwrap();
    a.auto_first_rotation = false;
    b.auto_first_rotation = false;
    a.configure(CONTEXT, old07::RecordOptions { sealed: true, ..Default::default() }).unwrap();
    b.configure(CONTEXT, sealed()).unwrap();
    a.approve(cb, 2).unwrap();
    b.approve(ca, 2).unwrap();
    a.publish_device_key(3).unwrap();
    b.publish_device_key(3).unwrap();
    a.rotate(4).unwrap();
    a.write(10, POOL, "node-1", b"pool").unwrap();
    a.write(11, TRAIN, "job-1", b"train").unwrap();
    a.write(12, CONTEXT, "chat-1", b"sealed chat").unwrap();
    let (a, b) = (Arc::new(Mutex::new(a)), Arc::new(Mutex::new(b)));
    let na = old07::start_node(ka.clone(), old07::node_config(true), a.clone()).unwrap();
    let nb = weirdnet_sync::start_node(kb.clone(), node_config(true), b.clone()).unwrap();
    let (aa, ab) = (addrs(&na), addrs(&nb));
    let end = Instant::now() + Duration::from_secs(10);
    let out = loop {
        let out = pull_types_shared(&b, &nb, na.peer_id(), &aa, &ALL);
        if out.is_ok() && b.lock().unwrap().current_key().id.is_some() || Instant::now() > end {
            break out;
        }
        // The old device admits the new one once it has its device key.
        let _ = old07::pull_from_shared(&a, &na, nb.peer_id(), &ab, POOL);
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(out.is_ok(), "{out:?}");
    let out = pull_types_shared(&b, &nb, na.peer_id(), &aa, &ALL);
    assert!(out.is_ok(), "{out:?}");
    let b = b.lock().unwrap();
    assert_eq!(values(&b, POOL), one("node-1", b"pool"));
    assert_eq!(values(&b, TRAIN), one("job-1", b"train"));
    assert_eq!(values(&b, CONTEXT), one("chat-1", b"sealed chat"));
    na.halt();
    nb.halt();
}
