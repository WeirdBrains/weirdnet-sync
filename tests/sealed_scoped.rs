//! Sealed records on service devices (0.8.4): a service device granted `ymir.context` reads
//! and writes its sealed records under the type-scoped record key, across rotations, while
//! one granted only `ymir.train` can neither pull nor open them, and a revoked one cannot
//! open what is sealed after the rotation that left it out.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, Multiaddr, Node, WEIRDNET};
use weirdnet_sync::record::{open_record, seal_record};
use weirdnet_sync::{
    DeviceClass, LinkBundle, LogEntry, RecordOptions, RecordRef, SyncState, node_config, open_record_scoped, pull_from, rotated_sync_key,
    seal_record_scoped, start_node,
};

const POOL: &str = "ymir.pool";
const TRAIN: &str = "ymir.train";
const CONTEXT: &str = "ymir.context";
const ROLE: &str = "ymir.model";
const SEED: [u8; 32] = *b"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";

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

/// A full device syncing all three types, `ymir.context` sealed, with its first rotation.
fn full(k: &Keypair) -> SyncState {
    let u = user();
    let mut st = SyncState::new(SEED.to_vec(), u.public(), cert(&u, k, "phone", 1), Some(k), strs(&[POOL, TRAIN, CONTEXT])).unwrap();
    st.auto_first_rotation = false;
    st.grant(&peer(k), DeviceClass::Full, &strs(&[ROLE]), &[], 2).unwrap();
    st.configure(CONTEXT, sealed()).unwrap();
    st.rotate(3).unwrap();
    st
}

/// Link `k` as a service device granted `types`; it syncs (and seals `ymir.context` like) Ymir.
fn link(a: &mut SyncState, k: &Keypair, label: &str, types: &[&str], at: i64) -> SyncState {
    let u = user();
    let bundle = a.service_bundle(&peer(k), &strs(&[ROLE]), &strs(types), at).unwrap();
    let bytes = bundle.to_bytes().unwrap().to_vec();
    let c = cert(&u, k, label, at);
    a.approve(c.clone(), at).unwrap();
    let mut st = SyncState::new_service(u.public(), c, k, strs(types), &LinkBundle::from_bytes(&bytes).unwrap()).unwrap();
    st.configure(CONTEXT, sealed()).unwrap();
    st
}

struct Dev {
    st: Arc<Mutex<SyncState>>,
    node: N,
}

impl Dev {
    fn lock(&self) -> std::sync::MutexGuard<'_, SyncState> {
        self.st.lock().unwrap()
    }
}

fn up(k: &Keypair, st: SyncState) -> Dev {
    let st = Arc::new(Mutex::new(st));
    let node = start_node(k.clone(), node_config(true), st.clone()).unwrap();
    Dev { st, node }
}

fn addrs(n: &N) -> Vec<Multiaddr> {
    n.reachable_addrs().into_iter().map(|s| s.parse().unwrap()).collect()
}

/// `to` pulls `typ` from `from`.
fn pull(from: &Dev, to: &Dev, typ: &str) -> Result<usize, weirdnet_sync::SyncError> {
    let mut st = to.lock();
    pull_from(&mut st, &to.node, from.node.peer_id(), &addrs(&from.node), typ)
}

fn latest(st: &SyncState, typ: &str, rid: &str) -> LogEntry {
    st.latest_entries(typ).into_iter().find(|e| e.record_id == rid).unwrap_or_else(|| panic!("{typ}/{rid} is held")).clone()
}

fn text(st: &SyncState, rid: &str) -> Option<Vec<u8>> {
    st.read(&latest(st, CONTEXT, rid)).ok()?.ready().map(|v| v.to_vec())
}

/// Which key a record is sealed under, checked with a full device's epoch key.
fn scheme(a: &SyncState, e: &LogEntry) -> &'static str {
    let v = e.value.as_ref().expect("a value");
    let s = v.seal.as_ref().expect("sealed");
    let ek = a.keys.get(&s.key).expect("the full device holds the rotation");
    let r = RecordRef::of(e);
    if open_record(ek, &a.user_id, &r, s, &v.body).is_ok() {
        return "epoch";
    }
    let tk = rotated_sync_key(ek, &a.user_id, &e.typ, s.epoch, &s.key).unwrap();
    if open_record_scoped(&tk, &a.user_id, &r, s, &v.body).is_ok() { "scoped" } else { "neither" }
}

/// Pull from `from` until `to` holds a key of `from`'s head rotation.
fn catch_up(from: &Dev, to: &Dev, typ: &str) {
    let head = from.lock().roster.head_id();
    let end = Instant::now() + Duration::from_secs(10);
    while to.lock().current_key().id != head {
        assert!(Instant::now() < end, "caught up with the rotation");
        let _ = pull(from, to, typ);
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn an_inference_node_reads_and_writes_sealed_context_and_a_model_node_cannot() {
    let (ka, ki, km) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    // Written before any service device shares ymir.context: sealed with the epoch key.
    a.write(100, CONTEXT, "chat-0", b"before the link").unwrap();
    assert!(!a.seals_scoped(CONTEXT));
    let m = link(&mut a, &km, "model", &[POOL, TRAIN], 10);
    assert!(!a.seals_scoped(CONTEXT), "a model node does not change how ymir.context is sealed");
    let i = link(&mut a, &ki, "inference", &[POOL, CONTEXT], 11);
    assert!(a.roster.service_granted(CONTEXT) && a.seals_scoped(CONTEXT) && i.seals_scoped(CONTEXT));
    assert!(!a.roster.service_granted("ymir.other"));
    a.write(101, CONTEXT, "chat-1", b"after the link").unwrap();
    a.write(102, TRAIN, "job-1", b"train job").unwrap();
    assert_eq!(scheme(&a, &latest(&a, CONTEXT, "chat-0")), "epoch");
    assert_eq!(scheme(&a, &latest(&a, CONTEXT, "chat-1")), "scoped");
    assert_eq!(text(&a, "chat-0").as_deref(), Some(&b"before the link"[..]));
    assert_eq!(text(&a, "chat-1").as_deref(), Some(&b"after the link"[..]));

    let (da, di, dm) = (up(&ka, a), up(&ki, i), up(&km, m));
    // The inference node pulls ymir.context: the type-scoped record opens, the one still
    // under the epoch key does not (yet).
    assert!(pull(&da, &di, CONTEXT).unwrap() >= 2);
    {
        let st = di.lock();
        assert_eq!(text(&st, "chat-1").as_deref(), Some(&b"after the link"[..]));
        assert!(st.read(&latest(&st, CONTEXT, "chat-0")).is_err());
    }
    // The model node is refused ymir.context and gets ymir.train, unsealed as before.
    assert!(pull(&da, &dm, CONTEXT).is_err());
    assert!(pull(&da, &dm, TRAIN).unwrap() >= 1);
    {
        let st = dm.lock();
        assert!(st.log.iter().all(|e| e.typ != CONTEXT));
        let job = latest(&st, TRAIN, "job-1");
        assert!(job.value.is_none(), "ymir.train stays a plain entry");
        assert_eq!(st.read(&job).unwrap().ready().unwrap().as_slice(), b"train job");
        // Even given the ciphertext, it opens neither record.
        let a = da.lock();
        for rid in ["chat-0", "chat-1"] {
            assert!(st.read(&latest(&a, CONTEXT, rid)).is_err(), "{rid}");
        }
    }

    // The inference node writes; the full device reads it, the model node cannot.
    di.lock().write(200, CONTEXT, "chat-2", b"from the inference node").unwrap();
    assert!(pull(&di, &da, CONTEXT).unwrap() >= 1);
    {
        let a = da.lock();
        assert_eq!(text(&a, "chat-2").as_deref(), Some(&b"from the inference node"[..]));
        assert_eq!(scheme(&a, &latest(&a, CONTEXT, "chat-2")), "scoped");
        assert!(dm.lock().read(&latest(&a, CONTEXT, "chat-2")).is_err());
    }

    // reseal_stale moves the record sealed with the epoch key to the type-scoped key.
    assert_eq!(da.lock().reseal_stale(300, CONTEXT).unwrap(), vec!["chat-0".to_string()]);
    assert!(da.lock().reseal_stale(301, CONTEXT).unwrap().is_empty(), "nothing left to move");
    {
        let a = da.lock();
        assert_eq!(scheme(&a, &latest(&a, CONTEXT, "chat-0")), "scoped");
    }
    pull(&da, &di, CONTEXT).unwrap();
    assert_eq!(text(&di.lock(), "chat-0").as_deref(), Some(&b"before the link"[..]));
    assert!(dm.lock().read(&latest(&da.lock(), CONTEXT, "chat-0")).is_err());
    // A service device never moves anything: it cannot open records under the epoch key.
    assert!(di.lock().reseal_stale(302, CONTEXT).unwrap().is_empty());
}

#[test]
fn a_revoked_inference_node_cannot_open_context_sealed_after_the_rotation() {
    let (ka, k1, k2) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    let i1 = link(&mut a, &k1, "inference-1", &[POOL, CONTEXT], 10);
    let i2 = link(&mut a, &k2, "inference-2", &[POOL, CONTEXT], 11);
    a.write(100, CONTEXT, "chat-1", b"before the revocation").unwrap();
    let (da, d1, d2) = (up(&ka, a), up(&k1, i1), up(&k2, i2));
    for d in [&d1, &d2] {
        assert!(pull(&da, d, CONTEXT).unwrap() >= 1);
        assert_eq!(text(&d.lock(), "chat-1").as_deref(), Some(&b"before the revocation"[..]));
    }

    // Revoking inference-1 rotates; the new rotation admits only inference-2.
    let old_head = da.lock().roster.head_id().unwrap();
    da.lock().revoke(&user(), &peer(&k1), 40).unwrap();
    let new_head = da.lock().roster.head_id().unwrap();
    assert_ne!(old_head, new_head);
    {
        let a = da.lock();
        let head = a.roster.chain_view().head().cloned().unwrap();
        assert!(!head.members.contains(&peer(&k1)) && head.members.contains(&peer(&k2)));
        assert!(a.seals_scoped(CONTEXT), "inference-2 still shares ymir.context");
    }
    da.lock().write(101, CONTEXT, "chat-2", b"after the revocation").unwrap();

    // inference-2 takes the new rotation's scoped key, reads and writes under it.
    catch_up(&da, &d2, CONTEXT);
    pull(&da, &d2, CONTEXT).unwrap();
    assert_eq!(text(&d2.lock(), "chat-2").as_deref(), Some(&b"after the revocation"[..]));
    d2.lock().write(200, CONTEXT, "chat-3", b"inference-2 after the rotation").unwrap();
    pull(&d2, &da, CONTEXT).unwrap();
    {
        let a = da.lock();
        let e = latest(&a, CONTEXT, "chat-3");
        assert_eq!(e.value.as_ref().unwrap().seal.as_ref().unwrap().key, new_head);
        assert_eq!(scheme(&a, &e), "scoped");
        assert_eq!(text(&a, "chat-3").as_deref(), Some(&b"inference-2 after the rotation"[..]));
    }

    // inference-1 is refused, holds no key of the new rotation, and opens neither new record
    // even given the ciphertext.
    let _ = pull(&da, &d1, CONTEXT);
    {
        let st = d1.lock();
        assert!(st.keys.get_scoped(&new_head, CONTEXT).is_none());
        assert!(!st.keys.has(&new_head));
        let a = da.lock();
        for rid in ["chat-2", "chat-3"] {
            assert!(st.read(&latest(&a, CONTEXT, rid)).is_err(), "{rid}");
        }
    }
    // What it still writes can only be under the rotation it held (peers refuse its sessions).
    {
        let mut st = d1.lock();
        st.write(300, CONTEXT, "chat-x", b"stale").unwrap();
        assert_eq!(latest(&st, CONTEXT, "chat-x").value.unwrap().seal.unwrap().key, old_head);
    }

    // Revoking inference-2 too: no service device shares ymir.context, so the full device
    // seals with the epoch key again and reseal_stale moves everything there.
    da.lock().revoke(&user(), &peer(&k2), 50).unwrap();
    let mut a = da.lock();
    assert!(!a.seals_scoped(CONTEXT));
    a.write(102, CONTEXT, "chat-4", b"full devices only").unwrap();
    assert_eq!(scheme(&a, &latest(&a, CONTEXT, "chat-4")), "epoch");
    let mut done = a.reseal_stale(400, CONTEXT).unwrap();
    done.sort();
    assert_eq!(done, strs(&["chat-1", "chat-2", "chat-3"]));
    for rid in ["chat-1", "chat-2", "chat-3", "chat-4"] {
        assert_eq!(scheme(&a, &latest(&a, CONTEXT, rid)), "epoch", "{rid}");
        assert!(text(&a, rid).is_some(), "{rid}");
    }
}

#[test]
fn record_keys_are_bound_to_their_scheme_type_and_rotation() {
    let (ka, ki) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka);
    let i = link(&mut a, &ki, "inference", &[POOL, CONTEXT], 10);
    let key = a.current_key();
    let id = key.id.clone().unwrap();
    let ek = a.keys.get(&id).unwrap().clone();
    let tk = rotated_sync_key(&ek, &a.user_id, CONTEXT, key.epoch, &id).unwrap();
    assert_eq!(i.keys.get_scoped(&id, CONTEXT).unwrap().0, tk.0, "the service holds the same type key");
    let r = RecordRef { typ: CONTEXT, record_id: "chat-1", node: "peer-a" };
    let (s, ct) = seal_record_scoped(&tk, &a.user_id, &r, key.epoch, &id, b"hi").unwrap();
    assert_eq!(&open_record_scoped(&tk, &a.user_id, &r, &s, &ct).unwrap()[..], b"hi");
    // Not the epoch-key scheme, not another record, type, writer, user or rotation.
    assert!(open_record(&ek, &a.user_id, &r, &s, &ct).is_err());
    for other in [RecordRef { record_id: "chat-2", ..r }, RecordRef { node: "peer-b", ..r }, RecordRef { typ: TRAIN, ..r }] {
        assert!(open_record_scoped(&tk, &a.user_id, &other, &s, &ct).is_err(), "{other:?}");
    }
    assert!(open_record_scoped(&tk, "user-2", &r, &s, &ct).is_err());
    let train = rotated_sync_key(&ek, &a.user_id, TRAIN, key.epoch, &id).unwrap();
    assert!(open_record_scoped(&train, &a.user_id, &r, &s, &ct).is_err(), "another type's key");
    let mut moved = s.clone();
    moved.key = "other".into();
    assert!(open_record_scoped(&tk, &a.user_id, &r, &moved, &ct).is_err());
    // An epoch-key seal does not open under the type-scoped scheme.
    let (s2, ct2) = seal_record(&ek, &a.user_id, &r, key.epoch, &id, b"hi").unwrap();
    assert!(open_record_scoped(&tk, &a.user_id, &r, &s2, &ct2).is_err());
    // The KDF labels differ from the epoch-key scheme.
    assert_ne!(
        weirdnet_sync::scoped_record_key(&tk, &a.user_id, CONTEXT, "chat-1", key.epoch, &id).unwrap().0,
        weirdnet_sync::record::record_key(&ek, &a.user_id, CONTEXT, "chat-1", key.epoch, &id).unwrap().0
    );
    assert_ne!(weirdnet_sync::scoped_record_aad(&r, key.epoch, &id), weirdnet_sync::record::record_aad(&r, key.epoch, &id));
}
