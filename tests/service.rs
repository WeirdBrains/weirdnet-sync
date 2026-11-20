//! Service devices: linked with a certificate and a grant, never the seed.
use std::sync::{Arc, Mutex};

use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, Multiaddr, Node, WEIRDNET};
use weirdnet_sync::{
    CallerCheck, DeviceClass, DeviceGrant, Envelope, Identity, KeyStatus, LinkBundle, Message, Pull, Roster, SyncError, SyncState, node_config,
    pull_from, start_node,
};

const T: &str = "ymir.pool";
const SEED: [u8; 32] = *b"SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS";

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

fn roles(r: &[&str]) -> Vec<String> {
    r.iter().map(|s| s.to_string()).collect()
}

/// A full device (holds the seed) that has made the first rotation.
fn full(k: &Keypair, label: &str) -> SyncState {
    let u = user();
    let mut st = SyncState::new(SEED.to_vec(), u.public(), cert(&u, k, label, 1), Some(k), vec![T.into()]).unwrap();
    st.auto_first_rotation = false;
    st
}

fn serve(k: &Keypair, st: SyncState) -> (Arc<Mutex<SyncState>>, N) {
    let st = Arc::new(Mutex::new(st));
    let n = start_node(k.clone(), node_config(true), st.clone()).unwrap();
    (st, n)
}

/// Link `k` as a service device from `a`, the way a device-link credential does.
fn link_service(a: &mut SyncState, k: &Keypair, label: &str, roles: &[String], types: &[String]) -> SyncState {
    let u = user();
    let bundle = a.service_bundle(&peer(k), roles, types, 10).unwrap();
    let bytes = bundle.to_bytes().unwrap();
    let c = cert(&u, k, label, 10);
    a.approve(c.clone(), 10).unwrap();
    SyncState::new_service(u.public(), c, k, vec![T.into()], &LinkBundle::from_bytes(&bytes).unwrap()).unwrap()
}

#[test]
fn a_service_node_with_types_syncs_without_the_seed_and_is_cut_off_by_revocation() {
    let (ka, ks) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka, "phone");
    assert!(a.roster.head_id().is_none());
    let s = link_service(&mut a, &ks, "inference", &roles(&["ymir.inference"]), &roles(&[T]));
    assert!(a.roster.head_id().is_some(), "a service link with types rotates first");
    assert!(s.is_service() && s.seed.is_none());
    assert!(matches!(s.key_status(), KeyStatus::Current { .. }), "{:?}", s.key_status());
    assert!(s.roster.has_role(&peer(&ks), "ymir.inference"));
    a.local_op(1_000, T, "r1", b"from a".to_vec());

    let (sa, na) = serve(&ka, a);
    let (ss, ns) = serve(&ks, s);
    {
        let mut st = ss.lock().unwrap();
        assert_eq!(pull_from(&mut st, &ns, na.peer_id(), &addrs(&na), T).unwrap(), 1);
        st.local_op(2_000, T, "r2", b"from s".to_vec());
    }
    {
        let mut st = sa.lock().unwrap();
        assert_eq!(pull_from(&mut st, &na, ns.peer_id(), &addrs(&ns), T).unwrap(), 1);
        assert_eq!(st.roster.check_caller(&WEIRDNET, &user().public(), &peer(&ks), None), CallerCheck::Linked);
    }
    // Nothing that needs the user key works there.
    {
        let mut st = ss.lock().unwrap();
        assert!(matches!(st.grant(&peer(&ka), DeviceClass::Full, &[], &[], 5), Err(SyncError::NotPermitted(_))));
        assert!(matches!(st.rotate(5), Err(SyncError::NotPermitted(_))));
        assert!(matches!(st.revoke(&user(), &peer(&ka), 5), Err(SyncError::NotPermitted(_))));
        let other = cert(&user(), &Keypair::generate_ed25519(), "x", 5);
        assert!(matches!(st.approve(other, 5), Err(SyncError::NotPermitted(_))));
        assert!(matches!(st.service_bundle("p", &[], &[], 5), Err(SyncError::NotPermitted(_))));
    }
    // A later rotation (another device revoked) is sealed to it: it keeps syncing.
    {
        let kc = Keypair::generate_ed25519();
        let mut st = sa.lock().unwrap();
        st.approve(cert(&user(), &kc, "old laptop", 2_100), 2_100).unwrap();
        st.revoke(&user(), &peer(&kc), 2_200).unwrap();
        st.local_op(2_300, T, "r2b", b"after a rotation".to_vec());
    }
    {
        let mut st = ss.lock().unwrap();
        pull_from(&mut st, &ns, na.peer_id(), &addrs(&na), T).unwrap();
        assert_eq!(st.roster.head_id(), sa.lock().unwrap().roster.head_id());
        assert!(matches!(st.key_status(), KeyStatus::Current { .. }), "{:?}", st.key_status());
        assert!(st.log.iter().any(|e| e.record_id == "r2b"));
    }
    // The phone revokes it: a new key leaves it out, and it is refused.
    let before = sa.lock().unwrap().roster.head_id();
    {
        let mut st = sa.lock().unwrap();
        st.revoke(&user(), &peer(&ks), 3_000).unwrap();
        assert_ne!(st.roster.head_id(), before);
        let head = st.roster.chain_view().head().cloned().unwrap();
        assert!(!head.members.contains(&peer(&ks)));
        st.local_op(4_000, T, "r3", b"after".to_vec());
    }
    let mut st = ss.lock().unwrap();
    match pull_from(&mut st, &ns, na.peer_id(), &addrs(&na), T) {
        Err(SyncError::Refused(r)) => assert_eq!(r, "revoked"),
        other => panic!("expected revoked, got {other:?}"),
    }
    assert!(st.log.iter().all(|e| e.record_id != "r3"));
}

#[test]
fn a_roster_only_node_follows_the_roster_and_holds_no_keys() {
    let (ka, km, kc) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let mut a = full(&ka, "phone");
    let m = link_service(&mut a, &km, "model", &roles(&["ymir.model"]), &[]);
    assert_eq!(m.key_status(), KeyStatus::RosterOnly);
    assert!(m.keys.is_empty());
    assert!(m.roster.head_id().is_none(), "no rotation needed for a roster-only link");
    assert!(!a.roster.chain.approved.contains(&peer(&km)), "never queued for admission");
    a.rotate(20).unwrap();
    let head = a.roster.chain_view().head().cloned().unwrap();
    assert!(!head.members.contains(&peer(&km)));
    assert_eq!(a.roster.check_caller(&WEIRDNET, &user().public(), &peer(&km), None), CallerCheck::Linked);

    let (sa, na) = serve(&ka, a);
    let (sm, nm) = serve(&km, m);
    // A device linked later, with a role, reaches the model node.
    {
        let mut st = sa.lock().unwrap();
        st.approve(cert(&user(), &kc, "laptop", 30), 30).unwrap();
        st.grant(&peer(&kc), DeviceClass::Full, &roles(&["ymir.app"]), &[], 30).unwrap();
        st.local_op(1_000, T, "secret", b"not for model nodes".to_vec());
    }
    {
        let mut st = sm.lock().unwrap();
        assert_eq!(pull_from(&mut st, &nm, na.peer_id(), &addrs(&na), T).unwrap(), 0);
        assert!(st.roster.get(&peer(&kc)).is_some_and(|c| c.active()));
        assert_eq!(st.roster.roles_of(&peer(&kc)), Some(&roles(&["ymir.app"])[..]));
        assert!(st.log.is_empty(), "a roster-only node pulls no records");
        assert!(st.keys.is_empty());
    }
    // A revocation reaches it too.
    sa.lock().unwrap().revoke(&user(), &peer(&kc), 40).unwrap();
    {
        let mut st = sm.lock().unwrap();
        pull_from(&mut st, &nm, na.peer_id(), &addrs(&na), T).unwrap();
        assert!(st.roster.get(&peer(&kc)).is_some_and(|c| !c.active()));
        assert_eq!(st.roster.check_caller(&WEIRDNET, &user().public(), &peer(&kc), None), CallerCheck::Revoked);
        assert!(st.keys.is_empty(), "the rotation after the revocation is not sealed to it");
    }
    // The phone pulling from the model node swaps rosters and does not fail.
    let mut st = sa.lock().unwrap();
    assert_eq!(pull_from(&mut st, &na, nm.peer_id(), &addrs(&nm), T).unwrap(), 0);
}

#[test]
fn grants_verify_under_the_user_key_and_the_newest_wins() {
    let u = user();
    let k = Keypair::generate_ed25519();
    let mut r = Roster::new();
    r.upsert(cert(&u, &k, "n", 1));
    let g1 = DeviceGrant::sign(&u, &peer(&k), DeviceClass::Service, &roles(&["b", "a", "a"]), &[], 5).unwrap();
    assert_eq!(g1.roles, roles(&["a", "b"]), "sorted and deduplicated");
    assert!(r.add_grant(g1.clone(), &u.public()));
    assert!(r.is_service(&peer(&k)) && !r.holds_keys(&peer(&k)));
    let older = DeviceGrant::sign(&u, &peer(&k), DeviceClass::Full, &[], &[], 4).unwrap();
    assert!(!r.add_grant(older, &u.public()));
    let newer = DeviceGrant::sign(&u, &peer(&k), DeviceClass::Service, &roles(&["c"]), &roles(&[T]), 6).unwrap();
    assert!(r.add_grant(newer, &u.public()));
    assert_eq!(r.roles_of(&peer(&k)), Some(&roles(&["c"])[..]));
    assert!(r.holds_keys(&peer(&k)));
    // Signed by anyone else: dropped.
    let forged = DeviceGrant::sign(&Keypair::generate_ed25519(), &peer(&k), DeviceClass::Full, &roles(&["admin"]), &[], 9).unwrap();
    assert!(!r.add_grant(forged.clone(), &u.public()));
    let mut tampered = r.grant_of(&peer(&k)).unwrap().clone();
    tampered.roles = roles(&["admin"]);
    tampered.issued_at = 99;
    assert!(!r.add_grant(tampered, &u.public()));
    assert!(DeviceGrant::sign(&u, "p", DeviceClass::Full, &roles(&["bad name"]), &[], 1).is_err());
    // Merge carries grants; a revoked cert's grant counts for nothing.
    let mut other = Roster::new();
    other.merge(&r, &u.public(), &WEIRDNET);
    assert_eq!(other.roles_of(&peer(&k)), Some(&roles(&["c"])[..]));
    let mut pk = Roster::new();
    pk.upsert(cert(&u, &k, "n", 1));
    pk.revoke(&WEIRDNET, &u, &peer(&k), 7).unwrap();
    pk.merge(&r, &u.public(), &WEIRDNET);
    assert!(pk.grant_of(&peer(&k)).is_none());
    // JSON (roster.json) round trip.
    let json = serde_json::to_string(&r).unwrap();
    let back: Roster = serde_json::from_str(&json).unwrap();
    assert_eq!(back.grants, r.grants);
}

#[test]
fn only_rosters_and_refusals_travel_unsealed() {
    let pull = Message::Pull(Pull { node_id: weirdnet_sync::NodeId("n".into()), after_seq: 0, typ: T.into(), limit: 1 });
    assert!(Envelope::clear(T, 0, &pull).is_err());
    let refuse = Message::Refuse(weirdnet_sync::Refuse::new("x"));
    let env = Envelope::clear(T, 3, &refuse).unwrap();
    assert_eq!(env.open_clear().unwrap(), refuse);
    // A clear envelope smuggling a pull is refused on open.
    let mut bad = env.clone();
    bad.sealed.ct = hex::encode(weirdnet_sync::encode(&pull).unwrap());
    assert!(bad.open_clear().is_err());
}

#[test]
fn a_service_identity_is_stored_without_a_seed() {
    let tmp = tempfile::tempdir().unwrap();
    let a = Identity::create(&tmp.path().join("a"), "phone", T).unwrap();
    let ks = Keypair::generate_ed25519();
    let bundle = a.service_bundle(&peer(&ks), &roles(&["ymir.inference"]), &roles(&[T])).unwrap();
    let user = a.user_keypair().unwrap();
    let c = WEIRDNET.certify(&user, &a.user_id(), &peer(&ks), "server", 10).unwrap();
    a.approve(c.clone()).unwrap();
    let dir = tmp.path().join("s");
    let s = Identity::adopt_service(&dir, ks.clone(), &a.user_key().encode_protobuf(), c.clone(), &bundle, T).unwrap();
    assert!(s.is_service());
    assert!(matches!(s.seed(), Err(SyncError::NotPermitted(_))));
    assert!(matches!(s.user_keypair(), Err(SyncError::NotPermitted(_))));
    assert!(matches!(s.revoke(&a.peer_id().to_string()), Err(SyncError::NotPermitted(_))));
    assert!(!dir.join("seed").exists() && dir.join("credential.json").is_file() && dir.join("node.key").is_file());
    drop(s);
    let s = Identity::open(&dir, T).unwrap().expect("reopened");
    assert!(s.is_service());
    assert_eq!(s.user_key(), a.user_key());
    assert!(s.roster().has_role(&s.peer_id().to_string(), "ymir.inference"));
    assert!(matches!(s.state().lock().unwrap().key_status(), KeyStatus::Current { .. }));
    // A certificate for another node, or a bundle for another node, is refused.
    let other = Keypair::generate_ed25519();
    assert!(Identity::adopt_service(&tmp.path().join("x"), other, &a.user_key().encode_protobuf(), c, &bundle, T).is_err());
    assert!(a.roster().is_service(&peer(&ks)));
}
