//! 0.7.1 devices and this version share sealed records unchanged: each writes, the other
//! pulls over `/weirdnet/sync/2` and reads the same bytes back.
use std::sync::{Arc, Mutex};

use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, Multiaddr, WEIRDNET};
use weirdnet_sync as new;
use weirdnet_sync_07 as old;

const CONTEXT: &str = "ymir.context";
const SEED: [u8; 32] = *b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

fn user() -> Keypair {
    let mut s = SEED;
    Keypair::ed25519_from_bytes(&mut s).unwrap()
}

fn peer(k: &Keypair) -> String {
    k.public().to_peer_id().to_string()
}

fn cert(user: &Keypair, k: &Keypair, label: &str) -> NodeCert {
    WEIRDNET.certify(user, &user::user_id(&user.public()), &peer(k), label, 1).unwrap()
}

fn addrs(r: Vec<String>) -> Vec<Multiaddr> {
    r.into_iter().map(|s| s.parse().unwrap()).collect()
}

fn values_new(st: &new::SyncState) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> =
        st.log.iter().filter(|e| e.typ == CONTEXT).filter_map(|e| st.read(e).ok()?.ready().map(|b| (e.record_id.clone(), b.to_vec()))).collect();
    v.sort();
    v
}

fn values_old(st: &old::SyncState) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> =
        st.log.iter().filter(|e| e.typ == CONTEXT).filter_map(|e| st.read(e).ok()?.ready().map(|b| (e.record_id.clone(), b.to_vec()))).collect();
    v.sort();
    v
}

#[test]
fn sealed_records_cross_between_0_7_1_and_this_version() {
    let u = user();
    let (ka, kb) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let (ca, cb) = (cert(&u, &ka, "old"), cert(&u, &kb, "new"));
    let mut a = old::SyncState::new(SEED.to_vec(), u.public(), ca.clone(), Some(&ka), vec![CONTEXT.into()]).unwrap();
    let mut b = new::SyncState::new(SEED.to_vec(), u.public(), cb.clone(), Some(&kb), vec![CONTEXT.into()]).unwrap();
    a.auto_first_rotation = false;
    b.auto_first_rotation = false;
    a.configure(CONTEXT, old::RecordOptions { sealed: true, ..Default::default() }).unwrap();
    b.configure(CONTEXT, new::RecordOptions { sealed: true, ..Default::default() }).unwrap();
    a.approve(cb, 2).unwrap();
    b.approve(ca, 2).unwrap();
    a.publish_device_key(3).unwrap();
    b.publish_device_key(3).unwrap();
    // The old device starts the key chain, as a lone device does.
    a.rotate(4).unwrap();
    let (a, b) = (Arc::new(Mutex::new(a)), Arc::new(Mutex::new(b)));
    let na = old::start_node(ka.clone(), old::node_config(true), a.clone()).unwrap();
    let nb = new::start_node(kb.clone(), new::node_config(true), b.clone()).unwrap();
    let (aa, ab) = (addrs(na.reachable_addrs()), addrs(nb.reachable_addrs()));
    let pass = || {
        let _ = new::pull_from_shared(&b, &nb, na.peer_id(), &aa, CONTEXT);
        let _ = old::pull_from_shared(&a, &na, nb.peer_id(), &ab, CONTEXT);
    };
    // Sync passes until the new device holds the chain's key (it is admitted once the old
    // one has its device key).
    a.lock().unwrap().write(10, CONTEXT, "turn-1", b"from 0.7.1").unwrap();
    let mut wrote = false;
    for _ in 0..10 {
        pass();
        if b.lock().unwrap().write(11, CONTEXT, "turn-2", b"from 0.8").is_ok() {
            wrote = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(wrote, "the 0.8 device got the key from the 0.7.1 one");
    pass();
    pass();
    let want = vec![("turn-1".to_string(), b"from 0.7.1".to_vec()), ("turn-2".to_string(), b"from 0.8".to_vec())];
    assert_eq!(values_new(&b.lock().unwrap()), want);
    assert_eq!(values_old(&a.lock().unwrap()), want);
    // The stored log entries are the same bytes on both sides.
    let enc_old: Vec<Vec<u8>> = a.lock().unwrap().log.iter().filter(|e| e.typ == CONTEXT).map(|e| old::encode(e).unwrap()).collect();
    let enc_new: Vec<Vec<u8>> = b.lock().unwrap().log.iter().filter(|e| e.typ == CONTEXT).map(|e| new::encode(e).unwrap()).collect();
    let (mut enc_old, mut enc_new) = (enc_old, enc_new);
    enc_old.sort();
    enc_new.sort();
    assert_eq!(enc_old, enc_new);
    na.halt();
    nb.halt();
}
