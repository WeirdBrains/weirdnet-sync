//! 0.8.3 type-scoped keys stay wire-compatible with 0.8.2 full devices: chains (rotations and
//! admissions) decode and re-encode byte for byte, so ids and signatures hold; epoch-key
//! exports import; and a scoped envelope from a service device opens with 0.8.2's epoch key.
use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, WEIRDNET};
use weirdnet_sync::{LinkBundle, Message, NodeId, Pull, SyncState, encode};
use weirdnet_sync_082 as old;

const TRAIN: &str = "ymir.train";
const SEED: [u8; 32] = *b"OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO";

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

#[test]
fn a_0_8_2_full_device_reads_0_8_3_chains_keys_and_scoped_envelopes() {
    let (ka, ks, kb) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
    let u = user();
    let mut a = SyncState::new(SEED.to_vec(), u.public(), cert(&u, &ka, "phone", 1), Some(&ka), vec![TRAIN.into()]).unwrap();
    a.auto_first_rotation = false;
    let bundle = a.service_bundle(&peer(&ks), &["ymir.model".into()], &[TRAIN.into()], 10).unwrap();
    let c = cert(&u, &ks, "model", 10);
    a.approve(c.clone(), 10).unwrap();
    let s = SyncState::new_service(u.public(), c, &ks, vec![TRAIN.into()], &LinkBundle::from_bytes(&bundle.to_bytes().unwrap()).unwrap()).unwrap();
    // Publish the service's device key, then rotate: the service gets a scoped admission.
    a.roster.chain.merge(&s.roster.chain.shared());
    a.rotate(20).unwrap();
    assert!(a.roster.chain.admissions.iter().any(|x| x.peer_id == peer(&ks)));

    // The chain, as 0.8.2 decodes it, re-encodes to the same bytes with the same ids.
    let bytes = encode(&a.roster.chain.shared()).unwrap();
    let oc: old::KeyChain = old::decode(&bytes).unwrap();
    assert_eq!(old::encode(&oc).unwrap(), bytes);
    let ids: Vec<String> = a.roster.chain.rotations.iter().map(|r| r.id()).collect();
    assert_eq!(oc.rotations.iter().map(|r| r.id()).collect::<Vec<_>>(), ids);
    let adm: Vec<String> = a.roster.chain.admissions.iter().map(|x| x.id()).collect();
    assert_eq!(oc.admissions.iter().map(|x| x.id()).collect::<Vec<_>>(), adm);
    let mut merged = old::KeyChain::default();
    merged.merge(&oc);
    assert_eq!((merged.rotations.len(), merged.admissions.len()), (oc.rotations.len(), oc.admissions.len()), "signatures verify on 0.8.2");

    // A full device's key export imports on 0.8.2.
    let ok = old::EpochKeys::import(&a.keys.export()).unwrap();
    assert_eq!(ok.len(), a.keys.len());

    // An envelope the service seals with its scoped key opens with 0.8.2's epoch key.
    let key = s.current_key();
    let id = key.id.clone().unwrap();
    let pull = Message::Pull(Pull { node_id: NodeId(peer(&ka)), after_seq: 0, typ: TRAIN.into(), limit: 1 });
    let env = s.seal_envelope(&key, TRAIN, &peer(&kb), &pull).unwrap();
    let oe: old::Envelope = old::decode(&encode(&env).unwrap()).unwrap();
    let opened = oe.open_keyed(a.keys.get(&id).unwrap(), &a.user_id, &peer(&kb)).unwrap();
    assert_eq!(old::encode(&opened).unwrap(), encode(&pull).unwrap());
    // And one 0.8.2 seals opens on the service.
    let back = old::Envelope::seal_keyed(a.keys.get(&id).unwrap(), &id, &a.user_id, TRAIN, key.epoch, &peer(&ks), &opened).unwrap();
    let ne: weirdnet_sync::Envelope = weirdnet_sync::decode(&old::encode(&back).unwrap()).unwrap();
    assert_eq!(s.open_envelope(&ne, &peer(&ks)).unwrap(), pull);
}
