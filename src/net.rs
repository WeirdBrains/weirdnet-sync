//! The pull protocol running on a [`weirdnet_net::Node`] (`/weirdnet/sync/1`).
//!
//! The official WeirdBrains relay must not store pages; this module only exchanges
//! sealed envelopes between the user's own nodes.
use crate::error::{Result, SyncError};
use crate::hlc::{Hlc, NodeId};
use crate::log::OpLog;
use crate::protocol::{Ack, Envelope, Hello, HelloOk, Message, PAGE_MAX, Pull, Refuse, RosterMsg, SYNC_PROFILE, decode, encode};
use crate::roster::{Roster, SessionCheck};
use std::sync::{Arc, Mutex};
use weirdnet_net::user::NodeCert;
use weirdnet_net::{Handler, Keypair, Multiaddr, Node, NodeConfig, PeerId, PublicKey, WEIRDNET};

/// Mutable state a sync node answers from and applies pages into.
pub struct SyncState {
    pub seed: Vec<u8>,
    pub user_id: String,
    pub user_key: PublicKey,
    pub our_cert: NodeCert,
    pub our_node: NodeId,
    pub types: Vec<String>,
    pub roster: Roster,
    pub log: OpLog,
    pub clock: Option<Hlc>,
}

impl SyncState {
    pub fn handle(&mut self, from: &str, env: Envelope) -> Result<Envelope> {
        // Open with our seed and user id; a foreign user fails here (wrong-user).
        let msg = match env.open(&self.seed, &self.user_id, from) {
            Ok(m) => m,
            Err(_) => {
                return self.refuse(from, &env.typ, env.epoch, "wrong-user");
            }
        };
        let reply = match msg {
            Message::Hello(h) => self.on_hello(from, h),
            Message::Pull(p) => self.on_pull(p),
            // An ack is the puller's progress, not ours: it must not move our cursors.
            Message::Ack(a) => Message::Ack(Ack { node_id: a.node_id, last_seq: a.last_seq }),
            Message::Roster(r) => {
                let incoming = Roster { epoch: r.epoch, certs: r.certs };
                self.roster.merge(&incoming, &self.user_key, &WEIRDNET);
                Message::Roster(RosterMsg { certs: self.roster.certs.clone(), epoch: self.roster.epoch })
            }
            Message::HelloOk(_) | Message::Page(_) | Message::Refuse(_) => {
                return Err(SyncError::Protocol("unexpected request".into()));
            }
        };
        Envelope::seal(&self.seed, &self.user_id, &env.typ, self.roster.epoch, from, &reply)
    }

    fn refuse(&self, from: &str, typ: &str, epoch: u32, reason: &'static str) -> Result<Envelope> {
        Envelope::seal(&self.seed, &self.user_id, typ, epoch, from, &Message::Refuse(Refuse::new(reason)))
    }

    fn on_hello(&self, _from: &str, h: Hello) -> Message {
        let check = self.roster.check_session(
            &WEIRDNET,
            &self.user_key,
            &self.user_id,
            &crate::roster::SessionOffer { cert: &h.cert, epoch: h.epoch, types: &h.types },
            &self.types,
        );
        if check == SessionCheck::EpochBehind {
            // A valid, unrevoked device of this user that missed a revocation: send the
            // roster (user-signed certs and revocations) so it can catch up and retry.
            return Message::Roster(RosterMsg { certs: self.roster.certs.clone(), epoch: self.roster.epoch });
        }
        if check != SessionCheck::Ok {
            return Message::Refuse(Refuse::new(check.reason().unwrap_or("wrong-user")));
        }
        let cursors = self.log.cursors().into_iter().collect();
        let revocations = self.roster.certs.iter().filter(|c| !c.active()).cloned().collect();
        Message::HelloOk(HelloOk { cert: self.our_cert.clone(), epoch: self.roster.epoch, cursors, revocations })
    }

    fn on_pull(&self, p: Pull) -> Message {
        if !self.types.iter().any(|t| t == &p.typ) {
            return Message::Refuse(Refuse::new("type-off"));
        }
        let limit = (p.limit as usize).clamp(1, 4096);
        let known = self.log.cursor_for(&p.node_id, &p.typ);
        let page = self.log.page_of_type(&p.node_id, &p.typ, p.after_seq, known, limit);
        Message::Page(crate::protocol::Page { typ: p.typ, page })
    }

    /// A local write: tick the clock, append one log op.
    pub fn local_op(&mut self, now_ms: u64, typ: &str, record_id: &str, op: Vec<u8>) {
        let hlc = Hlc::tick(self.clock.as_ref(), now_ms, self.our_node.clone());
        self.clock = Some(hlc.clone());
        self.log.append(self.our_node.clone(), hlc, typ, record_id, op);
    }
}

/// Request-response handler that talks [`Envelope`] on [`SYNC_PROFILE`].
pub struct SyncHandler {
    pub state: Arc<Mutex<SyncState>>,
}

impl Handler<Vec<u8>, Vec<u8>> for SyncHandler {
    fn request(&self, from: &PeerId, req: Vec<u8>) -> Vec<u8> {
        let env: Envelope = match decode(&req) {
            Ok(e) => e,
            Err(e) => return error_bytes(&e.to_string()),
        };
        let mut st = self.state.lock().expect("sync state");
        match st.handle(&from.to_string(), env) {
            Ok(reply) => encode(&reply).unwrap_or_else(|e| error_bytes(&e.to_string())),
            Err(e) => error_bytes(&e.to_string()),
        }
    }
}

fn error_bytes(msg: &str) -> Vec<u8> {
    encode(&Message::Refuse(Refuse { reason: format!("codec:{msg}") })).unwrap_or_default()
}

/// Listen with the in-memory transport (tests) or the caller's config, 256 KiB caps.
pub fn node_config(listen_memory: bool) -> NodeConfig {
    NodeConfig {
        listen: if listen_memory { vec!["/memory/0".parse().expect("memory addr")] } else { Vec::new() },
        memory: listen_memory,
        request_max: PAGE_MAX as u64,
        response_max: PAGE_MAX as u64,
        label: "sync".into(),
        ..Default::default()
    }
}

/// Start a sync node on [`SYNC_PROFILE`].
pub fn start_node(key: Keypair, cfg: NodeConfig, state: Arc<Mutex<SyncState>>) -> Result<Node<Vec<u8>, Vec<u8>>> {
    Ok(Node::start(&SYNC_PROFILE, key, cfg, Arc::new(SyncHandler { state }))?)
}

/// Hello then pull every roster member the peer advertised, applying pages and acking.
pub fn pull_from(state: &mut SyncState, node: &Node<Vec<u8>, Vec<u8>>, peer: PeerId, addrs: &[Multiaddr], typ_name: &str) -> Result<usize> {
    let from = node.peer_id().to_string();
    let mut retried = false;
    let ok = loop {
        let hello = Message::Hello(Hello {
            cert: state.our_cert.clone(),
            user_id: state.user_id.clone(),
            epoch: state.roster.epoch,
            types: state.types.clone(),
            our_cursors: state.log.cursors().into_iter().collect(),
            our_hlc: state.clock.clone().unwrap_or_else(|| Hlc::new(0, 0, state.our_node.clone())),
        });
        let env = Envelope::seal(&state.seed, &state.user_id, typ_name, state.roster.epoch, &from, &hello)?;
        let reply = request(node, peer, addrs, &env)?;
        match reply.open(&state.seed, &state.user_id, &from)? {
            Message::HelloOk(ok) => break ok,
            // We are behind a revocation: take the peer's signed roster, then hello again.
            Message::Roster(r) if !retried => {
                let before = state.roster.epoch;
                let key = state.user_key.clone();
                state.roster.merge(&Roster { epoch: r.epoch, certs: r.certs }, &key, &WEIRDNET);
                if state.roster.epoch == before {
                    return Err(SyncError::Refused("epoch-behind".into()));
                }
                if !state.roster.get(&state.our_cert.peer_id).is_none_or(|c| c.active()) {
                    return Err(SyncError::Refused("revoked".into()));
                }
                retried = true;
            }
            Message::Refuse(r) => return Err(SyncError::Refused(r.reason)),
            _ => return Err(SyncError::Protocol("expected HelloOk".into())),
        }
    };
    let key = state.user_key.clone();
    let behind = ok.epoch < state.roster.epoch;
    state.roster.merge(&Roster { epoch: ok.epoch, certs: ok.revocations.into_iter().chain([ok.cert]).collect() }, &key, &WEIRDNET);
    if behind {
        // The peer missed a revocation we hold: hand it our roster so it can catch up.
        let msg = Message::Roster(RosterMsg { certs: state.roster.certs.clone(), epoch: state.roster.epoch });
        let env = Envelope::seal(&state.seed, &state.user_id, typ_name, state.roster.epoch, &from, &msg)?;
        let _ = request(node, peer, addrs, &env)?;
    }
    let mut applied = 0;
    let mut to_pull: Vec<(NodeId, u64)> = ok.cursors;
    // Also pull the peer's own node if it wasn't in cursors yet.
    if !to_pull.iter().any(|(n, _)| n.0 == peer.to_string()) {
        to_pull.push((NodeId(peer.to_string()), 0));
    }
    for (nid, _their) in to_pull {
        loop {
            // Resume per type: a pull of another type over the same stream must not
            // move this type's position.
            let after = state.log.cursor_for(&nid, typ_name);
            let pull = Message::Pull(Pull { node_id: nid.clone(), after_seq: after, typ: typ_name.into(), limit: 512 });
            let env = Envelope::seal(&state.seed, &state.user_id, typ_name, state.roster.epoch, &from, &pull)?;
            let reply = request(node, peer, addrs, &env)?;
            match reply.open(&state.seed, &state.user_id, &from)? {
                Message::Page(p) => {
                    let last = p.page.to_seq;
                    if p.typ != typ_name || p.page.node_id != nid || p.page.ops.iter().any(|e| e.typ != typ_name) {
                        return Err(SyncError::Protocol("page of another type or node".into()));
                    }
                    if last <= after {
                        break;
                    }
                    applied += state.log.integrate(&p.page);
                    state.log.set_cursor_for(&nid, typ_name, last);
                    if last > state.log.cursor(&nid) {
                        state.log.set_cursor(&nid, last);
                    }
                    let ack = Message::Ack(Ack { node_id: nid.clone(), last_seq: last });
                    let env = Envelope::seal(&state.seed, &state.user_id, typ_name, state.roster.epoch, &from, &ack)?;
                    let _ = request(node, peer, addrs, &env)?;
                }
                Message::Refuse(r) => return Err(SyncError::Refused(r.reason)),
                _ => return Err(SyncError::Protocol("expected Page".into())),
            }
        }
    }
    observe(state, now_ms());
    Ok(applied)
}

/// Advance our clock past the newest op held, so the next local write orders after
/// everything this node has seen (a visit after a remote clear, say).
pub fn observe(state: &mut SyncState, wall_ms: u64) {
    if let Some(h) = state.log.newest_hlc().cloned()
        && state.clock.as_ref().is_none_or(|c| h.cmp_total(c).is_gt())
    {
        state.clock = Some(Hlc::receive(state.clock.as_ref(), &h, wall_ms, state.our_node.clone()));
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn request(node: &Node<Vec<u8>, Vec<u8>>, peer: PeerId, addrs: &[Multiaddr], env: &Envelope) -> Result<Envelope> {
    let bytes = encode(env)?;
    let reply = node.request(peer, addrs, bytes)?;
    decode(&reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::Roster;
    use crate::seal::typ;
    use weirdnet_net::user;

    const SEED: [u8; 32] = *b"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

    fn addrs(n: &Node<Vec<u8>, Vec<u8>>) -> Vec<Multiaddr> {
        n.reachable_addrs().into_iter().map(|s| s.parse().expect("addr")).collect()
    }

    fn pair() -> (Keypair, Keypair, Keypair, String) {
        let user = Keypair::generate_ed25519();
        let a = Keypair::generate_ed25519();
        let b = Keypair::generate_ed25519();
        let uid = user::user_id(&user.public());
        (user, a, b, uid)
    }

    fn state(user: &Keypair, node_key: &Keypair, uid: &str, label: &str, types: &[&str]) -> (Arc<Mutex<SyncState>>, NodeId) {
        let peer = node_key.public().to_peer_id().to_string();
        let cert = Roster::self_certify(&WEIRDNET, user, &peer, label, 1).unwrap();
        let mut roster = Roster::new();
        roster.upsert(cert.clone());
        let node = NodeId(peer.clone());
        let st = SyncState {
            seed: SEED.to_vec(),
            user_id: uid.into(),
            user_key: user.public(),
            our_cert: cert,
            our_node: node.clone(),
            types: types.iter().map(|s| s.to_string()).collect(),
            roster,
            log: OpLog::new(),
            clock: None,
        };
        (Arc::new(Mutex::new(st)), node)
    }

    #[test]
    fn two_memory_nodes_hello_and_pull_a_bookmark_op() {
        let (user, ka, kb, uid) = pair();
        let (sa, _) = state(&user, &ka, &uid, "a", &["bookmarks"]);
        let (sb, _) = state(&user, &kb, &uid, "b", &["bookmarks"]);
        // Each roster starts as one; at hello they learn the other.
        {
            let mut a = sa.lock().unwrap();
            a.local_op(1_000, typ::BOOKMARKS, "bm-1", b"{\"title\":\"Rust\"}".to_vec());
            a.local_op(1_001, typ::HISTORY, "v-1", b"https://example".to_vec());
            a.local_op(1_002, typ::BOOKMARKS, "bm-2", b"{}".to_vec());
        }
        let na = start_node(ka, node_config(true), sa.clone()).unwrap();
        let nb = start_node(kb, node_config(true), sb.clone()).unwrap();
        // Put each other in the roster (as a QR link would, plus hello).
        {
            let ca = sa.lock().unwrap().our_cert.clone();
            let cb = sb.lock().unwrap().our_cert.clone();
            sa.lock().unwrap().roster.upsert(cb);
            sb.lock().unwrap().roster.upsert(ca);
        }
        let mut st_b = sb.lock().unwrap();
        let applied = pull_from(&mut st_b, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS).unwrap();
        assert!(applied >= 1, "applied {applied}");
        let entry = st_b.log.get(&NodeId(na.peer_id().to_string()), 1).expect("bookmark op");
        assert_eq!(entry.typ, typ::BOOKMARKS);
        assert_eq!(entry.record_id, "bm-1");
        assert_eq!(entry.op, b"{\"title\":\"Rust\"}");
        let hist_visible = st_b.log.iter_node(&NodeId(na.peer_id().to_string())).any(|e| e.typ == typ::HISTORY);
        assert!(!hist_visible, "a bookmarks pull must not apply history ops");
        assert!(st_b.clock.as_ref().is_some_and(|c| c.physical_ms >= 1_000), "the clock moved past what was pulled");

        // The history op sits between two bookmarks on one stream: a later history pull
        // must still find it (0.1.0 lost it because the bookmarks pull moved one cursor
        // past it).
        let a_node = NodeId(na.peer_id().to_string());
        assert_eq!(st_b.log.get(&a_node, 3).expect("second bookmark").record_id, "bm-2");
        st_b.types.push(typ::HISTORY.into());
        sa.lock().unwrap().types.push(typ::HISTORY.into());
        let applied = pull_from(&mut st_b, &nb, na.peer_id(), &addrs(&na), typ::HISTORY).unwrap();
        assert_eq!(applied, 1);
        assert_eq!(st_b.log.get(&a_node, 2).expect("history op").record_id, "v-1");
        assert_eq!(pull_from(&mut st_b, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS).unwrap(), 0);
        assert_eq!(st_b.log.cursor_for(&a_node, typ::HISTORY), 3, "contiguous after both types");
        assert_eq!(pull_from(&mut st_b, &nb, na.peer_id(), &addrs(&na), typ::HISTORY).unwrap(), 0);
        assert_eq!(sa.lock().unwrap().log.cursor_for(&a_node, typ::BOOKMARKS), 3, "acks never move the server's cursors");
        drop(st_b);

        // A revoked B cannot pull after A revokes B and bumps the epoch.
        {
            let mut a = sa.lock().unwrap();
            let b_peer = nb.peer_id().to_string();
            a.roster.revoke(&WEIRDNET, &user, &b_peer, 9).unwrap();
        }
        let mut st_b = sb.lock().unwrap();
        let err = pull_from(&mut st_b, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS).unwrap_err();
        match err {
            SyncError::Refused(r) => assert!(r == "revoked" || r == "epoch-behind" || r == "wrong-user", "got {r}"),
            other => panic!("expected refuse, got {other}"),
        }
    }

    #[test]
    fn a_revocation_reaches_the_other_devices_both_ways() {
        let user = Keypair::generate_ed25519();
        let uid = user::user_id(&user.public());
        let (ka, kb, kc, kd) = (Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519(), Keypair::generate_ed25519());
        let types = ["bookmarks"];
        let (sa, _) = state(&user, &ka, &uid, "a", &types);
        let (sb, _) = state(&user, &kb, &uid, "b", &types);
        let (sc, _) = state(&user, &kc, &uid, "c", &types);
        let (sd, _) = state(&user, &kd, &uid, "d", &types);
        let all = [&sa, &sb, &sc, &sd];
        let certs: Vec<_> = all.iter().map(|s| s.lock().unwrap().our_cert.clone()).collect();
        for s in all {
            for c in &certs {
                s.lock().unwrap().roster.upsert(c.clone());
            }
        }
        sa.lock().unwrap().local_op(1, typ::BOOKMARKS, "a-1", vec![1]);
        let na = start_node(ka, node_config(true), sa.clone()).unwrap();
        let nb = start_node(kb, node_config(true), sb.clone()).unwrap();
        let nc = start_node(kc, node_config(true), sc.clone()).unwrap();
        let nd = start_node(kd, node_config(true), sd.clone()).unwrap();
        let c_peer = nc.peer_id().to_string();
        sa.lock().unwrap().roster.revoke(&WEIRDNET, &user, &c_peer, 9).unwrap();

        // B is a revocation behind A: A answers with its roster, B catches up and pulls.
        let applied = pull_from(&mut sb.lock().unwrap(), &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS).unwrap();
        assert_eq!(applied, 1);
        {
            let b = sb.lock().unwrap();
            assert_eq!(b.roster.epoch, 1);
            assert!(!b.roster.get(&c_peer).unwrap().active());
        }
        // A pulls from D (still behind): A pushes its roster to D.
        pull_from(&mut sa.lock().unwrap(), &na, nd.peer_id(), &addrs(&nd), typ::BOOKMARKS).unwrap();
        assert_eq!(sd.lock().unwrap().roster.epoch, 1);
        assert!(!sd.lock().unwrap().roster.get(&c_peer).unwrap().active());
        // C is refused everywhere that learned, and a roster reply never lets it back in.
        for (n, label) in [(&nb, "b"), (&nd, "d"), (&na, "a")] {
            let err = pull_from(&mut sc.lock().unwrap(), &nc, n.peer_id(), &addrs(n), typ::BOOKMARKS).unwrap_err();
            assert!(matches!(err, SyncError::Refused(ref r) if r == "revoked"), "{label}: {err}");
        }
    }

    #[test]
    fn a_foreign_user_is_refused() {
        let (user_a, ka, _, uid_a) = pair();
        let (user_b, kb, _, uid_b) = pair();
        let (sa, _) = state(&user_a, &ka, &uid_a, "a", &["bookmarks"]);
        let (sb, _) = state(&user_b, &kb, &uid_b, "b", &["bookmarks"]);
        let na = start_node(ka, node_config(true), sa.clone()).unwrap();
        let nb = start_node(kb, node_config(true), sb.clone()).unwrap();
        let mut st_b = sb.lock().unwrap();
        let err = pull_from(&mut st_b, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS).unwrap_err();
        match err {
            SyncError::Refused(r) => assert_eq!(r, "wrong-user"),
            // Opening the reply can also fail if A sealed a refuse under A's user id.
            SyncError::Crypto(_) => {}
            other => panic!("expected wrong-user, got {other}"),
        }
    }
}
