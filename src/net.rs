//! The pull protocol running on a [`weirdnet_net::Node`] (`/weirdnet/sync/1`).
//!
//! The official WeirdBrains relay must not store pages; this module only exchanges
//! sealed envelopes between the user's own nodes.
use crate::error::{Result, SyncError};
use crate::hlc::{Hlc, NodeId};
use crate::log::OpLog;
use crate::protocol::{Ack, Envelope, Hello, HelloOk, Message, PAGE_MAX, Pull, Refuse, RosterMsg, SYNC_PROFILE, decode, encode};
use crate::roster::{Roster, SessionCheck};
use crate::seal::typ;
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
            Message::Ack(a) => {
                self.log.set_cursor(&a.node_id, a.last_seq);
                Message::Ack(Ack { node_id: a.node_id, last_seq: a.last_seq })
            }
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
        let page = self.log.page(&p.node_id, p.after_seq, limit);
        Message::Page(crate::protocol::page_for_type(&p.typ, page))
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
    let opened = reply.open(&state.seed, &state.user_id, &from)?;
    let ok = match opened {
        Message::HelloOk(ok) => ok,
        Message::Refuse(r) => return Err(SyncError::Refused(r.reason)),
        _ => return Err(SyncError::Protocol("expected HelloOk".into())),
    };
    if ok.epoch > state.roster.epoch {
        state.roster.epoch = ok.epoch;
    }
    state.roster.upsert(ok.cert);
    for c in ok.revocations {
        state.roster.upsert(c);
    }
    let mut applied = 0;
    let mut to_pull: Vec<(NodeId, u64)> = ok.cursors;
    // Also pull the peer's own node if it wasn't in cursors yet.
    if !to_pull.iter().any(|(n, _)| n.0 == peer.to_string()) {
        to_pull.push((NodeId(peer.to_string()), 0));
    }
    for (nid, _their) in to_pull {
        loop {
            let after = state.log.cursor(&nid);
            let pull = Message::Pull(Pull { node_id: nid.clone(), after_seq: after, typ: typ_name.into(), limit: 512 });
            let env = Envelope::seal(&state.seed, &state.user_id, typ_name, state.roster.epoch, &from, &pull)?;
            let reply = request(node, peer, addrs, &env)?;
            match reply.open(&state.seed, &state.user_id, &from)? {
                Message::Page(p) => {
                    if p.page.ops.is_empty() {
                        break;
                    }
                    let n = state.log.integrate(&p.page);
                    applied += n;
                    let last = p.page.to_seq;
                    state.log.set_cursor(&nid, last);
                    let ack = Message::Ack(Ack { node_id: nid.clone(), last_seq: last });
                    let env = Envelope::seal(&state.seed, &state.user_id, typ_name, state.roster.epoch, &from, &ack)?;
                    let _ = request(node, peer, addrs, &env)?;
                    if n == 0 {
                        break;
                    }
                }
                Message::Refuse(r) => return Err(SyncError::Refused(r.reason)),
                _ => return Err(SyncError::Protocol("expected Page".into())),
            }
        }
    }
    let _ = typ::BOOKMARKS;
    Ok(applied)
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
