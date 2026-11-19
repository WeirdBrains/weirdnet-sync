//! The pull protocol running on a [`weirdnet_net::Node`] (`/weirdnet/sync/2`).
//!
//! The official WeirdBrains relay must not store pages; this module only exchanges
//! sealed envelopes between the user's own nodes.
use crate::error::{Result, SyncError};
use crate::hlc::{Hlc, NodeId};
use crate::log::OpLog;
use crate::protocol::{Ack, Envelope, Hello, HelloOk, KeyRef, Message, PAGE_MAX, Pull, Refuse, RosterMsg, SYNC_PROFILE, decode, encode};
use crate::record::{RecordOptions, base_type, chunk_type, is_chunk_type};
use crate::roster::{Roster, SessionCheck};
use crate::rotation::{Device, EpochKeys, KeyChain};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use weirdnet_net::user::NodeCert;
use weirdnet_net::{Handler, Keypair, Multiaddr, Node, NodeConfig, PeerId, PublicKey, WEIRDNET};

/// Mutable state a sync node answers from and applies pages into.
///
/// `Clone` (and [`SyncState::snapshot`]) copies everything, secrets included: pull into a
/// snapshot without holding the shared lock, then fold it back with
/// [`SyncState::merge_back`] (or let [`pull_from_shared`] do both).
#[derive(Clone)]
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
    /// This device's node and exchange secrets. Without them the state stays on
    /// seed-derived keys and cannot rotate or open a rotated key.
    pub device: Option<Device>,
    /// Rotated epoch keys this device holds (secret; persist encrypted).
    pub keys: EpochKeys,
    /// Make the first rotation automatically once it is due (see
    /// [`SyncState::first_rotation_due`]): right after the first link, and once after an
    /// upgrade from seed-only keys. On in [`SyncState::new`].
    pub auto_first_rotation: bool,
    /// Per-type write options (sealed, size limits); see [`SyncState::configure`].
    pub records: BTreeMap<String, RecordOptions>,
}

impl SyncState {
    /// A state for this device. With `node_key`, it publishes its device key so
    /// rotations can include it.
    pub fn new(seed: Vec<u8>, user_key: PublicKey, our_cert: NodeCert, node_key: Option<&Keypair>, types: Vec<String>) -> Result<Self> {
        let device = node_key.map(Device::from_node_key).transpose()?;
        let mut roster = Roster::new();
        roster.upsert(our_cert.clone());
        let mut st = Self {
            seed,
            user_id: our_cert.user_id.clone(),
            user_key,
            our_node: NodeId::new(our_cert.peer_id.clone()),
            our_cert,
            types,
            roster,
            log: OpLog::new(),
            clock: None,
            device,
            keys: EpochKeys::new(),
            auto_first_rotation: true,
            records: BTreeMap::new(),
        };
        if st.device.is_some() {
            st.publish_device_key(st.our_cert.issued_at)?;
        }
        Ok(st)
    }

    /// The key new envelopes are sealed with: the head epoch key when we hold it,
    /// otherwise the seed-derived key (enough to catch up and be re-admitted).
    pub fn current_key(&self) -> KeyRef {
        match self.roster.head_id() {
            Some(id) if self.keys.has(&id) => {
                let epoch = self.roster.chain_view().head().map(|h| h.epoch).unwrap_or(self.roster.epoch);
                KeyRef { epoch, id: Some(id) }
            }
            _ => KeyRef::seed(self.roster.epoch),
        }
    }

    pub fn seal_envelope(&self, key: &KeyRef, typ: &str, peer: &str, msg: &Message) -> Result<Envelope> {
        match &key.id {
            None => Envelope::seal(&self.seed, &self.user_id, typ, key.epoch, peer, msg),
            Some(id) => {
                let k = self.keys.get(id).ok_or_else(|| SyncError::Crypto("unknown epoch key".into()))?;
                Envelope::seal_keyed(k, id, &self.user_id, typ, key.epoch, peer, msg)
            }
        }
    }

    pub fn open_envelope(&self, env: &Envelope, peer: &str) -> Result<Message> {
        match &env.key {
            None => env.open(&self.seed, &self.user_id, peer),
            Some(id) => {
                let k = self.keys.get(id).ok_or_else(|| SyncError::Crypto("unknown epoch key".into()))?;
                env.open_keyed(k, &self.user_id, peer)
            }
        }
    }

    fn roster_msg(&self) -> Message {
        Message::Roster(RosterMsg { certs: self.roster.certs.clone(), epoch: self.roster.epoch, chain: self.roster.chain.shared() })
    }

    /// Merge certs, epoch and chain from a peer, then open any key sealed to us.
    fn absorb(&mut self, certs: Vec<NodeCert>, epoch: u32, chain: KeyChain) {
        let key = self.user_key.clone();
        self.roster.merge(&Roster { epoch, certs, chain }, &key, &WEIRDNET);
        self.refresh_keys();
    }

    /// Take the epoch keys (and adopted root) another copy of this state picked up,
    /// for apps that pull into a snapshot and fold it back. Merge the roster as well.
    #[deprecated(since = "0.5.1", note = "use `SyncState::merge_back`, which also merges the roster, the log, cursors and the clock")]
    pub fn take_keys_from(&mut self, other: &SyncState) {
        self.merge_keys(other);
    }

    fn merge_keys(&mut self, other: &SyncState) -> usize {
        let before = self.keys.len();
        self.keys.merge(&other.keys);
        if self.roster.chain.root.is_none() {
            self.roster.chain.root = other.roster.chain.root.clone();
        }
        self.keys.len() - before
    }

    /// A copy of this state to pull into without holding the shared lock (see
    /// [`pull_from_shared`]). Fold it back with [`SyncState::merge_back`]. Write locally
    /// to the shared state, not to the snapshot.
    pub fn snapshot(&self) -> SyncState {
        self.clone()
    }

    /// Fold a snapshot that was pulled into (or that otherwise moved on) back into this
    /// state, without losing anything this state learned or wrote meanwhile:
    ///
    /// - the roster: user-signed certs and revocations merge as on the wire, so a
    ///   revocation on either side wins and nothing is un-revoked; the epoch is the max;
    ///   the key chain (device keys, rotations, admissions) merges;
    /// - epoch keys and the adopted root (what `take_keys_from` did), then any key the
    ///   merged chain seals to this device; approved devices the snapshot admitted
    ///   leave this state's approval list;
    /// - log entries this state lacks (through [`OpLog::integrate`], so chunk and blob
    ///   indexes follow), and every peer and per-type cursor moves to the further of the
    ///   two;
    /// - the clock: the later of the two, then past every op now held.
    ///
    /// Configuration (types, record options, the device, `auto_first_rotation`) stays
    /// this state's.
    pub fn merge_back(&mut self, pulled: &SyncState) -> MergeOutcome {
        let mut out = MergeOutcome::default();
        let revoked_before = self.roster.certs.iter().filter(|c| !c.active()).count();
        let key = self.user_key.clone();
        self.roster.merge(&pulled.roster, &key, &WEIRDNET);
        out.revocations = self.roster.certs.iter().filter(|c| !c.active()).count() - revoked_before;
        out.keys = self.merge_keys(pulled);
        out.keys += self.refresh_keys();
        let admitted: Vec<&str> = pulled.roster.chain.admissions.iter().map(|a| a.peer_id.as_str()).collect();
        let still = &pulled.roster.chain.approved;
        self.roster.chain.approved.retain(|p| still.contains(p) || !admitted.contains(&p.as_str()));
        // Entries, a page per node (the log iterates by node, then seq).
        let mut run: Vec<crate::log::LogEntry> = Vec::new();
        for e in pulled.log.iter() {
            if run.first().is_some_and(|f| f.node_id != e.node_id) {
                out.entries += self.integrate_run(std::mem::take(&mut run));
            }
            if self.log.get(&e.node_id, e.seq).is_none() {
                run.push(e.clone());
            }
        }
        out.entries += self.integrate_run(run);
        for (node, seq) in pulled.log.cursors() {
            if seq > self.log.cursor(&node) {
                self.log.set_cursor(&node, seq);
            }
        }
        for ((node, typ), seq) in pulled.log.type_cursors() {
            if seq > self.log.cursor_for(&node, &typ) {
                self.log.set_cursor_for(&node, &typ, seq);
            }
        }
        if let Some(theirs) = &pulled.clock
            && self.clock.as_ref().is_none_or(|ours| theirs.cmp_total(ours).is_gt())
        {
            self.clock = Some(Hlc::receive(self.clock.as_ref(), theirs, now_ms(), self.our_node.clone()));
        }
        observe(self, now_ms());
        out
    }

    fn integrate_run(&mut self, ops: Vec<crate::log::LogEntry>) -> usize {
        let (Some(first), Some(last)) = (ops.first(), ops.last()) else { return 0 };
        let page = crate::log::Page { node_id: first.node_id.clone(), from_seq: first.seq, to_seq: last.seq, ops: ops.clone() };
        self.log.integrate(&page)
    }

    fn is_revoked(&self, peer: &str) -> bool {
        self.roster.get(peer).is_some_and(|c| !c.active())
    }

    pub fn handle(&mut self, from: &str, env: Envelope) -> Result<Envelope> {
        let key = KeyRef { epoch: env.epoch, id: env.key.clone() };
        // Open with our keys and user id; a foreign user fails here (wrong-user).
        let msg = match self.open_envelope(&env, from) {
            Ok(m) => m,
            // Sealed under a rotation we don't hold: we are behind. Say so under the seed
            // key, so the asker sends us its roster.
            Err(_) if env.key.is_some() => return self.refuse(from, &env.typ, env.epoch, "unknown-key"),
            Err(_) => return self.refuse(from, &env.typ, env.epoch, "wrong-user"),
        };
        let head = self.roster.head_id();
        // After a rotation only the head key carries data; older and seed-derived keys
        // (which a revoked device may hold) only get the roster.
        let at_head = head.is_none() || env.key == head;
        let reply = match msg {
            Message::Hello(h) => self.on_hello(from, h, at_head),
            Message::Pull(_) if !at_head => Message::Refuse(Refuse::new("epoch-behind")),
            Message::Pull(_) if self.is_revoked(from) => Message::Refuse(Refuse::new("revoked")),
            Message::Pull(p) => self.on_pull(p),
            // An ack is the puller's progress, not ours: it must not move our cursors.
            Message::Ack(a) => Message::Ack(Ack { node_id: a.node_id, last_seq: a.last_seq }),
            Message::Roster(r) => {
                self.absorb(r.certs, r.epoch, r.chain);
                self.roster_msg()
            }
            Message::HelloOk(_) | Message::Page(_) | Message::Refuse(_) => {
                return Err(SyncError::Protocol("unexpected request".into()));
            }
        };
        // Answer under the key the request came in, so a peer behind us can read it.
        self.seal_envelope(&key, &env.typ, from, &reply)
    }

    fn refuse(&self, from: &str, typ: &str, epoch: u32, reason: &'static str) -> Result<Envelope> {
        Envelope::seal(&self.seed, &self.user_id, typ, epoch, from, &Message::Refuse(Refuse::new(reason)))
    }

    fn on_hello(&mut self, _from: &str, h: Hello, at_head: bool) -> Message {
        let rotated = self.roster.head_id().is_some();
        // After a rotation the key decides who is current, not the epoch number.
        let epoch = if rotated { self.roster.epoch } else { h.epoch };
        let check = self.roster.check_session(
            &WEIRDNET,
            &self.user_key,
            &self.user_id,
            &crate::roster::SessionOffer { cert: &h.cert, epoch, types: &h.types },
            &self.types,
        );
        if matches!(check, SessionCheck::WrongUser | SessionCheck::Revoked) {
            return Message::Refuse(Refuse::new(check.reason().unwrap_or("wrong-user")));
        }
        // Learn the peer's device key and rotations (signed; checked on merge).
        if !h.chain.is_empty() {
            self.roster.chain.merge(&h.chain);
            self.refresh_keys();
            // A device the user approved here, saying hello for the first time: admit it
            // now, so the roster reply below already carries its admission.
            self.admit_approved(now_ms() as i64);
        }
        if (rotated && !at_head) || check == SessionCheck::EpochBehind {
            // A valid, unrevoked device of this user that missed a revocation or a
            // rotation, or one waiting to be re-admitted: send the roster (user-signed
            // certs and revocations, and the key chain) so it can catch up and retry.
            return self.roster_msg();
        }
        if check != SessionCheck::Ok {
            return Message::Refuse(Refuse::new(check.reason().unwrap_or("wrong-user")));
        }
        let cursors = self.log.cursors().into_iter().collect();
        let revocations = self.roster.certs.iter().filter(|c| !c.active()).cloned().collect();
        Message::HelloOk(HelloOk { cert: self.our_cert.clone(), epoch: self.roster.epoch, cursors, revocations, chain: self.roster.chain.shared() })
    }

    fn on_pull(&self, p: Pull) -> Message {
        // A type's chunks are served wherever the type is.
        let served = base_type(&p.typ).unwrap_or(&p.typ);
        if !self.types.iter().any(|t| t == served) {
            return Message::Refuse(Refuse::new("type-off"));
        }
        let limit = (p.limit as usize).clamp(1, 4096);
        let known = self.log.cursor_for(&p.node_id, &p.typ);
        let page = self.log.page_of_type(&p.node_id, &p.typ, p.after_seq, known, limit);
        Message::Page(crate::protocol::Page { typ: p.typ, page })
    }

    /// A local write: tick the clock, append one log op. Returns its seq. For values
    /// that may be large or that are sealed, use [`SyncState::write`].
    pub fn local_op(&mut self, now_ms: u64, typ: &str, record_id: &str, op: Vec<u8>) -> u64 {
        let hlc = self.tick(now_ms);
        self.log.append(self.our_node.clone(), hlc, typ, record_id, op).seq
    }

    pub(crate) fn tick(&mut self, now_ms: u64) -> Hlc {
        let hlc = Hlc::tick(self.clock.as_ref(), now_ms, self.our_node.clone());
        self.clock = Some(hlc.clone());
        hlc
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

/// What [`SyncState::merge_back`] took from the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergeOutcome {
    /// Log entries this state did not hold.
    pub entries: usize,
    /// Epoch keys this state did not hold (taken over or newly opened).
    pub keys: usize,
    /// Certs that became revoked here.
    pub revocations: usize,
}

/// The result of a pull that may have applied pages before it failed.
///
/// A pull applies and acks page by page, so a refusal or a network error on a later
/// page (or a rotation after the pull) leaves the earlier pages applied, cursors moved:
/// `applied` counts them either way, and `error` says why the pull stopped early.
#[derive(Debug)]
#[non_exhaustive]
pub struct PullOutcome {
    /// New log entries stored, before any error.
    pub applied: usize,
    /// Why the pull stopped, if it did not finish.
    pub error: Option<SyncError>,
}

impl PullOutcome {
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    /// `Ok(applied)`, or the error (dropping the count, as [`pull_from`] does).
    pub fn into_result(self) -> Result<usize> {
        match self.error {
            None => Ok(self.applied),
            Some(e) => Err(e),
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
///
/// Catches up on revocations and rotations both ways, and replaces a head rotation
/// that still includes a revoked device. Fails with `Refused("needs-admission")` when
/// the chain has moved on without this device (restored from the seed): another device
/// has to [`SyncState::admit`] it.
///
/// On an error the pages applied before it stay applied; [`pull_from_outcome`] also
/// reports how many there were.
pub fn pull_from(state: &mut SyncState, node: &Node<Vec<u8>, Vec<u8>>, peer: PeerId, addrs: &[Multiaddr], typ_name: &str) -> Result<usize> {
    pull_from_outcome(state, node, peer, addrs, typ_name).into_result()
}

/// [`pull_from`], reporting the entries applied even when the pull stops early (a later
/// page refused, the network gone, a rotation failing).
pub fn pull_from_outcome(state: &mut SyncState, node: &Node<Vec<u8>, Vec<u8>>, peer: PeerId, addrs: &[Multiaddr], typ_name: &str) -> PullOutcome {
    let mut applied = 0;
    let error = pull_session(state, node, peer, addrs, typ_name, &mut applied).err();
    PullOutcome { applied, error }
}

/// Pull for a state shared with this node's [`SyncHandler`], without holding its lock
/// across the network: snapshot, pull into the snapshot, then
/// [`SyncState::merge_back`] (also after an error, so pages already applied are kept).
///
/// Holding the lock for the whole pull (as `pull_from(&mut state.lock()..)` does) stops
/// this node answering meanwhile, and two nodes pulling from each other at once then
/// wait on each other until the request times out.
pub fn pull_from_shared(state: &Mutex<SyncState>, node: &Node<Vec<u8>, Vec<u8>>, peer: PeerId, addrs: &[Multiaddr], typ_name: &str) -> PullOutcome {
    let mut snap = match state.lock() {
        Ok(st) => st.snapshot(),
        Err(_) => return PullOutcome { applied: 0, error: Some(SyncError::Protocol("sync state lock poisoned".into())) },
    };
    let out = pull_from_outcome(&mut snap, node, peer, addrs, typ_name);
    match state.lock() {
        Ok(mut st) => {
            st.merge_back(&snap);
            out
        }
        Err(_) => PullOutcome { applied: out.applied, error: Some(SyncError::Protocol("sync state lock poisoned".into())) },
    }
}

fn pull_session(
    state: &mut SyncState,
    node: &Node<Vec<u8>, Vec<u8>>,
    peer: PeerId,
    addrs: &[Multiaddr],
    typ_name: &str,
    applied: &mut usize,
) -> Result<()> {
    let from = node.peer_id().to_string();
    let mut catch_ups = 0;
    let mut pushed = false;
    let ok = loop {
        let key = state.current_key();
        let hello = Message::Hello(Hello {
            cert: state.our_cert.clone(),
            user_id: state.user_id.clone(),
            epoch: key.epoch,
            types: state.types.clone(),
            our_cursors: state.log.cursors().into_iter().collect(),
            our_hlc: state.clock.clone().unwrap_or_else(|| Hlc::new(0, 0, state.our_node.clone())),
            chain: state.roster.chain.shared(),
        });
        let env = state.seal_envelope(&key, typ_name, &from, &hello)?;
        let reply = request(node, peer, addrs, &env)?;
        match state.open_envelope(&reply, &from)? {
            Message::HelloOk(ok) => break ok,
            // We are behind a revocation or rotation: take the peer's signed roster and
            // chain, then hello again.
            Message::Roster(r) if catch_ups < 3 => {
                state.absorb(r.certs, r.epoch, r.chain);
                if !state.roster.get(&state.our_cert.peer_id).is_none_or(|c| c.active()) {
                    return Err(SyncError::Refused("revoked".into()));
                }
                if state.current_key() == key {
                    let reason = if state.needs_admission() { "needs-admission" } else { "epoch-behind" };
                    return Err(SyncError::Refused(reason.into()));
                }
                catch_ups += 1;
            }
            // The peer missed a rotation we hold: hand it our roster under the seed key
            // (the chain is public; the epoch keys inside are sealed), then hello again.
            Message::Refuse(r) if r.reason == "unknown-key" && !pushed => {
                let env = state.seal_envelope(&KeyRef::seed(state.roster.epoch), typ_name, &from, &state.roster_msg())?;
                if let Ok(Message::Roster(back)) = request(node, peer, addrs, &env).and_then(|e| state.open_envelope(&e, &from)) {
                    state.absorb(back.certs, back.epoch, back.chain);
                }
                pushed = true;
            }
            Message::Refuse(r) => return Err(SyncError::Refused(r.reason)),
            _ => return Err(SyncError::Protocol("expected HelloOk".into())),
        }
    };
    let behind = ok.epoch < state.roster.epoch;
    state.absorb(ok.revocations.into_iter().chain([ok.cert]).collect(), ok.epoch, ok.chain);
    let key = state.current_key();
    if behind {
        // The peer missed a revocation we hold: hand it our roster so it can catch up.
        let env = state.seal_envelope(&key, typ_name, &from, &state.roster_msg())?;
        let _ = request(node, peer, addrs, &env)?;
    }
    let mut to_pull: Vec<(NodeId, u64)> = ok.cursors;
    // Also pull the peer's own node if it wasn't in cursors yet.
    if !to_pull.iter().any(|(n, _)| n.0 == peer.to_string()) {
        to_pull.push((NodeId(peer.to_string()), 0));
    }
    pull_type(state, node, peer, addrs, &key, &to_pull, typ_name, false, applied)?;
    // Chunks of entries that are still incomplete come along with their type (not
    // counted: they complete entries already counted).
    if !is_chunk_type(typ_name) && state.options(typ_name).limits.eager_chunks && !state.log.pending_blobs(typ_name).is_empty() {
        pull_type(state, node, peer, addrs, &key, &to_pull, &chunk_type(typ_name), true, &mut 0)?;
    }
    observe(state, now_ms());
    if state.auto_first_rotation && state.first_rotation_due() {
        // Linked devices still on seed-derived keys, all with device keys: start the
        // chain while every device is trusted.
        state.rotate(now_ms() as i64)?;
    } else if state.needs_rotation() {
        // The head still includes a device that has since been revoked (say, revoked
        // on a device without a node key): replace it.
        state.rotate(now_ms() as i64)?;
    }
    Ok(())
}

/// Pull `typ_name` of every node in `nodes` under `key`, adding new entries to
/// `applied` page by page. With `optional`, a server that does not serve the type (an
/// older peer asked for chunks) ends it quietly.
#[allow(clippy::too_many_arguments)]
fn pull_type(
    state: &mut SyncState,
    node: &Node<Vec<u8>, Vec<u8>>,
    peer: PeerId,
    addrs: &[Multiaddr],
    key: &KeyRef,
    nodes: &[(NodeId, u64)],
    typ_name: &str,
    optional: bool,
    applied: &mut usize,
) -> Result<()> {
    let from = node.peer_id().to_string();
    for (nid, _their) in nodes {
        loop {
            // Resume per type: a pull of another type over the same stream must not
            // move this type's position.
            let after = state.log.cursor_for(nid, typ_name);
            let pull = Message::Pull(Pull { node_id: nid.clone(), after_seq: after, typ: typ_name.into(), limit: 512 });
            let env = state.seal_envelope(key, typ_name, &from, &pull)?;
            let reply = request(node, peer, addrs, &env)?;
            match state.open_envelope(&reply, &from)? {
                Message::Page(p) => {
                    let last = p.page.to_seq;
                    if p.typ != typ_name || p.page.node_id != *nid || p.page.ops.iter().any(|e| e.typ != typ_name) {
                        return Err(SyncError::Protocol("page of another type or node".into()));
                    }
                    if last <= after {
                        break;
                    }
                    *applied += state.log.integrate(&p.page);
                    state.log.set_cursor_for(nid, typ_name, last);
                    if last > state.log.cursor(nid) {
                        state.log.set_cursor(nid, last);
                    }
                    let ack = Message::Ack(Ack { node_id: nid.clone(), last_seq: last });
                    let env = state.seal_envelope(key, typ_name, &from, &ack)?;
                    let _ = request(node, peer, addrs, &env)?;
                }
                Message::Refuse(r) if optional && r.reason == "type-off" => return Ok(()),
                Message::Refuse(r) => return Err(SyncError::Refused(r.reason)),
                // Anything else from a peer that does not serve chunks.
                _ if optional => return Ok(()),
                _ => return Err(SyncError::Protocol("expected Page".into())),
            }
        }
    }
    Ok(())
}

/// Pull the chunks of `typ` (for [`crate::Limits::eager_chunks`] off, or to retry):
/// the same session as [`pull_from`], for the companion type [`chunk_type`]`(typ)`.
pub fn pull_chunks(state: &mut SyncState, node: &Node<Vec<u8>, Vec<u8>>, peer: PeerId, addrs: &[Multiaddr], typ: &str) -> Result<usize> {
    pull_from(state, node, peer, addrs, &chunk_type(typ))
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
    use crate::rotation::KeyStatus;
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
            device: Some(Device::from_node_key(node_key).unwrap()),
            keys: EpochKeys::new(),
            auto_first_rotation: false,
            records: BTreeMap::new(),
        };
        let mut st = st;
        st.publish_device_key(1).unwrap();
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

    type Sn = (Arc<Mutex<SyncState>>, Node<Vec<u8>, Vec<u8>>);

    /// `n` linked devices of one user: every roster holds every cert, every chain every
    /// device key (as one round of sync would leave them), each on a memory node.
    fn linked(user: &Keypair, labels: &[&str]) -> Vec<Sn> {
        let uid = user::user_id(&user.public());
        let made: Vec<(Arc<Mutex<SyncState>>, Keypair)> = labels
            .iter()
            .map(|l| {
                let k = Keypair::generate_ed25519();
                (state(user, &k, &uid, l, &["bookmarks"]).0, k)
            })
            .collect();
        let certs: Vec<_> = made.iter().map(|(s, _)| s.lock().unwrap().our_cert.clone()).collect();
        let chains: Vec<_> = made.iter().map(|(s, _)| s.lock().unwrap().roster.chain.clone()).collect();
        for (s, _) in &made {
            let mut st = s.lock().unwrap();
            for c in &certs {
                st.roster.upsert(c.clone());
            }
            for ch in &chains {
                st.roster.chain.merge(ch);
            }
        }
        made.into_iter().map(|(s, k)| (s.clone(), start_node(k, node_config(true), s).unwrap())).collect()
    }

    fn pull(a: &Sn, b: &Sn) -> Result<usize> {
        pull_from(&mut a.0.lock().unwrap(), &a.1, b.1.peer_id(), &addrs(&b.1), typ::BOOKMARKS)
    }

    fn head(s: &Sn) -> Option<String> {
        s.0.lock().unwrap().roster.head_id()
    }

    fn records(s: &Sn) -> Vec<String> {
        let st = s.0.lock().unwrap();
        let mut v: Vec<String> = st.log.cursors().keys().flat_map(|n| st.log.iter_node(n).map(|e| e.record_id.clone()).collect::<Vec<_>>()).collect();
        v.sort();
        v
    }

    fn peer(s: &Sn) -> String {
        s.1.peer_id().to_string()
    }

    #[test]
    fn a_revoked_device_cannot_read_ops_written_after_the_rotation() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        a.0.lock().unwrap().local_op(1, typ::BOOKMARKS, "before", vec![1]);
        assert_eq!(pull(c, a).unwrap(), 1, "c reads what was written before");

        let rot = {
            let mut st = a.0.lock().unwrap();
            st.revoke(&user, &peer(c), 9).unwrap();
            st.local_op(10, typ::BOOKMARKS, "after", vec![2]);
            st.roster.head_id().unwrap()
        };
        {
            let st = a.0.lock().unwrap();
            let view = st.roster.chain_view();
            let h = view.head().unwrap();
            assert!(h.members.contains(&peer(a)) && h.members.contains(&peer(b)));
            assert!(!h.members.contains(&peer(c)), "the revoked device is not sealed a copy");
            assert_eq!(st.key_status(), KeyStatus::Current { epoch: h.epoch });
        }

        // B catches up through the roster reply and reads the new op.
        assert_eq!(pull(b, a).unwrap(), 2);
        assert_eq!(head(b).as_deref(), Some(rot.as_str()));
        assert!(b.0.lock().unwrap().keys.has(&rot));

        // C is refused, and learning the whole chain gives it no key.
        assert!(matches!(pull(c, a), Err(SyncError::Refused(ref r)) if r == "revoked"));
        let chain = a.0.lock().unwrap().roster.clone();
        {
            let mut st = c.0.lock().unwrap();
            let key = st.user_key.clone();
            st.roster.merge(&chain, &key, &WEIRDNET);
            st.refresh_keys();
            assert!(!st.keys.has(&rot));
            assert_eq!(st.key_status(), KeyStatus::Revoked);
        }

        // B's page with the post-rotation op, as it crosses the wire.
        let a_node = NodeId(peer(a));
        let page_env = {
            let bs = b.0.lock().unwrap();
            let pull = Message::Pull(Pull { node_id: a_node.clone(), after_seq: 0, typ: typ::BOOKMARKS.into(), limit: 10 });
            let env = bs.seal_envelope(&bs.current_key(), typ::BOOKMARKS, &peer(b), &pull).unwrap();
            a.0.lock().unwrap().handle(&peer(b), env).unwrap()
        };
        match b.0.lock().unwrap().open_envelope(&page_env, &peer(b)).unwrap() {
            Message::Page(p) => assert!(p.page.ops.iter().any(|e| e.record_id == "after")),
            other => panic!("expected a page, got {other:?}"),
        }
        let cs = c.0.lock().unwrap();
        assert!(cs.open_envelope(&page_env, &peer(b)).is_err(), "c holds the seed and every old key, and still cannot open it");
        assert!(page_env.open(&cs.seed, &cs.user_id, &peer(b)).is_err());
        // Nor can it pull with the seed-derived key, as itself or claiming to be B.
        for (from, label) in [(peer(c), "as c"), (peer(b), "as b")] {
            let pull = Message::Pull(Pull { node_id: a_node.clone(), after_seq: 0, typ: typ::BOOKMARKS.into(), limit: 10 });
            let env = cs.seal_envelope(&KeyRef::seed(cs.roster.epoch), typ::BOOKMARKS, &from, &pull).unwrap();
            let reply = a.0.lock().unwrap().handle(&from, env).unwrap();
            match cs.open_envelope(&reply, &from).unwrap() {
                Message::Refuse(r) => assert_eq!(r.reason, "epoch-behind", "{label}"),
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
        }
        drop(cs);

        // A new node certified with the seed's user key (what a revoked holder can mint)
        // gets the roster, not the key.
        let mint = Keypair::generate_ed25519();
        let uid = user::user_id(&user.public());
        let (ms, _) = state(&user, &mint, &uid, "minted", &["bookmarks"]);
        let mn = start_node(mint, node_config(true), ms.clone()).unwrap();
        let minted = (ms, mn);
        assert!(matches!(pull(&minted, a), Err(SyncError::Refused(ref r)) if r == "needs-admission"));
        assert!(!records(&minted).contains(&"after".to_string()));
    }

    #[test]
    fn the_remaining_devices_converge_after_a_rotation() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c", "d"]);
        let (a, b, c, d) = (&g[0], &g[1], &g[2], &g[3]);
        a.0.lock().unwrap().local_op(1, typ::BOOKMARKS, "a-1", vec![1]);
        a.0.lock().unwrap().revoke(&user, &peer(c), 5).unwrap();
        a.0.lock().unwrap().local_op(6, typ::BOOKMARKS, "a-2", vec![2]);
        // A pulls from B, which has not heard: B cannot open A's hello, A hands it the
        // roster, and the pull goes through under the new key.
        b.0.lock().unwrap().local_op(7, typ::BOOKMARKS, "b-1", vec![3]);
        assert_eq!(pull(a, b).unwrap(), 1);
        assert_eq!(head(b), head(a));
        // D was offline; it catches up from B, not from A.
        assert_eq!(pull(d, b).unwrap(), 1);
        assert_eq!(head(d), head(a));
        d.0.lock().unwrap().local_op(8, typ::BOOKMARKS, "d-1", vec![4]);
        assert_eq!(pull(a, d).unwrap(), 1);
        assert_eq!(pull(b, d).unwrap(), 1);
        pull(b, a).unwrap();
        pull(d, a).unwrap();
        let want = vec!["a-1", "a-2", "b-1", "d-1"];
        for (s, label) in [(a, "a"), (b, "b"), (d, "d")] {
            assert_eq!(records(s), want, "{label}");
            assert!(matches!(s.0.lock().unwrap().key_status(), KeyStatus::Current { .. }), "{label}");
        }
        assert!(matches!(pull(c, d), Err(SyncError::Refused(ref r)) if r == "revoked"));
    }

    #[test]
    fn a_restored_device_is_re_admitted_and_catches_up() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        a.0.lock().unwrap().local_op(1, typ::BOOKMARKS, "old", vec![1]);
        let first = {
            let mut st = a.0.lock().unwrap();
            st.revoke(&user, &peer(c), 2).unwrap();
            st.roster.head_id().unwrap()
        };
        let second = a.0.lock().unwrap().rotate(3).unwrap();
        a.0.lock().unwrap().local_op(4, typ::BOOKMARKS, "new", vec![2]);
        pull(b, a).unwrap();

        // Restored from the recovery words: same seed and user, a new node key.
        let uid = user::user_id(&user.public());
        let rk = Keypair::generate_ed25519();
        let (rs, _) = state(&user, &rk, &uid, "restored", &["bookmarks"]);
        let r = (rs.clone(), start_node(rk, node_config(true), rs).unwrap());
        assert!(matches!(pull(&r, a), Err(SyncError::Refused(ref x)) if x == "needs-admission"));
        assert_eq!(r.0.lock().unwrap().key_status(), KeyStatus::NeedsAdmission);
        assert!(r.0.lock().unwrap().roster.head_id().is_some(), "it knows the chain moved on");

        // On A the user approves it (as when linking). A learned its device key from the hello.
        let cert = r.0.lock().unwrap().our_cert.clone();
        let fp = r.0.lock().unwrap().roster.chain.device(&peer(&r)).unwrap().fingerprint();
        assert_eq!(a.0.lock().unwrap().roster.chain.device(&peer(&r)).unwrap().fingerprint(), fp);
        assert!(a.0.lock().unwrap().admit(cert, 5).unwrap());

        assert_eq!(pull(&r, a).unwrap(), 2);
        assert_eq!(records(&r), vec!["new", "old"]);
        {
            let st = r.0.lock().unwrap();
            assert!(st.keys.has(&first) && st.keys.has(&second), "older epochs come along for history");
            assert!(matches!(st.key_status(), KeyStatus::Current { .. }));
        }
        // It writes; B learns of it from A and then pulls from it directly.
        r.0.lock().unwrap().local_op(6, typ::BOOKMARKS, "restored-1", vec![3]);
        pull(b, a).unwrap();
        assert_eq!(pull(b, &r).unwrap(), 1);
        // A device approved before its key is known (the link flow) is admitted by its
        // first hello and catches up in that same pull.
        let rk2 = Keypair::generate_ed25519();
        let (rs2, _) = state(&user, &rk2, &uid, "restored-2", &["bookmarks"]);
        let r2 = (rs2.clone(), start_node(rk2, node_config(true), rs2).unwrap());
        let cert2 = r2.0.lock().unwrap().our_cert.clone();
        assert!(!a.0.lock().unwrap().approve(cert2, 8).unwrap(), "no device key yet");
        assert_eq!(a.0.lock().unwrap().roster.chain.approved, vec![peer(&r2)]);
        assert_eq!(pull(&r2, a).unwrap(), 2);
        assert!(a.0.lock().unwrap().roster.chain.approved.is_empty());
        assert!(a.0.lock().unwrap().roster.chain_view().head().unwrap().members.contains(&peer(&r2)));
        // A revoked device cannot be admitted again.
        let c_cert = c.0.lock().unwrap().our_cert.clone();
        assert!(matches!(a.0.lock().unwrap().admit(c_cert, 7), Err(SyncError::Refused(ref x)) if x == "revoked"));
    }

    #[test]
    fn concurrent_rotations_settle_on_one_head() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b"]);
        let (a, b) = (&g[0], &g[1]);
        a.0.lock().unwrap().rotate(1).unwrap();
        pull(b, a).unwrap();
        let ra = a.0.lock().unwrap().rotate(2).unwrap();
        let rb = b.0.lock().unwrap().rotate(2).unwrap();
        assert_ne!(ra, rb);
        a.0.lock().unwrap().local_op(3, typ::BOOKMARKS, "a-1", vec![1]);
        assert_eq!(pull(b, a).unwrap(), 1);
        pull(a, b).unwrap();
        let h = head(a).unwrap();
        assert_eq!(head(b).as_deref(), Some(h.as_str()));
        assert_eq!(h, ra.clone().min(rb.clone()), "the lower id wins a tie");
        assert!(a.0.lock().unwrap().keys.has(&ra) && a.0.lock().unwrap().keys.has(&rb));
    }

    #[test]
    fn two_first_roots_made_at_once_settle_on_one() {
        // A links B, then C, before anyone syncs. B knows only A and itself, sees itself
        // as the lowest and starts a root; C knows all three and starts another.
        let user = Keypair::generate_ed25519();
        let mut g = linked(&user, &["a", "b", "c"]);
        g.sort_by_key(peer);
        let (lo, mid, hi) = (&g[0], &g[1], &g[2]);
        let lo_cert = lo.0.lock().unwrap().our_cert.clone();
        let lo_key = lo.0.lock().unwrap().roster.chain.device(&peer(lo)).cloned().unwrap();
        {
            let mut st = mid.0.lock().unwrap();
            st.roster.certs.retain(|c| c.peer_id != peer(lo));
            st.roster.chain.devices.retain(|d| d.peer_id != peer(lo));
            st.rotate(1).unwrap();
            st.roster.upsert(lo_cert.clone());
            st.roster.chain.devices.push(lo_key);
        }
        lo.0.lock().unwrap().rotate(1).unwrap();
        // The device that linked the late one approved it.
        hi.0.lock().unwrap().approve(lo_cert, 2).unwrap();
        for _ in 0..3 {
            for i in 0..3 {
                for j in 0..3 {
                    if i != j {
                        let _ = pull(&g[i], &g[j]);
                    }
                }
            }
        }
        let heads: Vec<_> = g.iter().map(head).collect();
        assert!(heads[0].is_some() && heads.iter().all(|h| *h == heads[0]), "{heads:?}");
        for s in &g {
            assert!(matches!(s.0.lock().unwrap().key_status(), KeyStatus::Current { .. }));
        }
    }

    #[test]
    fn a_late_root_and_a_revoked_creator_do_not_move_the_head() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        a.0.lock().unwrap().rotate(1).unwrap();
        pull(b, a).unwrap();
        pull(c, a).unwrap();
        a.0.lock().unwrap().revoke(&user, &peer(c), 2).unwrap();
        let h = head(a).unwrap();
        // C, unaware, rotates off the root it still holds. Its rotation stops counting
        // once its revocation is known, so it never becomes the head.
        c.0.lock().unwrap().rotate(3).unwrap();
        c.0.lock().unwrap().rotate(4).unwrap();
        assert!(c.0.lock().unwrap().roster.chain_view().head().unwrap().epoch > a.0.lock().unwrap().roster.chain_view().head().unwrap().epoch);
        // A seed holder with a fresh node starts its own root that includes everyone.
        let uid = user::user_id(&user.public());
        let mk = Keypair::generate_ed25519();
        let (ms, _) = state(&user, &mk, &uid, "minted", &["bookmarks"]);
        {
            let mut m = ms.lock().unwrap();
            let r = a.0.lock().unwrap().roster.clone();
            let mut plain =
                Roster { epoch: r.epoch, certs: r.certs.clone(), chain: KeyChain { devices: r.chain.devices.clone(), ..Default::default() } };
            plain.certs.retain(|x| x.active());
            let key = m.user_key.clone();
            m.roster.merge(&plain, &key, &WEIRDNET);
            m.rotate(1).unwrap();
            assert!(m.roster.chain_view().head().unwrap().epoch > 2, "it outnumbers the real head");
        }
        let minted_cert = ms.lock().unwrap().our_cert.clone();
        let minted_chain = ms.lock().unwrap().roster.chain.clone();
        let c_roster = c.0.lock().unwrap().roster.clone();
        {
            let mut st = a.0.lock().unwrap();
            let key = st.user_key.clone();
            st.roster.merge(&c_roster, &key, &WEIRDNET);
            st.roster.upsert(minted_cert);
            st.roster.chain.merge(&minted_chain);
            st.refresh_keys();
            assert_eq!(st.roster.head_id().as_deref(), Some(h.as_str()));
            assert!(!st.needs_rotation());
        }
    }

    #[test]
    fn revoking_the_device_that_started_the_chain_keeps_the_chain() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        let root = c.0.lock().unwrap().rotate(1).unwrap();
        pull(a, c).unwrap();
        pull(b, c).unwrap();
        a.0.lock().unwrap().revoke(&user, &peer(c), 2).unwrap();
        let h = head(a).unwrap();
        assert_ne!(h, root);
        assert_eq!(a.0.lock().unwrap().roster.chain_view().root.as_deref(), Some(root.as_str()), "the chain C started lives on");
        a.0.lock().unwrap().local_op(3, typ::BOOKMARKS, "a-1", vec![1]);
        pull(b, a).unwrap();
        assert_eq!(head(b).as_deref(), Some(h.as_str()));
        assert!(matches!(b.0.lock().unwrap().key_status(), KeyStatus::Current { .. }));
        assert_eq!(records(b), vec!["a-1"]);
        // What C makes on its own after the revocation does not count.
        let _ = pull(c, a);
        let _ = c.0.lock().unwrap().rotate(4);
        let c_roster = c.0.lock().unwrap().roster.clone();
        let mut st = a.0.lock().unwrap();
        st.roster.chain.merge(&c_roster.chain);
        assert_eq!(st.roster.head_id().as_deref(), Some(h.as_str()));
        assert!(!c.0.lock().unwrap().keys.has(&h));
    }

    #[test]
    fn a_head_that_still_includes_a_revoked_device_is_replaced() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        let root = a.0.lock().unwrap().rotate(1).unwrap();
        pull(b, a).unwrap();
        // Revoked without a rotation (a 0.2 device, or one without its node key).
        b.0.lock().unwrap().roster.revoke(&WEIRDNET, &user, &peer(c), 2).unwrap();
        assert!(b.0.lock().unwrap().needs_rotation());
        pull(b, a).unwrap();
        let h = head(b).unwrap();
        assert_ne!(h, root);
        assert!(!b.0.lock().unwrap().needs_rotation());
        pull(a, b).unwrap();
        assert_eq!(head(a).as_deref(), Some(h.as_str()));
        assert!(!a.0.lock().unwrap().roster.chain_view().head().unwrap().members.contains(&peer(c)));
    }

    #[test]
    fn the_first_rotation_starts_once_every_linked_device_has_a_key() {
        let user = Keypair::generate_ed25519();
        let uid = user::user_id(&user.public());
        let (ka, kb) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
        let (sa, _) = state(&user, &ka, &uid, "a", &["bookmarks"]);
        let (sb, _) = state(&user, &kb, &uid, "b", &["bookmarks"]);
        for s in [&sa, &sb] {
            s.lock().unwrap().auto_first_rotation = true;
        }
        assert!(!sa.lock().unwrap().first_rotation_due(), "one device: nothing to rotate for");
        let a = (sa.clone(), start_node(ka, node_config(true), sa.clone()).unwrap());
        let b = (sb.clone(), start_node(kb, node_config(true), sb.clone()).unwrap());
        // The first link: each learns the other's cert, not yet its device key.
        let (ca, cb) = (sa.lock().unwrap().our_cert.clone(), sb.lock().unwrap().our_cert.clone());
        sa.lock().unwrap().roster.upsert(cb);
        sb.lock().unwrap().roster.upsert(ca);
        for s in [&sa, &sb] {
            let st = s.lock().unwrap();
            assert!(!st.first_rotation_due());
            assert_eq!(st.devices_without_key().len(), 1, "the other device has no key yet");
        }
        let (low, high) = if peer(&a) < peer(&b) { (&a, &b) } else { (&b, &a) };
        sa.lock().unwrap().local_op(1, typ::BOOKMARKS, "a-1", vec![1]);
        // The higher peer pulls first: it learns the lower one's key, but leaves the
        // first rotation to it.
        pull(high, low).unwrap();
        assert_eq!(head(high), None);
        assert!(low.0.lock().unwrap().first_rotation_due(), "the hello brought the other key");
        pull(low, high).unwrap();
        let root = head(low).expect("the lowest peer started the chain");
        assert!(!low.0.lock().unwrap().first_rotation_due());
        pull(high, low).unwrap();
        assert_eq!(head(high).as_deref(), Some(root.as_str()));
        assert!(matches!(high.0.lock().unwrap().key_status(), KeyStatus::Current { .. }));
        assert_eq!(records(&b), vec!["a-1"]);
        // Never again: later passes keep the same head.
        pull(low, high).unwrap();
        pull(high, low).unwrap();
        assert_eq!(head(low).as_deref(), Some(root.as_str()));
        assert_eq!(head(high).as_deref(), Some(root.as_str()));
    }

    #[test]
    fn an_upgrade_rotates_once_and_waits_for_every_device_key() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        // C has not upgraded yet: drop its device key everywhere.
        let c_peer = peer(&g[2]);
        for s in &g {
            let mut st = s.0.lock().unwrap();
            st.roster.chain.devices.retain(|d| d.peer_id != c_peer);
            st.auto_first_rotation = true;
        }
        for x in &g[..2] {
            let st = x.0.lock().unwrap();
            assert_eq!(st.devices_without_key().iter().map(|c| c.peer_id.clone()).collect::<Vec<_>>(), vec![c_peer.clone()]);
            assert!(!st.first_rotation_due());
        }
        assert_eq!(g[0].0.lock().unwrap().rotate_if_first_due(1).unwrap(), None);
        // C upgrades: its key spreads with its hellos, and the lowest peer rotates once.
        g[2].0.lock().unwrap().publish_device_key(2).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let _ = pull(&g[i], &g[j]);
                }
            }
        }
        for _ in 0..2 {
            for i in 0..3 {
                for j in 0..3 {
                    if i != j {
                        pull(&g[i], &g[j]).unwrap();
                    }
                }
            }
        }
        let heads: Vec<_> = g.iter().map(head).collect();
        assert!(heads[0].is_some() && heads.iter().all(|h| *h == heads[0]), "{heads:?}");
        for s in &g {
            let st = s.0.lock().unwrap();
            assert_eq!(st.roster.chain.rotations.len(), 1, "exactly one first rotation");
            assert!(matches!(st.key_status(), KeyStatus::Current { .. }));
        }
    }

    fn pull_t(a: &Sn, b: &Sn, typ: &str) -> Result<usize> {
        pull_from(&mut a.0.lock().unwrap(), &a.1, b.1.peer_id(), &addrs(&b.1), typ)
    }

    /// Every entry of `rid` in `typ` that `s` holds, oldest first.
    fn versions(s: &Sn, typ: &str, rid: &str) -> Vec<crate::LogEntry> {
        let st = s.0.lock().unwrap();
        let mut v: Vec<crate::LogEntry> = st
            .log
            .cursors()
            .keys()
            .flat_map(|n| st.log.iter_node(n).filter(|e| e.typ == typ && e.record_id == rid).cloned().collect::<Vec<_>>())
            .collect();
        v.sort_by(|a, b| a.hlc.cmp_total(&b.hlc));
        v
    }

    fn read(s: &Sn, e: &crate::LogEntry) -> Result<Vec<u8>> {
        match s.0.lock().unwrap().read(e)? {
            crate::RecordValue::Ready(v) => Ok(v.to_vec()),
            crate::RecordValue::Pending { missing } => Err(SyncError::Protocol(format!("{} chunks missing", missing.len()))),
        }
    }

    fn latest(s: &Sn, typ: &str, rid: &str) -> Result<Vec<u8>> {
        let e = versions(s, typ, rid).pop().ok_or_else(|| SyncError::Protocol(format!("no {rid}")))?;
        read(s, &e)
    }

    fn big(len: usize, salt: u8) -> Vec<u8> {
        (0..len).map(|i| ((i * 131 + salt as usize) % 251) as u8).collect()
    }

    fn sealed() -> RecordOptions {
        RecordOptions { sealed: true, ..Default::default() }
    }

    #[test]
    fn a_record_larger_than_a_page_syncs_in_chunks() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        for s in &g {
            s.0.lock().unwrap().configure("notes", RecordOptions::default()).unwrap();
        }
        let lazy = RecordOptions { limits: crate::Limits { eager_chunks: false, ..Default::default() }, ..Default::default() };
        c.0.lock().unwrap().configure("notes", lazy).unwrap();
        let data = big(1024 * 1024 + 17, 1);
        {
            let mut st = a.0.lock().unwrap();
            st.write(1, "notes", "small", b"short").unwrap();
            st.write_with_fallback(2, "notes", "answer", &data, b"clipped preview".to_vec()).unwrap();
            assert!(st.log.get(&st.our_node, 1).unwrap().value.is_none(), "a small plain value is a plain op");
            let chunks = st.log.iter_node(&st.our_node).filter(|e| e.typ == chunk_type("notes")).count();
            assert_eq!(chunks, data.len().div_ceil(crate::Limits::default().chunk_size));
            // The same value again reuses this node's chunks.
            st.write(3, "notes", "copy", &data).unwrap();
            assert_eq!(st.log.iter_node(&st.our_node).filter(|e| e.typ == chunk_type("notes")).count(), chunks);
            assert!(matches!(st.write(4, "notes", "huge", &big(17 * 1024 * 1024, 2)), Err(SyncError::Protocol(_))));
            assert!(st.write(4, &chunk_type("notes"), "x", b"y").is_err());
        }
        assert_eq!(pull_t(b, a, "notes").unwrap(), 3);
        assert_eq!(latest(b, "notes", "small").unwrap(), b"short");
        assert_eq!(latest(b, "notes", "answer").unwrap(), data);
        assert_eq!(latest(b, "notes", "copy").unwrap(), data);
        let e = versions(b, "notes", "answer").pop().unwrap();
        assert_eq!(e.op, b"clipped preview", "older peers and plain readers see the fallback");
        assert!(b.0.lock().unwrap().log.pending_blobs("notes").is_empty());

        // C pulls chunks only when asked, and here from B, which relays A's chunks.
        assert_eq!(pull_t(c, b, "notes").unwrap(), 3);
        assert!(
            matches!(c.0.lock().unwrap().read(&e).unwrap(), crate::RecordValue::Pending { ref missing } if missing.len() == data.len().div_ceil(crate::Limits::default().chunk_size))
        );
        assert_eq!(
            pull_chunks(&mut c.0.lock().unwrap(), &c.1, b.1.peer_id(), &addrs(&b.1), "notes").unwrap(),
            data.len().div_ceil(crate::Limits::default().chunk_size)
        );
        assert_eq!(latest(c, "notes", "answer").unwrap(), data);
    }

    #[test]
    fn sealed_records_follow_rotation_across_three_devices() {
        let user = Keypair::generate_ed25519();
        let uid = user::user_id(&user.public());
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        for s in &g {
            s.0.lock().unwrap().configure("secrets", sealed()).unwrap();
        }
        // Seed-derived keys are held by every seed holder: nothing is sealed under them.
        assert!(matches!(a.0.lock().unwrap().write(1, "secrets", "k1", b"one"), Err(SyncError::Refused(ref r)) if r == "no-epoch-key"));
        let root = a.0.lock().unwrap().rotate(1).unwrap();
        let secret = big(150_000, 3);
        {
            let mut st = a.0.lock().unwrap();
            st.write(2, "secrets", "k1", b"one").unwrap();
            st.write(3, "secrets", "big", &secret).unwrap();
        }
        pull_t(b, a, "secrets").unwrap();
        pull_t(c, a, "secrets").unwrap();
        for (s, label) in [(a, "a"), (b, "b"), (c, "c")] {
            assert!(s.0.lock().unwrap().keys.has(&root), "{label}");
            assert_eq!(latest(s, "secrets", "k1").unwrap(), b"one", "{label}");
            assert_eq!(latest(s, "secrets", "big").unwrap(), secret, "{label}");
        }
        // At rest, the entry holds ciphertext and an empty fallback.
        let e = versions(b, "secrets", "k1").pop().unwrap();
        assert!(e.op.is_empty());
        let v = e.value.clone().unwrap();
        assert_eq!(v.seal.as_ref().unwrap().key, root);
        assert!(!v.body.windows(3).any(|w| w == b"one"));
        // An unsealed entry in a sealed type (a seed holder writing around the seal) is refused.
        let forged = crate::LogEntry { value: None, op: b"evil".to_vec(), ..e.clone() };
        assert!(b.0.lock().unwrap().read(&forged).is_err());

        // A revokes C and rotates; new and updated secrets go under the new head.
        let (second, a_written) = {
            let mut st = a.0.lock().unwrap();
            st.revoke(&user, &peer(c), 9).unwrap();
            let head = st.roster.head_id().unwrap();
            let from = st.log.cursor(&st.our_node);
            st.write(10, "secrets", "k2", b"two").unwrap();
            st.write(11, "secrets", "k1", b"one, changed").unwrap();
            st.write(12, "secrets", "big2", &big(150_000, 4)).unwrap();
            (head, from)
        };
        assert_ne!(second, root);
        pull_t(b, a, "secrets").unwrap();
        assert_eq!(head(b).as_deref(), Some(second.as_str()));
        assert_eq!(latest(b, "secrets", "k2").unwrap(), b"two");
        assert_eq!(latest(b, "secrets", "k1").unwrap(), b"one, changed");
        assert_eq!(latest(b, "secrets", "big2").unwrap(), big(150_000, 4));
        let k1 = versions(b, "secrets", "k1");
        assert_eq!(read(b, &k1[0]).unwrap(), b"one", "members keep older epochs readable");

        // C is refused, and even holding A's raw entries (a backup, a relay) it cannot open
        // anything written after the rotation, though it holds the seed and the root key.
        assert!(matches!(pull_t(c, a, "secrets"), Err(SyncError::Refused(ref r)) if r == "revoked"));
        let leaked: Vec<crate::LogEntry> = {
            let st = a.0.lock().unwrap();
            st.log.iter_node(&st.our_node).filter(|e| e.seq > a_written).cloned().collect()
        };
        {
            let mut st = c.0.lock().unwrap();
            let page = crate::LogPage { node_id: NodeId(peer(a)), from_seq: a_written + 1, to_seq: a_written + leaked.len() as u64, ops: leaked };
            st.log.integrate(&page);
            assert!(st.keys.has(&root) && !st.keys.has(&second));
        }
        for rid in ["k2", "k1", "big2"] {
            assert!(matches!(latest(c, "secrets", rid), Err(SyncError::Crypto(_))), "c must not read {rid}");
        }
        assert_eq!(read(c, &versions(c, "secrets", "k1")[0]).unwrap(), b"one", "what it read before stays what it was");

        // Optional re-seal moves the record still under the root key to the head key.
        let done = a.0.lock().unwrap().reseal_stale(13, "secrets").unwrap();
        assert_eq!(done, vec!["big".to_string()]);
        assert!(a.0.lock().unwrap().reseal_stale(14, "secrets").unwrap().is_empty());
        pull_t(b, a, "secrets").unwrap();
        let resealed = versions(b, "secrets", "big").pop().unwrap();
        assert_eq!(resealed.value.as_ref().unwrap().seal.as_ref().unwrap().key, second);
        assert_eq!(read(b, &resealed).unwrap(), secret);
        {
            let mut st = c.0.lock().unwrap();
            let a_log = a.0.lock().unwrap();
            let ops: Vec<crate::LogEntry> = a_log.log.iter_node(&a_log.our_node).cloned().collect();
            st.log.integrate(&crate::LogPage { node_id: a_log.our_node.clone(), from_seq: 1, to_seq: ops.len() as u64, ops });
            assert!(st.log.pending_blobs("secrets").is_empty(), "c holds every chunk");
        }
        assert!(matches!(read(c, &resealed), Err(SyncError::Crypto(_))));

        // B writes under the head too, and A reads it.
        b.0.lock().unwrap().write(15, "secrets", "k3", b"three").unwrap();
        pull_t(a, b, "secrets").unwrap();
        assert_eq!(latest(a, "secrets", "k3").unwrap(), b"three");

        // A device restored and admitted later reads the secrets of both epochs.
        let rk = Keypair::generate_ed25519();
        let (rs, _) = state(&user, &rk, &uid, "restored", &["bookmarks"]);
        let r = (rs.clone(), start_node(rk, node_config(true), rs).unwrap());
        r.0.lock().unwrap().configure("secrets", sealed()).unwrap();
        let cert = r.0.lock().unwrap().our_cert.clone();
        a.0.lock().unwrap().approve(cert, 16).unwrap();
        pull_t(&r, a, "secrets").unwrap();
        for (rid, want) in [("k1", b"one, changed".to_vec()), ("k2", b"two".to_vec()), ("k3", b"three".to_vec()), ("big", secret.clone())] {
            assert_eq!(latest(&r, "secrets", rid).unwrap(), want, "{rid}");
        }
        assert_eq!(read(&r, &versions(&r, "secrets", "k1")[0]).unwrap(), b"one");
    }

    /// Answers like [`SyncHandler`], but refuses every pull after the first page while `on`.
    struct RefuseLaterPages {
        state: Arc<Mutex<SyncState>>,
        on: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Handler<Vec<u8>, Vec<u8>> for RefuseLaterPages {
        fn request(&self, from: &PeerId, req: Vec<u8>) -> Vec<u8> {
            if self.on.load(std::sync::atomic::Ordering::SeqCst)
                && let Ok(env) = decode::<Envelope>(&req)
            {
                let st = self.state.lock().unwrap();
                if let Ok(Message::Pull(p)) = st.open_envelope(&env, &from.to_string())
                    && p.after_seq > 0
                {
                    return encode(&st.refuse(&from.to_string(), &env.typ, env.epoch, "test-later-page").unwrap()).unwrap();
                }
            }
            SyncHandler { state: self.state.clone() }.request(from, req)
        }
    }

    #[test]
    fn a_refused_later_page_keeps_the_pages_before_it() {
        let (user, ka, kb, uid) = pair();
        let (sa, _) = state(&user, &ka, &uid, "a", &["bookmarks"]);
        let (sb, _) = state(&user, &kb, &uid, "b", &["bookmarks"]);
        {
            let ca = sa.lock().unwrap().our_cert.clone();
            let cb = sb.lock().unwrap().our_cert.clone();
            sa.lock().unwrap().roster.upsert(cb);
            sb.lock().unwrap().roster.upsert(ca);
            let mut a = sa.lock().unwrap();
            for i in 0..600u64 {
                a.local_op(1_000 + i, typ::BOOKMARKS, &format!("bm-{i}"), vec![i as u8]);
            }
        }
        let on = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let na = Node::start(&SYNC_PROFILE, ka, node_config(true), Arc::new(RefuseLaterPages { state: sa.clone(), on: on.clone() })).unwrap();
        let nb = start_node(kb, node_config(true), sb.clone()).unwrap();
        let a_node = NodeId(na.peer_id().to_string());

        // Pages are 512 ops: the first is applied and acked, the second refused.
        let mut copy = sb.lock().unwrap().snapshot();
        let out = pull_from_outcome(&mut copy, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS);
        assert_eq!(out.applied, 512);
        assert!(!out.is_ok());
        assert!(matches!(out.error, Some(SyncError::Refused(ref r)) if r == "test-later-page"), "{:?}", out.error);
        assert_eq!(copy.log.cursor_for(&a_node, typ::BOOKMARKS), 512);
        // pull_from keeps its signature: an error, the pages still applied.
        let mut copy = sb.lock().unwrap().snapshot();
        assert!(pull_from(&mut copy, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS).is_err());
        assert_eq!(copy.log.iter_node(&a_node).count(), 512);
        assert!(sb.lock().unwrap().log.iter_node(&a_node).next().is_none(), "snapshots leave the shared state alone");

        // Through the shared state: the partial pull is merged back, then the rest follows.
        let out = pull_from_shared(&sb, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS);
        assert_eq!((out.applied, out.is_ok()), (512, false));
        assert_eq!(sb.lock().unwrap().log.iter_node(&a_node).count(), 512);
        assert_eq!(sb.lock().unwrap().log.cursor_for(&a_node, typ::BOOKMARKS), 512);
        on.store(false, std::sync::atomic::Ordering::SeqCst);
        let out = pull_from_shared(&sb, &nb, na.peer_id(), &addrs(&na), typ::BOOKMARKS);
        assert!(out.is_ok(), "{:?}", out.error);
        assert_eq!(out.applied, 88);
        let b = sb.lock().unwrap();
        assert_eq!(b.log.iter_node(&a_node).count(), 600);
        assert_eq!(b.log.cursor_for(&a_node, typ::BOOKMARKS), 600);
        assert!(b.clock.as_ref().is_some_and(|c| c.physical_ms >= 1_599));
    }

    #[test]
    fn two_shared_states_pull_from_each_other_at_once() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b"]);
        let (a, b) = (&g[0], &g[1]);
        a.0.lock().unwrap().local_op(1, typ::BOOKMARKS, "from-a", vec![1]);
        b.0.lock().unwrap().local_op(2, typ::BOOKMARKS, "from-b", vec![2]);
        // Each pull asks the other node, whose handler needs its own state's lock: neither
        // pull may hold its lock across the network.
        let (ra, rb) = std::thread::scope(|s| {
            let ta = s.spawn(|| pull_from_shared(&a.0, &a.1, b.1.peer_id(), &addrs(&b.1), typ::BOOKMARKS));
            let tb = s.spawn(|| pull_from_shared(&b.0, &b.1, a.1.peer_id(), &addrs(&a.1), typ::BOOKMARKS));
            (ta.join().unwrap(), tb.join().unwrap())
        });
        assert!(ra.is_ok() && rb.is_ok(), "{:?} {:?}", ra.error, rb.error);
        assert_eq!((ra.applied, rb.applied), (1, 1));
        assert_eq!(records(a), ["from-a", "from-b"]);
        assert_eq!(records(b), ["from-a", "from-b"]);
    }

    #[test]
    fn merge_back_folds_records_keys_roster_and_clock() {
        let user = Keypair::generate_ed25519();
        let g = linked(&user, &["a", "b", "c"]);
        let (a, b, c) = (&g[0], &g[1], &g[2]);
        for s in &g {
            s.0.lock().unwrap().configure("notes", RecordOptions::default()).unwrap();
        }
        let data = big(300 * 1024 + 5, 7);
        {
            let mut st = a.0.lock().unwrap();
            st.write(5_000, "notes", "small", b"short").unwrap();
            st.write(5_001, "notes", "answer", &data).unwrap();
        }
        let a_node = NodeId(peer(a));

        // Pull into a snapshot, and rotate there (the first rotation, say).
        let mut snap = b.0.lock().unwrap().snapshot();
        assert_eq!(pull_from(&mut snap, &b.1, a.1.peer_id(), &addrs(&a.1), "notes").unwrap(), 2);
        let head = snap.rotate(6_000).unwrap();
        let pulled = snap.log.iter_node(&a_node).count();
        assert!(pulled > 2, "the value came in chunks");

        // Meanwhile the shared state writes and revokes C.
        {
            let mut st = b.0.lock().unwrap();
            st.write(5_500, "notes", "local", b"mine").unwrap();
            st.roster.revoke(&WEIRDNET, &user, &peer(c), 5_600).unwrap();
            assert!(st.keys.is_empty());
        }

        let out = b.0.lock().unwrap().merge_back(&snap);
        assert_eq!(out.entries, pulled);
        assert!(out.keys >= 1);
        assert_eq!(out.revocations, 0);
        {
            let st = b.0.lock().unwrap();
            assert!(!st.roster.get(&peer(c)).unwrap().active(), "the snapshot's active copy never un-revokes");
            assert!(st.keys.has(&head));
            assert_eq!(st.roster.chain.root, snap.roster.chain.root);
            assert_eq!(st.current_key().id, Some(head.clone()));
            assert_eq!(st.log.cursor_for(&a_node, "notes"), snap.log.cursor_for(&a_node, "notes"));
            assert_eq!(st.log.cursor(&a_node), snap.log.cursor(&a_node));
            assert!(st.log.pending_blobs("notes").is_empty());
            assert!(st.clock.as_ref().unwrap().cmp_total(snap.clock.as_ref().unwrap()).is_ge());
        }
        assert_eq!(latest(b, "notes", "small").unwrap(), b"short");
        assert_eq!(latest(b, "notes", "answer").unwrap(), data);
        assert_eq!(latest(b, "notes", "local").unwrap(), b"mine");
        // A local write after the merge orders after everything pulled.
        let seq = b.0.lock().unwrap().write(1, "notes", "after", b"x").unwrap();
        let st = b.0.lock().unwrap();
        let after = st.log.get(&st.our_node, seq).unwrap().hlc.clone();
        assert!(st.log.iter_node(&a_node).all(|e| after.cmp_total(&e.hlc).is_gt()));
        drop(st);
        // Folding the same snapshot again changes nothing.
        assert_eq!(b.0.lock().unwrap().merge_back(&snap), MergeOutcome::default());
    }
}
