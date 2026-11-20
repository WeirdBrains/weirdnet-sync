//! Majority-vote leases with fencing terms (since 0.8).
//!
//! The op log is eventually consistent, so it can't give mutual exclusion by itself. A lease
//! comes from a small quorum protocol between *voters*: the user's devices that hold a role
//! grant (for Ymir, `ymir.inference`; [`Voters::Role`]). A candidate asks every voter at once
//! and holds the lease while a majority granted it, timed by its own monotonic clock and cut
//! short by the assumed clock-rate drift. Each new holder gets a higher [`Term`], the fencing
//! token: resources refuse commands with a term older than one they have seen
//! ([`FenceGuard`]), so a paused or partitioned ex-holder can do no harm.
//!
//! Asks and answers are [`Message`](crate::Message) variants on `/weirdnet/sync/2`, sealed
//! like every other request, so only active, admitted devices of the user take part. A
//! voter answers only candidates that are in the same voter set. Safety needs no wall clock
//! and no HLC; only rate drift within [`LeaseConfig::max_drift`].
//!
//! Voters keep the highest term per lease (persist [`Voter::export`]); after a restart a
//! voter refuses takeovers for one maximum lease duration, so it can't hand out an
//! overlapping lease.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use weirdnet_net::profile::WEIRDNET;
use weirdnet_net::{Multiaddr, Node, PeerId};

use crate::error::{Result, SyncError};
use crate::net::SyncState;
use crate::protocol::{Message, decode, encode};
use crate::roster::{CallerCheck, Roster};

/// Default time a grant lasts at a voter.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(15);
/// Default renewal interval (a third of the duration).
pub const DEFAULT_RENEW_EVERY: Duration = Duration::from_secs(5);
/// Default worst clock-rate drift assumed between devices.
pub const DEFAULT_MAX_DRIFT: f64 = 0.01;
/// Default delay per candidate rank after a lapse.
pub const DEFAULT_STAGGER: Duration = Duration::from_millis(500);
/// Taken off every lease besides the drift.
const EPSILON: Duration = Duration::from_millis(50);
/// The envelope type lease messages travel under.
pub const LEASE_TYPE: &str = "weirdnet.lease";
const MAX_NAME: usize = 200;

/// A lease name, scoped by the app: `ymir.scheduler`, `ymir.jobs/<job id>`. 1 to 200 of
/// `A-Z a-z 0-9 . - _ : / + #`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LeaseName(String);

impl LeaseName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let ok = !name.is_empty() && name.len() <= MAX_NAME && name.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:/+#".contains(c));
        if ok { Ok(Self(name)) } else { Err(SyncError::Protocol(format!("bad lease name {name:?}"))) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LeaseName {
    type Error = SyncError;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl From<LeaseName> for String {
    fn from(n: LeaseName) -> String {
        n.0
    }
}

impl std::fmt::Display for LeaseName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Fencing token: strictly increases per lease name across holders.
#[derive(Debug, Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Term(pub u64);

impl Term {
    pub fn next(self) -> Term {
        Term(self.0.saturating_add(1))
    }
}

impl std::fmt::Display for Term {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Who votes (and who may stand): devices with an active cert in the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Voters {
    /// Devices whose grant holds this role (`Roster::has_role`), for example `ymir.inference`.
    Role(String),
    /// A fixed set of peer ids (those with an active cert count).
    Peers(Vec<String>),
}

impl Voters {
    /// The voters now, sorted (the order is the candidate rank).
    pub fn resolve(&self, roster: &Roster) -> Vec<String> {
        let mut v: Vec<String> = match self {
            Voters::Role(role) => roster.active().filter(|c| roster.has_role(&c.peer_id, role)).map(|c| c.peer_id.clone()).collect(),
            Voters::Peers(peers) => peers.iter().filter(|p| roster.get(p).is_some_and(|c| c.active())).cloned().collect(),
        };
        v.sort();
        v.dedup();
        v
    }

    /// A digest of [`resolve`](Self::resolve): candidates send it with every ask and a voter
    /// grants only when its own view of the voter set is the same, so a candidate with a stale
    /// roster can't win a majority of a voter set that has since changed.
    pub fn digest(&self, roster: &Roster) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"weirdnet-sync/v1/voters\n");
        for v in self.resolve(roster) {
            h.update(v.as_bytes());
            h.update(b"\n");
        }
        h.finalize().to_hex()[..32].to_string()
    }

    pub fn contains(&self, roster: &Roster, peer: &str) -> bool {
        match self {
            Voters::Role(role) => roster.get(peer).is_some_and(|c| c.active()) && roster.has_role(peer, role),
            Voters::Peers(peers) => peers.iter().any(|p| p == peer) && roster.get(peer).is_some_and(|c| c.active()),
        }
    }
}

/// How a lease is held.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LeaseConfig {
    /// How long a grant lasts at a voter (capped by the voter's maximum).
    pub duration: Duration,
    /// How often the [`Elector`] renews.
    pub renew_every: Duration,
    /// Assumed worst clock-rate drift; the holder's lease is shortened by it.
    pub max_drift: f64,
    pub voters: Voters,
    /// Extra wait per candidate rank after a lapse, so the lowest rank tries first.
    pub stagger: Duration,
    /// Write a [`LeaseRecord`] under this record type on each new term (informational).
    pub record_type: Option<String>,
}

impl LeaseConfig {
    /// The defaults (15 s, renew every 5 s, 1 % drift, 500 ms stagger) with these voters.
    pub fn new(voters: Voters) -> Self {
        Self {
            duration: DEFAULT_DURATION,
            renew_every: DEFAULT_RENEW_EVERY,
            max_drift: DEFAULT_MAX_DRIFT,
            voters,
            stagger: DEFAULT_STAGGER,
            record_type: None,
        }
    }

    /// Voters are the devices granted `role`.
    pub fn for_role(role: impl Into<String>) -> Self {
        Self::new(Voters::Role(role.into()))
    }

    /// Sets the duration and renews every third of it.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self.renew_every = duration / 3;
        self
    }

    pub fn with_stagger(mut self, stagger: Duration) -> Self {
        self.stagger = stagger;
        self
    }

    pub fn with_max_drift(mut self, drift: f64) -> Self {
        self.max_drift = drift.clamp(0.0, 0.5);
        self
    }

    pub fn with_record_type(mut self, typ: impl Into<String>) -> Self {
        self.record_type = Some(typ.into());
        self
    }
}

/// A candidate asks for (or renews) a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseAsk {
    pub name: LeaseName,
    pub term: Term,
    pub duration_ms: u32,
    pub renew: bool,
    /// [`Voters::digest`] of the voter set the candidate counts its majority in.
    pub voters: String,
}

/// A voter granted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub name: LeaseName,
    pub term: Term,
    pub duration_ms: u32,
}

/// A voter did not grant it: who it promised, for how much longer, and the highest term it
/// has granted (ask with a higher one next time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseDeny {
    pub name: LeaseName,
    pub promised: Term,
    pub holder: String,
    pub remaining_ms: u32,
    pub max_term: Term,
}

/// The holder lets go (also the answer to one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseFree {
    pub name: LeaseName,
    pub term: Term,
}

/// Who holds a lease, written to the op log on each new term for display. Nothing trusts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub name: LeaseName,
    pub term: Term,
    pub holder: String,
}

#[derive(Debug, Clone)]
struct Promise {
    term: Term,
    holder: String,
    until: Instant,
}

#[derive(Debug, Clone, Default)]
struct Slot {
    max_term: Term,
    /// Who `max_term` went to.
    max_holder: String,
    promise: Option<Promise>,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    v: u8,
    terms: Vec<(LeaseName, Term, String)>,
}

type Persist = Arc<dyn Fn(&[u8]) -> std::io::Result<()> + Send + Sync>;

/// The voter side (one per device, kept in [`SyncState::voter`]). Not secret.
///
/// Give it a store with [`with_persist`](Self::with_persist) (or use
/// [`Identity::enable_voter`](crate::Identity::enable_voter)): every new term is then written
/// before it is granted. Without one, a voter that crashes before the app saved
/// [`export`](Self::export) may grant a term it already gave out, so two holders could share
/// a fencing token (their leases still never overlap in time).
#[derive(Clone)]
pub struct Voter {
    candidates: Voters,
    max_duration: Duration,
    grace_until: Instant,
    slots: HashMap<LeaseName, Slot>,
    persist: Option<Persist>,
}

impl std::fmt::Debug for Voter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Voter")
            .field("candidates", &self.candidates)
            .field("max_duration", &self.max_duration)
            .field("slots", &self.slots)
            .field("persist", &self.persist.is_some())
            .finish()
    }
}

impl Voter {
    /// A voter answering candidates in `candidates` (normally the same [`Voters`] the
    /// leases use). It refuses takeovers for [`DEFAULT_DURATION`] after it starts.
    pub fn new(candidates: Voters) -> Self {
        Self { candidates, max_duration: DEFAULT_DURATION, grace_until: Instant::now() + DEFAULT_DURATION, slots: HashMap::new(), persist: None }
    }

    /// Write [`export`](Self::export) with `store` before each new term is granted (renewals
    /// write nothing). If the write fails the ask is denied.
    pub fn with_persist(mut self, store: impl Fn(&[u8]) -> std::io::Result<()> + Send + Sync + 'static) -> Self {
        self.persist = Some(Arc::new(store));
        self
    }

    /// The longest grant it gives, which is also the restart grace (default 15 s).
    pub fn with_max_duration(mut self, max: Duration) -> Self {
        let started = self.grace_until - self.max_duration;
        self.max_duration = max;
        self.grace_until = started + max;
        self
    }

    /// The highest terms (and their holders), to persist; not secret.
    pub fn export(&self) -> Vec<u8> {
        let mut terms: Vec<_> = self.slots.iter().map(|(n, s)| (n.clone(), s.max_term, s.max_holder.clone())).collect();
        terms.sort();
        encode(&Persisted { v: 1, terms }).unwrap_or_default()
    }

    /// A voter restarted from [`export`](Self::export): it never grants an old term again and
    /// refuses takeovers for one maximum duration.
    pub fn import(bytes: &[u8], candidates: Voters) -> Result<Self> {
        let p: Persisted = decode(bytes)?;
        let mut v = Self::new(candidates);
        for (name, term, holder) in p.terms {
            v.slots.insert(name, Slot { max_term: term, max_holder: holder, promise: None });
        }
        Ok(v)
    }

    /// The longest grant it gives (and its restart grace).
    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// The highest term granted for `name`.
    pub fn max_term(&self, name: &LeaseName) -> Term {
        self.slots.get(name).map(|s| s.max_term).unwrap_or_default()
    }

    pub fn candidates(&self) -> &Voters {
        &self.candidates
    }

    /// The voter rule. `from` is the transport-authenticated asker.
    pub fn on_ask(&mut self, from: &str, ask: &LeaseAsk, now: Instant) -> Message {
        let in_grace = now < self.grace_until;
        let grace_left = self.grace_until.saturating_duration_since(now);
        let duration = Duration::from_millis(ask.duration_ms as u64).min(self.max_duration);
        let slot = self.slots.entry(ask.name.clone()).or_default();
        let live = slot.promise.as_ref().filter(|p| p.until > now).cloned();
        // Renewal (or re-establishing a lapsed promise): only the holder the term went to, and
        // only while no higher term was granted here.
        let renewal = ask.term == slot.max_term && slot.max_holder == from && ask.term.0 > 0;
        // Takeover or first grant: a higher term, nobody else promised.
        let takeover = ask.term > slot.max_term && live.as_ref().is_none_or(|p| p.holder == from) && !in_grace;
        if renewal || takeover {
            let before = slot.clone();
            slot.max_term = ask.term;
            slot.max_holder = from.to_string();
            slot.promise = Some(Promise { term: ask.term, holder: from.to_string(), until: now + duration });
            if takeover && let Some(store) = self.persist.clone() {
                // The new term must be durable before anyone acts on it.
                if store(&self.export()).is_err() {
                    let slot = self.slots.entry(ask.name.clone()).or_default();
                    *slot = before;
                    return Message::LeaseDeny(LeaseDeny {
                        name: ask.name.clone(),
                        promised: slot.max_term,
                        holder: String::new(),
                        remaining_ms: 0,
                        max_term: slot.max_term,
                    });
                }
            }
            return Message::LeaseGrant(LeaseGrant { name: ask.name.clone(), term: ask.term, duration_ms: duration.as_millis() as u32 });
        }
        let (promised, holder, remaining) = match &live {
            Some(p) => (p.term, p.holder.clone(), p.until - now),
            None if in_grace => (slot.max_term, slot.max_holder.clone(), grace_left),
            None => (slot.max_term, String::new(), Duration::ZERO),
        };
        Message::LeaseDeny(LeaseDeny {
            name: ask.name.clone(),
            promised,
            holder,
            remaining_ms: remaining.as_millis().min(u32::MAX as u128) as u32,
            max_term: slot.max_term,
        })
    }

    /// The holder lets go of `term`.
    pub fn on_free(&mut self, from: &str, free: &LeaseFree) {
        if let Some(slot) = self.slots.get_mut(&free.name)
            && slot.promise.as_ref().is_some_and(|p| p.term == free.term && p.holder == from)
        {
            slot.promise = None;
        }
    }
}

impl SyncState {
    /// Makes this device a voter (or stops it voting with `None`).
    pub fn set_voter(&mut self, voter: Option<Voter>) {
        self.voter = voter;
    }

    /// A lease message from `from` (already opened under the head key).
    pub(crate) fn on_lease(&mut self, from: &str, msg: Message) -> Message {
        use crate::protocol::Refuse;
        let check = self.roster.check_caller(&WEIRDNET, &self.user_key, from, None);
        if check != CallerCheck::Linked {
            return Message::Refuse(Refuse::new(check.reason().unwrap_or("unknown-device")));
        }
        let roster = &self.roster;
        let Some(voter) = self.voter.as_mut() else { return Message::Refuse(Refuse::new("not-a-voter")) };
        if !voter.candidates.contains(roster, from) {
            return Message::Refuse(Refuse::new("not-a-candidate"));
        }
        let me = self.our_cert.peer_id.as_str();
        match msg {
            // Only a device that is itself in the voter set votes, and only for a candidate
            // that counts the same voter set.
            Message::LeaseAsk(_) if !voter.candidates.contains(roster, me) => Message::Refuse(Refuse::new("not-a-voter")),
            Message::LeaseAsk(ask) if ask.voters != voter.candidates.digest(roster) => Message::Refuse(Refuse::new("voters-differ")),
            Message::LeaseAsk(ask) => voter.on_ask(from, &ask, Instant::now()),
            Message::LeaseFree(free) => {
                voter.on_free(from, &free);
                Message::LeaseFree(free)
            }
            _ => Message::Refuse(Refuse::new("unexpected")),
        }
    }
}

/// A held lease. Valid only while [`is_valid`](Self::is_valid); carry [`term`](Self::term) in
/// every fenced command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseHandle {
    name: LeaseName,
    term: Term,
    holder: String,
    valid_until: Instant,
}

impl LeaseHandle {
    pub fn name(&self) -> &LeaseName {
        &self.name
    }

    pub fn term(&self) -> Term {
        self.term
    }

    /// This device's peer id.
    pub fn holder(&self) -> &str {
        &self.holder
    }

    pub fn is_valid(&self) -> bool {
        Instant::now() < self.valid_until
    }

    pub fn remaining(&self) -> Duration {
        self.valid_until.saturating_duration_since(Instant::now())
    }
}

/// Why a lease was not got or kept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LeaseError {
    /// Someone else holds it; try again after `retry_in`.
    #[error("held by {holder} (term {term}), retry in {retry_in:?}")]
    Held { holder: String, term: Term, retry_in: Duration },
    /// Not enough voters answered with a grant.
    #[error("no quorum: {reached} of {needed} grants")]
    NoQuorum { reached: usize, needed: usize },
    /// The lease ran out before a renewal reached a quorum: stop acting.
    #[error("lease lost")]
    Lost,
    /// This device is not among the voters (only voters stand), or no longer is.
    #[error("not a voter for this lease")]
    NotEligible,
    #[error("{0}")]
    Sync(String),
}

impl From<SyncError> for LeaseError {
    fn from(e: SyncError) -> Self {
        LeaseError::Sync(e.to_string())
    }
}

/// What an [`Elector`] sees.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseState {
    Held {
        term: Term,
    },
    /// Learned from a voter's answer.
    Follower {
        holder: String,
        term: Term,
    },
    /// Nobody known to hold it.
    Vacant,
    NoQuorum {
        reached: usize,
        needed: usize,
    },
}

type SyncNode = Node<Vec<u8>, Vec<u8>>;
type AddrBook = Arc<dyn Fn(&str) -> Vec<Multiaddr> + Send + Sync>;

/// The candidate side: acquires, renews and releases leases through a sync node and its
/// shared state (as served by [`crate::start_node`]). The state's lock is never held across
/// the network.
#[derive(Clone)]
pub struct Leases {
    node: Arc<SyncNode>,
    state: Arc<Mutex<SyncState>>,
    addrs: AddrBook,
    terms: Arc<Mutex<HashMap<LeaseName, Term>>>,
}

enum Answer {
    Grant(Duration),
    Deny(LeaseDeny),
    None,
}

impl Leases {
    pub fn new(node: Arc<SyncNode>, state: Arc<Mutex<SyncState>>) -> Self {
        Self { node, state, addrs: Arc::new(|_| Vec::new()), terms: Arc::default() }
    }

    /// The shared state the leases use.
    pub fn state(&self) -> &Arc<Mutex<SyncState>> {
        &self.state
    }

    /// Addresses to dial each voter on (default none: the node's known addresses).
    pub fn with_addrs(mut self, addrs: impl Fn(&str) -> Vec<Multiaddr> + Send + Sync + 'static) -> Self {
        self.addrs = Arc::new(addrs);
        self
    }

    fn known_term(&self, name: &LeaseName) -> Term {
        let local = self.terms.lock().map(|t| t.get(name).copied().unwrap_or_default()).unwrap_or_default();
        let voted = self.state.lock().ok().and_then(|st| st.voter.as_ref().map(|v| v.max_term(name))).unwrap_or_default();
        local.max(voted)
    }

    fn learn(&self, name: &LeaseName, term: Term) {
        if let Ok(mut t) = self.terms.lock() {
            let e = t.entry(name.clone()).or_default();
            *e = (*e).max(term);
        }
    }

    /// Ask every voter at once (this device's own voter answers locally) and collect answers
    /// until all came, `needed` grants came, or `wait` passed. Unreachable voters can't hold
    /// a round up beyond `wait`; their threads finish on their own.
    fn ask_all(&self, voters: &[String], me: &str, msg: &Message, needed: usize, wait: Duration) -> Vec<Answer> {
        let (tx, rx) = std::sync::mpsc::channel();
        for v in voters {
            let (this, v, me, msg, tx) = (self.clone(), v.clone(), me.to_string(), msg.clone(), tx.clone());
            std::thread::spawn(move || {
                let _ = tx.send(this.ask_one(&v, &me, &msg));
            });
        }
        drop(tx);
        let deadline = Instant::now() + wait;
        let mut out = Vec::new();
        let mut grants = 0;
        while out.len() < voters.len() && grants < needed {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(a) => {
                    if matches!(a, Answer::Grant(_)) {
                        grants += 1;
                    }
                    out.push(a);
                }
                Err(_) => break,
            }
        }
        out
    }

    /// Tell voters to drop a promise, waiting at most `wait` for them.
    fn free_all(&self, voters: &[String], me: &str, free: LeaseFree, wait: Duration) {
        let _ = self.ask_all(voters, me, &Message::LeaseFree(free), usize::MAX, wait);
    }

    fn ask_one(&self, voter: &str, me: &str, msg: &Message) -> Answer {
        let reply = if voter == me {
            match self.state.lock() {
                Ok(mut st) => st.on_lease(me, msg.clone()),
                Err(_) => return Answer::None,
            }
        } else {
            match self.request(voter, msg) {
                Ok(m) => m,
                Err(_) => return Answer::None,
            }
        };
        match reply {
            Message::LeaseGrant(g) => Answer::Grant(Duration::from_millis(g.duration_ms as u64)),
            Message::LeaseDeny(d) => Answer::Deny(d),
            _ => Answer::None,
        }
    }

    fn request(&self, voter: &str, msg: &Message) -> Result<Message> {
        let peer: PeerId = voter.parse().map_err(|_| SyncError::Protocol("bad voter peer id".into()))?;
        // Envelopes are bound to the asking peer (us), as in every other sync request.
        let me = self.node.peer_id().to_string();
        let env = {
            let st = self.state.lock().map_err(|_| SyncError::Protocol("sync state lock poisoned".into()))?;
            let key = st.current_key();
            st.seal_envelope(&key, LEASE_TYPE, &me, msg)?
        };
        let addrs = (self.addrs)(voter);
        let reply = self.node.request(peer, &addrs, encode(&env)?)?;
        let env: crate::protocol::Envelope = decode(&reply)?;
        let st = self.state.lock().map_err(|_| SyncError::Protocol("sync state lock poisoned".into()))?;
        st.open_envelope(&env, &me)
    }

    fn voters(&self, cfg: &LeaseConfig) -> std::result::Result<(String, Vec<String>), LeaseError> {
        let st = self.state.lock().map_err(|_| LeaseError::Sync("sync state lock poisoned".into()))?;
        Ok((st.our_cert.peer_id.clone(), cfg.voters.resolve(&st.roster)))
    }

    fn digest(&self, cfg: &LeaseConfig) -> String {
        self.state.lock().map(|st| cfg.voters.digest(&st.roster)).unwrap_or_default()
    }

    /// Acquire `name` with a new term. Fails with [`LeaseError::Held`] while another
    /// device holds it (with when to try again) or [`LeaseError::NoQuorum`].
    pub fn acquire(&self, name: &LeaseName, cfg: &LeaseConfig) -> std::result::Result<LeaseHandle, LeaseError> {
        let (me, voters) = self.voters(cfg)?;
        let needed = voters.len() / 2 + 1;
        if !voters.contains(&me) {
            return Err(LeaseError::NotEligible);
        }
        let term = self.known_term(name).next();
        let ask = LeaseAsk {
            name: name.clone(),
            term,
            duration_ms: cfg.duration.as_millis().min(u32::MAX as u128) as u32,
            renew: false,
            voters: self.digest(cfg),
        };
        let t0 = Instant::now();
        let answers = self.ask_all(&voters, &me, &Message::LeaseAsk(ask), needed, ask_wait(cfg));
        let granted: Vec<Duration> = answers.iter().filter_map(|a| if let Answer::Grant(d) = a { Some(*d) } else { None }).collect();
        // A term some voter granted is used up; one nobody granted can be asked for again, so
        // retrying while a holder lives doesn't inflate the terms.
        if !granted.is_empty() {
            self.learn(name, term);
        }
        if granted.len() >= needed {
            let handle = LeaseHandle { name: name.clone(), term, holder: me.clone(), valid_until: valid_until(t0, &granted, cfg) };
            if let Some(typ) = &cfg.record_type
                && let Ok(mut st) = self.state.lock()
            {
                let rec = LeaseRecord { name: name.clone(), term, holder: me };
                if let Ok(bytes) = encode(&rec) {
                    let _ = st.write(wall_ms(), typ, name.as_str(), &bytes);
                }
            }
            return Ok(handle);
        }
        // Let go of the grants we did get, so the next candidate needn't wait them out.
        if !granted.is_empty() {
            self.free_all(&voters, &me, LeaseFree { name: name.clone(), term }, Duration::ZERO);
        }
        let denies: Vec<&LeaseDeny> = answers.iter().filter_map(|a| if let Answer::Deny(d) = a { Some(d) } else { None }).collect();
        if let Some(max) = denies.iter().map(|d| d.max_term).max() {
            self.learn(name, max);
        }
        if let Some(d) =
            denies.iter().filter(|d| !d.holder.is_empty() && d.holder != me && d.remaining_ms > 0).max_by_key(|d| (d.promised, d.remaining_ms))
        {
            return Err(LeaseError::Held { holder: d.holder.clone(), term: d.promised, retry_in: Duration::from_millis(d.remaining_ms as u64) });
        }
        Err(LeaseError::NoQuorum { reached: granted.len(), needed })
    }

    /// Renew a held lease (same term). Until it runs out a failed renewal is
    /// [`LeaseError::NoQuorum`] and the handle stays valid; after, [`LeaseError::Lost`].
    pub fn renew(&self, handle: &mut LeaseHandle, cfg: &LeaseConfig) -> std::result::Result<(), LeaseError> {
        let (me, voters) = self.voters(cfg)?;
        let needed = voters.len() / 2 + 1;
        let ask = LeaseAsk {
            name: handle.name.clone(),
            term: handle.term,
            duration_ms: cfg.duration.as_millis().min(u32::MAX as u128) as u32,
            renew: true,
            voters: self.digest(cfg),
        };
        let t0 = Instant::now();
        let answers = self.ask_all(&voters, &me, &Message::LeaseAsk(ask), needed, ask_wait(cfg));
        let granted: Vec<Duration> = answers.iter().filter_map(|a| if let Answer::Grant(d) = a { Some(*d) } else { None }).collect();
        if !voters.contains(&me) {
            return if handle.is_valid() { Err(LeaseError::NotEligible) } else { Err(LeaseError::Lost) };
        }
        if granted.len() >= needed {
            handle.valid_until = handle.valid_until.max(valid_until(t0, &granted, cfg));
            return Ok(());
        }
        for a in &answers {
            if let Answer::Deny(d) = a {
                self.learn(&handle.name, d.max_term);
            }
        }
        if handle.is_valid() { Err(LeaseError::NoQuorum { reached: granted.len(), needed }) } else { Err(LeaseError::Lost) }
    }

    /// Let go of a lease: voters drop the promise, so the next holder needn't wait it out.
    pub fn release(&self, handle: LeaseHandle, cfg: &LeaseConfig) {
        if let Ok((me, voters)) = self.voters(cfg) {
            self.free_all(&voters, &me, LeaseFree { name: handle.name.clone(), term: handle.term }, ask_wait(cfg));
        }
    }

    /// Keep acquiring and renewing `name` in the background (see [`Elector`]).
    pub fn elect(&self, name: LeaseName, cfg: LeaseConfig) -> Elector {
        Elector::start(self.clone(), name, cfg)
    }
}

/// How long a round waits for answers: a third of the lease, so a lease got is still worth
/// most of its duration.
fn ask_wait(cfg: &LeaseConfig) -> Duration {
    (cfg.duration / 3).max(Duration::from_millis(100))
}

fn valid_until(t0: Instant, granted: &[Duration], cfg: &LeaseConfig) -> Instant {
    let shortest = granted.iter().min().copied().unwrap_or_default().min(cfg.duration);
    let safe = shortest.mul_f64(1.0 - cfg.max_drift).saturating_sub(EPSILON);
    t0 + safe
}

/// A random wait in `[0, max)`.
fn jitter(max: Duration) -> Duration {
    let mut b = [0u8; 8];
    if max.is_zero() || getrandom::fill(&mut b).is_err() {
        return Duration::ZERO;
    }
    let ms = max.as_millis().max(1) as u64;
    Duration::from_millis(u64::from_le_bytes(b) % ms)
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

struct Shared {
    state: Mutex<(LeaseState, Option<LeaseHandle>)>,
    changed: Condvar,
    stop: AtomicBool,
}

/// Acquires and renews one lease in a background thread. No preemption: a live holder keeps
/// it; after a lapse the lowest-ranked candidate tries first. Dropping it (or
/// [`release`](Self::release)) lets go.
pub struct Elector {
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Elector {
    fn start(leases: Leases, name: LeaseName, cfg: LeaseConfig) -> Self {
        let shared = Arc::new(Shared { state: Mutex::new((LeaseState::Vacant, None)), changed: Condvar::new(), stop: AtomicBool::new(false) });
        let s = shared.clone();
        let thread =
            std::thread::Builder::new().name(format!("lease {name}")).spawn(move || run_elector(leases, name, cfg, s)).expect("spawn lease thread");
        Self { shared, thread: Some(thread) }
    }

    pub fn state(&self) -> LeaseState {
        self.shared.state.lock().map(|s| s.0.clone()).unwrap_or(LeaseState::Vacant)
    }

    /// The lease while held and valid.
    pub fn handle(&self) -> Option<LeaseHandle> {
        self.shared.state.lock().ok().and_then(|s| s.1.clone()).filter(|h| h.is_valid())
    }

    /// Wait until `want` holds for the state, at most `timeout`. Returns the state then.
    pub fn wait_for(&self, timeout: Duration, want: impl Fn(&LeaseState) -> bool) -> LeaseState {
        let deadline = Instant::now() + timeout;
        let mut g = match self.shared.state.lock() {
            Ok(g) => g,
            Err(_) => return LeaseState::Vacant,
        };
        while !want(&g.0) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            g = match self.shared.changed.wait_timeout(g, left) {
                Ok((g, _)) => g,
                Err(_) => return LeaseState::Vacant,
            };
        }
        g.0.clone()
    }

    /// Stop and let go of the lease.
    pub fn release(mut self) {
        self.stop_now();
    }

    fn stop_now(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.changed.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Elector {
    fn drop(&mut self) {
        self.stop_now();
    }
}

fn set(shared: &Shared, state: LeaseState, handle: Option<LeaseHandle>) {
    if let Ok(mut g) = shared.state.lock() {
        *g = (state, handle);
    }
    shared.changed.notify_all();
}

fn sleep(shared: &Shared, d: Duration) {
    let deadline = Instant::now() + d;
    while !shared.stop.load(Ordering::SeqCst) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

fn run_elector(leases: Leases, name: LeaseName, cfg: LeaseConfig, shared: Arc<Shared>) {
    let mut held: Option<LeaseHandle> = None;
    while !shared.stop.load(Ordering::SeqCst) {
        let (me, voters) = match leases.voters(&cfg) {
            Ok(v) => v,
            Err(_) => return,
        };
        let rank = voters.iter().position(|v| *v == me).unwrap_or(voters.len()) as u32;
        if let Some(h) = held.as_mut() {
            sleep(&shared, cfg.renew_every.min(h.remaining()));
            if shared.stop.load(Ordering::SeqCst) {
                break;
            }
            match leases.renew(h, &cfg) {
                Ok(()) => set(&shared, LeaseState::Held { term: h.term }, Some(h.clone())),
                Err(LeaseError::NoQuorum { .. }) if h.is_valid() => {}
                Err(_) => {
                    held = None;
                    set(&shared, LeaseState::Vacant, None);
                }
            }
            continue;
        }
        match leases.acquire(&name, &cfg) {
            Ok(h) => {
                set(&shared, LeaseState::Held { term: h.term }, Some(h.clone()));
                held = Some(h);
            }
            Err(LeaseError::Held { holder, term, retry_in }) => {
                set(&shared, LeaseState::Follower { holder, term }, None);
                sleep(&shared, retry_in.min(cfg.duration) + cfg.stagger * rank + jitter(cfg.stagger));
            }
            Err(LeaseError::NoQuorum { reached, needed }) => {
                // Two candidates that split the votes back off by rank plus a random part, so
                // they don't keep colliding.
                set(&shared, LeaseState::NoQuorum { reached, needed }, None);
                let base = (cfg.stagger * (rank + 1)).min(cfg.renew_every.max(Duration::from_millis(50)));
                sleep(&shared, base + jitter(cfg.stagger * 2));
            }
            Err(_) => {
                set(&shared, LeaseState::Vacant, None);
                sleep(&shared, cfg.renew_every.max(Duration::from_millis(50)));
            }
        }
    }
    if let Some(h) = held {
        leases.release(h, &cfg);
    }
    set(&shared, LeaseState::Vacant, None);
}

/// Resource side: refuses commands that carry an older term than one already seen. Persist
/// [`export`](Self::export) so a restart keeps refusing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FenceGuard {
    seen: HashMap<LeaseName, Term>,
}

/// A command from an older term than the guard has seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("stale term: {seen} already seen")]
pub struct Stale {
    pub seen: Term,
}

impl FenceGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts `term` if it is at least the highest seen (and records it).
    pub fn check(&mut self, name: &LeaseName, term: Term) -> std::result::Result<(), Stale> {
        let seen = self.seen.entry(name.clone()).or_default();
        if term < *seen {
            return Err(Stale { seen: *seen });
        }
        *seen = term;
        Ok(())
    }

    pub fn seen(&self, name: &LeaseName) -> Option<Term> {
        self.seen.get(name).copied()
    }

    pub fn export(&self) -> Vec<u8> {
        let mut v: Vec<_> = self.seen.iter().map(|(n, t)| (n.clone(), *t)).collect();
        v.sort();
        encode(&v).unwrap_or_default()
    }

    pub fn import(bytes: &[u8]) -> Result<Self> {
        let v: Vec<(LeaseName, Term)> = decode(bytes)?;
        Ok(Self { seen: v.into_iter().collect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> LeaseName {
        LeaseName::new(s).unwrap()
    }

    fn ask(n: &str, term: u64, renew: bool) -> LeaseAsk {
        LeaseAsk { name: name(n), term: Term(term), duration_ms: 1_000, renew, voters: String::new() }
    }

    fn fresh() -> Voter {
        let mut v = Voter::new(Voters::Peers(vec![])).with_max_duration(Duration::from_secs(1));
        v.grace_until = Instant::now() - Duration::from_secs(1);
        v
    }

    #[test]
    fn a_voter_promises_one_holder_at_a_time() {
        let mut v = fresh();
        let t = Instant::now();
        assert!(matches!(v.on_ask("a", &ask("s", 1, false), t), Message::LeaseGrant(_)));
        // Another candidate, even with a higher term, waits for the promise to end.
        let Message::LeaseDeny(d) = v.on_ask("b", &ask("s", 2, false), t + Duration::from_millis(10)) else { panic!() };
        assert_eq!((d.holder.as_str(), d.promised, d.max_term), ("a", Term(1), Term(1)));
        assert!(d.remaining_ms > 900);
        // The holder renews; b still can't.
        assert!(matches!(v.on_ask("a", &ask("s", 1, true), t + Duration::from_millis(500)), Message::LeaseGrant(_)));
        assert!(matches!(v.on_ask("b", &ask("s", 2, false), t + Duration::from_millis(1_200)), Message::LeaseDeny(_)));
        // After it lapses b takes over with a higher term, never the same or a lower one.
        let later = t + Duration::from_millis(1_600);
        assert!(matches!(v.on_ask("b", &ask("s", 1, false), later), Message::LeaseDeny(_)));
        assert!(matches!(v.on_ask("b", &ask("s", 2, false), later), Message::LeaseGrant(_)));
        // a's renewal of the old term is refused now.
        assert!(matches!(v.on_ask("a", &ask("s", 1, true), later), Message::LeaseDeny(_)));
        // Release lets the next one in at once.
        v.on_free("b", &LeaseFree { name: name("s"), term: Term(2) });
        assert!(matches!(v.on_ask("a", &ask("s", 3, false), later), Message::LeaseGrant(_)));
        // Durations are capped.
        let mut long = ask("t", 1, false);
        long.duration_ms = 600_000;
        let Message::LeaseGrant(g) = v.on_ask("a", &long, later) else { panic!() };
        assert_eq!(g.duration_ms, 1_000);
    }

    #[test]
    fn a_restarted_voter_refuses_takeovers_for_one_duration_and_keeps_its_terms() {
        let mut v = fresh();
        let t = Instant::now();
        v.on_ask("a", &ask("s", 4, false), t);
        let bytes = v.export();
        let mut back = Voter::import(&bytes, Voters::Peers(vec![])).unwrap().with_max_duration(Duration::from_secs(1));
        assert_eq!(back.max_term(&name("s")), Term(4));
        let now = Instant::now();
        // b can't take over during the grace, a can renew the term it holds.
        let Message::LeaseDeny(d) = back.on_ask("b", &ask("s", 5, false), now) else { panic!() };
        assert_eq!(d.holder, "a");
        assert!(d.remaining_ms > 0);
        assert!(matches!(back.on_ask("a", &ask("s", 4, true), now), Message::LeaseGrant(_)));
        // A new lease name is refused during the grace too.
        assert!(matches!(back.on_ask("b", &ask("other", 1, false), now), Message::LeaseDeny(_)));
    }

    #[test]
    fn a_new_term_is_stored_before_it_is_granted() {
        use std::sync::atomic::AtomicUsize;
        let writes = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let (w, f) = (writes.clone(), fail.clone());
        let mut v = fresh().with_persist(move |bytes| {
            if f.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("disk full"));
            }
            assert!(Voter::import(bytes, Voters::Peers(vec![])).is_ok());
            w.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let t = Instant::now();
        assert!(matches!(v.on_ask("a", &ask("s", 1, false), t), Message::LeaseGrant(_)));
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        // Renewals write nothing.
        assert!(matches!(v.on_ask("a", &ask("s", 1, true), t), Message::LeaseGrant(_)));
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        // A term that can't be stored is not granted, and leaves no trace.
        fail.store(true, Ordering::SeqCst);
        let later = t + Duration::from_secs(2);
        assert!(matches!(v.on_ask("b", &ask("s", 2, false), later), Message::LeaseDeny(_)));
        assert_eq!(v.max_term(&name("s")), Term(1));
        fail.store(false, Ordering::SeqCst);
        assert!(matches!(v.on_ask("b", &ask("s", 2, false), later), Message::LeaseGrant(_)));
        assert_eq!(writes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_fence_refuses_older_terms() {
        let mut g = FenceGuard::new();
        let n = name("ymir.scheduler");
        g.check(&n, Term(3)).unwrap();
        g.check(&n, Term(3)).unwrap();
        assert_eq!(g.check(&n, Term(2)), Err(Stale { seen: Term(3) }));
        g.check(&n, Term(4)).unwrap();
        let back = FenceGuard::import(&g.export()).unwrap();
        assert_eq!(back.seen(&n), Some(Term(4)));
    }

    #[test]
    fn names_are_checked_and_the_holder_stops_before_any_voter() {
        assert!(LeaseName::new("ymir.jobs/42").is_ok());
        assert!(LeaseName::new("").is_err());
        assert!(LeaseName::new("bad name").is_err());
        assert!(LeaseName::new("x".repeat(201)).is_err());
        let cfg = LeaseConfig::for_role("r");
        let t0 = Instant::now();
        let until = valid_until(t0, &[Duration::from_secs(15), Duration::from_secs(10)], &cfg);
        assert!(until < t0 + Duration::from_millis(9_900) && until > t0 + Duration::from_millis(9_800));
        assert_eq!((cfg.duration, cfg.renew_every, cfg.stagger, cfg.max_drift), (DEFAULT_DURATION, DEFAULT_RENEW_EVERY, DEFAULT_STAGGER, 0.01));
    }

    #[test]
    fn skewed_clock_rates_within_the_drift_never_overlap_two_holders() {
        // The holder counts from before it sent the ask, the voter from when it got it. With
        // clock rates up to half the drift apart either way, the holder's lease (in real time)
        // ends before the voter's promise does, so a takeover can't overlap it.
        let cfg = LeaseConfig::for_role("r");
        let t0 = Instant::now();
        let safe = valid_until(t0, &[cfg.duration], &cfg) - t0;
        let half = cfg.max_drift / 2.0;
        for (holder_rate, voter_rate) in [(1.0 - half, 1.0 + half), (1.0, 1.0 + cfg.max_drift - 1e-9), (1.0 + half, 1.0 - half), (1.0, 1.0)] {
            let holder_real = safe.as_secs_f64() / holder_rate;
            let voter_real = cfg.duration.as_secs_f64() / voter_rate;
            assert!(holder_real < voter_real, "holder {holder_rate} voter {voter_rate}: {holder_real} >= {voter_real}");
        }
        // Wall clocks play no part: a lease is the same however far apart they are.
        assert_eq!(valid_until(t0, &[cfg.duration], &cfg), t0 + safe);
    }
}
