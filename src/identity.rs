//! This device's place in the user's Weirdnet: the user identity, its own node key and
//! certificate, and the linked-devices roster it shares with the user's other devices (Morph,
//! Ymir, Bragi, …), kept current by sync passes.
//!
//! An [`Identity`] lives in one directory (0700 on Unix), secrets in 0600 files:
//!
//! - `seed`: the user key seed, which a device link delivers;
//! - `node.key`: this node's key (libp2p protobuf encoding);
//! - `keys`: the epoch keys ([`EpochKeys::export`]);
//! - `roster.json`: the public roster, in the format Morph links with.
//!
//! The files are plain, not sealed. Apps that keep secrets in the OS keystore should hold
//! [`SyncState`] themselves until this store grows a keystore backend.
//!
//! Each identity announces one sync type (`ymir.pool`, `bragi.app`, …). [`Identity::tick`] runs
//! a pass of that type against every other active device with [`pull_from_shared`], so devices
//! linked or revoked elsewhere reach this one even when the type carries no records yet: the
//! roster and the key chain ride along with every pass.
//!
//! ```no_run
//! # fn main() -> weirdnet_sync::Result<()> {
//! use weirdnet_sync::identity::Identity;
//! let dir = std::path::Path::new("/tmp/example-identity");
//! let me = match Identity::open(dir, "example.app")? {
//!     Some(me) => me,
//!     None => Identity::create(dir, "my laptop", "example.app")?,
//! };
//! println!("{} on {}", me.user_id(), me.peer_id());
//! # Ok(()) }
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use weirdnet_net::user::NodeCert;
use weirdnet_net::{Keypair, Multiaddr, Node, PeerId, PublicKey, WEIRDNET};

use crate::net::{SyncState, pull_from_shared};
use crate::roster::Roster;
use crate::rotation::{Device, EpochKeys};
use crate::{NodeId, OpLog, Result, SyncError};

/// What a link transfer carries besides the identity: the roster, in Morph's format, so any two
/// Weirdnet apps can link each other.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LinkSettings {
    #[serde(default)]
    pub roster: Roster,
}

/// The node type sync passes run on.
pub type SyncNode = Node<Vec<u8>, Vec<u8>>;

/// What one [`Identity::tick`] did.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Tick {
    /// Devices a pass finished against.
    pub reached: usize,
    /// New log entries stored, over all devices.
    pub applied: usize,
    /// Devices a pass did not finish against (peer id) and why.
    pub failed: Vec<(String, SyncError)>,
}

/// The user identity, this node's key and certificate, and the roster, stored in a directory.
pub struct Identity {
    dir: PathBuf,
    node_key: Keypair,
    sync_type: String,
    state: Arc<Mutex<SyncState>>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the seed or keys.
        f.debug_struct("Identity").field("dir", &self.dir).field("peer_id", &self.peer_id()).field("sync_type", &self.sync_type).finish()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn err(msg: impl Into<String>) -> SyncError {
    SyncError::Identity(msg.into())
}

fn io(what: &str, path: &Path, e: std::io::Error) -> SyncError {
    SyncError::Io(format!("{what} {}: {e}", path.display()))
}

/// The user key from its 32-byte seed.
fn user_from_seed(seed: &[u8]) -> Result<Keypair> {
    let mut bytes: [u8; 32] = seed.try_into().map_err(|_| err("the identity seed is not 32 bytes"))?;
    Keypair::ed25519_from_bytes(&mut bytes).map_err(|e| err(format!("identity seed: {e}")))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|e| io("writing", &tmp, e))?;
        f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| io("writing", &tmp, e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| io("writing", path, e))
}

fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| io("creating", dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| io("securing", dir, e))?;
    }
    Ok(())
}

impl Identity {
    /// Whether `dir` holds an identity.
    pub fn exists(dir: &Path) -> bool {
        dir.join("seed").is_file() && dir.join("node.key").is_file()
    }

    /// A new Weirdnet user identity with this device as its first node, announcing `sync_type`.
    /// To join the user's existing devices, link from one of them and [`Identity::adopt`].
    /// Never overwrites an identity.
    pub fn create(dir: &Path, label: &str, sync_type: impl Into<String>) -> Result<Self> {
        if Self::exists(dir) {
            return Err(err(format!("{} already holds an identity", dir.display())));
        }
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| err(format!("random seed: {e}")))?;
        let user = user_from_seed(&seed)?;
        let node_key = Keypair::generate_ed25519();
        let cert = Roster::self_certify(&WEIRDNET, &user, &node_key.public().to_peer_id().to_string(), label, now_ms())
            .map_err(|e| err(format!("certifying this node: {e}")))?;
        let mut roster = Roster::new();
        roster.upsert(cert.clone());
        let me = Self::build(dir, seed.to_vec(), node_key, cert, roster, EpochKeys::default(), sync_type.into())?;
        me.save()?;
        Ok(me)
    }

    /// The identity a device link delivered: `seed`, the node certificate the existing device
    /// made for `node_key`, and its [`LinkSettings`] (JSON; empty or unreadable means none).
    pub fn adopt(dir: &Path, node_key: Keypair, seed: &[u8], cert: NodeCert, settings: &str, sync_type: impl Into<String>) -> Result<Self> {
        if Self::exists(dir) {
            return Err(err(format!("{} already holds an identity", dir.display())));
        }
        let user = user_from_seed(seed)?;
        let peer = node_key.public().to_peer_id().to_string();
        if cert.peer_id != peer || cert.user_id != weirdnet_net::user::user_id(&user.public()) || !WEIRDNET.verify_cert(&user.public(), &cert) {
            return Err(err("the link's certificate is not for this node and identity"));
        }
        let given: LinkSettings = serde_json::from_str(settings).unwrap_or_default();
        let mut roster = Roster::new();
        roster.merge(&given.roster, &user.public(), &WEIRDNET);
        roster.upsert(cert.clone());
        let me = Self::build(dir, seed.to_vec(), node_key, cert, roster, EpochKeys::default(), sync_type.into())?;
        me.save()?;
        Ok(me)
    }

    /// The identity stored in `dir`, if any, announcing `sync_type`.
    pub fn open(dir: &Path, sync_type: impl Into<String>) -> Result<Option<Self>> {
        if !Self::exists(dir) {
            return Ok(None);
        }
        let seed_path = dir.join("seed");
        let seed = std::fs::read(&seed_path).map_err(|e| io("reading", &seed_path, e))?;
        let key_path = dir.join("node.key");
        let node_key = Keypair::from_protobuf_encoding(&std::fs::read(&key_path).map_err(|e| io("reading", &key_path, e))?)
            .map_err(|e| err(format!("node key: {e}")))?;
        let roster: Roster = match std::fs::read(dir.join("roster.json")) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| err(format!("roster.json: {e}")))?,
            Err(_) => Roster::new(),
        };
        let keys = std::fs::read(dir.join("keys")).ok().and_then(|b| EpochKeys::import(&b).ok()).unwrap_or_default();
        let peer = node_key.public().to_peer_id().to_string();
        let cert = roster.get(&peer).cloned().ok_or_else(|| err("the roster has no certificate for this node"))?;
        Self::build(dir, seed, node_key, cert, roster, keys, sync_type.into()).map(Some)
    }

    fn build(dir: &Path, seed: Vec<u8>, node_key: Keypair, our_cert: NodeCert, roster: Roster, keys: EpochKeys, sync_type: String) -> Result<Self> {
        ensure_dir(dir)?;
        let user = user_from_seed(&seed)?;
        let mut st = SyncState {
            user_id: our_cert.user_id.clone(),
            user_key: user.public(),
            our_node: NodeId::new(our_cert.peer_id.clone()),
            our_cert,
            seed,
            types: vec![sync_type.clone()],
            roster,
            log: OpLog::new(),
            clock: None,
            device: Device::from_node_key(&node_key).ok(),
            keys,
            auto_first_rotation: true,
            records: Default::default(),
        };
        st.publish_device_key(now_ms())?;
        st.refresh_keys();
        Ok(Self { dir: dir.to_path_buf(), node_key, sync_type, state: Arc::new(Mutex::new(st)) })
    }

    fn lock(&self) -> MutexGuard<'_, SyncState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Writes the roster and keys (and, the first time, the seed and node key).
    pub fn save(&self) -> Result<()> {
        ensure_dir(&self.dir)?;
        let (seed, roster, keys) = {
            let st = self.lock();
            let roster = serde_json::to_vec_pretty(&st.roster).map_err(|e| err(format!("roster.json: {e}")))?;
            (st.seed.clone(), roster, st.keys.export())
        };
        if !self.dir.join("seed").is_file() {
            write_private(&self.dir.join("seed"), &seed)?;
        }
        if !self.dir.join("node.key").is_file() {
            let key = self.node_key.to_protobuf_encoding().map_err(|e| err(format!("node key: {e}")))?;
            write_private(&self.dir.join("node.key"), &key)?;
        }
        write_private(&self.dir.join("roster.json"), &roster)?;
        write_private(&self.dir.join("keys"), &keys)
    }

    /// The directory it is stored in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The sync type it announces.
    pub fn sync_type(&self) -> &str {
        &self.sync_type
    }

    pub fn node_key(&self) -> &Keypair {
        &self.node_key
    }

    pub fn peer_id(&self) -> PeerId {
        self.node_key.public().to_peer_id()
    }

    /// The shared sync state, for a [`crate::SyncHandler`] answering peers that pull from here.
    pub fn state(&self) -> Arc<Mutex<SyncState>> {
        self.state.clone()
    }

    pub fn user_key(&self) -> PublicKey {
        self.lock().user_key.clone()
    }

    pub fn user_id(&self) -> String {
        self.lock().user_id.clone()
    }

    pub fn our_cert(&self) -> NodeCert {
        self.lock().our_cert.clone()
    }

    pub fn roster(&self) -> Roster {
        self.lock().roster.clone()
    }

    /// The roster as it is now, for callers that check peers later (an inference server's
    /// roster check, the pool's linked nodes).
    pub fn roster_view(&self) -> Arc<dyn Fn() -> Roster + Send + Sync> {
        let st = self.state.clone();
        Arc::new(move || st.lock().unwrap_or_else(|e| e.into_inner()).roster.clone())
    }

    /// The [`LinkSettings`] payload (JSON) for a device linked from here.
    pub fn link_settings(&self) -> String {
        serde_json::to_string(&LinkSettings { roster: self.roster() }).unwrap_or_else(|_| "{}".into())
    }

    /// The seed, for a device link sent from here.
    pub fn seed(&self) -> Result<weirdnet_net::Key32> {
        weirdnet_net::Key32::from_slice(&self.lock().seed).map_err(|e| err(format!("identity seed: {e}")))
    }

    /// The user linked `cert`'s device from here: it joins the roster (and the key chain once
    /// its device key is known), and the roster is saved.
    pub fn approve(&self, cert: NodeCert) -> Result<()> {
        self.lock().approve(cert, now_ms())?;
        self.save()
    }

    /// Revokes a device everywhere this roster reaches (and rotates the keys), then saves.
    /// This node's own certificate can't be revoked here.
    pub fn revoke(&self, peer: &str) -> Result<NodeCert> {
        let cert = {
            let mut st = self.lock();
            if peer == st.our_cert.peer_id {
                return Err(err("this is this node's own certificate"));
            }
            let user = user_from_seed(&st.seed)?;
            st.revoke(&user, peer, now_ms())?
        };
        self.save()?;
        Ok(cert)
    }

    /// One sync pass of [`Identity::sync_type`] against every other active device in the roster,
    /// then a save. Blocking; call it from a blocking task. `addrs` gives the addresses to dial a
    /// device at. Each pull goes into a snapshot that is merged back
    /// ([`pull_from_shared`]), so a handler on the same state can answer a peer pulling from
    /// here at the same moment. Errors only if saving fails.
    pub fn tick(&self, node: &SyncNode, addrs: &dyn Fn(&NodeCert) -> Vec<Multiaddr>) -> Result<Tick> {
        let me = node.peer_id().to_string();
        let peers: Vec<NodeCert> = self.lock().roster.active().filter(|c| c.peer_id != me).cloned().collect();
        let mut tick = Tick::default();
        for cert in peers {
            let Ok(peer) = PeerId::from_str(&cert.peer_id) else { continue };
            let out = pull_from_shared(&self.state, node, peer, &addrs(&cert), &self.sync_type);
            tick.applied += out.applied;
            match out.error {
                None => tick.reached += 1,
                Some(e) => tick.failed.push((cert.peer_id.clone(), e)),
            }
        }
        self.save()?;
        Ok(tick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CallerCheck;

    const TYPE: &str = "test.app";

    #[test]
    fn create_open_link_and_revoke() {
        let tmp = tempfile::tempdir().unwrap();
        let a_dir = tmp.path().join("a");
        let a = Identity::create(&a_dir, "box-a", TYPE).unwrap();
        assert!(Identity::create(&a_dir, "again", TYPE).is_err(), "never overwrites an identity");
        assert_eq!(a.sync_type(), TYPE);
        assert_eq!(a.state().lock().unwrap().types, [TYPE]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["seed", "node.key", "keys", "roster.json"] {
                assert_eq!(std::fs::metadata(a_dir.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
            }
            assert_eq!(std::fs::metadata(&a_dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert!(!format!("{a:?}").contains("seed:"), "Debug shows no secrets");

        // Link a second device the way a device link does: a cert from the seed holder.
        let b_key = Keypair::generate_ed25519();
        let user = user_from_seed(&a.seed().unwrap().0).unwrap();
        let b_cert = Roster::self_certify(&WEIRDNET, &user, &b_key.public().to_peer_id().to_string(), "box-b", now_ms()).unwrap();
        a.approve(b_cert.clone()).unwrap();
        let (seed, settings) = (a.seed().unwrap(), a.link_settings());
        let wrong_key = Keypair::generate_ed25519();
        assert!(Identity::adopt(&tmp.path().join("x"), wrong_key, &seed.0, b_cert.clone(), &settings, TYPE).is_err(), "cert for another node");
        let b = Identity::adopt(&tmp.path().join("b"), b_key, &seed.0, b_cert.clone(), &settings, "other.app").unwrap();
        assert_eq!(b.user_id(), a.user_id());
        let a_peer = a.peer_id().to_string();
        let b_peer = b.peer_id().to_string();
        assert_eq!(b.roster().check_caller(&WEIRDNET, &b.user_key(), &a_peer, None), CallerCheck::Linked);
        assert_eq!(a.roster().check_caller(&WEIRDNET, &a.user_key(), &b_peer, Some(&b_cert)), CallerCheck::Linked);

        // A stranger with another identity is not admitted.
        let c = Identity::create(&tmp.path().join("c"), "stranger", TYPE).unwrap();
        assert_eq!(a.roster().check_caller(&WEIRDNET, &a.user_key(), &c.peer_id().to_string(), Some(&c.our_cert())), CallerCheck::WrongUser);

        // Reopening keeps the roster; revoking sticks.
        assert!(Identity::open(&tmp.path().join("none"), TYPE).unwrap().is_none());
        let again = Identity::open(&a_dir, TYPE).unwrap().unwrap();
        assert_eq!(again.peer_id(), a.peer_id());
        again.revoke(&b_peer).unwrap();
        let reopened = Identity::open(&a_dir, TYPE).unwrap().unwrap();
        assert_eq!(reopened.roster().check_caller(&WEIRDNET, &reopened.user_key(), &b_peer, None), CallerCheck::Revoked);
        assert!(reopened.revoke(&a_peer).is_err());
        assert!((reopened.roster_view())().get(&b_peer).is_some_and(|c| !c.active()));
    }

    /// A links B; B links C. One tick on A (against B, over memory nodes) teaches A about C.
    #[test]
    fn tick_brings_devices_linked_elsewhere() {
        use crate::net::{node_config, start_node};
        let tmp = tempfile::tempdir().unwrap();
        let a = Identity::create(&tmp.path().join("a"), "a", TYPE).unwrap();
        let user = user_from_seed(&a.seed().unwrap().0).unwrap();
        let link = |from: &Identity, name: &str| {
            let key = Keypair::generate_ed25519();
            let cert = Roster::self_certify(&WEIRDNET, &user, &key.public().to_peer_id().to_string(), name, now_ms()).unwrap();
            from.approve(cert.clone()).unwrap();
            Identity::adopt(&tmp.path().join(name), key, &from.seed().unwrap().0, cert, &from.link_settings(), TYPE).unwrap()
        };
        let b = link(&a, "b");
        let c = link(&b, "c");
        let c_peer = c.peer_id().to_string();
        assert!(a.roster().get(&c_peer).is_none());

        let node_a = start_node(a.node_key().clone(), node_config(true), a.state()).unwrap();
        let node_b = start_node(b.node_key().clone(), node_config(true), b.state()).unwrap();
        let b_addrs: Vec<Multiaddr> = node_b.reachable_addrs().into_iter().map(|s| s.parse().unwrap()).collect();
        let b_peer = b.peer_id().to_string();
        let tick = a.tick(&node_a, &|cert| if cert.peer_id == b_peer { b_addrs.clone() } else { Vec::new() }).unwrap();
        assert_eq!((tick.reached, tick.failed.len()), (1, 0), "{:?}", tick.failed);
        assert!(a.roster().get(&c_peer).is_some_and(|c| c.active()), "A learned C");
        let saved = Identity::open(a.dir(), TYPE).unwrap().unwrap();
        assert!(saved.roster().get(&c_peer).is_some(), "the tick saved the roster");
    }
}
