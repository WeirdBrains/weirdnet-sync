//! Real key rotation: random epoch keys sealed to each remaining device.
//!
//! Every device holds the identity seed, so a seed-derived key can never shut a revoked
//! device out. A rotation therefore makes a fresh random epoch key and seals one copy to
//! each remaining device's exchange key (X25519, derived from its node key). The sealed
//! copies travel in the roster ([`Roster::chain`]). A device that is not a recipient,
//! revoked or restored from the seed alone, cannot open the new key; a restored device
//! is let back in by an [`Admission`] from a device that holds the key.
//!
//! Rules (all checked on every device, so they converge):
//!
//! - A [`DeviceKey`] is signed by the device's own node key, so no other device (even
//!   one holding the user key) can swap in its own exchange key.
//! - A [`Rotation`] is signed by its creator's node key. It is valid when the creator has
//!   an active cert and is a member of the parent rotation, and its epoch is the parent's
//!   plus one. A root (no parent) is valid when its creator is a member of it. A
//!   revoked creator's rotations count only when an active device built on them, so a
//!   chain started by a device revoked later lives on, and whatever a revoked device
//!   makes on its own drops out.
//! - Once a device holds a key from a root it keeps that root ([`KeyChain::root`]); a
//!   later root from someone holding only the seed is ignored. Two devices can each
//!   start a root before they know of each other; a root whose creator is a member of
//!   the chain a device follows is trusted, and the earliest trusted root wins. A
//!   device in both chains admits the devices it approved into both, so they merge.
//! - The members of a rotation are its recipients plus devices admitted to it by a
//!   member. The head is the valid rotation with the highest epoch, then one with no
//!   revoked member, then the lowest id. A head with a revoked member needs another
//!   rotation; [`crate::pull_from`] makes it.
use crate::error::{Result, SyncError};
use crate::net::SyncState;
use crate::protocol::{decode, encode};
use crate::roster::Roster;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use weirdnet_keys::exchange::{self, ExchangeSecret};
use weirdnet_keys::mac::HmacSha256;
use weirdnet_keys::{Key32, Sealed, kdf, open, seal};
use weirdnet_net::profile::WEIRDNET;
use weirdnet_net::user::NodeCert;
use weirdnet_net::{Keypair, PeerId, PublicKey};
use zeroize::{Zeroize, Zeroizing};

const DEVICE_KEY: &str = "weirdnet-sync/v1/device-key";
const ROTATION: &str = "weirdnet-sync/v1/rotation";
const ADMISSION: &str = "weirdnet-sync/v1/admission";
const SEAL_KEY: &[u8] = b"weirdnet-sync/v1/seal-key";
const SEAL_SAS: &[u8] = b"weirdnet-sync/v1/seal-sas";

/// The node public key inside an Ed25519 (identity-multihash) peer id.
pub fn peer_public(peer: &str) -> Option<PublicKey> {
    let pid: PeerId = peer.parse().ok()?;
    let bytes = pid.to_bytes();
    if bytes.len() < 2 || bytes[0] != 0 || bytes.len() != 2 + bytes[1] as usize {
        return None;
    }
    let key = PublicKey::try_decode_protobuf(&bytes[2..]).ok()?;
    (key.to_peer_id() == pid).then_some(key)
}

fn hash_hex(domain: &[u8], data: &[u8], n: usize) -> String {
    let mut h = HmacSha256::new(domain);
    h.update(data);
    hex::encode(&h.finalize()[..n])
}

fn key_check(key: &Key32) -> String {
    let mut h = HmacSha256::new(&key.0);
    h.update(b"weirdnet-sync/v1/key-check");
    hex::encode(&h.finalize()[..16])
}

fn crypto(msg: impl Into<String>) -> SyncError {
    SyncError::Crypto(msg.into())
}

/// A device's public exchange key, signed by the device's node key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKey {
    pub peer_id: String,
    /// X25519 public key, hex.
    pub exchange: String,
    pub at_ms: i64,
    pub sig: Vec<u8>,
}

impl DeviceKey {
    fn signing_bytes(peer: &str, exchange: &str, at: i64) -> Vec<u8> {
        format!("{DEVICE_KEY}\n{peer}\n{exchange}\n{at}").into_bytes()
    }

    /// The signature is the device's own and the key is well formed.
    pub fn verify(&self) -> bool {
        self.public().is_some()
            && peer_public(&self.peer_id).is_some_and(|k| k.verify(&Self::signing_bytes(&self.peer_id, &self.exchange, self.at_ms), &self.sig))
    }

    pub fn public(&self) -> Option<[u8; 32]> {
        hex::decode(&self.exchange).ok()?.try_into().ok()
    }

    /// A short code to compare on both screens before re-admitting a device.
    pub fn fingerprint(&self) -> String {
        let h = hash_hex(b"weirdnet-sync/v1/fingerprint", format!("{}|{}", self.peer_id, self.exchange).as_bytes(), 6);
        format!("{}-{}-{}", &h[..4], &h[4..8], &h[8..])
    }
}

/// This device's signing and exchange secrets. The exchange secret is derived from the
/// node key, so nothing new has to be stored.
pub struct Device {
    node: Keypair,
    exchange: ExchangeSecret,
}

impl Clone for Device {
    fn clone(&self) -> Self {
        Self { node: self.node.clone(), exchange: ExchangeSecret::from_bytes(*self.exchange.to_bytes()) }
    }
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Device({})", self.peer_id())
    }
}

impl Device {
    pub fn from_node_key(node: &Keypair) -> Result<Self> {
        let bytes = Zeroizing::new(node.to_protobuf_encoding().map_err(|e| crypto(format!("node key: {e}")))?);
        let k = kdf::hkdf(&bytes, Some(b"weirdnet-sync/v1"), b"weirdnet-sync/v1/exchange")?;
        Ok(Self { node: node.clone(), exchange: ExchangeSecret::from_bytes(k.0) })
    }

    pub fn peer_id(&self) -> String {
        self.node.public().to_peer_id().to_string()
    }

    pub fn device_key(&self, at_ms: i64) -> Result<DeviceKey> {
        let peer = self.peer_id();
        let exchange = hex::encode(self.exchange.public());
        let sig = self.sign(&DeviceKey::signing_bytes(&peer, &exchange, at_ms))?;
        Ok(DeviceKey { peer_id: peer, exchange, at_ms, sig })
    }

    pub(crate) fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.node.sign(bytes).map_err(|e| crypto(format!("sign: {e}")))
    }
}

/// One recipient's copy of an epoch key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedKey {
    pub peer_id: String,
    pub sealed: Sealed,
}

/// A new random epoch key, sealed to each remaining device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rotation {
    pub epoch: u32,
    /// The rotation this one replaces; `None` for the first one (out of seed-derived keys).
    pub parent: Option<String>,
    pub by: String,
    pub at_ms: i64,
    /// Ephemeral X25519 public key, hex.
    pub eph: String,
    /// Commitment to the key, so every holder can tell it got the same one.
    pub check: String,
    pub keys: Vec<SealedKey>,
    pub sig: Vec<u8>,
}

impl Rotation {
    fn body(&self) -> Vec<u8> {
        encode(&(ROTATION, self.epoch, &self.parent, &self.by, self.at_ms, &self.eph, &self.check, &self.keys)).unwrap_or_default()
    }

    pub fn id(&self) -> String {
        hash_hex(ROTATION.as_bytes(), &self.body(), 16)
    }

    fn signed(&self) -> bool {
        peer_public(&self.by).is_some_and(|k| k.verify(&self.body(), &self.sig))
    }

    pub fn recipients(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|k| k.peer_id.as_str())
    }

    fn transcript(&self, recipient: &str, recipient_pub: &[u8; 32]) -> Vec<u8> {
        let parent = self.parent.as_deref().unwrap_or("-");
        format!("{ROTATION}|e{}|{parent}|{}|{recipient}|{}|{}", self.epoch, self.by, self.eph, hex::encode(recipient_pub)).into_bytes()
    }
}

/// A member's grant of the current key (and the older ones it holds) to a device,
/// such as one restored from the seed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Admission {
    pub rotation: String,
    pub peer_id: String,
    pub by: String,
    pub at_ms: i64,
    pub eph: String,
    pub sealed: Sealed,
    pub sig: Vec<u8>,
}

impl Admission {
    fn body(&self) -> Vec<u8> {
        encode(&(ADMISSION, &self.rotation, &self.peer_id, &self.by, self.at_ms, &self.eph, &self.sealed)).unwrap_or_default()
    }

    pub fn id(&self) -> String {
        hash_hex(ADMISSION.as_bytes(), &self.body(), 16)
    }

    fn signed(&self) -> bool {
        peer_public(&self.by).is_some_and(|k| k.verify(&self.body(), &self.sig))
    }

    fn transcript(&self, recipient_pub: &[u8; 32]) -> Vec<u8> {
        format!("{ADMISSION}|{}|{}|{}|{}|{}", self.rotation, self.peer_id, self.by, self.eph, hex::encode(recipient_pub)).into_bytes()
    }
}

/// The public part of rotation: device keys, rotations and admissions. Gossiped with the
/// roster; holds no secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct KeyChain {
    #[serde(default)]
    pub devices: Vec<DeviceKey>,
    #[serde(default)]
    pub rotations: Vec<Rotation>,
    #[serde(default)]
    pub admissions: Vec<Admission>,
    /// The root this device follows, once it holds a key from it. Local; never merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Devices the user approved on this device (by linking) that wait for an
    /// admission. Local; never merged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved: Vec<String>,
}

impl KeyChain {
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty() && self.rotations.is_empty() && self.admissions.is_empty()
    }

    pub fn is_empty_and_rootless(&self) -> bool {
        self.is_empty() && self.root.is_none() && self.approved.is_empty()
    }

    pub fn device(&self, peer_id: &str) -> Option<&DeviceKey> {
        self.devices.iter().find(|d| d.peer_id == peer_id)
    }

    /// Add or replace (newer `at_ms`) a device key. Returns false if it does not verify.
    pub fn add_device(&mut self, dk: DeviceKey) -> bool {
        if !dk.verify() {
            return false;
        }
        match self.devices.iter_mut().find(|d| d.peer_id == dk.peer_id) {
            Some(d) if d.at_ms < dk.at_ms => *d = dk,
            Some(_) => {}
            None => self.devices.push(dk),
        }
        true
    }

    /// Take another replica's device keys, rotations and admissions (signed ones only).
    /// `root` stays ours.
    pub fn merge(&mut self, other: &KeyChain) {
        for d in &other.devices {
            self.add_device(d.clone());
        }
        let have: BTreeSet<String> = self.rotations.iter().map(Rotation::id).collect();
        for r in &other.rotations {
            if !have.contains(&r.id()) && r.signed() {
                self.rotations.push(r.clone());
            }
        }
        let have: BTreeSet<String> = self.admissions.iter().map(Admission::id).collect();
        for a in &other.admissions {
            if !have.contains(&a.id()) && a.signed() {
                self.admissions.push(a.clone());
            }
        }
    }

    /// This chain without the local `root` and `approved`, for the wire.
    pub fn shared(&self) -> KeyChain {
        KeyChain { root: None, approved: Vec::new(), ..self.clone() }
    }
}

/// A rotation that counts, with its members.
#[derive(Debug, Clone)]
pub struct ValidRotation {
    pub id: String,
    pub epoch: u32,
    pub members: BTreeSet<String>,
    pub clean: bool,
}

/// A chain entry with its id.
type Ided<'a, T> = (String, &'a T);

/// The chain as this roster sees it: valid rotations from the root, and the head.
#[derive(Debug, Clone, Default)]
pub struct ChainView {
    pub root: Option<String>,
    pub valid: BTreeMap<String, ValidRotation>,
    pub admissions: Vec<String>,
    pub head: Option<String>,
}

impl ChainView {
    pub fn head(&self) -> Option<&ValidRotation> {
        self.head.as_ref().and_then(|h| self.valid.get(h))
    }

    /// The head has a member that has since been revoked.
    pub fn dirty(&self) -> bool {
        self.head().is_some_and(|h| !h.clean)
    }
}

impl Roster {
    fn revoked_set(&self) -> BTreeSet<&str> {
        self.certs.iter().filter(|c| !c.active()).map(|c| c.peer_id.as_str()).collect()
    }

    fn active_set(&self) -> BTreeSet<&str> {
        self.active().map(|c| c.peer_id.as_str()).collect()
    }

    fn signed_parts(&self) -> (Vec<Ided<'_, Rotation>>, Vec<Ided<'_, Admission>>) {
        let active = self.active_set();
        let known: BTreeSet<&str> = self.certs.iter().map(|c| c.peer_id.as_str()).collect();
        // What a service device signs once it is one does not count: it may not rotate or admit.
        let by_service = |by: &str, at: i64| self.service_since(by).is_some_and(|t| at >= t);
        let rots = self
            .chain
            .rotations
            .iter()
            .filter(|r| known.contains(r.by.as_str()) && !by_service(&r.by, r.at_ms) && r.signed())
            .map(|r| (r.id(), r))
            .collect();
        let adms = self
            .chain
            .admissions
            .iter()
            .filter(|a| active.contains(a.by.as_str()) && !by_service(&a.by, a.at_ms) && a.signed())
            .map(|a| (a.id(), a))
            .collect();
        (rots, adms)
    }

    /// The view from every root, the followed one or not. A device that is in two
    /// chains (two first roots made at once) uses these to bring the devices it
    /// approved into both, so the chains can merge.
    pub fn all_views(&self) -> Vec<ChainView> {
        let revoked = self.revoked_set();
        let (rots, adms) = self.signed_parts();
        rots.iter()
            .filter(|(_, r)| r.parent.is_none() && r.recipients().any(|p| p == r.by))
            .map(|root| self.view_from(root, &rots, &adms, &revoked))
            .collect()
    }

    /// Work out which rotations count, their members, and the head.
    pub fn chain_view(&self) -> ChainView {
        let revoked = self.revoked_set();
        let (rots, adms) = self.signed_parts();

        let roots: Vec<&(String, &Rotation)> = rots.iter().filter(|(_, r)| r.parent.is_none() && r.recipients().any(|p| p == r.by)).collect();
        fn order(r: &(String, &Rotation)) -> (u32, String) {
            (r.1.epoch, r.0.clone())
        }
        let mut root = match &self.chain.root {
            Some(id) => roots.iter().find(|(rid, _)| rid == id).copied(),
            None => roots.iter().copied().min_by_key(|r| order(r)),
        };
        // Two devices can start a root at once (both saw themselves as the first). A
        // root whose creator is a member of the chain we follow is trusted; the earliest
        // trusted root wins, so every device ends up on the same one. A root from a
        // device nobody in our chain admitted stays ignored.
        let mut seen = BTreeSet::new();
        while let Some(cur) = root {
            if !seen.insert(cur.0.clone()) {
                break;
            }
            let view = self.view_from(cur, &rots, &adms, &revoked);
            let trusted = |r: &&&(String, &Rotation)| view.valid.values().any(|v| v.members.contains(&r.1.by));
            match roots.iter().filter(trusted).min_by_key(|r| order(r)) {
                Some(best) if order(best) < order(cur) => root = Some(best),
                _ => return view,
            }
        }
        root.map(|r| self.view_from(r, &rots, &adms, &revoked)).unwrap_or_default()
    }

    fn view_from(
        &self,
        (root_id, root_rot): &(String, &Rotation),
        rots: &[(String, &Rotation)],
        adms: &[(String, &Admission)],
        revoked: &BTreeSet<&str>,
    ) -> ChainView {
        let mut view = ChainView { root: Some(root_id.clone()), ..ChainView::default() };

        let members_of = |id: &str, r: &Rotation, admitted: &mut Vec<String>| -> BTreeSet<String> {
            let mut m: BTreeSet<String> = r.recipients().map(str::to_string).collect();
            loop {
                let mut grew = false;
                for (aid, a) in adms.iter().filter(|(_, a)| a.rotation == id) {
                    if m.contains(&a.by) && !revoked.contains(a.by.as_str()) && !m.contains(&a.peer_id) {
                        m.insert(a.peer_id.clone());
                        admitted.push(aid.clone());
                        grew = true;
                    }
                }
                if !grew {
                    return m;
                }
            }
        };
        let mut admitted = Vec::new();
        let add = |view: &mut ChainView, id: &str, r: &Rotation, admitted: &mut Vec<String>| {
            let members = members_of(id, r, admitted);
            let clean = !members.iter().any(|m| revoked.contains(m.as_str()));
            view.valid.insert(id.to_string(), ValidRotation { id: id.to_string(), epoch: r.epoch, members, clean });
        };
        add(&mut view, root_id, root_rot, &mut admitted);
        loop {
            let mut grew = false;
            for (id, r) in rots {
                if view.valid.contains_key(id) {
                    continue;
                }
                let Some(p) = r.parent.as_ref().and_then(|p| view.valid.get(p)) else { continue };
                if r.epoch == p.epoch.saturating_add(1) && p.members.contains(&r.by) && r.recipients().any(|x| x == r.by) {
                    add(&mut view, id, r, &mut admitted);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        // A revoked device's rotations count only when a device still active built on
        // them (so the chain it started before its revocation lives on); whatever it
        // made on its own, unaware or not, drops out with it.
        let parent: BTreeMap<&str, Option<&str>> = rots.iter().map(|(id, r)| (id.as_str(), r.parent.as_deref())).collect();
        let mut keep: BTreeSet<String> = BTreeSet::new();
        for (id, r) in rots {
            if !view.valid.contains_key(id) || revoked.contains(r.by.as_str()) {
                continue;
            }
            let mut cur = Some(id.as_str());
            while let Some(c) = cur {
                if !keep.insert(c.to_string()) {
                    break;
                }
                cur = parent.get(c).copied().flatten();
            }
        }
        view.valid.retain(|id, _| keep.contains(id));
        if view.valid.is_empty() {
            return ChainView::default();
        }
        let kept_adm: BTreeSet<String> = adms.iter().filter(|(_, a)| view.valid.contains_key(&a.rotation)).map(|(id, _)| id.clone()).collect();
        admitted.retain(|id| kept_adm.contains(id));
        view.admissions = admitted;
        view.head = view
            .valid
            .values()
            .max_by(|a, b| (a.epoch, a.clean, std::cmp::Reverse(&a.id)).cmp(&(b.epoch, b.clean, std::cmp::Reverse(&b.id))))
            .map(|v| v.id.clone());
        view
    }

    /// The head rotation id, if the chain has started.
    pub fn head_id(&self) -> Option<String> {
        self.chain_view().head
    }
}

/// The epoch keys this device holds, by rotation id. Secret: the application stores it
/// encrypted ([`EpochKeys::export`]) and never logs it.
#[derive(Clone, Default, PartialEq)]
pub struct EpochKeys {
    keys: BTreeMap<String, (u32, Key32)>,
}

impl std::fmt::Debug for EpochKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochKeys({} keys)", self.keys.len())
    }
}

#[derive(Serialize, Deserialize)]
struct KeyEntry {
    id: String,
    epoch: u32,
    key: [u8; 32],
}

impl EpochKeys {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, id: &str) -> Option<&Key32> {
        self.keys.get(id).map(|(_, k)| k)
    }
    pub fn has(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }
    pub fn insert(&mut self, id: String, epoch: u32, key: Key32) {
        self.keys.insert(id, (epoch, key));
    }
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    pub fn ids(&self) -> impl Iterator<Item = (&str, u32)> {
        self.keys.iter().map(|(id, (e, _))| (id.as_str(), *e))
    }
    /// Take keys held by another copy of this state (keys are never dropped).
    pub fn merge(&mut self, other: &EpochKeys) {
        for (id, v) in &other.keys {
            self.keys.entry(id.clone()).or_insert_with(|| v.clone());
        }
    }

    fn entries(&self, only: impl Fn(&str) -> bool) -> Zeroizing<Vec<u8>> {
        let mut list: Vec<KeyEntry> =
            self.keys.iter().filter(|(id, _)| only(id)).map(|(id, (e, k))| KeyEntry { id: id.clone(), epoch: *e, key: k.0 }).collect();
        let out = Zeroizing::new(encode(&list).unwrap_or_default());
        for e in &mut list {
            e.key.zeroize();
        }
        out
    }

    fn absorb(&mut self, bytes: &[u8], accept: impl Fn(&str, &Key32) -> bool) -> Result<usize> {
        let mut list: Vec<KeyEntry> = decode(bytes)?;
        let mut n = 0;
        for e in &mut list {
            let key = Key32(e.key);
            e.key.zeroize();
            if !self.has(&e.id) && accept(&e.id, &key) {
                self.keys.insert(e.id.clone(), (e.epoch, key));
                n += 1;
            }
        }
        Ok(n)
    }

    /// CBOR for the application's encrypted store.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        self.entries(|_| true)
    }

    pub fn import(bytes: &[u8]) -> Result<Self> {
        let mut k = Self::new();
        k.absorb(bytes, |_, _| true)?;
        Ok(k)
    }
}

fn seal_to(eph: &ExchangeSecret, to: &[u8; 32], transcript: &[u8], plain: &[u8]) -> Result<Sealed> {
    let shared = eph.agree(to).ok_or_else(|| crypto("low-order device key"))?;
    let (k, _) = exchange::derive(&shared, transcript, SEAL_KEY, SEAL_SAS)?;
    Ok(seal(&k, plain, transcript)?)
}

fn open_from(me: &ExchangeSecret, eph_hex: &str, transcript: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    let eph: [u8; 32] = hex::decode(eph_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| crypto("bad ephemeral key"))?;
    let shared = me.agree(&eph).ok_or_else(|| crypto("low-order ephemeral key"))?;
    let (k, _) = exchange::derive(&shared, transcript, SEAL_KEY, SEAL_SAS)?;
    Ok(open(&k, sealed, transcript)?)
}

/// Where this device stands with rotated keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    /// No rotation yet: keys come from the seed, as in 0.2.
    Seed,
    /// Holding the head key at this epoch.
    Current { epoch: u32 },
    /// The chain has moved on and this device was not given the key: another device
    /// must re-admit it (for example after a restore from the recovery words).
    NeedsAdmission,
    /// This device has been revoked.
    Revoked,
    /// A service device linked without data keys (a roster-only grant): it syncs the
    /// roster and nothing else, and never needs admission.
    RosterOnly,
}

impl SyncState {
    /// Put this device's exchange key in the roster so rotations can include it.
    pub fn publish_device_key(&mut self, at_ms: i64) -> Result<()> {
        let device = self.device.as_ref().ok_or_else(|| SyncError::Protocol("no device key".into()))?;
        if self.roster.chain.device(&device.peer_id()).is_none() {
            let dk = device.device_key(at_ms)?;
            self.roster.chain.add_device(dk);
        }
        Ok(())
    }

    pub fn key_status(&self) -> KeyStatus {
        if self.roster.get(&self.our_cert.peer_id).is_some_and(|c| !c.active()) || !self.our_cert.active() {
            return KeyStatus::Revoked;
        }
        if !self.roster.holds_keys(&self.our_cert.peer_id) {
            return KeyStatus::RosterOnly;
        }
        let view = self.roster.chain_view();
        match view.head() {
            None => KeyStatus::Seed,
            Some(h) if self.keys.has(&h.id) => KeyStatus::Current { epoch: h.epoch },
            Some(_) => KeyStatus::NeedsAdmission,
        }
    }

    pub fn needs_admission(&self) -> bool {
        self.key_status() == KeyStatus::NeedsAdmission
    }

    /// Active devices that have not published a device key yet (not upgraded, or not
    /// synced since). A rotation now leaves them out; they would need re-admission.
    /// Apps warn before revoking while this is not empty.
    /// Roster-only service devices never need one and are not listed.
    pub fn devices_without_key(&self) -> Vec<NodeCert> {
        self.roster
            .active()
            .filter(|c| self.roster.holds_keys(&c.peer_id) && self.roster.chain.device(&c.peer_id).is_none_or(|d| !d.verify()))
            .cloned()
            .collect()
    }

    /// The first rotation should happen now, on this device: there is no rotation yet,
    /// at least two devices are linked, every active device has published its device
    /// key, and this device has the lowest peer id among them (so only one device
    /// starts the chain). Covers both "right after the first link" and "once after an
    /// upgrade from seed-only keys". [`crate::pull_from`] does it when
    /// [`SyncState::auto_first_rotation`] is on; apps may also call
    /// [`SyncState::rotate_if_first_due`].
    pub fn first_rotation_due(&self) -> bool {
        let Some(device) = &self.device else { return false };
        if self.is_service() || self.key_status() != KeyStatus::Seed {
            return false;
        }
        // Only devices that may rotate take part in choosing who starts the chain.
        let active: Vec<&NodeCert> = self.roster.active().filter(|c| !self.roster.is_service(&c.peer_id)).collect();
        let me = device.peer_id();
        active.len() >= 2 && active.iter().any(|c| c.peer_id == me) && self.devices_without_key().is_empty() && active.iter().all(|c| c.peer_id >= me)
    }

    /// Make the first rotation if [`SyncState::first_rotation_due`]. Returns its id.
    pub fn rotate_if_first_due(&mut self, at_ms: i64) -> Result<Option<String>> {
        if self.first_rotation_due() { self.rotate(at_ms).map(Some) } else { Ok(None) }
    }

    /// The head has a revoked member and this device can replace it.
    pub fn needs_rotation(&self) -> bool {
        let view = self.roster.chain_view();
        self.device.is_some()
            && !self.is_service()
            && view.dirty()
            && view.head().is_some_and(|h| self.keys.has(&h.id))
            && self.key_status() != KeyStatus::Revoked
    }

    /// Open every key sealed or admitted to this device and adopt the root. Returns how
    /// many keys were new.
    pub fn refresh_keys(&mut self) -> usize {
        let Some(device) = self.device.clone() else { return 0 };
        let me = device.peer_id();
        let Some(my_pub) = self.roster.chain.device(&me).and_then(DeviceKey::public) else { return 0 };
        let view = self.roster.chain_view();
        let views = self.roster.all_views();
        let valid = |id: &str| views.iter().any(|v| v.valid.contains_key(id));
        let mut n = 0;
        let checks: BTreeMap<String, String> = self.roster.chain.rotations.iter().map(|r| (r.id(), r.check.clone())).collect();
        for r in &self.roster.chain.rotations {
            let id = r.id();
            if !valid(&id) || self.keys.has(&id) {
                continue;
            }
            let Some(sk) = r.keys.iter().find(|k| k.peer_id == me) else { continue };
            if let Ok(plain) = open_from(&device.exchange, &r.eph, &r.transcript(&me, &my_pub), &sk.sealed)
                && let Ok(key) = Key32::from_slice(&plain)
                && key_check(&key) == r.check
            {
                self.keys.insert(id, r.epoch, key);
                n += 1;
            }
        }
        for a in &self.roster.chain.admissions {
            if a.peer_id != me || !views.iter().any(|v| v.admissions.contains(&a.id())) {
                continue;
            }
            if let Ok(plain) = open_from(&device.exchange, &a.eph, &a.transcript(&my_pub), &a.sealed) {
                n += self.keys.absorb(&plain, |id, key| valid(id) && checks.get(id).is_some_and(|c| *c == key_check(key))).unwrap_or(0);
            }
        }
        if self.roster.chain.root.is_none()
            && let Some(root) = &view.root
            && view.valid.keys().any(|id| self.keys.has(id))
        {
            self.roster.chain.root = Some(root.clone());
        }
        if let Some(h) = view.head() {
            self.roster.epoch = self.roster.epoch.max(h.epoch);
        }
        n
    }

    /// Make a fresh random epoch key and seal it to every remaining device that has
    /// published a device key. Returns the new rotation id.
    pub fn rotate(&mut self, at_ms: i64) -> Result<String> {
        let view = self.roster.chain_view();
        self.rotate_on(&view, at_ms)
    }

    /// Rotate on top of `view`'s head (taken before a revocation, whose creator's
    /// rotations would otherwise drop out of the view until someone builds on them).
    fn rotate_on(&mut self, view: &ChainView, at_ms: i64) -> Result<String> {
        if self.is_service() {
            return Err(SyncError::NotPermitted("rotate".into()));
        }
        let device = self.device.clone().ok_or_else(|| SyncError::Protocol("no device key".into()))?;
        let me = device.peer_id();
        self.publish_device_key(at_ms)?;
        if self.key_status() == KeyStatus::Revoked {
            return Err(SyncError::Refused("revoked".into()));
        }
        let active: BTreeSet<String> = self.roster.active().map(|c| c.peer_id.clone()).collect();
        let (parent, epoch, mut candidates): (Option<String>, u32, BTreeSet<String>) = match view.head() {
            Some(h) if !self.keys.has(&h.id) => return Err(SyncError::Refused("needs-admission".into())),
            Some(h) => (Some(h.id.clone()), h.epoch.saturating_add(1), h.members.clone()),
            None => (None, self.roster.epoch.saturating_add(1), active.clone()),
        };
        candidates.extend(self.roster.chain.approved.iter().cloned());
        // Service devices with sync types got their keys at link time, not as members of a
        // rotation: keep them in. Roster-only ones never get a key.
        candidates.extend(self.roster.active().filter(|c| self.roster.is_service(&c.peer_id)).map(|c| c.peer_id.clone()));
        candidates.retain(|p| self.roster.holds_keys(p));
        let key = Key32::random()?;
        let eph = ExchangeSecret::generate();
        let mut r = Rotation {
            epoch,
            parent,
            by: me.clone(),
            at_ms,
            eph: hex::encode(eph.public()),
            check: key_check(&key),
            keys: Vec::new(),
            sig: Vec::new(),
        };
        let mut recipients: Vec<String> = candidates.into_iter().filter(|p| active.contains(p)).collect();
        if !recipients.contains(&me) {
            recipients.push(me.clone());
        }
        for peer in recipients {
            let Some(public) = self.roster.chain.device(&peer).and_then(DeviceKey::public) else { continue };
            let sealed = seal_to(&eph, &public, &r.transcript(&peer, &public), &key.0)?;
            r.keys.push(SealedKey { peer_id: peer, sealed });
        }
        r.sig = device.sign(&r.body())?;
        let id = r.id();
        if r.parent.is_none() {
            self.roster.chain.root = Some(id.clone());
        }
        self.roster.chain.rotations.push(r);
        self.keys.insert(id.clone(), epoch, key);
        self.roster.epoch = self.roster.epoch.max(epoch);
        Ok(id)
    }

    /// Revoke a device and, when this state has a device key, rotate so the revoked
    /// device cannot read anything written afterwards even though it holds the seed.
    pub fn revoke(&mut self, user: &Keypair, peer_id: &str, at_ms: i64) -> Result<NodeCert> {
        if self.is_service() {
            return Err(SyncError::NotPermitted("revoke".into()));
        }
        let before = self.roster.chain_view();
        let cert = self.roster.revoke(&WEIRDNET, user, peer_id, at_ms)?;
        if self.device.is_some() {
            self.rotate_on(&before, at_ms)?;
        }
        Ok(cert)
    }

    /// The user approved this device here (as when linking it). It is admitted now if
    /// its device key is known, otherwise as soon as one of its hellos brings the key.
    /// Returns whether it was admitted now.
    pub fn approve(&mut self, cert: NodeCert, at_ms: i64) -> Result<bool> {
        if self.is_service() {
            return Err(SyncError::NotPermitted("approve".into()));
        }
        if !WEIRDNET.verify_cert(&self.user_key, &cert) || !cert.active() || cert.user_id != self.user_id {
            return Err(SyncError::Refused("wrong-user".into()));
        }
        if self.roster.get(&cert.peer_id).is_some_and(|c| !c.active()) {
            return Err(SyncError::Refused("revoked".into()));
        }
        let peer = cert.peer_id.clone();
        self.roster.upsert(cert);
        if !self.roster.holds_keys(&peer) {
            // A roster-only service device: in the roster, never in the key chain.
            return Ok(false);
        }
        if !self.roster.chain.approved.contains(&peer) {
            self.roster.chain.approved.push(peer.clone());
        }
        Ok(self.admit_approved(at_ms).contains(&peer))
    }

    /// Admit every approved device whose device key is known and that is not yet a
    /// member of the head, in every chain whose head key this device holds (normally
    /// one; two when two first roots were made at once). Members of all of them and
    /// revoked devices leave the list. Returns the devices admitted.
    pub fn admit_approved(&mut self, at_ms: i64) -> Vec<String> {
        let mut admitted = Vec::new();
        if self.roster.chain.approved.is_empty() || self.device.is_none() || self.is_service() {
            return admitted;
        }
        let roster = &self.roster;
        let drop: Vec<String> = roster.chain.approved.iter().filter(|p| !roster.holds_keys(p)).cloned().collect();
        self.roster.chain.approved.retain(|p| !drop.contains(p));
        for peer in self.roster.chain.approved.clone() {
            let active = self.roster.get(&peer).is_some_and(|c| c.active());
            let mut done = active;
            let mut any = false;
            for view in self.roster.all_views() {
                let Some(head) = view.head() else { continue };
                if !self.keys.has(&head.id) {
                    if view.root == self.roster.chain_view().root {
                        done = false;
                    }
                    continue;
                }
                any = true;
                if !active || head.members.contains(&peer) {
                    continue;
                }
                let admitted_now = self.roster.chain.device(&peer).is_some()
                    && self.roster.get(&peer).cloned().is_some_and(|cert| self.admit_to(cert, &view, at_ms).unwrap_or(false));
                if admitted_now {
                    if !admitted.contains(&peer) {
                        admitted.push(peer.clone());
                    }
                } else {
                    done = false;
                }
            }
            if !active || (any && done) {
                self.roster.chain.approved.retain(|p| p != &peer);
            }
        }
        admitted
    }

    /// Let a device back in (after the user approved it on this device, as when
    /// linking; [`SyncState::approve`] waits for its device key): seal the head key and the older keys this device holds to its device
    /// key. Returns false when there is nothing to admit to (no rotation yet: the seed
    /// is enough).
    pub fn admit(&mut self, cert: NodeCert, at_ms: i64) -> Result<bool> {
        if !WEIRDNET.verify_cert(&self.user_key, &cert) || !cert.active() || cert.user_id != self.user_id {
            return Err(SyncError::Refused("wrong-user".into()));
        }
        if self.roster.get(&cert.peer_id).is_some_and(|c| !c.active()) {
            return Err(SyncError::Refused("revoked".into()));
        }
        self.roster.upsert(cert.clone());
        let view = self.roster.chain_view();
        self.admit_to(cert, &view, at_ms)
    }

    fn admit_to(&mut self, cert: NodeCert, view: &ChainView, at_ms: i64) -> Result<bool> {
        if self.is_service() {
            return Err(SyncError::NotPermitted("admit".into()));
        }
        if !self.roster.holds_keys(&cert.peer_id) {
            return Ok(false);
        }
        let device = self.device.clone().ok_or_else(|| SyncError::Protocol("no device key".into()))?;
        let peer = cert.peer_id.clone();
        let Some(head) = view.head() else { return Ok(false) };
        if !self.keys.has(&head.id) {
            return Err(SyncError::Refused("needs-admission".into()));
        }
        let public = self
            .roster
            .chain
            .device(&peer)
            .and_then(DeviceKey::public)
            .ok_or_else(|| SyncError::Protocol(format!("no device key for {peer} yet")))?;
        let eph = ExchangeSecret::generate();
        let mut a = Admission {
            rotation: head.id.clone(),
            peer_id: peer,
            by: device.peer_id(),
            at_ms,
            eph: hex::encode(eph.public()),
            sealed: Sealed { nonce: String::new(), ct: String::new() },
            sig: Vec::new(),
        };
        let plain = self.keys.entries(|id| view.valid.contains_key(id));
        a.sealed = seal_to(&eph, &public, &a.transcript(&public), &plain)?;
        a.sig = device.sign(&a.body())?;
        self.roster.chain.admissions.push(a);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_key_verifies_only_for_its_own_node() {
        let node = Keypair::generate_ed25519();
        let d = Device::from_node_key(&node).unwrap();
        let dk = d.device_key(5).unwrap();
        assert!(dk.verify());
        assert_eq!(dk.peer_id, node.public().to_peer_id().to_string());
        // Same node key, same exchange key (nothing new to store).
        assert_eq!(Device::from_node_key(&node).unwrap().device_key(5).unwrap().exchange, dk.exchange);
        let other = Device::from_node_key(&Keypair::generate_ed25519()).unwrap().device_key(5).unwrap();
        assert!(!DeviceKey { exchange: other.exchange.clone(), ..dk.clone() }.verify(), "a swapped exchange key fails");
        assert!(!DeviceKey { peer_id: other.peer_id.clone(), ..dk.clone() }.verify());
        assert_eq!(dk.fingerprint().len(), 14);
        assert!(format!("{d:?}").starts_with("Device(12D3"));
    }

    #[test]
    fn epoch_keys_export_and_import() {
        let mut k = EpochKeys::new();
        k.insert("a".into(), 1, Key32::random().unwrap());
        k.insert("b".into(), 2, Key32::random().unwrap());
        let back = EpochKeys::import(&k.export()).unwrap();
        assert_eq!(back, k);
        assert_eq!(format!("{k:?}"), "EpochKeys(2 keys)");
    }

    #[test]
    fn a_sealed_copy_opens_only_for_its_recipient() {
        let a = Device::from_node_key(&Keypair::generate_ed25519()).unwrap();
        let b = Device::from_node_key(&Keypair::generate_ed25519()).unwrap();
        let eph = ExchangeSecret::generate();
        let to = a.exchange.public();
        let s = seal_to(&eph, &to, b"t", b"key").unwrap();
        let eph_hex = hex::encode(eph.public());
        assert_eq!(&open_from(&a.exchange, &eph_hex, b"t", &s).unwrap()[..], b"key");
        assert!(open_from(&b.exchange, &eph_hex, b"t", &s).is_err());
        assert!(open_from(&a.exchange, &eph_hex, b"other", &s).is_err());
    }

    #[test]
    fn peer_public_round_trips() {
        let k = Keypair::generate_ed25519();
        let pid = k.public().to_peer_id().to_string();
        assert_eq!(peer_public(&pid).unwrap(), k.public());
        assert!(peer_public("not-a-peer").is_none());
    }
}
