//! Device roster: self-issued [`NodeCert`]s, revocations and the key epoch.
//!
//! Certificates themselves are created and checked by [`weirdnet_net::user`] /
//! [`Profile::certify`]. This module keeps the set, bumps the epoch on revoke, and
//! decides whether a peer may start a sync session. The key chain ([`KeyChain`]: device
//! keys, rotations and admissions) travels with the roster; see [`crate::rotation`].
use crate::error::{Result, SyncError};
use crate::rotation::KeyChain;
use serde::{Deserialize, Serialize};
use weirdnet_net::profile::{Profile, WEIRDNET};
use weirdnet_net::user::{self, NodeCert};
use weirdnet_net::{Keypair, PublicKey};

const GRANT: &str = "weirdnet-sync/v1/grant";
/// Most roles one grant carries.
pub const MAX_GRANT_ROLES: usize = 16;
/// Most sync types one grant scopes.
pub const MAX_GRANT_TYPES: usize = 64;
const MAX_NAME: usize = 128;

/// What kind of device a [`DeviceGrant`] makes a cert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceClass {
    /// Holds (or may hold) the identity seed: admits, revokes, grants and rotates.
    Full,
    /// Linked with a certificate only, never the seed (a server such as a model or
    /// inference node). It cannot admit, revoke, grant or rotate, and its rotations and
    /// admissions are ignored. With no `types` it gets no data keys at all.
    Service,
}

/// The user's signed statement of what a device is: its class, its roles and, for a
/// service device, the sync types it may hold keys for. Signed by the user key, so only
/// a device holding the seed can make one; it travels in the roster with the certs.
///
/// Roles are application strings (`ymir.inference`, `ymir.model`, …): what a device may
/// do, as opposed to the role toggles an app announces about itself, which anyone can
/// claim. Per device the newest grant (by `issued_at`) that verifies wins; a grant for a
/// revoked cert counts for nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGrant {
    pub user_id: String,
    pub peer_id: String,
    pub class: DeviceClass,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub types: Vec<String>,
    pub issued_at: i64,
    #[serde(with = "crate::bytes")]
    pub sig: Vec<u8>,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:/+#".contains(&b))
}

impl DeviceGrant {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = format!("{GRANT}\n").into_bytes();
        out.extend(
            crate::protocol::encode(&(&self.user_id, &self.peer_id, self.class, &self.roles, &self.types, self.issued_at)).unwrap_or_default(),
        );
        out
    }

    /// A grant for `peer_id`, signed by the user key. Roles and types are sorted and
    /// deduplicated; names are 1..=128 of `A-Z a-z 0-9 . - _ : / + #`.
    pub fn sign(user: &Keypair, peer_id: &str, class: DeviceClass, roles: &[String], types: &[String], issued_at: i64) -> Result<Self> {
        let norm = |v: &[String], max: usize, what: &str| -> Result<Vec<String>> {
            let mut v: Vec<String> = v.to_vec();
            v.sort();
            v.dedup();
            if v.len() > max || !v.iter().all(|s| valid_name(s)) {
                return Err(SyncError::Protocol(format!("grant: bad {what}")));
            }
            Ok(v)
        };
        let mut g = Self {
            user_id: user::user_id(&user.public()),
            peer_id: peer_id.into(),
            class,
            roles: norm(roles, MAX_GRANT_ROLES, "roles")?,
            types: norm(types, MAX_GRANT_TYPES, "types")?,
            issued_at,
            sig: Vec::new(),
        };
        g.sig = user.sign(&g.signing_bytes()).map_err(|e| SyncError::Crypto(format!("grant: {e}")))?;
        Ok(g)
    }

    /// Signed by this user key, for this user, and well formed.
    pub fn verify(&self, user_key: &PublicKey) -> bool {
        user::user_id(user_key) == self.user_id
            && self.roles.len() <= MAX_GRANT_ROLES
            && self.types.len() <= MAX_GRANT_TYPES
            && self.roles.iter().chain(&self.types).all(|s| valid_name(s))
            && user_key.verify(&self.signing_bytes(), &self.sig)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// The sync types a service device with this grant holds type-scoped keys for instead
    /// of the epoch keys (since 0.8.3): its granted types, their chunk types
    /// ([`crate::chunk_type`]) and [`LEASE_TYPE`](crate::lease::LEASE_TYPE), which every
    /// service device with sync types gets so it can vote and stand for leases (grant only
    /// `weirdnet.lease` for a lease-only device). `None` for a full device (it holds the
    /// epoch keys) and for a roster-only one (no keys).
    pub fn scoped_types(&self) -> Option<Vec<String>> {
        if self.class != DeviceClass::Service || self.roster_only() {
            return None;
        }
        let mut out: Vec<String> = Vec::with_capacity(self.types.len() * 2 + 1);
        for t in &self.types {
            out.push(t.clone());
            if t != crate::lease::LEASE_TYPE {
                out.push(crate::record::chunk_type(t));
            }
        }
        out.push(crate::lease::LEASE_TYPE.to_string());
        out.sort();
        out.dedup();
        Some(out)
    }

    /// A service device with no sync types: it gets the roster but no data keys.
    pub fn roster_only(&self) -> bool {
        self.class == DeviceClass::Service && self.types.is_empty()
    }
}

/// The user's devices and the current sealing epoch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Roster {
    pub epoch: u32,
    pub certs: Vec<NodeCert>,
    /// Device keys, rotations and admissions (public; sealed epoch keys inside).
    #[serde(default, skip_serializing_if = "KeyChain::is_empty_and_rootless")]
    pub chain: KeyChain,
    /// Device grants (roles, class). Kept only when they verify under the user key
    /// (checked on [`Roster::add_grant`] and [`Roster::merge`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<DeviceGrant>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    /// The first device to hold an identity self-certifies and is the initial roster of one.
    pub fn self_certify(profile: &Profile, user: &Keypair, peer_id: &str, label: &str, at_ms: i64) -> Result<NodeCert> {
        let uid = user::user_id(&user.public());
        Ok(profile.certify(user, &uid, peer_id, label, at_ms)?)
    }

    /// Insert or replace the cert for this peer id. Does not change the epoch.
    pub fn upsert(&mut self, cert: NodeCert) {
        if let Some(existing) = self.certs.iter_mut().find(|c| c.peer_id == cert.peer_id) {
            *existing = cert;
        } else {
            self.certs.push(cert);
        }
    }

    pub fn get(&self, peer_id: &str) -> Option<&NodeCert> {
        self.certs.iter().find(|c| c.peer_id == peer_id)
    }

    pub fn active(&self) -> impl Iterator<Item = &NodeCert> {
        self.certs.iter().filter(|c| c.active())
    }

    /// Sign a revocation, attach it to the cert, and bump the key epoch. This alone does
    /// not shut out a device that holds the seed: use [`crate::SyncState::revoke`], which
    /// also rotates to a random epoch key.
    pub fn revoke(&mut self, profile: &Profile, user: &Keypair, peer_id: &str, at_ms: i64) -> Result<NodeCert> {
        let uid = user::user_id(&user.public());
        let sig = profile.revoke(user, &uid, peer_id, at_ms)?;
        let cert = self.certs.iter_mut().find(|c| c.peer_id == peer_id).ok_or_else(|| SyncError::Protocol(format!("no cert for {peer_id}")))?;
        if cert.user_id != uid {
            return Err(SyncError::Protocol("revocation user does not match the cert".into()));
        }
        cert.revoked_at = Some(at_ms);
        cert.revocation = Some(sig);
        self.epoch = self.epoch.saturating_add(1);
        Ok(cert.clone())
    }

    /// Add a grant if it verifies under `key` and is newer than the one held for that
    /// device. Returns whether it was taken.
    pub fn add_grant(&mut self, grant: DeviceGrant, key: &PublicKey) -> bool {
        if !grant.verify(key) {
            return false;
        }
        match self.grants.iter_mut().find(|g| g.peer_id == grant.peer_id) {
            Some(g) if (g.issued_at, &g.sig) >= (grant.issued_at, &grant.sig) => false,
            Some(g) => {
                *g = grant;
                true
            }
            None => {
                self.grants.push(grant);
                true
            }
        }
    }

    /// The grant in force for `peer_id`: the newest held, and only while its cert is
    /// active. Grants are verified when they are added, so this does not check again.
    pub fn grant_of(&self, peer_id: &str) -> Option<&DeviceGrant> {
        self.get(peer_id).filter(|c| c.active())?;
        self.grants.iter().find(|g| g.peer_id == peer_id)
    }

    /// The roles granted to `peer_id`, `None` when it has no grant (a device linked
    /// before grants, or one never given any).
    pub fn roles_of(&self, peer_id: &str) -> Option<&[String]> {
        self.grant_of(peer_id).map(|g| g.roles.as_slice())
    }

    /// Whether `peer_id` holds a grant with `role`.
    pub fn has_role(&self, peer_id: &str, role: &str) -> bool {
        self.grant_of(peer_id).is_some_and(|g| g.has_role(role))
    }

    /// Whether `peer_id` was linked as a service device (no seed).
    pub fn is_service(&self, peer_id: &str) -> bool {
        self.grant_of(peer_id).is_some_and(|g| g.class == DeviceClass::Service)
    }

    /// Whether `peer_id` may hold data keys: every device except a roster-only service
    /// device.
    pub fn holds_keys(&self, peer_id: &str) -> bool {
        !self.grant_of(peer_id).is_some_and(DeviceGrant::roster_only)
    }

    /// The sync types `peer_id` holds type-scoped keys for instead of the epoch keys
    /// (since 0.8.3; see [`DeviceGrant::scoped_types`]), while its cert is active. `None`
    /// for every other device: a full device holds the epoch keys, a roster-only one none.
    pub fn scoped_types(&self, peer_id: &str) -> Option<Vec<String>> {
        self.grant_of(peer_id)?.scoped_types()
    }

    /// Whether an active service device is granted `typ` (since 0.8.4). Full devices then
    /// seal `typ`'s records under the type-scoped record key so it can open them
    /// ([`crate::SyncState::seals_scoped`]).
    pub fn service_granted(&self, typ: &str) -> bool {
        self.active().any(|c| self.grant_of(&c.peer_id).is_some_and(|g| g.class == DeviceClass::Service && g.types.iter().any(|t| t == typ)))
    }

    /// Whether `peer_id` may sync `typ` with this device (since 0.8.3): every device may,
    /// except a service device, which may sync only the types in its grant (and their
    /// chunk types) plus [`LEASE_TYPE`](crate::lease::LEASE_TYPE), and nothing when its
    /// grant is roster-only. Checked on every hello, pull, ack and lease request.
    pub fn may_sync(&self, peer_id: &str, typ: &str) -> bool {
        let Some(g) = self.grants.iter().find(|g| g.peer_id == peer_id) else { return true };
        if g.class != DeviceClass::Service {
            return true;
        }
        if g.roster_only() {
            return false;
        }
        let base = crate::record::base_type(typ).unwrap_or(typ);
        typ == crate::lease::LEASE_TYPE || g.types.iter().any(|t| t == typ || t == base)
    }

    /// When `peer_id`'s grant made it a service device (one grant is held per device), for
    /// ignoring the rotations and admissions it signs from then on.
    pub(crate) fn service_since(&self, peer_id: &str) -> Option<i64> {
        self.grants.iter().find(|g| g.peer_id == peer_id && g.class == DeviceClass::Service).map(|g| g.issued_at)
    }

    /// Merge another replica's certs, key chain and grants. A signed revocation wins over
    /// a still-active copy of the same cert. The epoch is the max of the two.
    pub fn merge(&mut self, other: &Roster, key: &PublicKey, profile: &Profile) {
        self.epoch = self.epoch.max(other.epoch);
        self.chain.merge(&other.chain);
        for g in &other.grants {
            self.add_grant(g.clone(), key);
        }
        for c in &other.certs {
            if !profile.verify_cert(key, c) {
                continue;
            }
            match self.certs.iter_mut().find(|x| x.peer_id == c.peer_id) {
                Some(existing) => {
                    if !existing.active() {
                        continue;
                    }
                    if !c.active() {
                        *existing = c.clone();
                    }
                }
                None => self.certs.push(c.clone()),
            }
        }
    }
}

/// Why a hello is refused, as sent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCheck {
    Ok,
    WrongUser,
    Revoked,
    EpochBehind,
    TypeOff,
}

impl SessionCheck {
    pub fn reason(self) -> Option<&'static str> {
        match self {
            SessionCheck::Ok => None,
            SessionCheck::WrongUser => Some("wrong-user"),
            SessionCheck::Revoked => Some("revoked"),
            SessionCheck::EpochBehind => Some("epoch-behind"),
            SessionCheck::TypeOff => Some("type-off"),
        }
    }
}

/// What a peer presents in Hello, for [`Roster::check_session`].
pub struct SessionOffer<'a> {
    pub cert: &'a NodeCert,
    pub epoch: u32,
    pub types: &'a [String],
}

impl Roster {
    /// Accept a session only if the cert is for `user_id`, verifies, is not revoked, and
    /// the peer's epoch is not behind ours. `offered_types` must intersect `our_types`.
    pub fn check_session(
        &self,
        profile: &Profile,
        user_key: &PublicKey,
        user_id: &str,
        offer: &SessionOffer<'_>,
        our_types: &[String],
    ) -> SessionCheck {
        let cert = offer.cert;
        if cert.user_id != user_id || user::user_id(user_key) != user_id || !profile.verify_cert(user_key, cert) {
            return SessionCheck::WrongUser;
        }
        let revoked_here = self.get(&cert.peer_id).is_some_and(|c| !c.active()) || !cert.active();
        if revoked_here || !profile.verify_cert(user_key, cert) {
            return SessionCheck::Revoked;
        }
        if offer.epoch < self.epoch {
            return SessionCheck::EpochBehind;
        }
        if !offer.types.iter().any(|t| our_types.iter().any(|o| o == t)) {
            return SessionCheck::TypeOff;
        }
        SessionCheck::Ok
    }
}

/// What [`Roster::check_caller`] decided about a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerCheck {
    /// An active, verified device of this user, in the key chain's head once there is one.
    Linked,
    /// No cert for this peer in the roster. A cert the caller presents is not enough: anyone
    /// holding the seed (a revoked device too) can mint one.
    Unknown,
    /// Revoked here, or the caller presented a revoked cert.
    Revoked,
    /// The cert is for another user or another peer, or does not verify.
    WrongUser,
    /// In the roster but not a member of the current key chain's head (not yet admitted).
    NotAdmitted,
}

impl CallerCheck {
    /// The refusal reason to send back, `None` for [`CallerCheck::Linked`].
    pub fn reason(self) -> Option<&'static str> {
        match self {
            CallerCheck::Linked => None,
            CallerCheck::Unknown => Some("unknown-device"),
            CallerCheck::Revoked => Some("revoked"),
            CallerCheck::WrongUser => Some("wrong-user"),
            CallerCheck::NotAdmitted => Some("needs-admission"),
        }
    }
}

impl Roster {
    /// Whether the caller of an app call or stream served by this device is one of the
    /// user's linked devices. `peer` must be the transport-authenticated peer id (Noise),
    /// never one the caller sent. `presented` is the cert the caller sent with the call, if
    /// any; it must match `peer` and the user, and a revoked one is refused, but only this
    /// roster's own cert admits a caller.
    pub fn check_caller(&self, profile: &Profile, user_key: &PublicKey, peer: &str, presented: Option<&NodeCert>) -> CallerCheck {
        let uid = user::user_id(user_key);
        if let Some(p) = presented {
            if p.peer_id != peer || p.user_id != uid || !profile.verify_cert(user_key, p) {
                return CallerCheck::WrongUser;
            }
            if !p.active() {
                return CallerCheck::Revoked;
            }
        }
        let Some(cert) = self.get(peer) else { return CallerCheck::Unknown };
        if !cert.active() {
            return CallerCheck::Revoked;
        }
        if cert.user_id != uid || !profile.verify_cert(user_key, cert) {
            return CallerCheck::WrongUser;
        }
        // A service device is never a member of a rotation it did not need (a roster-only
        // one holds no keys at all); its grant admits it.
        if self.chain_view().head().is_some_and(|h| !h.members.contains(peer)) && !self.is_service(peer) {
            return CallerCheck::NotAdmitted;
        }
        CallerCheck::Linked
    }
}

/// Default profile used for certs unless the application passes another.
pub fn default_profile() -> &'static Profile {
    &WEIRDNET
}

#[cfg(test)]
mod tests {
    use super::*;
    use weirdnet_net::Keypair;

    fn user() -> Keypair {
        Keypair::generate_ed25519()
    }

    #[test]
    fn first_device_self_certifies_and_is_the_roster_of_one() {
        let u = user();
        let cert = Roster::self_certify(&WEIRDNET, &u, "peer-a", "desktop", 1_000).unwrap();
        assert_eq!(cert.peer_id, "peer-a");
        assert!(cert.active());
        assert!(WEIRDNET.verify_cert(&u.public(), &cert));
        let mut r = Roster::new();
        r.upsert(cert);
        assert_eq!(r.active().count(), 1);
        assert_eq!(r.epoch, 0);
    }

    #[test]
    fn revoke_bumps_the_epoch_and_rejects_that_peer() {
        let u = user();
        let uid = user::user_id(&u.public());
        let mut r = Roster::new();
        r.upsert(Roster::self_certify(&WEIRDNET, &u, "peer-a", "phone", 1).unwrap());
        r.upsert(Roster::self_certify(&WEIRDNET, &u, "peer-b", "desktop", 2).unwrap());
        let revoked = r.revoke(&WEIRDNET, &u, "peer-a", 3).unwrap();
        assert_eq!(r.epoch, 1);
        assert!(!revoked.active());
        assert!(WEIRDNET.verify_cert(&u.public(), &revoked));
        let check = r.check_session(
            &WEIRDNET,
            &u.public(),
            &uid,
            &SessionOffer { cert: &revoked, epoch: 1, types: &["bookmarks".into()] },
            &["bookmarks".into()],
        );
        assert_eq!(check, SessionCheck::Revoked);
        let b = r.get("peer-b").unwrap().clone();
        assert_eq!(
            r.check_session(&WEIRDNET, &u.public(), &uid, &SessionOffer { cert: &b, epoch: 1, types: &["bookmarks".into()] }, &["bookmarks".into()]),
            SessionCheck::Ok
        );
        assert_eq!(
            r.check_session(&WEIRDNET, &u.public(), &uid, &SessionOffer { cert: &b, epoch: 0, types: &["bookmarks".into()] }, &["bookmarks".into()]),
            SessionCheck::EpochBehind
        );
        assert_eq!(
            r.check_session(&WEIRDNET, &u.public(), &uid, &SessionOffer { cert: &b, epoch: 1, types: &["settings".into()] }, &["bookmarks".into()]),
            SessionCheck::TypeOff
        );
    }

    #[test]
    fn a_foreign_user_cert_is_wrong_user() {
        let a = user();
        let b = user();
        let cert = Roster::self_certify(&WEIRDNET, &b, "peer-x", "x", 1).unwrap();
        let r = Roster::new();
        let uid = user::user_id(&a.public());
        assert_eq!(
            r.check_session(
                &WEIRDNET,
                &a.public(),
                &uid,
                &SessionOffer { cert: &cert, epoch: 0, types: &["bookmarks".into()] },
                &["bookmarks".into()]
            ),
            SessionCheck::WrongUser
        );
    }

    #[test]
    fn callers_are_checked_against_the_roster() {
        let u = user();
        let mut r = Roster::new();
        r.upsert(Roster::self_certify(&WEIRDNET, &u, "peer-a", "desktop", 1).unwrap());
        r.upsert(Roster::self_certify(&WEIRDNET, &u, "peer-b", "phone", 2).unwrap());
        let a = r.get("peer-a").unwrap().clone();
        let check = |r: &Roster, peer: &str, presented: Option<&NodeCert>| r.check_caller(&WEIRDNET, &u.public(), peer, presented);
        assert_eq!(check(&r, "peer-a", None), CallerCheck::Linked);
        assert_eq!(check(&r, "peer-a", Some(&a)), CallerCheck::Linked);
        assert_eq!(check(&r, "peer-b", Some(&a)), CallerCheck::WrongUser, "a cert for another peer");
        // A cert minted with the user key for a peer this roster never had.
        let minted = Roster::self_certify(&WEIRDNET, &u, "peer-m", "minted", 3).unwrap();
        assert_eq!(check(&r, "peer-m", Some(&minted)), CallerCheck::Unknown);
        assert_eq!(check(&r, "peer-x", None), CallerCheck::Unknown);
        // Another user's device.
        let other = user();
        let foreign = Roster::self_certify(&WEIRDNET, &other, "peer-a", "x", 1).unwrap();
        assert_eq!(check(&r, "peer-a", Some(&foreign)), CallerCheck::WrongUser);
        let mut theirs = Roster::new();
        theirs.upsert(foreign);
        assert_eq!(check(&theirs, "peer-a", None), CallerCheck::WrongUser);
        // Revoked here, and a revoked cert presented to a roster that has not heard.
        let stale = r.clone();
        let revoked = r.revoke(&WEIRDNET, &u, "peer-b", 4).unwrap();
        assert_eq!(check(&r, "peer-b", None), CallerCheck::Revoked);
        assert_eq!(check(&stale, "peer-b", Some(&revoked)), CallerCheck::Revoked);
        assert_eq!(CallerCheck::Revoked.reason(), Some("revoked"));
        assert_eq!(CallerCheck::Linked.reason(), None);
    }

    #[test]
    fn merge_takes_a_signed_revocation_and_the_higher_epoch() {
        let u = user();
        let mut a = Roster::new();
        let mut b = Roster::new();
        let ca = Roster::self_certify(&WEIRDNET, &u, "peer-a", "a", 1).unwrap();
        let cb = Roster::self_certify(&WEIRDNET, &u, "peer-b", "b", 2).unwrap();
        a.upsert(ca.clone());
        a.upsert(cb.clone());
        b.upsert(ca);
        b.upsert(cb);
        b.revoke(&WEIRDNET, &u, "peer-a", 9).unwrap();
        a.merge(&b, &u.public(), &WEIRDNET);
        assert_eq!(a.epoch, 1);
        assert!(!a.get("peer-a").unwrap().active());
        assert!(a.get("peer-b").unwrap().active());
    }
}
