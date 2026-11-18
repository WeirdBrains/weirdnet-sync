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

/// The user's devices and the current sealing epoch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Roster {
    pub epoch: u32,
    pub certs: Vec<NodeCert>,
    /// Device keys, rotations and admissions (public; sealed epoch keys inside).
    #[serde(default, skip_serializing_if = "KeyChain::is_empty_and_rootless")]
    pub chain: KeyChain,
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

    /// Merge another replica's certs and key chain. A signed revocation wins over a
    /// still-active copy of the same cert. The epoch is the max of the two.
    pub fn merge(&mut self, other: &Roster, key: &PublicKey, profile: &Profile) {
        self.epoch = self.epoch.max(other.epoch);
        self.chain.merge(&other.chain);
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
