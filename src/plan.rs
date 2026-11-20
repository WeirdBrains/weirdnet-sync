//! Plans (since 0.8): one signed, versioned document per name, written by a lease holder and
//! ordered by `(term, version)`, never by wall clock or HLC, so a stale holder whose clock
//! runs ahead can't override a newer holder's plan.
//!
//! Each plan is signed by the writing device's node key over the user, record type, name and
//! body, so a device that relays the page can't alter or move it, and it only counts while the
//! signer's certificate is active. Stored as a normal record (configure the type
//! `RecordOptions::sealed` to seal it).
use serde::{Deserialize, Serialize};

use crate::error::{Result, SyncError};
use crate::hlc::Hlc;
use crate::lease::{LeaseHandle, Term};
use crate::net::SyncState;
use crate::protocol::{decode, encode};
use crate::rotation::peer_public;

const PLAN_DOMAIN: &[u8] = b"weirdnet-sync/v1/plan\n";

/// A body signed by a device's node key, bound to where it is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedDoc {
    pub signer: String,
    #[serde(with = "crate::bytes")]
    pub body: Vec<u8>,
    #[serde(with = "crate::bytes")]
    pub sig: Vec<u8>,
}

fn doc_bytes(domain: &[u8], user_id: &str, typ: &str, record_id: &str, body: &[u8]) -> Vec<u8> {
    let mut b = domain.to_vec();
    for part in [user_id, typ, record_id] {
        b.extend_from_slice(part.as_bytes());
        b.push(b'\n');
    }
    b.extend_from_slice(body);
    b
}

impl SyncState {
    pub(crate) fn sign_doc(&self, domain: &[u8], typ: &str, record_id: &str, body: Vec<u8>) -> Result<SignedDoc> {
        let device = self.device.as_ref().ok_or_else(|| SyncError::NotPermitted("signing needs this device's node key".into()))?;
        let sig = device.sign(&doc_bytes(domain, &self.user_id, typ, record_id, &body))?;
        Ok(SignedDoc { signer: device.peer_id(), body, sig })
    }

    /// The signed docs under `typ`/`record_id` whose signature verifies and whose signer is an
    /// active device, with each entry's HLC.
    pub(crate) fn signed_docs(&self, domain: &[u8], typ: &str, record_id: &str) -> Vec<(SignedDoc, Hlc)> {
        let mut out = Vec::new();
        for e in self.log.iter().filter(|e| e.typ == typ && e.record_id == record_id) {
            let Some(bytes) = self.read(e).ok().and_then(|v| v.ready()) else { continue };
            let Ok(doc) = decode::<SignedDoc>(&bytes) else { continue };
            let Some(key) = peer_public(&doc.signer) else { continue };
            if !self.roster.get(&doc.signer).is_some_and(|c| c.active()) {
                continue;
            }
            if key.verify(&doc_bytes(domain, &self.user_id, typ, record_id, &doc.body), &doc.sig) {
                out.push((doc, e.hlc.clone()));
            }
        }
        out
    }
}

#[derive(Serialize, Deserialize)]
struct PlanBody {
    term: Term,
    version: u64,
    #[serde(with = "crate::bytes")]
    body: Vec<u8>,
}

/// A plan as read back: the newest by `(term, version)` among valid ones.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    pub name: String,
    pub term: Term,
    pub version: u64,
    pub body: Vec<u8>,
    /// The device that wrote it.
    pub signer: String,
    pub hlc: Hlc,
}

impl SyncState {
    /// Write the plan `name` under `typ` (for example `ymir.plan`) while holding `lease`.
    /// The version is the previous one of the same term plus one, or 1 on a new term.
    pub fn publish_plan(&mut self, now_ms: u64, typ: &str, name: &str, lease: &LeaseHandle, body: &[u8]) -> Result<Plan> {
        if !lease.is_valid() {
            return Err(SyncError::NotPermitted("the lease is no longer valid".into()));
        }
        if lease.holder() != self.our_cert.peer_id {
            return Err(SyncError::NotPermitted("the lease is another device's".into()));
        }
        let version = match self.current_plan(typ, name) {
            Some(p) if p.term > lease.term() => return Err(SyncError::NotPermitted(format!("a newer term ({}) has published", p.term))),
            Some(p) if p.term == lease.term() => p.version + 1,
            _ => 1,
        };
        let inner = encode(&PlanBody { term: lease.term(), version, body: body.to_vec() })?;
        let doc = self.sign_doc(PLAN_DOMAIN, typ, name, inner)?;
        let signer = doc.signer.clone();
        self.write(now_ms, typ, name, &encode(&doc)?)?;
        let hlc = self.clock.clone().ok_or_else(|| SyncError::Protocol("no clock after a write".into()))?;
        Ok(Plan { name: name.into(), term: lease.term(), version, body: body.to_vec(), signer, hlc })
    }

    /// The current plan `name`: the highest `(term, version)` whose signature verifies and whose
    /// signer has an active certificate. HLC only breaks exact ties.
    pub fn current_plan(&self, typ: &str, name: &str) -> Option<Plan> {
        self.current_plan_where(typ, name, |_| true)
    }

    /// [`current_plan`](Self::current_plan) counting only signers `signer_ok` accepts (for
    /// example `|p| roster.has_role(p, "ymir.inference")`).
    pub fn current_plan_where(&self, typ: &str, name: &str, signer_ok: impl Fn(&str) -> bool) -> Option<Plan> {
        self.signed_docs(PLAN_DOMAIN, typ, name)
            .into_iter()
            .filter(|(d, _)| signer_ok(&d.signer))
            .filter_map(|(d, hlc)| {
                let b: PlanBody = decode(&d.body).ok()?;
                Some(Plan { name: name.into(), term: b.term, version: b.version, body: b.body, signer: d.signer, hlc })
            })
            .max_by(|a, b| (a.term, a.version).cmp(&(b.term, b.version)).then_with(|| a.hlc.cmp_total(&b.hlc)))
    }
}
