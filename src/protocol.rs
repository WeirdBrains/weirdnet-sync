//! `weirdnet-sync/v1` messages and length-prefixed CBOR framing.
//!
//! After the authenticated channel is up, payloads that carry records, cursors or
//! certificates are sealed under [`crate::sync_key`]. An [`Envelope`] carries the type and
//! epoch in the clear so the receiver can pick the key; the body is sealed.
use crate::error::{Result, SyncError};
use crate::hlc::{Hlc, NodeId};
use crate::log::{LogEntry, Page as LogPage};
use crate::rotation::KeyChain;
use crate::seal::{open_page, page_aad_keyed, rotated_sync_key, seal_page, sync_key};
use serde::{Deserialize, Serialize};
use weirdnet_keys::{Key32, Sealed};
use weirdnet_net::profile::{Profile, WEIRDNET};
use weirdnet_net::user::NodeCert;
use zeroize::Zeroizing;

/// Request-response protocol id, same style as `/weirdnet/link/1`.
pub const PROTOCOL: &str = "/weirdnet/sync/1";

/// Largest sealed page (and the reply cap to set on a sync node). Still under weirdnet-net's 8 MiB default.
pub const PAGE_MAX: usize = 256 * 1024;

/// Identifier profile: `/weirdnet/sync/1` for request-response, otherwise [`WEIRDNET`].
pub static SYNC_PROFILE: Profile = Profile { protocol: PROTOCOL, thread: "weirdnet-sync", ..WEIRDNET };

/// Last seq applied from each node, as sent in Hello.
pub type Cursors = Vec<(NodeId, u64)>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub cert: NodeCert,
    pub user_id: String,
    pub epoch: u32,
    pub types: Vec<String>,
    pub our_cursors: Cursors,
    pub our_hlc: Hlc,
    /// The sender's key chain, so device keys and rotations spread. Absent from 0.2.
    #[serde(default)]
    pub chain: KeyChain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloOk {
    pub cert: NodeCert,
    pub epoch: u32,
    pub cursors: Cursors,
    pub revocations: Vec<NodeCert>,
    #[serde(default)]
    pub chain: KeyChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refuse {
    pub reason: String,
}

impl Refuse {
    pub fn new(reason: &'static str) -> Self {
        Self { reason: reason.into() }
    }
}

pub type RefuseReason = Refuse;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pull {
    pub node_id: NodeId,
    pub after_seq: u64,
    pub typ: String,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub typ: String,
    pub page: LogPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub node_id: NodeId,
    pub last_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RosterMsg {
    pub certs: Vec<NodeCert>,
    pub epoch: u32,
    /// Device keys, rotations (with the sealed epoch keys) and admissions.
    #[serde(default)]
    pub chain: KeyChain,
}

/// Application-level message, before sealing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Message {
    Hello(Hello),
    HelloOk(HelloOk),
    Refuse(Refuse),
    Pull(Pull),
    Page(Page),
    Ack(Ack),
    Roster(RosterMsg),
}

/// What goes on the request-response wire: type, epoch and (after a rotation) the
/// rotation id in the clear, body sealed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub typ: String,
    pub epoch: u32,
    /// Rotation id of the epoch key; `None` for the seed-derived key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub sealed: Sealed,
}

/// Which key an envelope is sealed under: the seed-derived one at `epoch`, or the
/// rotated one with this id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    pub epoch: u32,
    pub id: Option<String>,
}

impl KeyRef {
    pub fn seed(epoch: u32) -> Self {
        Self { epoch, id: None }
    }
}

impl Envelope {
    /// Seal under a rotated epoch key (rotation `id`).
    pub fn seal_keyed(epoch_key: &Key32, id: &str, user_id: &str, typ: &str, epoch: u32, asking_peer: &str, msg: &Message) -> Result<Self> {
        let key = rotated_sync_key(epoch_key, user_id, typ, epoch, id)?;
        let plain = encode(msg)?;
        let sealed = weirdnet_keys::seal(&key, &plain, &page_aad_keyed(typ, epoch, id, asking_peer))?;
        Ok(Self { typ: typ.into(), epoch, key: Some(id.into()), sealed })
    }

    pub fn open_keyed(&self, epoch_key: &Key32, user_id: &str, asking_peer: &str) -> Result<Message> {
        let id = self.key.as_deref().ok_or_else(|| SyncError::Crypto("not sealed under a rotated key".into()))?;
        let key = rotated_sync_key(epoch_key, user_id, &self.typ, self.epoch, id)?;
        let plain: Zeroizing<Vec<u8>> = weirdnet_keys::open(&key, &self.sealed, &page_aad_keyed(&self.typ, self.epoch, id, asking_peer))?;
        decode(&plain)
    }

    pub fn seal(seed: &[u8], user_id: &str, typ: &str, epoch: u32, asking_peer: &str, msg: &Message) -> Result<Self> {
        let key = sync_key(seed, user_id, typ, epoch)?;
        let plain = encode(msg)?;
        let sealed = seal_page(&key, typ, epoch, asking_peer, &plain)?;
        Ok(Self { typ: typ.into(), epoch, key: None, sealed })
    }

    /// Open a seed-sealed envelope. One sealed under a rotated key fails here.
    pub fn open(&self, seed: &[u8], user_id: &str, asking_peer: &str) -> Result<Message> {
        if self.key.is_some() {
            return Err(SyncError::Crypto("sealed under a rotated key".into()));
        }
        let key = sync_key(seed, user_id, &self.typ, self.epoch)?;
        let plain: Zeroizing<Vec<u8>> = open_page(&key, &self.typ, self.epoch, asking_peer, &self.sealed)?;
        decode(&plain)
    }
}

/// Length-prefixed CBOR (u32 big-endian length, then the item). For a raw stream;
/// `Node::request` already frames [`Envelope`] as CBOR through libp2p.
pub fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    cbor4ii::serde::to_vec(Vec::new(), v).map_err(|e| SyncError::Codec(e.to_string()))
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    cbor4ii::serde::from_slice(bytes).map_err(|e| SyncError::Codec(e.to_string()))
}

pub fn encode_framed<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let body = encode(v)?;
    if body.len() > u32::MAX as usize {
        return Err(SyncError::Codec("frame too large".into()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_framed<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    if bytes.len() < 4 {
        return Err(SyncError::Codec("short frame".into()));
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if bytes.len() != 4 + n {
        return Err(SyncError::Codec(format!("frame length {n} does not match {}", bytes.len().saturating_sub(4))));
    }
    decode(&bytes[4..])
}

/// Build a `Page` message from a log page, dropping ops whose typ does not match (they
/// stay in the log for a later pull of that type).
pub fn page_for_type(typ: &str, page: LogPage) -> Page {
    let ops: Vec<LogEntry> = page.ops.into_iter().filter(|e| e.typ == typ).collect();
    let from_seq = ops.first().map(|e| e.seq).unwrap_or(page.from_seq);
    let to_seq = ops.last().map(|e| e.seq).unwrap_or(page.to_seq);
    Page { typ: typ.into(), page: LogPage { node_id: page.node_id, from_seq, to_seq, ops } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::roster::Roster;
    use weirdnet_net::Keypair;
    use weirdnet_net::user;

    const SEED: [u8; 32] = *b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    fn hello() -> (Message, String, Keypair) {
        let u = Keypair::generate_ed25519();
        let uid = user::user_id(&u.public());
        let cert = Roster::self_certify(&WEIRDNET, &u, "peer-a", "a", 1).unwrap();
        let msg = Message::Hello(Hello {
            cert,
            user_id: uid.clone(),
            epoch: 0,
            types: vec!["bookmarks".into()],
            our_cursors: vec![(NodeId::new("peer-a"), 3)],
            our_hlc: Hlc::new(10, 0, NodeId::new("peer-a")),
            chain: Default::default(),
        });
        (msg, uid, u)
    }

    #[test]
    fn framed_cbor_round_trips_and_rejects_a_truncated_frame() {
        let (msg, _, _) = hello();
        let bytes = encode_framed(&msg).unwrap();
        assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize, bytes.len() - 4);
        let back: Message = decode_framed(&bytes).unwrap();
        assert_eq!(back, msg);
        assert!(decode_framed::<Message>(&bytes[..3]).is_err());
        assert!(decode_framed::<Message>(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn a_sealed_hello_opens_for_the_same_seed_and_user_only() {
        let (msg, uid, _) = hello();
        let env = Envelope::seal(&SEED, &uid, "bookmarks", 0, "peer-b", &msg).unwrap();
        let opened = env.open(&SEED, &uid, "peer-b").unwrap();
        assert_eq!(opened, msg);
        assert!(env.open(&SEED, "other-user", "peer-b").is_err());
        assert!(env.open(&SEED, &uid, "peer-c").is_err());
        assert!(Envelope { typ: "history".into(), ..env.clone() }.open(&SEED, &uid, "peer-b").is_err());
    }
}
