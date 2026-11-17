//! `SyncKey` derivation and page sealing.
//!
//! `SyncKey(type) = HKDF-SHA256(seed, salt = user id, info = weirdnet-sync/v1/<type>)`,
//! or `weirdnet-sync/v1/<type>/e<n>` after a revocation bumps the epoch.
use crate::error::Result;
use weirdnet_keys::{Key32, Sealed, kdf, open, seal};

/// Common record types; the wire also accepts any other application string.
pub mod typ {
    pub const BOOKMARKS: &str = "bookmarks";
    pub const HISTORY: &str = "history";
    pub const SETTINGS: &str = "settings";
}

pub use typ as SyncType;

/// A derived page-sealing key. Zeroized on drop via [`Key32`].
pub type SyncKey = Key32;

/// HKDF info string for this type and epoch (`e0` is omitted: `weirdnet-sync/v1/<type>`).
pub fn sync_key_info(typ: &str, epoch: u32) -> String {
    if epoch == 0 { format!("weirdnet-sync/v1/{typ}") } else { format!("weirdnet-sync/v1/{typ}/e{epoch}") }
}

/// Derive `SyncKey(type)` from the identity seed. The seed is not stored.
pub fn sync_key(seed: &[u8], user_id: &str, typ: &str, epoch: u32) -> Result<SyncKey> {
    let info = sync_key_info(typ, epoch);
    Ok(kdf::hkdf(seed, Some(user_id.as_bytes()), info.as_bytes())?)
}

/// Associated data of a sealed page: type, epoch and the asking peer, so a page cannot
/// be replayed under another type, epoch or peer.
pub fn page_aad(typ: &str, epoch: u32, peer: &str) -> Vec<u8> {
    format!("weirdnet-sync/v1|{typ}|e{epoch}|{peer}").into_bytes()
}

pub fn seal_page(key: &SyncKey, typ: &str, epoch: u32, peer: &str, plaintext: &[u8]) -> Result<Sealed> {
    Ok(seal(key, plaintext, &page_aad(typ, epoch, peer))?)
}

pub fn open_page(key: &SyncKey, typ: &str, epoch: u32, peer: &str, sealed: &Sealed) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(open(key, sealed, &page_aad(typ, epoch, peer))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn typed_keys_differ_by_type_user_epoch_and_seed() {
        let a = sync_key(&SEED, "user-1", typ::BOOKMARKS, 0).unwrap();
        let b = sync_key(&SEED, "user-1", typ::HISTORY, 0).unwrap();
        let c = sync_key(&SEED, "user-2", typ::BOOKMARKS, 0).unwrap();
        let d = sync_key(&SEED, "user-1", typ::BOOKMARKS, 1).unwrap();
        let e = sync_key(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "user-1", typ::BOOKMARKS, 0).unwrap();
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, c.0);
        assert_ne!(a.0, d.0);
        assert_ne!(a.0, e.0);
        assert_eq!(sync_key_info(typ::BOOKMARKS, 0), "weirdnet-sync/v1/bookmarks");
        assert_eq!(sync_key_info(typ::BOOKMARKS, 3), "weirdnet-sync/v1/bookmarks/e3");
        // Same inputs, same key (two devices with the same seed).
        assert_eq!(sync_key(&SEED, "user-1", typ::BOOKMARKS, 0).unwrap().0, a.0);
    }

    #[test]
    fn a_page_opens_only_with_the_matching_key_aad() {
        let key = sync_key(&SEED, "user-1", typ::BOOKMARKS, 0).unwrap();
        let sealed = seal_page(&key, typ::BOOKMARKS, 0, "peer-b", b"ops").unwrap();
        let plain = open_page(&key, typ::BOOKMARKS, 0, "peer-b", &sealed).unwrap();
        assert_eq!(&plain[..], b"ops");
        assert!(open_page(&key, typ::HISTORY, 0, "peer-b", &sealed).is_err());
        assert!(open_page(&key, typ::BOOKMARKS, 0, "peer-c", &sealed).is_err());
        assert!(open_page(&key, typ::BOOKMARKS, 1, "peer-b", &sealed).is_err());
        let other = sync_key(&SEED, "user-1", typ::BOOKMARKS, 1).unwrap();
        assert!(open_page(&other, typ::BOOKMARKS, 1, "peer-b", &sealed).is_err());
    }
}
