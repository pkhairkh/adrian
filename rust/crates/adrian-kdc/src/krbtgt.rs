//! # krbtgt key rotation manager (ADR-015)
//!
//! Maintains exactly two HSM-bound krbtgt keys at any time (current + previous),
//! matching AD's dual-krbtgt mode (Server 2012+). The current key is used to
//! issue new TGTs; the previous key is retained for `2 × TGT lifetime` (default
//! 20 hours per ADR-015 §Decision) to validate existing TGTs during the overlap
//! window.
//!
//! ## What's REAL here
//!
//! - `KrbtgtManager::new()` calls `Hsm::generate_key("krbtgt", Aes256)` and
//!   stashes the returned `KeyHandle`.
//! - `rotate()` calls `Hsm::rotate_key("krbtgt")` — the HSM generates fresh
//!   key material and bumps the version. The previous current `KeyHandle` is
//!   demoted to `previous`; the previous-previous (if any) is dropped (the
//!   manager never holds more than 2 keys, per ADR-015 §Decision).
//! - `current_key()` / `previous_key()` are non-async accessors over an
//!   `Arc<Mutex<KrbtgtState>>` — fast-path callers don't await on the HSM.
//!
//! ## What's STUB / deferred
//!
//! - 30-day auto-rotation scheduler (a tokio task that calls `rotate()` on a
//!   timer) is NOT wired here — a future wave's ops layer (`adrian-operator`)
//!   will own the scheduler.
//! - The `kvno` attribute on the directory's `CN=krbtgt` account is NOT
//!   written by this manager — directory writes go through `DirectoryStore::put`
//!   in a future wave that wires `KrbtgtManager` to the storage layer.
//! - The "previous key destruction after 2× TGT lifetime" timer is NOT
//!   enforced — `rotate()` always overwrites `previous` immediately on the
//!   next rotation. ADR-015's retention window assumes a real clock plus
//!   scheduling; the manager simply enforces "exactly 2 keys at any time".
//!
//! ## Async runtime
//!
//! `tokio::sync::Mutex` (not `std::sync::Mutex`) because `rotate()` awaits
//! on the HSM while holding the lock. The critical section is short (one HSM
//! roundtrip + two `KeyHandle` clones), so contention is bounded.

#![forbid(unsafe_code)]

use crate::KdcError;
use adrian_hsm::{Hsm, KeyHandle, KeyType};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default rotation interval for the krbtgt key (ADR-015 §Decision: 30 days).
pub const DEFAULT_ROTATION_INTERVAL_DAYS: u32 = 30;

/// Default TGT lifetime (ADR-015 §Decision: 10 hours). The previous key is
/// retained for 2× TGT lifetime = 20 hours.
pub const DEFAULT_TGT_LIFETIME_HOURS: u32 = 10;

/// krbtgt key ID passed to the HSM. Stable across rotations — the HSM bumps
/// the version on each `rotate_key` call.
pub const KRBGTGT_KEY_ID: &str = "krbtgt";

#[derive(Clone, Debug)]
struct KrbtgtState {
    current: KeyHandle,
    previous: Option<KeyHandle>,
}

/// Manager for the HSM-bound krbtgt key. Wraps an `Arc<dyn Hsm>` and the
/// current/previous key handles. Cloning the manager shares the underlying
/// state (Arc semantics).
#[derive(Clone)]
pub struct KrbtgtManager {
    hsm: Arc<dyn Hsm>,
    state: Arc<Mutex<KrbtgtState>>,
}

impl KrbtgtManager {
    /// Construct a new manager and generate the initial krbtgt key in the HSM.
    /// On success, `current_key().version == 1` and `previous_key()` is `None`.
    pub async fn new(hsm: Arc<dyn Hsm>) -> Result<Self, KdcError> {
        let current = hsm
            .generate_key(KRBGTGT_KEY_ID, KeyType::Aes256)
            .await
            .map_err(|e| KdcError::Storage(format!("hsm generate krbtgt: {e}")))?;
        Ok(Self {
            hsm,
            state: Arc::new(Mutex::new(KrbtgtState {
                current,
                previous: None,
            })),
        })
    }

    /// One-click rotation (ADR-015 §Decision: "atomic: generate new key in
    /// HSM → promote to current → demote previous current to previous →
    /// schedule destruction of previous after 2× TGT lifetime").
    ///
    /// Implementation: the HSM generates fresh key material under the same
    /// `id` and bumps the version; the manager promotes the new handle to
    /// `current` and demotes the old `current` to `previous`. The old
    /// `previous` (if any) is dropped — exactly 2 keys are retained.
    pub async fn rotate(&self) -> Result<(), KdcError> {
        // Await the HSM roundtrip BEFORE taking the lock — minimises the
        // critical section.
        let new_key = self
            .hsm
            .rotate_key(KRBGTGT_KEY_ID)
            .await
            .map_err(|e| KdcError::Storage(format!("hsm rotate krbtgt: {e}")))?;
        let mut state = self.state.lock().await;
        // Demote current → previous (overwriting any existing previous).
        state.previous = Some(state.current.clone());
        state.current = new_key;
        Ok(())
    }

    /// Snapshot of the current krbtgt key handle (used to issue new TGTs).
    /// Cloning the handle is cheap (it's a `String` + `u32` + enum).
    pub async fn current_key(&self) -> KeyHandle {
        self.state.lock().await.current.clone()
    }

    /// Snapshot of the previous krbtgt key handle, if any (used to verify
    /// old TGTs during the 2× TGT lifetime overlap window). Returns `None`
    /// before the first rotation and after the previous key has been
    /// destroyed (the latter is not enforced by this manager — see module
    /// docs).
    pub async fn previous_key(&self) -> Option<KeyHandle> {
        self.state.lock().await.previous.clone()
    }

    /// Number of krbtgt keys currently retained (1 or 2 per ADR-015).
    pub async fn key_count(&self) -> usize {
        let state = self.state.lock().await;
        1 + state.previous.is_some() as usize
    }

    /// Current `kvno` (key version number) — matches AD's `kvno` attribute
    /// on the krbtgt account (ADR-015 §Decision).
    pub async fn kvno(&self) -> u32 {
        self.state.lock().await.current.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_hsm::SoftwareHsm;

    async fn new_manager() -> KrbtgtManager {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        KrbtgtManager::new(hsm).await.expect("manager init")
    }

    /// `new()` generates the initial krbtgt key (version 1, Aes256) and
    /// `previous_key()` is `None` (no rotation has happened yet).
    #[tokio::test]
    async fn new_generates_initial_key_version_1() {
        let mgr = new_manager().await;
        let current = mgr.current_key().await;
        assert_eq!(current.id, KRBGTGT_KEY_ID);
        assert_eq!(current.version, 1, "initial key must be version 1");
        assert_eq!(current.key_type, KeyType::Aes256);
        assert!(
            mgr.previous_key().await.is_none(),
            "no previous before first rotation"
        );
        assert_eq!(mgr.key_count().await, 1);
        assert_eq!(mgr.kvno().await, 1);
    }

    /// First rotation: current → previous, new key becomes current. Exactly
    /// 2 keys are retained (ADR-015 §Decision: "exactly 2 krbtgt keys at any
    /// time").
    #[tokio::test]
    async fn first_rotation_preserves_one_previous_key() {
        let mgr = new_manager().await;
        let old_current = mgr.current_key().await;
        mgr.rotate().await.expect("rotate");

        let new_current = mgr.current_key().await;
        assert_eq!(
            new_current.version,
            old_current.version + 1,
            "version must bump"
        );
        assert_eq!(new_current.id, KRBGTGT_KEY_ID, "id stable across rotation");
        assert_eq!(new_current.key_type, KeyType::Aes256);

        let previous = mgr.previous_key().await.expect("previous must be Some");
        assert_eq!(
            previous.version, old_current.version,
            "previous must be the old current"
        );
        assert_eq!(mgr.key_count().await, 2, "exactly 2 keys retained");
        assert_eq!(mgr.kvno().await, 2);
    }

    /// Second rotation: previous-previous is dropped; the new current becomes
    /// `current`, the just-rotated current becomes `previous`. The manager
    /// never holds more than 2 keys.
    #[tokio::test]
    async fn second_rotation_drops_previous_previous() {
        let mgr = new_manager().await;
        mgr.rotate().await.expect("rotate 1");
        let prev_after_first = mgr.previous_key().await.expect("prev after 1st").version;
        mgr.rotate().await.expect("rotate 2");

        let current = mgr.current_key().await;
        let previous = mgr.previous_key().await.expect("prev after 2nd");
        assert_eq!(current.version, 3, "version 3 after 2nd rotation");
        assert_eq!(
            previous.version,
            prev_after_first + 1,
            "previous is the just-rotated current (v{prev_after_first} → v{})",
            prev_after_first + 1
        );
        assert_eq!(mgr.key_count().await, 2, "still exactly 2 keys");
        // The PREVIOUS key from before the 2nd rotation (v1) must NOT be
        // reachable as `previous` after the 2nd rotation — it's been dropped.
        assert_ne!(
            previous.version, 1,
            "v1 (previous-previous) must be dropped after 2nd rotation"
        );
    }

    /// Three consecutive rotations: the manager always retains exactly 2 keys,
    /// and the kvno tracks the rotation count.
    #[tokio::test]
    async fn three_rotations_retain_exactly_two_keys() {
        let mgr = new_manager().await;
        for expected_kvno in 2..=4 {
            mgr.rotate().await.expect("rotate");
            assert_eq!(mgr.kvno().await, expected_kvno);
            assert_eq!(
                mgr.key_count().await,
                2,
                "exactly 2 keys after rotation {expected_kvno}"
            );
        }
    }
}
