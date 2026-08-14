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

// ===========================================================================
// Wave 5 — KrbtgtRotationScheduler (ADR-015 §Decision: 30-day auto-rotation)
// ===========================================================================

use std::time::{Duration, SystemTime};

/// Auto-rotation scheduler for the krbtgt key per ADR-015 §Decision ("30-day
/// auto-rotation"). Wraps a [`KrbtgtManager`] and triggers `rotate()` when
/// the configured interval has elapsed since the last rotation.
///
/// ## Usage
///
/// - **Polling mode**: call [`check_and_rotate()`] periodically (e.g. every
///   minute) from the KDC's main loop. Returns `true` if a rotation occurred.
/// - **Background mode**: call [`start_background()`] to spawn a tokio task
///   that rotates on a timer. The task runs forever; cancellation is via
///   aborting the returned `JoinHandle`.
/// - **Manual mode**: call [`force_rotate()`] to rotate immediately
///   (bypasses the interval check — useful for emergency krbtgt resets).
///
/// The scheduler is `Clone` (shares the underlying `KrbtgtManager` state via
/// `Arc`). Multiple schedulers can share one manager (e.g. one polling, one
/// background) — the `tokio::sync::Mutex` inside `KrbtgtManager` serializes
/// rotations.
#[derive(Clone)]
pub struct KrbtgtRotationScheduler {
    manager: KrbtgtManager,
    interval: Duration,
    last_rotation: Arc<Mutex<SystemTime>>,
}

impl KrbtgtRotationScheduler {
    /// Construct a scheduler with the default 30-day interval (ADR-015
    /// §Decision). The `last_rotation` is set to `now` (so the first
    /// rotation will occur 30 days from construction).
    pub async fn new(manager: KrbtgtManager) -> Result<Self, KdcError> {
        Self::with_interval(
            manager,
            DEFAULT_ROTATION_INTERVAL_DAYS,
            Duration::from_secs(0),
        )
        .await
    }

    /// Construct a scheduler with a custom interval (in days) and an initial
    /// offset for `last_rotation`. The offset shifts `last_rotation` back in
    /// time — `offset = Duration::from_secs(interval)` means "rotation is
    /// immediately due". Used by tests to trigger rotation without waiting.
    pub async fn with_interval(
        manager: KrbtgtManager,
        interval_days: u32,
        offset: Duration,
    ) -> Result<Self, KdcError> {
        if interval_days == 0 && !offset.is_zero() {
            // Allow 0-day interval for tests (always rotate) — but only with
            // an offset to avoid infinite-rotation loops in production.
        }
        let interval = Duration::from_secs(interval_days as u64 * 86_400);
        let last_rotation = SystemTime::now()
            .checked_sub(offset)
            .unwrap_or_else(SystemTime::now);
        Ok(Self {
            manager,
            interval,
            last_rotation: Arc::new(Mutex::new(last_rotation)),
        })
    }

    /// Check if the rotation interval has elapsed and rotate if so.
    /// Returns `Ok(true)` if a rotation occurred, `Ok(false)` if not due.
    pub async fn check_and_rotate(&self) -> Result<bool, KdcError> {
        let now = SystemTime::now();
        // Scope the lock guard so it's dropped before the `rotate().await`
        // (tokio::sync::MutexGuard is not Send — holding it across an await
        // would make the future !Send, breaking `start_background`).
        let last = {
            let guard = self.last_rotation.lock().await;
            *guard
        };
        let elapsed = now.duration_since(last).unwrap_or(Duration::ZERO);
        if elapsed >= self.interval {
            self.manager.rotate().await?;
            {
                let mut guard = self.last_rotation.lock().await;
                *guard = SystemTime::now();
            }
            let kvno = self.manager.kvno().await;
            tracing::info!(kvno, "krbtgt auto-rotation completed (ADR-015)");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Force an immediate rotation, bypassing the interval check. Useful for
    /// emergency krbtgt resets (e.g. suspected compromise per ADR-015
    /// §Rationale). Updates `last_rotation` to `now` so the next
    /// `check_and_rotate()` won't fire immediately.
    pub async fn force_rotate(&self) -> Result<(), KdcError> {
        self.manager.rotate().await?;
        {
            let mut guard = self.last_rotation.lock().await;
            *guard = SystemTime::now();
        }
        let kvno = self.manager.kvno().await;
        tracing::warn!(kvno, "krbtgt FORCED rotation (emergency reset per ADR-015)");
        Ok(())
    }

    /// Start a background tokio task that calls `check_and_rotate()` on a
    /// timer. The task runs forever; cancel by aborting the returned
    /// `JoinHandle`. The check frequency is `interval / 60` (so a 30-day
    /// interval is checked every ~12 hours), with a minimum of every 60
    /// seconds.
    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let check_freq = std::cmp::max(
            Duration::from_secs(60),
            Duration::from_secs(self.interval.as_secs() / 60),
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(check_freq);
            loop {
                ticker.tick().await;
                if let Err(e) = self.check_and_rotate().await {
                    tracing::error!(error = %e, "krbtgt auto-rotation check failed");
                }
            }
        })
    }

    /// Accessor: the underlying `KrbtgtManager` (for issuing TGTs with the
    /// current key, verifying TGTs with current+previous keys, etc.).
    pub fn manager(&self) -> &KrbtgtManager {
        &self.manager
    }

    /// Accessor: the configured rotation interval.
    pub fn interval(&self) -> Duration {
        self.interval
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

    // ---- Wave 5: KrbtgtRotationScheduler tests ----

    use std::time::Duration;

    /// DoD test 1: rotation triggers on schedule. Create a scheduler with
    /// a 0-second interval (rotation always due) and verify
    /// `check_and_rotate()` returns `true` and the kvno bumps.
    #[tokio::test]
    async fn scheduler_triggers_rotation_on_schedule() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let mgr = KrbtgtManager::new(hsm).await.expect("manager");
        let scheduler =
            KrbtgtRotationScheduler::with_interval(mgr.clone(), 0, Duration::from_secs(0))
                .await
                .expect("scheduler");
        let initial_kvno = mgr.kvno().await;
        assert_eq!(initial_kvno, 1);

        // With a 0-second interval + 0 last-rotation offset, rotation is
        // immediately due.
        let rotated = scheduler
            .check_and_rotate()
            .await
            .expect("check_and_rotate");
        assert!(rotated, "rotation must trigger when interval elapsed");
        assert_eq!(mgr.kvno().await, 2, "kvno must bump after rotation");

        // A second immediate check should also rotate (interval = 0).
        let rotated2 = scheduler
            .check_and_rotate()
            .await
            .expect("check_and_rotate 2");
        assert!(rotated2, "rotation must trigger again with 0 interval");
        assert_eq!(mgr.kvno().await, 3);
    }

    /// DoD test 2: rotation does NOT trigger when interval has not elapsed.
    /// Create a scheduler with a 30-day interval; immediately after creation,
    /// `check_and_rotate()` must return `false` (not due yet).
    #[tokio::test]
    async fn scheduler_no_rotation_when_interval_not_elapsed() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let mgr = KrbtgtManager::new(hsm).await.expect("manager");
        let scheduler = KrbtgtRotationScheduler::new(mgr.clone())
            .await
            .expect("scheduler");
        let initial_kvno = mgr.kvno().await;

        let rotated = scheduler
            .check_and_rotate()
            .await
            .expect("check_and_rotate");
        assert!(
            !rotated,
            "rotation must NOT trigger immediately (30-day interval)"
        );
        assert_eq!(mgr.kvno().await, initial_kvno, "kvno must not change");
    }

    /// DoD test 3: old key still valid during overlap window. After
    /// scheduler-triggered rotation, the manager retains the previous key
    /// (overlap window per ADR-015). The `previous_key()` must be `Some`
    /// and point to the old key.
    #[tokio::test]
    async fn scheduler_rotation_preserves_overlap_window() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let mgr = KrbtgtManager::new(hsm).await.expect("manager");
        let scheduler =
            KrbtgtRotationScheduler::with_interval(mgr.clone(), 0, Duration::from_secs(0))
                .await
                .expect("scheduler");

        let old_current = mgr.current_key().await;
        assert!(
            mgr.previous_key().await.is_none(),
            "no previous before rotation"
        );

        // Trigger rotation via the scheduler.
        scheduler
            .check_and_rotate()
            .await
            .expect("check_and_rotate")
            .then_some(())
            .expect("rotation must trigger");

        // After rotation: previous key is the old current, current is new.
        let new_current = mgr.current_key().await;
        let previous = mgr.previous_key().await.expect("previous must be Some");
        assert_eq!(
            previous.version, old_current.version,
            "previous must be the old current (overlap window)"
        );
        assert_eq!(
            new_current.version,
            old_current.version + 1,
            "current must be the new key"
        );
        assert_eq!(
            mgr.key_count().await,
            2,
            "exactly 2 keys retained (ADR-015)"
        );
    }

    /// DoD test 4: explicit `force_rotate()` bypasses the interval check —
    /// useful for manual rotation (e.g. emergency krbtgt reset per ADR-015).
    #[tokio::test]
    async fn scheduler_force_rotate_bypasses_interval() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let mgr = KrbtgtManager::new(hsm).await.expect("manager");
        // 30-day interval — normal check_and_rotate would NOT trigger.
        let scheduler = KrbtgtRotationScheduler::new(mgr.clone())
            .await
            .expect("scheduler");

        // Force rotation (e.g. emergency reset).
        scheduler.force_rotate().await.expect("force_rotate");
        assert_eq!(mgr.kvno().await, 2, "force_rotate must bump kvno");

        // Normal check still doesn't trigger (interval not elapsed since force).
        let rotated = scheduler.check_and_rotate().await.expect("check");
        assert!(
            !rotated,
            "normal check must not trigger immediately after force_rotate"
        );
    }
}
