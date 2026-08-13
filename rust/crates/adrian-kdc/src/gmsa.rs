//! # gMSA (Group Managed Service Account) password derivation (ADR-020)
//!
//! Derives gMSA passwords from the HSM-bound KDS root key. The derivation is
//! deterministic — all KDC instances in the realm compute the same password
//! for the same `(root_key, gMSA_DN, cycle)` triple (ADR-020 §Decision).
//!
//! ## What's REAL here
//!
//! - `GmsaManager::new()` generates a KDS root key in the HSM with `KeyType::HmacSha1`.
//! - `current_cycle()` returns `floor(unix_time / rotation_interval_seconds)`
//!   — the same cycle for all KDCs at the same wall-clock time.
//! - `compute_gmsa_password()` derives a 32-byte password via SP800-108 KDF
//!   in HMAC-SHA1 counter mode (NIST SP800-108 §5.1) using the HSM's `sign`
//!   operation. The output is the raw bytes — callers encode as needed
//!   (hex / base64 / UTF-16-LE for the NT hash) per MS-ADTS §2.2.20.
//!
//! ## What's STUB / deferred vs. real AD
//!
//! - AD's actual KDS derivation uses a custom algorithm documented in
//!   MS-ADTS §2.2.20 that involves the gMSA's SID (not DN), the cycle
//!   timestamp (not a counter), and a 32-byte output split into 4 quarters
//!   with specific bit-mixing. Matching AD byte-for-byte for AD-interop is
//!   out of scope for this wave (requires reverse-engineering — see
//!   ADR-020 §Open Questions). The derivation here is a real, standardised
//!   KDF (SP800-108) using real HMAC-SHA1 via the HSM.
//! - The `EffectiveTime` trick (`now + 10 hours`, ADR-020 §Decision) is NOT
//!   enforced — `new()` accepts the root key immediately. A future wave's
//!   `kds-add-root-key` CLI will enforce the 10-hour delay.
//! - The host ACL (`msDS-GroupMSAMembership`) is NOT enforced here —
//!   `compute_gmsa_password` does not check the caller's group membership.
//!   The directory-service layer enforces the ACL on the password-fetch RPC.
//! - The MS-NRPC password-fetch protocol (`NetrServerRetrieveBaseDelta`) is
//!   NOT implemented — this module exposes only the in-process derivation.

#![forbid(unsafe_code)]

use crate::KdcError;
use adrian_hsm::{Hsm, KeyHandle, KeyType};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// KDS root key ID passed to the HSM (stable across rotations).
pub const KDS_ROOT_KEY_ID: &str = "kds-root";

/// Default rotation interval (ADR-020 §Decision: 30 days).
pub const DEFAULT_ROTATION_INTERVAL_DAYS: u64 = 30;

/// Output length of the derived gMSA password (32 bytes). AD uses 256 bits
/// (32 bytes) — matches.
pub const GMSA_PASSWORD_LEN: usize = 32;

/// gMSA manager. Holds the HSM-bound KDS root key handle. Cloning shares
/// the underlying state (Arc semantics).
#[derive(Clone)]
pub struct GmsaManager {
    hsm: Arc<dyn Hsm>,
    kds_root_key: KeyHandle,
    rotation_interval_secs: u64,
}

impl std::fmt::Debug for GmsaManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmsaManager")
            .field("kds_root_key", &self.kds_root_key)
            .field("rotation_interval_secs", &self.rotation_interval_secs)
            .finish()
    }
}

impl GmsaManager {
    /// Construct a new gMSA manager and generate the KDS root key in the HSM.
    /// `interval_days` must be in `[1, 90]` (ADR-020 §Decision: "minimum 1
    /// day, maximum 90 days").
    pub async fn new(hsm: Arc<dyn Hsm>, interval_days: u64) -> Result<Self, KdcError> {
        if !(1..=90).contains(&interval_days) {
            return Err(KdcError::Policy(format!(
                "gMSA rotation interval {interval_days} days out of range [1, 90]"
            )));
        }
        let kds_root_key = hsm
            .generate_key(KDS_ROOT_KEY_ID, KeyType::HmacSha1)
            .await
            .map_err(|e| KdcError::Storage(format!("hsm generate kds-root: {e}")))?;
        Ok(Self {
            hsm,
            kds_root_key,
            rotation_interval_secs: interval_days * 86_400,
        })
    }

    /// Wrap an existing KDS root key handle (used by callers that loaded the
    /// handle from durable storage).
    pub fn with_root_key(hsm: Arc<dyn Hsm>, root_key: KeyHandle, interval_days: u64) -> Result<Self, KdcError> {
        if !(1..=90).contains(&interval_days) {
            return Err(KdcError::Policy(format!(
                "gMSA rotation interval {interval_days} days out of range [1, 90]"
            )));
        }
        Ok(Self {
            hsm,
            kds_root_key: root_key,
            rotation_interval_secs: interval_days * 86_400,
        })
    }

    /// Current cycle (epoch aligned to `rotation_interval_secs`-day intervals
    /// per ADR-020 §Decision). All KDCs in the realm compute the same cycle
    /// for the same wall-clock time.
    pub fn current_cycle(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // floor(now / interval)
        now / self.rotation_interval_secs
    }

    /// Derive the gMSA password for the given cycle. Uses SP800-108 KDF in
    /// HMAC-SHA1 counter mode (NIST SP800-108 §5.1):
    ///
    /// ```text
    /// K(1) = HMAC-SHA1-96(root_key, [counter=1] || label || 0x00 || context || [L=256 bits])
    /// K(2) = HMAC-SHA1-96(root_key, [counter=2] || label || 0x00 || context || [L=256 bits])
    /// password = K(1) || K(2) || ... truncated to 32 bytes
    /// ```
    ///
    /// where:
    /// - `label`    = b"adrian-gmsa"
    /// - `context`  = `gmsa_dn` || `cycle` (big-endian u64)
    /// - `L`        = 256 (output length in bits)
    ///
    /// `HmacSha1` keys produce 12-byte HMAC-SHA1-96 signatures (per
    /// `SoftwareHsm::sign`), so we need 3 iterations (3 × 12 = 36 bytes),
    /// truncated to 32.
    pub async fn compute_gmsa_password(
        &self,
        gmsa_dn: &str,
        cycle: u64,
    ) -> Result<Vec<u8>, KdcError> {
        let label: &[u8] = b"adrian-gmsa";
        // Build the context portion (fixed across iterations).
        let mut context = Vec::with_capacity(gmsa_dn.len() + 8);
        context.extend_from_slice(gmsa_dn.as_bytes());
        context.extend_from_slice(&cycle.to_be_bytes());
        // L = 256 bits (big-endian u32 per SP800-108).
        let l_bits: u32 = (GMSA_PASSWORD_LEN * 8) as u32;

        let mut out = Vec::with_capacity(GMSA_PASSWORD_LEN);
        let mut counter: u32 = 1;
        while out.len() < GMSA_PASSWORD_LEN {
            // K(i) = HMAC(root_key, [i:4 BE] || label || 0x00 || context || [L:4 BE])
            let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(label);
            input.push(0x00);
            input.extend_from_slice(&context);
            input.extend_from_slice(&l_bits.to_be_bytes());
            let block = self
                .hsm
                .sign(&self.kds_root_key, &input)
                .await
                .map_err(|e| KdcError::Storage(format!("hsm sign gmsa block: {e}")))?;
            out.extend_from_slice(&block);
            counter = counter.saturating_add(1);
            // Safety bound — avoid infinite loop on a misbehaving HSM.
            if counter > 64 {
                return Err(KdcError::Storage(
                    "gMSA KDF exceeded 64 iterations (HSM misbehaving?)".into(),
                ));
            }
        }
        out.truncate(GMSA_PASSWORD_LEN);
        Ok(out)
    }

    /// Convenience: derive the password for the CURRENT cycle.
    pub async fn compute_current_password(&self, gmsa_dn: &str) -> Result<Vec<u8>, KdcError> {
        let cycle = self.current_cycle();
        self.compute_gmsa_password(gmsa_dn, cycle).await
    }

    /// Accessor: the KDS root key handle (for diagnostics / status).
    pub fn root_key_handle(&self) -> &KeyHandle {
        &self.kds_root_key
    }

    /// Accessor: the rotation interval in seconds.
    pub fn rotation_interval_secs(&self) -> u64 {
        self.rotation_interval_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_hsm::SoftwareHsm;

    async fn new_manager(interval_days: u64) -> GmsaManager {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        GmsaManager::new(hsm, interval_days).await.expect("manager init")
    }

    /// `current_cycle()` advances predictably: at time T and T + interval, the
    /// cycle is `floor(T/interval)` and `floor((T+interval)/interval)`. We
    /// can't pin wall-clock time in a unit test, but we CAN assert that two
    /// calls ~0 ms apart produce the same cycle (deterministic within a
    /// cycle) and that the interval is correctly set.
    #[tokio::test]
    async fn current_cycle_is_deterministic_within_call_pair() {
        let mgr = new_manager(DEFAULT_ROTATION_INTERVAL_DAYS).await;
        let c1 = mgr.current_cycle();
        // Two back-to-back calls must produce the same cycle (the rotation
        // interval is 30 days = 2_592_000 seconds; sub-millisecond gap).
        let c2 = mgr.current_cycle();
        assert_eq!(
            c1, c2,
            "back-to-back current_cycle() calls must agree (interval={}s)",
            mgr.rotation_interval_secs()
        );
    }

    /// The password is deterministic for the same `(root_key, dn, cycle)` —
    /// this is the ADR-020 §Decision invariant: "all DCs compute the same
    /// password for the same gMSA at the same point in time".
    #[tokio::test]
    async fn password_is_deterministic_for_same_inputs() {
        let mgr = new_manager(DEFAULT_ROTATION_INTERVAL_DAYS).await;
        let dn = "CN=svc-web,CN=Managed Service Accounts,DC=adrian,DC=example,DC=com";
        let p1 = mgr.compute_gmsa_password(dn, 42).await.expect("derive 1");
        let p2 = mgr.compute_gmsa_password(dn, 42).await.expect("derive 2");
        assert_eq!(p1.len(), GMSA_PASSWORD_LEN, "password length is 32 bytes");
        assert_eq!(
            p1, p2,
            "same (root_key, dn, cycle) MUST produce the same password"
        );
    }

    /// The password differs for different cycles (rotation is effective —
    /// an attacker who captures a TGS for cycle N has at most one rotation
    /// interval to crack before the password changes, per ADR-020 §Rationale).
    #[tokio::test]
    async fn password_differs_across_cycles() {
        let mgr = new_manager(DEFAULT_ROTATION_INTERVAL_DAYS).await;
        let dn = "CN=svc-web,CN=Managed Service Accounts,DC=adrian,DC=example,DC=com";
        let p_n = mgr.compute_gmsa_password(dn, 100).await.expect("derive cycle 100");
        let p_n1 = mgr.compute_gmsa_password(dn, 101).await.expect("derive cycle 101");
        assert_ne!(
            p_n, p_n1,
            "password MUST change across cycles (rotation is cryptographically effective)"
        );
    }

    /// The password differs for different gMSA DNs (each service account gets
    /// a distinct password derived from the same root key).
    #[tokio::test]
    async fn password_differs_across_gmsa_dns() {
        let mgr = new_manager(DEFAULT_ROTATION_INTERVAL_DAYS).await;
        let cycle = 7;
        let p1 = mgr
            .compute_gmsa_password("CN=svc-a,CN=MSA,DC=adrian,DC=com", cycle)
            .await
            .expect("derive a");
        let p2 = mgr
            .compute_gmsa_password("CN=svc-b,CN=MSA,DC=adrian,DC=com", cycle)
            .await
            .expect("derive b");
        assert_ne!(p1, p2, "different gMSAs must produce different passwords");
    }

    /// Different root keys produce different passwords (HSM root-key
    /// rotation invalidates all derived gMSA passwords — security property).
    #[tokio::test]
    async fn different_root_keys_produce_different_passwords() {
        let hsm1: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let hsm2: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let mgr1 = GmsaManager::new(hsm1.clone(), DEFAULT_ROTATION_INTERVAL_DAYS).await.unwrap();
        let mgr2 = GmsaManager::new(hsm2.clone(), DEFAULT_ROTATION_INTERVAL_DAYS).await.unwrap();
        let dn = "CN=svc,CN=MSA,DC=adrian,DC=com";
        let cycle = 5;
        let p1 = mgr1.compute_gmsa_password(dn, cycle).await.unwrap();
        let p2 = mgr2.compute_gmsa_password(dn, cycle).await.unwrap();
        assert_ne!(p1, p2, "different root keys MUST produce different passwords");
    }

    /// Interval out of range (< 1 day) is rejected (ADR-020 §Decision: 1–90 days).
    #[tokio::test]
    async fn interval_below_one_day_rejected() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let err = GmsaManager::new(hsm, 0).await.expect_err("interval=0");
        match err {
            KdcError::Policy(msg) => assert!(msg.contains("out of range"), "{msg}"),
            other => panic!("expected Policy error, got {other:?}"),
        }
    }

    /// Interval above 90 days is rejected (ADR-020 §Decision: 1–90 days).
    #[tokio::test]
    async fn interval_above_90_days_rejected() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let err = GmsaManager::new(hsm, 91).await.expect_err("interval=91");
        assert!(matches!(err, KdcError::Policy(_)), "{err:?}");
    }
}
