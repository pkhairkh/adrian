//! # gMSA (Group Managed Service Account) password derivation (ADR-020)
//!
//! Derives gMSA passwords from the KDS root key. The derivation is
//! deterministic — all KDC instances in the realm compute the same password
//! for the same `(root_key, gMSA_DN, cycle)` triple (ADR-020 §Decision).
//!
//! ## What's REAL here (v0.8.0 — SP800-108 §5.1 fix)
//!
//! - `GmsaManager::new()` generates a 20-byte KDS root key (full HMAC-SHA1
//!   key length) using `ring::rand::SystemRandom`.
//! - `current_cycle()` returns `floor(unix_time / rotation_interval_seconds)`
//!   — the same cycle for all KDCs at the same wall-clock time.
//! - `compute_gmsa_password()` derives a 32-byte password via SP800-108 KDF
//!   in HMAC-SHA1 counter mode (NIST SP800-108 §5.1) using the **full
//!   20-byte HMAC-SHA1 output** per block (v0.7.0 bug fix: previously used
//!   the 12-byte HMAC-SHA1-96 truncation from the HSM's `sign` operation,
//!   which is the RFC 3961 checksum profile — NOT the SP800-108 PRF).
//!   The output is the raw bytes — callers encode as needed (hex / base64 /
//!   UTF-16-LE for the NT hash) per MS-ADTS §2.2.20.
//!
//! ## v0.8.0 KDF fix (SP800-108 §5.1 compliance)
//!
//! The v0.7.0 implementation used `Hsm::sign()` with an `HmacSha1` key,
//! which returns the 12-byte HMAC-SHA1-96 truncation (RFC 3961 checksum
//! profile). SP800-108 §5.1 requires the **full** PRF output as the KDF
//! block — for HMAC-SHA1, that's 20 bytes per block. The v0.8.0 fix holds
//! the raw 20-byte KDS root key material in the manager and computes
//! HMAC-SHA1 directly via the `hmac` + `sha1` crates (already workspace
//! dependencies), producing 20-byte blocks. This is the spec-compliant
//! SP800-108 counter-mode KDF.
//!
//! The HSM-binding (ADR-020 §Decision: "KDS root key is HSM-bound") is
//! temporarily relaxed in v0.8.0 — the key material lives in process memory
//! (same security posture as the `SoftwareHsm`, which also stores keys in
//! plaintext process memory per the adrian-hsm docs). A future wave will
//! re-introduce HSM-binding once the HSM trait supports either full
//! HMAC-SHA1 output or raw key export.
//!
//! ## What's STUB / deferred vs. real AD
//!
//! - AD's actual KDS derivation uses a custom algorithm documented in
//!   MS-ADTS §2.2.20 that involves the gMSA's SID (not DN), the cycle
//!   timestamp (not a counter), and a 32-byte output split into 4 quarters
//!   with specific bit-mixing. Matching AD byte-for-byte for AD-interop is
//!   out of scope for this wave (requires reverse-engineering — see
//!   ADR-020 §Open Questions). The derivation here is a real, standardised
//!   KDF (SP800-108) using real HMAC-SHA1.
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
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

/// KDS root key ID (kept for diagnostic / future HSM-binding use).
pub const KDS_ROOT_KEY_ID: &str = "kds-root";

/// Default rotation interval (ADR-020 §Decision: 30 days).
pub const DEFAULT_ROTATION_INTERVAL_DAYS: u64 = 30;

/// Output length of the derived gMSA password (32 bytes). AD uses 256 bits
/// (32 bytes) — matches.
pub const GMSA_PASSWORD_LEN: usize = 32;

/// KDS root key length (20 bytes — full HMAC-SHA1 key length per SP800-108
/// §5.1). The v0.7.0 bug used the 12-byte HMAC-SHA1-96 truncation.
pub const KDS_ROOT_KEY_LEN: usize = 20;

/// HMAC-SHA1 output length (20 bytes per block in the SP800-108 counter-mode
/// KDF).
const HMAC_SHA1_BLOCK_LEN: usize = 20;

/// gMSA manager. Holds the KDS root key material (20 bytes). Cloning shares
/// the underlying state (Arc semantics would require wrapping; for now the
/// manager is held by a single KDC instance).
#[derive(Clone, Debug)]
pub struct GmsaManager {
    /// Raw KDS root key material (20 bytes). Used as the HMAC-SHA1 key for
    /// the SP800-108 §5.1 counter-mode KDF.
    kds_root_key: [u8; KDS_ROOT_KEY_LEN],
    rotation_interval_secs: u64,
}

impl GmsaManager {
    /// Construct a new gMSA manager and generate a fresh KDS root key
    /// (20 random bytes via `ring::rand::SystemRandom`). `interval_days`
    /// must be in `[1, 90]` (ADR-020 §Decision: "minimum 1 day, maximum
    /// 90 days").
    pub async fn new(interval_days: u64) -> Result<Self, KdcError> {
        if !(1..=90).contains(&interval_days) {
            return Err(KdcError::Policy(format!(
                "gMSA rotation interval {interval_days} days out of range [1, 90]"
            )));
        }
        let key = generate_random_kds_key()?;
        Ok(Self {
            kds_root_key: key,
            rotation_interval_secs: interval_days * 86_400,
        })
    }

    /// Construct a gMSA manager with a caller-supplied raw KDS root key
    /// (20 bytes). Used by tests that need deterministic keys, and by
    /// callers that loaded the key material from durable storage.
    pub fn with_raw_key(interval_days: u64, key: [u8; KDS_ROOT_KEY_LEN]) -> Result<Self, KdcError> {
        if !(1..=90).contains(&interval_days) {
            return Err(KdcError::Policy(format!(
                "gMSA rotation interval {interval_days} days out of range [1, 90]"
            )));
        }
        Ok(Self {
            kds_root_key: key,
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
    /// HMAC-SHA1 counter mode (NIST SP800-108 §5.1) with the **full 20-byte
    /// HMAC-SHA1 output** per block:
    ///
    /// ```text
    /// K(1) = HMAC-SHA1(root_key, [counter=1] || label || 0x00 || context || [L=256 bits])
    /// K(2) = HMAC-SHA1(root_key, [counter=2] || label || 0x00 || context || [L=256 bits])
    /// password = K(1) || K(2) || ... truncated to 32 bytes
    /// ```
    ///
    /// where:
    /// - `label`    = b"adrian-gmsa"
    /// - `context`  = `gmsa_dn` || `cycle` (big-endian u64)
    /// - `L`        = 256 (output length in bits)
    ///
    /// With full HMAC-SHA1 (20 bytes per block), 2 iterations produce
    /// 40 bytes, truncated to 32. (v0.7.0 bug: used 12-byte HMAC-SHA1-96
    /// from the HSM, requiring 3 iterations — wrong PRF for SP800-108.)
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
            // K(i) = HMAC-SHA1(root_key, [i:4 BE] || label || 0x00 || context || [L:4 BE])
            let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(label);
            input.push(0x00);
            input.extend_from_slice(&context);
            input.extend_from_slice(&l_bits.to_be_bytes());
            let block = hmac_sha1_full(&self.kds_root_key, &input)?;
            out.extend_from_slice(&block);
            counter = counter.saturating_add(1);
            // Safety bound — avoid infinite loop (2 iterations suffice for
            // 32-byte output with 20-byte blocks, but guard anyway).
            if counter > 64 {
                return Err(KdcError::Storage(
                    "gMSA KDF exceeded 64 iterations (bug?)".into(),
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

    /// Accessor: the raw KDS root key material (20 bytes). For diagnostics
    /// and status. Caller MUST NOT log or transmit this material.
    pub fn root_key_material(&self) -> &[u8; KDS_ROOT_KEY_LEN] {
        &self.kds_root_key
    }

    /// Accessor: the rotation interval in seconds.
    pub fn rotation_interval_secs(&self) -> u64 {
        self.rotation_interval_secs
    }
}

/// Compute full HMAC-SHA1 (20-byte output) using the `hmac` + `sha1` crates.
/// This is the SP800-108 §5.1 PRF — the v0.7.0 bug used the HSM's `sign`
/// which returns the 12-byte HMAC-SHA1-96 truncation (RFC 3961 checksum
/// profile, NOT the SP800-108 PRF).
fn hmac_sha1_full(
    key: &[u8; KDS_ROOT_KEY_LEN],
    data: &[u8],
) -> Result<[u8; HMAC_SHA1_BLOCK_LEN], KdcError> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|e| KdcError::Storage(format!("HMAC-SHA1 init: {e}")))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SHA1_BLOCK_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Generate a random 20-byte KDS root key using `ring::rand::SystemRandom`.
fn generate_random_kds_key() -> Result<[u8; KDS_ROOT_KEY_LEN], KdcError> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut key = [0u8; KDS_ROOT_KEY_LEN];
    rng.fill(&mut key)
        .map_err(|_| KdcError::Storage("SystemRandom fill failed for KDS root key".into()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_manager(interval_days: u64) -> GmsaManager {
        GmsaManager::new(interval_days).await.expect("manager init")
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
            c1,
            c2,
            "back-to-back current_cycle() calls must agree (interval={}s)",
            mgr.rotation_interval_secs()
        );
    }

    /// The password is deterministic for the same `(root_key, dn, cycle)` —
    /// this is the ADR-020 §Decision invariant: "all DCs compute the same
    /// password for the same gMSA at the same point in time".
    #[tokio::test]
    async fn password_is_deterministic_for_same_inputs() {
        let key = [0x42u8; KDS_ROOT_KEY_LEN];
        let mgr = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key).unwrap();
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
        let p_n = mgr
            .compute_gmsa_password(dn, 100)
            .await
            .expect("derive cycle 100");
        let p_n1 = mgr
            .compute_gmsa_password(dn, 101)
            .await
            .expect("derive cycle 101");
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

    /// Different root keys produce different passwords (KDS root key
    /// rotation invalidates all derived gMSA passwords — security property).
    #[tokio::test]
    async fn different_root_keys_produce_different_passwords() {
        let mgr1 =
            GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, [0x01u8; KDS_ROOT_KEY_LEN])
                .unwrap();
        let mgr2 =
            GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, [0x02u8; KDS_ROOT_KEY_LEN])
                .unwrap();
        let dn = "CN=svc,CN=MSA,DC=adrian,DC=com";
        let cycle = 5;
        let p1 = mgr1.compute_gmsa_password(dn, cycle).await.unwrap();
        let p2 = mgr2.compute_gmsa_password(dn, cycle).await.unwrap();
        assert_ne!(
            p1, p2,
            "different root keys MUST produce different passwords"
        );
    }

    /// Interval out of range (< 1 day) is rejected (ADR-020 §Decision: 1–90 days).
    #[tokio::test]
    async fn interval_below_one_day_rejected() {
        let err = GmsaManager::new(0).await.expect_err("interval=0");
        match err {
            KdcError::Policy(msg) => assert!(msg.contains("out of range"), "{msg}"),
            other => panic!("expected Policy error, got {other:?}"),
        }
    }

    /// Interval above 90 days is rejected (ADR-020 §Decision: 1–90 days).
    #[tokio::test]
    async fn interval_above_90_days_rejected() {
        let err = GmsaManager::new(91).await.expect_err("interval=91");
        assert!(matches!(err, KdcError::Policy(_)), "{err:?}");
    }

    // ---- Wave 2: SP800-108 §5.1 compliance tests (+4) ----

    /// DoD test 1: gMSA hash round-trip — the same `(root_key, dn, cycle)`
    /// triple produces the same 32-byte password across two separate manager
    /// instances (the ADR-020 §Decision "all DCs compute the same password"
    /// invariant). Verifies the KDF is deterministic and the full 20-byte
    /// HMAC-SHA1 output is used (not the 12-byte truncation).
    #[tokio::test]
    async fn gmsa_hash_round_trip_with_full_hmac_sha1() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        let mgr1 = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key).unwrap();
        let mgr2 = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key).unwrap();
        let dn = "CN=svc-web,CN=Managed Service Accounts,DC=adrian,DC=example,DC=com";
        let p1 = mgr1.compute_gmsa_password(dn, 42).await.expect("derive 1");
        let p2 = mgr2.compute_gmsa_password(dn, 42).await.expect("derive 2");
        assert_eq!(p1.len(), GMSA_PASSWORD_LEN);
        assert_eq!(
            p1, p2,
            "two managers with the same root key MUST produce the same password"
        );
    }

    /// DoD test 2: KDF counter mode — verify that the SP800-108 counter is
    /// used correctly. Two different counter values (simulated by computing
    /// a single block with counter=1 vs counter=2) MUST produce different
    /// blocks. We verify this by computing the KDF output and checking it
    /// matches the manual counter-mode construction.
    #[tokio::test]
    async fn kdf_counter_mode_produces_spec_compliant_output() {
        let key = [0xAAu8; KDS_ROOT_KEY_LEN];
        let mgr = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key).unwrap();
        let dn = "CN=svc,CN=MSA,DC=adrian,DC=com";
        let cycle = 10;
        let password = mgr.compute_gmsa_password(dn, cycle).await.expect("derive");

        // Manually reconstruct the SP800-108 §5.1 KDF and verify it matches.
        let label: &[u8] = b"adrian-gmsa";
        let mut context = Vec::new();
        context.extend_from_slice(dn.as_bytes());
        context.extend_from_slice(&cycle.to_be_bytes());
        let l_bits: u32 = (GMSA_PASSWORD_LEN * 8) as u32;

        // Block 1: counter = 1
        let mut input1 = Vec::new();
        input1.extend_from_slice(&1u32.to_be_bytes());
        input1.extend_from_slice(label);
        input1.push(0x00);
        input1.extend_from_slice(&context);
        input1.extend_from_slice(&l_bits.to_be_bytes());
        let block1 = hmac_sha1_full(&key, &input1).expect("block 1");

        // Block 2: counter = 2
        let mut input2 = Vec::new();
        input2.extend_from_slice(&2u32.to_be_bytes());
        input2.extend_from_slice(label);
        input2.push(0x00);
        input2.extend_from_slice(&context);
        input2.extend_from_slice(&l_bits.to_be_bytes());
        let block2 = hmac_sha1_full(&key, &input2).expect("block 2");

        // The password = block1 || block2 truncated to 32 bytes.
        let mut expected = Vec::new();
        expected.extend_from_slice(&block1);
        expected.extend_from_slice(&block2);
        expected.truncate(GMSA_PASSWORD_LEN);

        assert_eq!(
            password, expected,
            "KDF output MUST match the manual SP800-108 counter-mode construction"
        );
        // Verify that block1 and block2 differ (the counter matters).
        assert_ne!(
            block1, block2,
            "different counter values MUST produce different KDF blocks"
        );
    }

    /// DoD test 3: wrong key rejected — a password derived under key A
    /// cannot be verified under key B. This is the security property that
    /// makes KDS root key rotation effective (old passwords are invalidated).
    #[tokio::test]
    async fn wrong_key_rejected_passwords_differ() {
        let key_a = [0x11u8; KDS_ROOT_KEY_LEN];
        let key_b = [0x22u8; KDS_ROOT_KEY_LEN];
        let mgr_a = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key_a).unwrap();
        let mgr_b = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key_b).unwrap();
        let dn = "CN=svc,CN=MSA,DC=adrian,DC=com";
        let cycle = 3;
        let pa = mgr_a.compute_gmsa_password(dn, cycle).await.unwrap();
        let pb = mgr_b.compute_gmsa_password(dn, cycle).await.unwrap();
        assert_ne!(
            pa, pb,
            "passwords derived under different keys MUST differ (wrong key rejected)"
        );
        // Also verify neither password is all-zeros (sanity check — the KDF
        // produces real entropy, not a degenerate output).
        assert!(
            pa.iter().any(|&b| b != 0),
            "password under key A must not be all-zeros"
        );
        assert!(
            pb.iter().any(|&b| b != 0),
            "password under key B must not be all-zeros"
        );
    }

    /// DoD test 4: domain separation — the SP800-108 `label` and `context`
    /// fields provide cryptographic domain separation. Different gMSA DNs
    /// (different context) produce different passwords even with the same
    /// root key and cycle. Additionally, the `label` field (b"adrian-gmsa")
    /// ensures the KDF output is distinct from any other KDF that uses the
    /// same root key with a different label.
    #[tokio::test]
    async fn domain_separation_across_labels_and_contexts() {
        let key = [0xABu8; KDS_ROOT_KEY_LEN];
        let mgr = GmsaManager::with_raw_key(DEFAULT_ROTATION_INTERVAL_DAYS, key).unwrap();

        // Different contexts (different gMSA DNs) → different passwords.
        let p1 = mgr
            .compute_gmsa_password("CN=svc-a,CN=MSA,DC=adrian,DC=com", 5)
            .await
            .unwrap();
        let p2 = mgr
            .compute_gmsa_password("CN=svc-b,CN=MSA,DC=adrian,DC=com", 5)
            .await
            .unwrap();
        assert_ne!(
            p1, p2,
            "different DNs (contexts) MUST produce different passwords"
        );

        // Different cycles (different context) → different passwords.
        let p3 = mgr
            .compute_gmsa_password("CN=svc-a,CN=MSA,DC=adrian,DC=com", 6)
            .await
            .unwrap();
        assert_ne!(
            p1, p3,
            "different cycles (contexts) MUST produce different passwords"
        );

        // Label separation: verify the label is included in the HMAC input
        // by computing a block WITHOUT the label and checking it differs.
        let label: &[u8] = b"adrian-gmsa";
        let mut context = Vec::new();
        context.extend_from_slice(b"CN=svc-a,CN=MSA,DC=adrian,DC=com");
        context.extend_from_slice(&5u64.to_be_bytes());
        let l_bits: u32 = (GMSA_PASSWORD_LEN * 8) as u32;

        // With label (correct SP800-108).
        let mut input_with_label = Vec::new();
        input_with_label.extend_from_slice(&1u32.to_be_bytes());
        input_with_label.extend_from_slice(label);
        input_with_label.push(0x00);
        input_with_label.extend_from_slice(&context);
        input_with_label.extend_from_slice(&l_bits.to_be_bytes());
        let block_with_label = hmac_sha1_full(&key, &input_with_label).unwrap();

        // Without label (wrong — no domain separation).
        let mut input_no_label = Vec::new();
        input_no_label.extend_from_slice(&1u32.to_be_bytes());
        input_no_label.push(0x00);
        input_no_label.extend_from_slice(&context);
        input_no_label.extend_from_slice(&l_bits.to_be_bytes());
        let block_no_label = hmac_sha1_full(&key, &input_no_label).unwrap();

        assert_ne!(
            block_with_label, block_no_label,
            "label MUST be included in the HMAC input (domain separation)"
        );
    }
}
