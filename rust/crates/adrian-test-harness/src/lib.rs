//! # adrian-test-harness
//!
//! Shared test fixtures and interop test utilities for the Adrian framework.
//!
//! Per finaldraft/04-rust-workspace-design.md §8 (Testing strategy), this
//! crate provides:
//!
//! - Mock implementations of `DirectoryStore`, `Replicator`,
//!   `IdentityMapping` (re-exported from `adrian-storage-testkit`,
//!   `adrian-repl-testkit`, `adrian-identity-testkit`)
//! - Shared test fixtures (sample principals, sample SIDs, sample objects,
//!   sample schema projections)
//! - Integration test helpers (spin up an in-process FDB cluster, an
//!   `adrian-directory-service` instance, an LDAP client that performs a
//!   bind + search + modify + delete sequence)
//! - Interop test utilities (Windows Server 2022 fixture, MIT krb5 fixture,
//!   Samba 4.20 fixture, OpenLDAP fixture, FreeIPA 4.10 fixture — gated
//!   behind the `ad-interop` feature flag)
//!
//! ## ADRs
//!
//! - ADR-073: FoundationDB as sole storage engine (in-process FDB testkit)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Re-exports the
//! three testkit crates; adds shared fixtures.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Re-export the three testkit crates so consumers can `use adrian_test_harness::*`.
pub use adrian_identity_testkit::InMemoryIdentityMapping;
pub use adrian_repl_testkit::InMemoryReplicator;
pub use adrian_storage_testkit::InMemoryDirectoryStore;

use adrian_identity_core::{Principal, PrincipalType};
use adrian_sid::Sid;
use uuid::Uuid;

/// A test fixture: a sample user principal (per Decision 3 §Decision).
pub fn sample_user_principal() -> Principal {
    Principal {
        uuid: Uuid::nil(),
        sid: "S-1-5-21-3623811015-3361044348-30300820-500"
            .parse()
            .expect("sample user SID must parse"),
        sid_history: Vec::new(),
        principal_type: PrincipalType::User,
    }
}

/// A test fixture: a sample group principal (per Decision 3 §Decision).
pub fn sample_group_principal() -> Principal {
    Principal {
        uuid: Uuid::nil(),
        sid: "S-1-5-21-3623811015-3361044348-30300820-512"
            .parse()
            .expect("sample group SID must parse"),
        sid_history: Vec::new(),
        principal_type: PrincipalType::Group,
    }
}

/// A test fixture: a sample domain SID (per MS-DTYP §2.4.2).
pub fn sample_domain_sid() -> Sid {
    "S-1-5-21-3623811015-3361044348-30300820"
        .parse()
        .expect("sample domain SID must parse")
}

/// A test fixture: a sample administrator SID (RID 500, per MS-ADTS).
pub fn sample_administrator_sid() -> Sid {
    "S-1-5-21-3623811015-3361044348-30300820-500"
        .parse()
        .expect("sample administrator SID must parse")
}

/// A test fixture: a sample Domain Admins SID (RID 512, per MS-ADTS).
pub fn sample_domain_admins_sid() -> Sid {
    "S-1-5-21-3623811015-3361044348-30300820-512"
        .parse()
        .expect("sample Domain Admins SID must parse")
}

/// A test fixture: a sample well-known SID (per MS-DTYP §2.4.2.2 —
/// `S-1-1-0` Everyone).
pub fn sample_everyone_sid() -> Sid {
    "S-1-1-0".parse().expect("sample Everyone SID must parse")
}

/// A test fixture: a sample well-known SID (per MS-DTYP §2.4.2.2 —
/// `S-1-5-11` Authenticated Users).
pub fn sample_authenticated_users_sid() -> Sid {
    "S-1-5-11"
        .parse()
        .expect("sample Authenticated Users SID must parse")
}

/// A test fixture: a sample DSA invocation ID (per MS-ADTS §3.1.1.3.2.6).
pub fn sample_invocation_id() -> Uuid {
    Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff")
        .expect("sample invocation ID must parse")
}

// TODO: implement in-process FDB cluster spinup (per finaldraft/04-rust-workspace-design.md §8).
// TODO: implement integration test harness (spin up adrian-directory-service + LDAP client, run bind+search+modify+delete sequence).
// TODO: implement interop test fixtures (Windows Server 2022, MIT krb5, Samba 4.20, OpenLDAP, FreeIPA 4.10) per finaldraft/04-rust-workspace-design.md §8.
