#![forbid(unsafe_code)]
//! # adrian-cli
//!
//! Unified cross-platform CLI. Replaces `samba-tool`, `kinit/kadmin`,
//! `gpupdate`, `domain join`, `ad-cli` with a single `adrian` binary.
//!
//! ## ADRs
//!
//! - ADR-063: Unified cross-platform CLI
//! - ADR-048: PSSO Extension + macOS join
//! - ADR-050: authselect standard PAM (Linux join)
//! - ADR-054: Per-host LAPS rotation (CLI subcommand)
//! - ADR-127: GPO translation CLI
//! - ADR-126: sIDHistory migration CLI
//! - ADR-129: Password hash migration CLI
//!
//! ## Wave 3c — no silent Ok (W6-3c)
//!
//! Prior to Wave 3c, eight subcommands (`gpupdate`, `klist`, `kinit`,
//! `auth`, `cert enroll`, `file mount`, `migrate *`, `gpo-translate`,
//! `kdc rotate-krbtgt`, `leave`) silently returned `Ok(())` after a
//! `tracing::info!` log line — pretending success without doing work.
//! This was worse than a loud stub: operators saw "ok" and assumed the
//! command had taken effect.
//!
//! Wave 3c replaces every silent-Ok arm with one of:
//!
//! 1. **Real dispatch** — call the underlying SDK module / crate function
//!    and surface its loud-stub error to the operator. Used for `auth`,
//!    `kinit`, `gpo-translate`, and `migrate *` (the SDK module or
//!    underlying crate is itself a loud stub, so its typed error
//!    propagates with no CLI-level masking).
//! 2. **Loud `CliError::NotImplemented`** — used when no SDK method
//!    exists with the right shape (e.g. `gpupdate` needs a
//!    `DeclarativePolicy` argument the CLI doesn't have; `klist` has
//!    no ticket-cache accessor on the SDK; `kdc rotate-krbtgt` would
//!    need a `KrbtgtManager` instance the CLI doesn't construct).
//!
//! The contract: **`dispatch(...)` returns `Ok(())` only when work was
//! actually done.** Anything else surfaces a typed error.

use clap::{Parser, Subcommand};
use thiserror::Error;

/// Unified Adrian CLI.
#[derive(Parser, Debug)]
#[command(name = "adrian", version, about = "Adrian framework CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands. The surface mirrors the legacy AD tool inventory
/// (`samba-tool`, `kinit`, `gpupdate`, `certutil`, `mount.cifs`,
/// `kadmin -kt`) per ADR-063 §Decision, plus the framework-specific
/// `kdc rotate-krbtgt` lifecycle command (ADR-065).
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Join the host to a framework domain.
    Join {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        user: String,
    },
    /// Leave the domain and clean up local state.
    Leave,
    /// Refresh policy (pull + apply).
    Gpupdate,
    /// Kerberos ticket operations.
    Klist,
    /// Acquire a Kerberos ticket-granting ticket for a principal.
    Kinit {
        #[arg(long)]
        principal: String,
    },
    /// Migrate from AD / NTLM / sIDHistory / passwords.
    Migrate {
        #[command(subcommand)]
        subcommand: MigrateSub,
    },
    /// Translate GPO (ADMX/PReg/GptTmpl → declarative JSON).
    GpoTranslate {
        #[arg(long)]
        source: String,
        #[arg(long)]
        out: String,
    },
    /// Authenticate a principal via Kerberos (ADR-063 + ADR-108).
    Auth {
        /// Principal name, e.g. `admin@ADRIAN.DEV`.
        principal: String,
        /// Optional password. If omitted, the CLI prompts interactively.
        #[arg(long)]
        password: Option<String>,
    },
    /// Declarative policy management (ADR-025, ADR-031).
    Policy {
        #[command(subcommand)]
        subcommand: PolicySub,
    },
    /// X.509 certificate enrollment via ACME (ADR-035, RFC 8555).
    Cert {
        #[command(subcommand)]
        subcommand: CertSub,
    },
    /// File gateway — SMB client (ADR-106).
    File {
        #[command(subcommand)]
        subcommand: FileSub,
    },
    /// KDC administration (krbtgt rotation per ADR-065).
    Kdc {
        #[command(subcommand)]
        subcommand: KdcSub,
    },
}

/// `adrian migrate` subcommands.
#[derive(Subcommand, Debug)]
pub enum MigrateSub {
    /// Audit NTLM usage on the network.
    AuditNtlm,
    /// Plan NTLM phase-out.
    PlanNtlm,
    /// sIDHistory injection/migration.
    Sidhistory,
    /// Password hash migration.
    Passwords,
}

/// `adrian policy` subcommands.
#[derive(Subcommand, Debug)]
pub enum PolicySub {
    /// Apply a declarative JSON policy file.
    Apply {
        /// Path to the JSON policy document.
        file: String,
    },
}

/// `adrian cert` subcommands.
#[derive(Subcommand, Debug)]
pub enum CertSub {
    /// Enroll a certificate via ACME (RFC 8555).
    Enroll {
        /// Subject common name (CN).
        #[arg(long)]
        subject: String,
        /// Subject Alternative Name(s) — DNS entries; may be repeated.
        #[arg(long = "san", num_args = 0..)]
        sans: Vec<String>,
    },
}

/// `adrian file` subcommands.
#[derive(Subcommand, Debug)]
pub enum FileSub {
    /// Mount an SMB share at a local mountpoint (ADR-106).
    Mount {
        /// `server/share` URI, e.g. `fs01.adrian.dev/users`.
        server_share: String,
        /// Local mount point path.
        mountpoint: String,
    },
}

/// `adrian kdc` subcommands.
#[derive(Subcommand, Debug)]
pub enum KdcSub {
    /// Rotate the krbtgt account key (ADR-065).
    RotateKrbtgt,
}

/// Typed CLI error. Returned by [`dispatch`] for any path that can't
/// actually perform the requested work. `NotImplemented` is the loud-
/// stub variant — the CLI never silently returns `Ok(())` for an
/// unimplemented operation (Wave 3c, W6-3c).
///
/// `Sdk` wraps an `SdkError` propagated unchanged from the underlying
/// SDK module — this preserves the typed-error contract per ADR-107
/// (callers branch on `SdkError` variants).
#[derive(Debug, Error)]
pub enum CliError {
    /// The subcommand is not yet wired to a real backend. The message
    /// names the subcommand, the backend it would delegate to, and the
    /// governing ADR — so operators see an actionable error rather than
    /// silent success.
    #[error("not implemented: {0}")]
    NotImplemented(String),
    /// An SDK module was invoked and returned its typed `SdkError`.
    /// Propagated unchanged so callers can branch on `SdkError` variants
    /// per ADR-107's error-propagation contract.
    #[error("sdk: {0}")]
    Sdk(#[from] adrian_sdk::SdkError),
}

/// Entry point. The `[[bin]]` `main.rs` delegates here.
///
/// Each subcommand parses its arguments via `clap::Parser` and dispatches
/// to the corresponding `adrian-sdk` module (`AdrianSdk` + its
/// accessors). The SDK methods are currently loud-stubs (per ADR-107 /
/// Wave 5); this function surfaces their `SdkError` variants to the user
/// as `anyhow::Error` rather than silently succeeding, so callers see
/// "framework not yet implemented" instead of a misleading success.
pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing::debug!(?cli.command, "adrian-cli dispatch");
    dispatch(cli.command).await.map_err(anyhow::Error::from)
}

/// Dispatch a parsed [`Command`] to the corresponding SDK call.
///
/// Extracted as a free function so unit tests can exercise the dispatch
/// table without re-parsing `std::env::args`.
///
/// ## Wave 3c contract (W6-3c)
///
/// `dispatch` returns `Ok(())` only when work was actually done. For
/// every subcommand whose backend is a loud stub, the underlying typed
/// error is surfaced via [`CliError`] — the CLI never masks an
/// unimplemented operation as silent success.
async fn dispatch(command: Command) -> Result<(), CliError> {
    // Construct the SDK with the framework's default stub impls. Each
    // module's stub returns a typed `SdkError` variant naming the
    // backend it would delegate to (ADR-107). When v0.7.0 wires real
    // backends, this single call site picks them up automatically.
    let sdk = adrian_sdk::AdrianSdk::with_default_stubs();

    match command {
        Command::Join { domain, user } => {
            tracing::info!(%domain, %user, "adrian join: delegating to SDK");
            // The SDK's `join` is a loud-stub until ADR-107 lands — surface
            // its `NotJoined` error to the caller rather than silently Ok.
            //
            // We use the legacy `AdrianClient` here because the trait-based
            // SDK doesn't expose `join` (the join flow is host-platform
            // glue, not a module trait). This is consistent with the
            // `adrian-sdk-c/jni/swift/python` FFI wrappers.
            let client = adrian_sdk::AdrianClient::new();
            client.join(&domain).await.map_err(CliError::Sdk)
        }
        Command::Leave => {
            tracing::info!("adrian leave: no SDK leave() method yet (ADR-107)");
            Err(CliError::NotImplemented(
                "leave: SDK leave() not yet wired (ADR-107); use `adrian join` on a fresh host"
                    .into(),
            ))
        }
        Command::Gpupdate => {
            tracing::info!("adrian gpupdate: would pull + apply via SDK policy module");
            // Real dispatch would be `sdk.policy.apply(&policy)` — but the
            // SDK's `apply` requires a `DeclarativePolicy` argument the
            // CLI doesn't have (gpupdate pulls from the DC). Surface the
            // gap as a loud NotImplemented naming the backend + ADR.
            Err(CliError::NotImplemented(
                "gpupdate: pull+apply path not yet wired to adrian-policy-executor (ADR-025/113); \
                 use `adrian policy apply <file>` for declarative policy"
                    .into(),
            ))
        }
        Command::Klist => {
            tracing::info!("adrian klist: would list ticket cache via SDK auth module");
            // No SDK method exists for listing the ticket cache (ADR-111
            // ticket-cache abstraction is not yet implemented). Surface
            // the gap as a loud NotImplemented.
            Err(CliError::NotImplemented(
                "klist: ticket cache listing not yet wired (ADR-111)".into(),
            ))
        }
        Command::Kinit { principal } => {
            tracing::info!(%principal, "adrian kinit: delegating to SDK auth module");
            // Dispatch through the SDK's trait-based AuthModule. The
            // default stub returns `SdkError::Auth("... call
            // KerberosAuthModule::with_kdc ...")` — an actionable error
            // rather than silent success. Once `with_kdc` is wired by
            // the host platform (or a future `adrian kinit --kdc-config`
            // flag), this same dispatch path completes the AS-REQ.
            let _ = sdk.auth.authenticate_kerberos(&principal, "").await?;
            // On success (v0.7.0+), the TGT would be stored in the
            // platform ticket cache; `klist` would then surface it.
            Ok(())
        }
        Command::Migrate { subcommand } => {
            dispatch_migrate(subcommand).await
        }
        Command::GpoTranslate { source, out } => {
            tracing::info!(%source, %out, "adrian gpo-translate: delegating to adrian-gpo-translate");
            // Real dispatch: call into the `adrian-gpo-translate` crate.
            // The crate is itself a loud stub (returns
            // `GpoTranslateError::Io("not yet implemented")`), so its
            // error propagates with no CLI masking. We try each
            // InputFormat in turn — for v0.6.0 we attempt Admx first
            // (most common); a future wave will sniff the file magic.
            let format = adrian_gpo_translate::InputFormat::Admx;
            let docs = adrian_gpo_translate::translate(format, &source)
                .await
                .map_err(|e| {
                    CliError::NotImplemented(format!(
                        "gpo-translate({format:?}, {source}): adrian-gpo-translate crate returned: \
                         {e} (ADR-127 / ADR-090)"
                    ))
                })?;
            // On success (v0.7.0+), serialize the policy docs to `out`
            // as canonical JSON. For now we never reach here because the
            // translate stub returns Err.
            let json = serde_json::to_string_pretty(&docs.len()).map_err(|e| {
                CliError::NotImplemented(format!(
                    "gpo-translate: failed to serialize output to {out}: {e}"
                ))
            })?;
            std::fs::write(&out, json).map_err(|e| {
                CliError::NotImplemented(format!(
                    "gpo-translate: failed to write output to {out}: {e}"
                ))
            })?;
            Ok(())
        }
        Command::Auth {
            principal,
            password,
        } => {
            tracing::info!(%principal, has_password = password.is_some(), "adrian auth: delegating to SDK auth module");
            // Real dispatch through the SDK's AuthModule trait. The
            // default stub surfaces its loud error. The password is
            // optional at the CLI surface (interactive prompt is a
            // future task); we pass an empty string when omitted — the
            // SDK's loud stub doesn't actually use the password.
            let pw = password.unwrap_or_default();
            let _token = sdk.auth.authenticate_kerberos(&principal, &pw).await?;
            // On success (v0.7.0+), the AuthToken would be stashed in the
            // process's credential cache for use by subsequent file /
            // directory calls.
            Ok(())
        }
        Command::Policy { subcommand } => match subcommand {
            PolicySub::Apply { file } => {
                tracing::info!(%file, "adrian policy apply: reading declarative JSON");
                // Read the JSON file and surface parse errors; full policy
                // application lives in `adrian-policy-executor` (Wave 4a).
                let text = std::fs::read_to_string(&file).map_err(|e| {
                    CliError::NotImplemented(format!("policy file `{file}`: {e}"))
                })?;
                let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
                    CliError::NotImplemented(format!(
                        "policy file `{file}` is not valid JSON: {e}"
                    ))
                })?;
                tracing::info!(%file, "policy file parsed; delegating to SDK policy module");
                // Build a minimal DeclarativePolicy from the parsed JSON
                // and dispatch through the SDK's PolicyModule trait. The
                // default stub surfaces its loud error.
                let policy = adrian_sdk::DeclarativePolicy {
                    name: value
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unnamed>")
                        .to_string(),
                    version: value
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0")
                        .to_string(),
                    settings: Vec::new(),
                };
                let _applied = sdk.policy.apply(&policy).await?;
                Ok(())
            }
        },
        Command::Cert { subcommand } => match subcommand {
            CertSub::Enroll { subject, sans } => {
                tracing::info!(%subject, ?sans, "adrian cert enroll: delegating to ACME client (future wave)");
                // The SDK's CertModule::enroll requires a DER-encoded CSR
                // (CertEnrollRequest.csr: Vec<u8>) — the CLI doesn't
                // generate CSRs yet (a future `--csr <path>` flag is
                // planned). Surface this as a loud NotImplemented naming
                // the missing piece + the ACME ADR.
                Err(CliError::NotImplemented(format!(
                    "cert enroll for subject '{subject}' (SANs={sans:?}): CSR generation + ACME \
                     enrollment not yet wired to adrian-acme-server (ADR-095/097)"
                )))
            }
        },
        Command::File { subcommand } => match subcommand {
            FileSub::Mount {
                server_share,
                mountpoint,
            } => {
                tracing::info!(%server_share, %mountpoint, "adrian file mount: would delegate to SDK file module");
                // The SDK's FileModule::mount_share requires an AuthToken
                // (the caller must have already authenticated via
                // `adrian auth`). The CLI doesn't yet thread the auth
                // token through — surface this as a loud NotImplemented
                // naming the dependency + ADR.
                Err(CliError::NotImplemented(format!(
                    "file mount '\\\\{server_share}' at '{mountpoint}': SDK FileModule requires an \
                     AuthToken (run `adrian auth` first) + adrian-smb-client wiring pending \
                     (ADR-106)"
                )))
            }
        },
        Command::Kdc { subcommand } => match subcommand {
            KdcSub::RotateKrbtgt => {
                tracing::info!("adrian kdc rotate-krbtgt: would delegate to KrbtgtManager (ADR-065)");
                // `KrbtgtManager::rotate()` requires an `Arc<dyn Hsm>`
                // instance the CLI doesn't construct (the operator
                // runtime owns it). Surface this as a loud NotImplemented.
                Err(CliError::NotImplemented(
                    "kdc rotate-krbtgt: KrbtgtManager::rotate not yet wired from CLI (requires \
                     HSM context; ADR-065 / ADR-015)"
                        .into(),
                ))
            }
        },
    }
}

/// Dispatch the `adrian migrate` subcommand to the `adrian-migrate` crate.
///
/// Each subcommand calls the corresponding `adrian_migrate::*` function,
/// which is itself a loud stub (returns `MigrationError::SourceAd("not
/// yet implemented")`). The crate's typed error propagates with no CLI-
/// level masking — operators see exactly what the migrate crate returns.
async fn dispatch_migrate(sub: MigrateSub) -> Result<(), CliError> {
    // Default NTLM audit config; v0.7.0 will add CLI flags for source_dc
    // + window_hours.
    let config = adrian_migrate::NtlmAuditConfig {
        source_dc: "<unset>".into(),
        window_hours: 24,
    };
    match sub {
        MigrateSub::AuditNtlm => {
            tracing::info!("adrian migrate audit-ntlm: delegating to adrian-migrate");
            adrian_migrate::audit_ntlm(&config)
                .await
                .map_err(|e| CliError::NotImplemented(format!("migrate audit-ntlm: {e} (ADR-086)")))
        }
        MigrateSub::PlanNtlm => {
            tracing::info!("adrian migrate plan-ntlm: delegating to adrian-migrate");
            adrian_migrate::plan_ntlm(&config)
                .await
                .map_err(|e| CliError::NotImplemented(format!("migrate plan-ntlm: {e} (ADR-086/011)")))
        }
        MigrateSub::Sidhistory => {
            tracing::info!("adrian migrate sidhistory: delegating to adrian-migrate");
            adrian_migrate::migrate_sidhistory("<unset>", "<unset>")
                .await
                .map_err(|e| {
                    CliError::NotImplemented(format!("migrate sidhistory: {e} (ADR-126/124)"))
                })
        }
        MigrateSub::Passwords => {
            tracing::info!("adrian migrate passwords: delegating to adrian-migrate");
            adrian_migrate::migrate_passwords("<unset>", "<unset>")
                .await
                .map_err(|e| CliError::NotImplemented(format!("migrate passwords: {e} (ADR-129)")))
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-cli`. Cover CLI command structure (subcommand
    //! parsing + field propagation) and the dispatch entry point. No real
    //! network join / Kerberos / GPO translation is performed — the SDK
    //! modules are loud-stubs (ADR-107), surfaced via `CliError`.

    use clap::Parser;

    use super::*;

    // --------------------------------------------------------------------
    // Existing structural tests (preserved from earlier waves).
    // --------------------------------------------------------------------

    #[test]
    fn parse_join_subcommand_populates_domain_and_user() {
        let cli = Cli::try_parse_from([
            "adrian",
            "join",
            "--domain",
            "adrian.dev",
            "--user",
            "admin",
        ])
        .expect("join parse should succeed");
        match cli.command {
            Command::Join { domain, user } => {
                assert_eq!(domain, "adrian.dev");
                assert_eq!(user, "admin");
            }
            other => panic!("expected Command::Join, got {other:?}"),
        }
    }

    #[test]
    fn parse_leaf_subcommands_without_args() {
        for (argv, expected) in [
            (vec!["adrian", "leave"], "leave"),
            (vec!["adrian", "gpupdate"], "gpupdate"),
            (vec!["adrian", "klist"], "klist"),
        ] {
            let cli = Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("parsing {expected} should succeed: {e}"));
            let rendered = match cli.command {
                Command::Join { .. } => "join",
                Command::Leave => "leave",
                Command::Gpupdate => "gpupdate",
                Command::Klist => "klist",
                Command::Kinit { .. } => "kinit",
                Command::Migrate { .. } => "migrate",
                Command::GpoTranslate { .. } => "gpo-translate",
                Command::Auth { .. } => "auth",
                Command::Policy { .. } => "policy",
                Command::Cert { .. } => "cert",
                Command::File { .. } => "file",
                Command::Kdc { .. } => "kdc",
            };
            assert_eq!(rendered, expected);
        }
    }

    #[test]
    fn parse_kinit_subcommand_populates_principal() {
        let cli = Cli::try_parse_from(["adrian", "kinit", "--principal", "admin@ADRIAN.DEV"])
            .expect("kinit parse should succeed");
        match cli.command {
            Command::Kinit { principal } => {
                assert_eq!(principal, "admin@ADRIAN.DEV");
            }
            other => panic!("expected Command::Kinit, got {other:?}"),
        }
    }

    #[test]
    fn parse_migrate_subsubcommand_routes_to_migratesub() {
        let cases: &[(&[&str], &str)] = &[
            (&["adrian", "migrate", "audit-ntlm"], "audit-ntlm"),
            (&["adrian", "migrate", "plan-ntlm"], "plan-ntlm"),
            (&["adrian", "migrate", "sidhistory"], "sidhistory"),
            (&["adrian", "migrate", "passwords"], "passwords"),
        ];
        for (argv, expected) in cases {
            let cli = Cli::try_parse_from(*argv)
                .unwrap_or_else(|e| panic!("parsing migrate {expected} should succeed: {e}"));
            let sub = match cli.command {
                Command::Migrate { subcommand } => subcommand,
                other => panic!("expected Command::Migrate, got {other:?}"),
            };
            let rendered = match sub {
                MigrateSub::AuditNtlm => "audit-ntlm",
                MigrateSub::PlanNtlm => "plan-ntlm",
                MigrateSub::Sidhistory => "sidhistory",
                MigrateSub::Passwords => "passwords",
            };
            assert_eq!(rendered, *expected);
        }
    }

    #[test]
    fn parse_gpo_translate_subcommand_populates_source_and_out() {
        let cli = Cli::try_parse_from([
            "adrian",
            "gpo-translate",
            "--source",
            "GPO_IN",
            "--out",
            "policy.json",
        ])
        .expect("gpo-translate parse should succeed");
        match cli.command {
            Command::GpoTranslate { source, out } => {
                assert_eq!(source, "GPO_IN");
                assert_eq!(out, "policy.json");
            }
            other => panic!("expected Command::GpoTranslate, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_missing_required_join_args() {
        let result = Cli::try_parse_from(["adrian", "join"]);
        assert!(result.is_err(), "join without args should error");
        let err = result.unwrap_err();
        assert!(
            err.kind() == clap::error::ErrorKind::MissingRequiredArgument,
            "expected MissingRequiredArgument, got {:?}",
            err.kind()
        );
    }

    // --------------------------------------------------------------------
    // New subcommands: auth, policy apply, cert enroll, file mount, kdc.
    // --------------------------------------------------------------------

    #[test]
    fn parse_auth_subcommand_populates_principal_and_optional_password() {
        let cli = Cli::try_parse_from(["adrian", "auth", "admin@ADRIAN.DEV"])
            .expect("auth parse should succeed");
        match cli.command {
            Command::Auth {
                principal,
                password,
            } => {
                assert_eq!(principal, "admin@ADRIAN.DEV");
                assert!(password.is_none(), "no --password => None");
            }
            other => panic!("expected Command::Auth, got {other:?}"),
        }

        let cli =
            Cli::try_parse_from(["adrian", "auth", "admin@ADRIAN.DEV", "--password", "s3cret"])
                .expect("auth --password parse should succeed");
        match cli.command {
            Command::Auth {
                principal,
                password,
            } => {
                assert_eq!(principal, "admin@ADRIAN.DEV");
                assert_eq!(password.as_deref(), Some("s3cret"));
            }
            other => panic!("expected Command::Auth, got {other:?}"),
        }
    }

    #[test]
    fn parse_policy_apply_subcommand_routes_and_populates_file() {
        let cli = Cli::try_parse_from(["adrian", "policy", "apply", "/etc/adrian/policy.json"])
            .expect("policy apply parse should succeed");
        match cli.command {
            Command::Policy {
                subcommand: PolicySub::Apply { file },
            } => {
                assert_eq!(file, "/etc/adrian/policy.json");
            }
            other => panic!("expected Command::Policy::Apply, got {other:?}"),
        }
    }

    #[test]
    fn parse_cert_enroll_subcommand_populates_subject_and_sans() {
        let cli = Cli::try_parse_from(["adrian", "cert", "enroll", "--subject", "dc01.adrian.dev"])
            .expect("cert enroll (no SAN) parse should succeed");
        match cli.command {
            Command::Cert {
                subcommand: CertSub::Enroll { subject, sans },
            } => {
                assert_eq!(subject, "dc01.adrian.dev");
                assert!(sans.is_empty(), "no --san => empty vec");
            }
            other => panic!("expected Command::Cert::Enroll, got {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "adrian",
            "cert",
            "enroll",
            "--subject",
            "dc01.adrian.dev",
            "--san",
            "dc01.adrian.dev",
            "--san",
            "dc01",
        ])
        .expect("cert enroll (multi-SAN) parse should succeed");
        match cli.command {
            Command::Cert {
                subcommand: CertSub::Enroll { subject, sans },
            } => {
                assert_eq!(subject, "dc01.adrian.dev");
                assert_eq!(sans.len(), 2, "two --san flags => two entries");
                assert_eq!(sans[0], "dc01.adrian.dev");
                assert_eq!(sans[1], "dc01");
            }
            other => panic!("expected Command::Cert::Enroll, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_mount_subcommand_populates_server_share_and_mountpoint() {
        let cli = Cli::try_parse_from([
            "adrian",
            "file",
            "mount",
            "fs01.adrian.dev/users",
            "/mnt/users",
        ])
        .expect("file mount parse should succeed");
        match cli.command {
            Command::File {
                subcommand:
                    FileSub::Mount {
                        server_share,
                        mountpoint,
                    },
            } => {
                assert_eq!(server_share, "fs01.adrian.dev/users");
                assert_eq!(mountpoint, "/mnt/users");
            }
            other => panic!("expected Command::File::Mount, got {other:?}"),
        }
    }

    #[test]
    fn parse_kdc_rotate_krbtgt_subcommand_routes() {
        let cli = Cli::try_parse_from(["adrian", "kdc", "rotate-krbtgt"])
            .expect("kdc rotate-krbtgt parse should succeed");
        match cli.command {
            Command::Kdc {
                subcommand: KdcSub::RotateKrbtgt,
            } => {}
            other => panic!("expected Command::Kdc::RotateKrbtgt, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_auth_without_principal() {
        let result = Cli::try_parse_from(["adrian", "auth"]);
        assert!(result.is_err(), "auth without principal should error");
        let err = result.unwrap_err();
        assert!(
            err.kind() == clap::error::ErrorKind::MissingRequiredArgument,
            "expected MissingRequiredArgument, got {:?}",
            err.kind()
        );
    }

    #[test]
    fn parse_rejects_cert_enroll_without_subject() {
        let result = Cli::try_parse_from(["adrian", "cert", "enroll"]);
        assert!(
            result.is_err(),
            "cert enroll without --subject should error"
        );
        let err = result.unwrap_err();
        assert!(
            err.kind() == clap::error::ErrorKind::MissingRequiredArgument,
            "expected MissingRequiredArgument, got {:?}",
            err.kind()
        );
    }

    #[test]
    fn parse_rejects_file_mount_with_missing_positional() {
        let result = Cli::try_parse_from(["adrian", "file", "mount", "fs01/users"]);
        assert!(
            result.is_err(),
            "file mount without mountpoint should error"
        );
        let err = result.unwrap_err();
        assert!(
            err.kind() == clap::error::ErrorKind::MissingRequiredArgument,
            "expected MissingRequiredArgument, got {:?}",
            err.kind()
        );
    }

    #[test]
    fn parse_rejects_policy_apply_with_unknown_subcommand() {
        let result = Cli::try_parse_from(["adrian", "policy", "delete", "x.json"]);
        assert!(
            result.is_err(),
            "policy delete should error (not a valid subcommand)"
        );
        let err = result.unwrap_err();
        assert!(
            err.kind() == clap::error::ErrorKind::InvalidSubcommand,
            "expected InvalidSubcommand, got {:?}",
            err.kind()
        );
    }

    // --------------------------------------------------------------------
    // Dispatch — exercises the real `dispatch` function end-to-end.
    //
    // Wave 3c (W6-3c): NO silent-Ok. Every dispatch arm that previously
    // returned `Ok(())` after a `tracing::info!` now surfaces a typed
    // `CliError` — either `NotImplemented` (CLI-level loud stub) or
    // `Sdk(SdkError)` (SDK module's loud stub propagated unchanged).
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_join_surfaces_sdk_not_joined_error() {
        let err = dispatch(Command::Join {
            domain: "adrian.dev".into(),
            user: "admin".into(),
        })
        .await
        .expect_err("dispatch(join) must surface SdkError::NotJoined");
        let msg = format!("{err}");
        assert!(
            msg.contains("not joined"),
            "expected 'not joined' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_policy_apply_surfaces_missing_file_error() {
        let err = dispatch(Command::Policy {
            subcommand: PolicySub::Apply {
                file: "/nonexistent/adrian-policy.json".into(),
            },
        })
        .await
        .expect_err("dispatch(policy apply) on missing file should error");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy file") && msg.contains("/nonexistent/adrian-policy.json"),
            "expected 'policy file' + path in error, got: {msg}"
        );
    }

    // ---- Wave 3c (W6-3c): every previously-silent-Ok arm now errors. ----

    #[tokio::test]
    async fn dispatch_leave_returns_loud_not_implemented() {
        let err = dispatch(Command::Leave)
            .await
            .expect_err("dispatch(leave) must not silently succeed");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("leave"),
            "expected 'not implemented' + 'leave' in error, got: {msg}"
        );
        assert!(msg.contains("ADR-107"), "expected ADR ref in error; got: {msg}");
    }

    #[tokio::test]
    async fn dispatch_gpupdate_returns_loud_not_implemented() {
        // W6-3c: gpupdate must NOT silently Ok — it returns a loud
        // NotImplemented naming the backend + ADR.
        let err = dispatch(Command::Gpupdate)
            .await
            .expect_err("dispatch(gpupdate) must not silently succeed");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("gpupdate"),
            "expected 'not implemented' + 'gpupdate' in error, got: {msg}"
        );
        assert!(
            msg.contains("adrian-policy-executor"),
            "expected backend name in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_klist_returns_not_implemented() {
        // W6-3c acceptance test (priority 3): `adrian klist` must
        // surface a loud error, not silent Ok.
        let err = dispatch(Command::Klist)
            .await
            .expect_err("dispatch(klist) must not silently succeed");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("klist"),
            "expected 'not implemented' + 'klist' in error, got: {msg}"
        );
        assert!(
            msg.contains("ADR-111"),
            "expected ticket-cache ADR ref in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_kinit_surfaces_sdk_auth_error() {
        // W6-3c: kinit dispatches through the SDK's AuthModule trait.
        // The default stub returns `SdkError::Auth("... call
        // KerberosAuthModule::with_kdc ...")` — an actionable error
        // rather than silent Ok.
        let err = dispatch(Command::Kinit {
            principal: "admin@ADRIAN.DEV".into(),
        })
        .await
        .expect_err("dispatch(kinit) must surface SDK auth error");
        let msg = format!("{err}");
        // SDK error surfaces via `CliError::Sdk(SdkError::Auth(...))` →
        // Display includes "sdk: auth: ...".
        assert!(
            msg.contains("admin@ADRIAN.DEV"),
            "expected principal in error; got: {msg}"
        );
        assert!(
            msg.contains("with_kdc"),
            "expected actionable 'with_kdc' hint in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_auth_surfaces_sdk_auth_error() {
        // W6-3c: `adrian auth` dispatches through the SDK's AuthModule
        // trait (same as kinit, but accepts --password). The default
        // stub surfaces its loud error.
        let err = dispatch(Command::Auth {
            principal: "admin@ADRIAN.DEV".into(),
            password: Some("s3cret".into()),
        })
        .await
        .expect_err("dispatch(auth) must surface SDK auth error");
        let msg = format!("{err}");
        assert!(
            msg.contains("admin@ADRIAN.DEV"),
            "expected principal in error; got: {msg}"
        );
        assert!(
            msg.contains("with_kdc"),
            "expected actionable 'with_kdc' hint in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_migrate_audit_ntlm_surfaces_migrate_crate_error() {
        // W6-3c: `adrian migrate audit-ntlm` dispatches to
        // `adrian_migrate::audit_ntlm` — the migrate crate's loud stub
        // surfaces unchanged through the CLI.
        let err = dispatch(Command::Migrate {
            subcommand: MigrateSub::AuditNtlm,
        })
        .await
        .expect_err("dispatch(migrate audit-ntlm) must surface migrate crate error");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("audit-ntlm"),
            "expected 'not implemented' + 'audit-ntlm' in error; got: {msg}"
        );
        assert!(
            msg.contains("ADR-086"),
            "expected NTLM audit ADR ref in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_migrate_sidhistory_surfaces_migrate_crate_error() {
        let err = dispatch(Command::Migrate {
            subcommand: MigrateSub::Sidhistory,
        })
        .await
        .expect_err("dispatch(migrate sidhistory) must surface migrate crate error");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("sidhistory"),
            "got: {msg}"
        );
        assert!(
            msg.contains("ADR-126"),
            "expected sIDHistory ADR ref; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_gpo_translate_surfaces_translate_crate_error() {
        // W6-3c: `adrian gpo-translate` dispatches to
        // `adrian_gpo_translate::translate` — the crate's loud stub
        // surfaces unchanged.
        let err = dispatch(Command::GpoTranslate {
            source: "GPO_IN".into(),
            out: "/tmp/policy.json".into(),
        })
        .await
        .expect_err("dispatch(gpo-translate) must surface translate crate error");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("gpo-translate"),
            "got: {msg}"
        );
        assert!(
            msg.contains("ADR-127"),
            "expected GPO translation ADR ref; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_cert_enroll_returns_not_implemented() {
        // W6-3c acceptance test (priority 3): `adrian cert enroll` must
        // surface a loud error, not silent Ok.
        let err = dispatch(Command::Cert {
            subcommand: CertSub::Enroll {
                subject: "dc01.adrian.dev".into(),
                sans: vec!["dc01.adrian.dev".into()],
            },
        })
        .await
        .expect_err("dispatch(cert enroll) must not silently succeed");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("cert enroll"),
            "expected 'not implemented' + 'cert enroll' in error; got: {msg}"
        );
        assert!(
            msg.contains("dc01.adrian.dev"),
            "expected subject in error; got: {msg}"
        );
        assert!(
            msg.contains("adrian-acme-server"),
            "expected ACME backend name in error; got: {msg}"
        );
        assert!(
            msg.contains("ADR-095") || msg.contains("ADR-097"),
            "expected ACME ADR ref in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_file_mount_returns_not_implemented() {
        // W6-3c: `adrian file mount` previously returned silent Ok.
        // Must now surface a loud NotImplemented naming the dependency
        // (AuthToken from `adrian auth`) + ADR.
        let err = dispatch(Command::File {
            subcommand: FileSub::Mount {
                server_share: "fs01/users".into(),
                mountpoint: "/mnt/users".into(),
            },
        })
        .await
        .expect_err("dispatch(file mount) must not silently succeed");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("file mount"),
            "got: {msg}"
        );
        assert!(
            msg.contains("fs01/users") && msg.contains("/mnt/users"),
            "expected server_share + mountpoint in error; got: {msg}"
        );
        assert!(
            msg.contains("ADR-106"),
            "expected SMB client ADR ref; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_kdc_rotate_krbtgt_returns_not_implemented() {
        // W6-3c: `adrian kdc rotate-krbtgt` previously returned silent
        // Ok. Must now surface a loud NotImplemented naming the
        // KrbtgtManager + ADR.
        let err = dispatch(Command::Kdc {
            subcommand: KdcSub::RotateKrbtgt,
        })
        .await
        .expect_err("dispatch(kdc rotate-krbtgt) must not silently succeed");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("rotate-krbtgt"),
            "got: {msg}"
        );
        assert!(
            msg.contains("KrbtgtManager"),
            "expected KrbtgtManager name in error; got: {msg}"
        );
        assert!(
            msg.contains("ADR-065") || msg.contains("ADR-015"),
            "expected krbtgt ADR ref; got: {msg}"
        );
    }
}
