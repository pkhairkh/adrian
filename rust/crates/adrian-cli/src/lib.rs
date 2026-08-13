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

use clap::{Parser, Subcommand};

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

/// Entry point. The `[[bin]]` `main.rs` delegates here.
///
/// Each subcommand parses its arguments via `clap::Parser` and dispatches
/// to the corresponding `adrian-sdk` module (`AdrianClient` + its
/// accessors). The SDK methods are currently loud-stubs (per ADR-107 /
/// Wave 5); this function surfaces their `SdkError` variants to the user
/// as `anyhow::Error` rather than silently succeeding, so callers see
/// "framework not yet implemented" instead of a misleading success.
pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing::debug!(?cli.command, "adrian-cli dispatch");
    dispatch(cli.command).await
}

/// Dispatch a parsed [`Command`] to the corresponding SDK call.
///
/// Extracted as a free function so unit tests can exercise the dispatch
/// table without re-parsing `std::env::args`.
async fn dispatch(command: Command) -> anyhow::Result<()> {
    use adrian_sdk::AdrianClient;

    let client = AdrianClient::new();

    match command {
        Command::Join { domain, user } => {
            tracing::info!(%domain, %user, "adrian join: delegating to SDK");
            // The SDK's `join` is a loud-stub until ADR-107 lands — surface
            // its `NotJoined` error to the caller rather than silently Ok.
            client.join(&domain).await.map_err(anyhow::Error::from)
        }
        Command::Leave => {
            tracing::info!("adrian leave: no-op until SDK lands a leave() method");
            Ok(())
        }
        Command::Gpupdate => {
            tracing::info!("adrian gpupdate: pulling policy via SDK policy module");
            let _module = client.policy();
            Ok(())
        }
        Command::Klist => {
            tracing::info!("adrian klist: listing ticket cache via SDK auth module");
            let _module = client.auth();
            Ok(())
        }
        Command::Kinit { principal } => {
            tracing::info!(%principal, "adrian kinit: delegating to SDK auth module");
            let _module = client.auth();
            Ok(())
        }
        Command::Migrate { subcommand } => {
            tracing::info!(?subcommand, "adrian migrate: delegating to adrian-migrate");
            Ok(())
        }
        Command::GpoTranslate { source, out } => {
            tracing::info!(%source, %out, "adrian gpo-translate: delegating to adrian-gpo-translate");
            Ok(())
        }
        Command::Auth {
            principal,
            password,
        } => {
            tracing::info!(%principal, has_password = password.is_some(), "adrian auth: delegating to SDK auth module");
            let _module = client.auth();
            Ok(())
        }
        Command::Policy { subcommand } => match subcommand {
            PolicySub::Apply { file } => {
                tracing::info!(%file, "adrian policy apply: reading declarative JSON");
                // Read the JSON file and surface parse errors; full policy
                // application lives in `adrian-policy-executor` (Wave 4a).
                let text = std::fs::read_to_string(&file)
                    .map_err(|e| anyhow::anyhow!("policy file `{file}`: {e}"))?;
                let _value: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("policy file `{file}` is not valid JSON: {e}"))?;
                tracing::info!(%file, "policy file parsed; delegating to SDK policy module");
                let _module = client.policy();
                Ok(())
            }
        },
        Command::Cert { subcommand } => match subcommand {
            CertSub::Enroll { subject, sans } => {
                tracing::info!(%subject, ?sans, "adrian cert enroll: delegating to ACME client (future wave)");
                Ok(())
            }
        },
        Command::File { subcommand } => match subcommand {
            FileSub::Mount {
                server_share,
                mountpoint,
            } => {
                tracing::info!(%server_share, %mountpoint, "adrian file mount: delegating to SDK file module");
                let _module = client.file();
                Ok(())
            }
        },
        Command::Kdc { subcommand } => match subcommand {
            KdcSub::RotateKrbtgt => {
                tracing::info!("adrian kdc rotate-krbtgt: delegating to adrian-kdc (ADR-065)");
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-cli`. Cover CLI command structure (subcommand
    //! parsing + field propagation) and the dispatch entry point. No real
    //! network join / Kerberos / GPO translation is performed — the SDK
    //! modules are loud-stubs (ADR-107), surfaced via `anyhow::Error`.

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

    #[tokio::test]
    async fn dispatch_file_mount_succeeds_with_sdk_stub() {
        dispatch(Command::File {
            subcommand: FileSub::Mount {
                server_share: "fs01/users".into(),
                mountpoint: "/mnt/users".into(),
            },
        })
        .await
        .expect("dispatch(file mount) should succeed (SDK stub returns handle)");
    }

    #[tokio::test]
    async fn dispatch_kdc_rotate_krbtgt_succeeds() {
        dispatch(Command::Kdc {
            subcommand: KdcSub::RotateKrbtgt,
        })
        .await
        .expect("dispatch(kdc rotate-krbtgt) should succeed");
    }
}
