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

/// Top-level subcommands.
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

/// Entry point. The `[[bin]]` `main.rs` delegates here.
pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing::debug!(?cli.command, "adrian-cli dispatch");
    // TODO: dispatch to adrian-sdk / adrian-migrate / adrian-gpo-translate
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-cli`. Per the task instructions these cover
    //! CLI command structure (subcommand parsing + field propagation) and
    //! the dispatch entry point — no real network join / Kerberos / GPO
    //! translation is performed.

    use clap::Parser;

    use super::*;

    #[test]
    fn parse_join_subcommand_populates_domain_and_user() {
        // `adrian join --domain <d> --user <u>` — verifies the kebab-case
        // `join` subcommand maps to `Command::Join` and the `--domain` /
        // `--user` long options populate the struct variant fields.
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
        // `Leave`, `Gpupdate`, `Klist` are unit variants — no flags. This
        // guards the seam: if any of them accidentally gains a required
        // arg in a later wave, parsing would fail and the test would break
        // before the CLI ships.
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
        // `adrian migrate <sub>` — verifies the nested `#[command(subcommand)]`
        // on `Command::Migrate` parses each `MigrateSub` variant and that
        // clap's auto-kebab-casing (`audit-ntlm`, `plan-ntlm`) matches the
        // documented CLI surface (ADR-086 / ADR-126 / ADR-129).
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
        // `adrian gpo-translate --source <s> --out <o>` — ADR-127 surface.
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
        // `adrian join` without `--domain` / `--user` must surface a clap
        // error (not panic, not silently succeed). This guards the seam so
        // that a future refactor that drops `required = true` semantics
        // fails loudly before shipping.
        let result = Cli::try_parse_from(["adrian", "join"]);
        assert!(result.is_err(), "join without args should error");
        let err = result.unwrap_err();
        assert!(
            err.kind() == clap::error::ErrorKind::MissingRequiredArgument,
            "expected MissingRequiredArgument, got {:?}",
            err.kind()
        );
    }
}
