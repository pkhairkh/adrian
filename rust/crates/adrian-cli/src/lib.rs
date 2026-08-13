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
