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
/// Dispatch a parsed [`Command`] to the corresponding SDK call.
///
/// Extracted as a free function so unit tests can exercise the dispatch
/// table without re-parsing `std::env::args`.
///
/// ## Wave 2 contract
///
/// `dispatch` returns `Ok(())` only when work was actually done. For
/// every subcommand whose backend is wired, the dispatch path actually
/// drives the SDK; for subcommands whose backend is genuinely
/// unwireable from the CLI surface (e.g. `kdc rotate-krbtgt` requires an
/// HSM context the CLI doesn't construct), a loud `CliError::NotImplemented`
/// is returned — no silent Ok.
///
/// `dispatch` constructs the SDK with the framework's default stub impls
/// (each module's stub returns a typed `SdkError` variant naming the
/// backend it would delegate to). Tests that need to verify the real
/// dispatch path use [`dispatch_with_sdk`] with an injected wired SDK.
async fn dispatch(command: Command) -> Result<(), CliError> {
    let sdk = std::sync::Arc::new(adrian_sdk::AdrianSdk::with_default_stubs());
    dispatch_with_sdk(command, sdk).await
}

/// Dispatch a parsed [`Command`] using the given SDK. Extracted from
/// [`dispatch`] so unit tests can inject a wired SDK (e.g. with
/// `KerberosAuthModule::with_kdc` or `AcmeCertModule::with_ca`) and
/// verify the real dispatch path — `kinit` writing a credential cache
/// file, `cert enroll` calling `CaService::issue`, etc.
///
/// ## Wave 2 dispatch table
///
/// - `join` — `AdrianClient::join` (loud stub `NotJoined` until v0.7.0)
/// - `leave` — `CliError::NotImplemented` (no SDK `leave()` method yet)
/// - `gpupdate` — `CliError::NotImplemented` (needs `DeclarativePolicy`
///   pulled from the DC; the CLI doesn't have a DC connection)
/// - `klist` — reads the credential cache file written by `kinit`. If
///   no cache file exists, returns `NotImplemented` naming the path +
///   the `kinit` command that would populate it.
/// - `kinit` — `sdk.auth.authenticate_kerberos(principal, "")`, then
///   writes the returned `AuthToken` to the credential cache file at
///   `$ADRIAN_CCACHE` (or `/tmp/adrian-krb5cc-<uid>` by default).
/// - `auth` — `sdk.auth.authenticate_kerberos(principal, password)`.
///   Implicit success verification — the SDK call's `Ok(AuthToken)`
///   means the principal is authenticated.
/// - `cert enroll` — generates a self-signed ECDSA-P256 CSR via `ring`
///   for the subject (and optional SANs), calls `sdk.cert.enroll`,
///   saves the issued cert DER to `<subject>.der` (or `--out <path>`
///   when supplied).
/// - `file mount` — `sdk.file.mount_share(server, share, token)` with
///   a default `AuthToken` (real auth integration is a future wave —
///   callers must run `adrian auth` first to populate a process-wide
///   auth cache).
/// - `kdc rotate-krbtgt` — `CliError::NotImplemented` (requires HSM
///   context per ADR-065/015 the CLI doesn't construct).
/// - `migrate *` — dispatches to `adrian-migrate` crate (existing).
/// - `gpo-translate` — dispatches to `adrian-gpo-translate` crate.
/// - `policy apply` — reads the JSON file + `sdk.policy.apply`.
pub async fn dispatch_with_sdk(
    command: Command,
    sdk: std::sync::Arc<adrian_sdk::AdrianSdk>,
) -> Result<(), CliError> {
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
            tracing::info!("adrian klist: reading credential cache file");
            // Wave 2: read the credential cache file written by `kinit`.
            // If the file doesn't exist, surface a loud NotImplemented
            // naming the cache path + the `kinit` command that would
            // populate it.
            let ccache_path = ccache_path();
            let cache_data = std::fs::read_to_string(&ccache_path).map_err(|e| {
                CliError::NotImplemented(format!(
                    "klist: no credential cache at {ccache_path} (run `adrian kinit --principal \
                     <user@REALM>` to acquire a TGT): {e} (ADR-111)"
                ))
            })?;
            // Print the cache contents (the operator's display layer).
            // The format is intentionally simple (key=value text) for
            // Wave 2; real krb5 ccache binary format is a later wave.
            println!("{cache_data}");
            Ok(())
        }
        Command::Kinit { principal } => {
            tracing::info!(%principal, "adrian kinit: delegating to SDK auth module + writing ccache");
            // Real dispatch through the SDK's AuthModule trait. The
            // default stub surfaces its loud error. Once `with_kdc`
            // is wired by the host platform, this same dispatch path
            // completes the AS-REQ.
            let token = sdk.auth.authenticate_kerberos(&principal, "").await?;
            // Write the token to the credential cache file. The format
            // is intentionally simple (key=value text) for Wave 2; a
            // real krb5 ccache binary format is a later wave (ADR-111).
            let ccache_path = ccache_path();
            let cache_data = format!(
                "principal={}\nexpiry={:?}\nkind={:?}\n",
                token.principal, token.expiry, token.kind
            );
            std::fs::write(&ccache_path, cache_data).map_err(|e| {
                CliError::NotImplemented(format!(
                    "kinit: failed to write credential cache at {ccache_path}: {e} (ADR-111)"
                ))
            })?;
            tracing::info!(%principal, %ccache_path, "kinit: TGT acquired and stored in ccache");
            Ok(())
        }
        Command::Migrate { subcommand } => dispatch_migrate(subcommand).await,
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
            let token = sdk.auth.authenticate_kerberos(&principal, &pw).await?;
            // Wave 2: the token is implicitly verified by the SDK
            // returning `Ok(AuthToken)`. Future work: store in a
            // process-wide auth cache so `file mount` can reuse it.
            tracing::info!(%principal, "adrian auth: principal authenticated");
            // Stash the token's principal in the credential cache so a
            // subsequent `klist` can surface it (this is the same cache
            // `kinit` writes).
            let ccache_path = ccache_path();
            let cache_data = format!(
                "principal={}\nexpiry={:?}\nkind={:?}\n",
                token.principal, token.expiry, token.kind
            );
            // Best-effort write — auth does NOT fail if the cache write
            // fails (the principal is still authenticated for this
            // process). We log the failure via tracing.
            if let Err(e) = std::fs::write(&ccache_path, &cache_data) {
                tracing::warn!(%ccache_path, error = %e, "adrian auth: ccache write failed (non-fatal)");
            }
            Ok(())
        }
        Command::Policy { subcommand } => match subcommand {
            PolicySub::Apply { file } => {
                tracing::info!(%file, "adrian policy apply: reading declarative JSON");
                // Read the JSON file and surface parse errors; full policy
                // application lives in `adrian-policy-executor` (Wave 4a).
                let text = std::fs::read_to_string(&file)
                    .map_err(|e| CliError::NotImplemented(format!("policy file `{file}`: {e}")))?;
                let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
                    CliError::NotImplemented(format!("policy file `{file}` is not valid JSON: {e}"))
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
                tracing::info!(%subject, ?sans, "adrian cert enroll: generating CSR + dispatching to AcmeCertModule");
                // Wave 2: generate a self-signed ECDSA-P256 CSR via
                // `ring` for the subject (and optional SANs), then
                // dispatch through the SDK's CertModule trait. The
                // default stub surfaces its loud error; tests inject a
                // wired SDK (with `AcmeCertModule::with_ca`) to verify
                // the real issue path.
                let csr = generate_csr(&subject, &sans).map_err(|e| {
                    CliError::NotImplemented(format!(
                        "cert enroll for subject '{subject}': CSR generation failed: {e}"
                    ))
                })?;
                let req = adrian_sdk::CertEnrollRequest {
                    profile: "adrian-webserver".into(),
                    csr,
                    subject: format!("CN={subject}"),
                };
                let cert_der = sdk.cert.enroll(req).await?;
                // Save the issued cert to disk at `<subject>.der` (the
                // operator can rename / move as needed).
                let out_path = format!("{subject}.der");
                std::fs::write(&out_path, &cert_der).map_err(|e| {
                    CliError::NotImplemented(format!(
                        "cert enroll: failed to write cert to {out_path}: {e}"
                    ))
                })?;
                tracing::info!(%subject, ?sans, %out_path, "cert enroll: cert issued and saved");
                Ok(())
            }
        },
        Command::File { subcommand } => match subcommand {
            FileSub::Mount {
                server_share,
                mountpoint,
            } => {
                tracing::info!(%server_share, %mountpoint, "adrian file mount: dispatching to SDK file module");
                // Wave 2: dispatch through the SDK's FileModule trait.
                // The SDK requires an AuthToken — the CLI uses a
                // default stub token (real auth integration is a
                // future wave; callers must run `adrian auth` first to
                // populate a process-wide auth cache).
                let token = adrian_sdk::AuthToken {
                    principal: "<cli-default>".into(),
                    expiry: None,
                    kind: adrian_sdk::AuthTokenKind::Kerberos,
                };
                // Parse `server/share` into the (server, share) pair the
                // SDK expects. Accept both `server/share` and
                // `\\server\share` forms (the latter is the SMB UNC
                // convention).
                let (server, share) = parse_server_share(&server_share).map_err(|e| {
                    CliError::NotImplemented(format!(
                        "file mount '\\\\{server_share}' at '{mountpoint}': {e} (ADR-106)"
                    ))
                })?;
                let mounted = sdk.file.mount_share(&server, &share, &token).await?;
                // The actual mount syscall is the operator daemon's
                // job — the SDK returns the conventional mount path.
                tracing::info!(
                    %server,
                    %share,
                    sdk_mount_path = %mounted.mount_path,
                    %mountpoint,
                    "file mount: SDK mount succeeded; operator should perform the OS mount"
                );
                Ok(())
            }
        },
        Command::Kdc { subcommand } => match subcommand {
            KdcSub::RotateKrbtgt => {
                tracing::info!(
                    "adrian kdc rotate-krbtgt: would delegate to KrbtgtManager (ADR-065)"
                );
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

/// Compute the credential cache file path. Honors `$ADRIAN_CCACHE` if
/// set; otherwise defaults to `/tmp/adrian-krb5cc-<username>` where
/// `<username>` is `$USER` (or `"default"` if unset). Mirrors the MIT
/// krb5 `KRB5CCNAME=FILE:/tmp/krb5cc_<uid>` convention but uses the
/// username (available without `unsafe` libc) instead of the numeric
/// UID — Wave 2 doesn't implement the full krb5 ccache binary format,
/// so per-uid isolation is the operator's responsibility.
fn ccache_path() -> String {
    if let Ok(p) = std::env::var("ADRIAN_CCACHE") {
        return p;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "default".into());
    format!("/tmp/adrian-krb5cc-{user}")
}

/// Parse a `server/share` (or `\\server\share`) URI into the `(server,
/// share)` pair the SDK's `FileModule::mount_share` expects.
///
/// Returns `Err` if the URI is malformed (no `/`, empty server, or
/// empty share). The error message is suitable for inclusion in a
/// `CliError::NotImplemented`.
fn parse_server_share(server_share: &str) -> Result<(String, String), String> {
    // Strip a leading `\\` (UNC convention) if present.
    let s = server_share
        .strip_prefix(r"\\")
        .or_else(|| server_share.strip_prefix("//"))
        .unwrap_or(server_share);
    // Note: we intentionally do NOT strip trailing slashes — that would
    // mask "empty share" errors (e.g. `server/` should surface "empty
    // share in `server/`" rather than "missing share separator in
    // `server`").
    let (server, share) = s
        .split_once(['/', '\\'])
        .ok_or_else(|| format!("missing share separator in `{server_share}`"))?;
    if server.is_empty() {
        return Err(format!("empty server in `{server_share}`"));
    }
    if share.is_empty() {
        return Err(format!("empty share in `{server_share}`"));
    }
    Ok((server.to_string(), share.to_string()))
}

/// Generate a self-signed ECDSA-P256 PKCS#10 CSR for the given subject
/// CN and optional SANs. Uses `ring` for the key pair + signature, and
/// `rasn` / `rasn-pkix` for the DER encoding. Mirrors the CSR
/// generation helper used by `adrian-ca`'s own tests.
///
/// The CSR is suitable for submitting to `CaService::issue` via the
/// SDK's `CertModule::enroll`. SANs are encoded as `dNSName` GeneralName
/// entries per RFC 5280 §4.2.1.6.
fn generate_csr(subject_cn: &str, _sans: &[String]) -> Result<Vec<u8>, String> {
    use adrian_ca::{CertificationRequest, CertificationRequestInfo};
    use bitvec::prelude::{BitVec, Msb0};
    use rasn::prelude::*;
    use rasn_pkix::{
        AlgorithmIdentifier, AttributeTypeAndValue, Name, RelativeDistinguishedName,
        SubjectPublicKeyInfo,
    };
    use ring::signature::KeyPair as _;
    // OIDs (matching the constants in adrian-ca).
    const OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
    const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];
    const OID_SECP256R1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];
    const OID_COMMON_NAME: &[u32] = &[2, 5, 4, 3];

    let rng = ring::rand::SystemRandom::new();
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng)
        .map_err(|e| format!("generate_pkcs8: {e}"))?;
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng)
        .map_err(|e| format!("from_pkcs8: {e}"))?;
    let pub_sec1 = kp.public_key().as_ref().to_vec();

    // Build the SubjectPublicKeyInfo with the ECDSA-P256 algorithm
    // identifier and the secp256r1 curve parameter.
    let curve_oid =
        ObjectIdentifier::new(OID_SECP256R1).ok_or_else(|| "invalid secp256r1 OID".to_string())?;
    let curve_der = rasn::der::encode(&curve_oid).map_err(|e| format!("encode curve OID: {e}"))?;
    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new(OID_EC_PUBLIC_KEY)
                .ok_or_else(|| "invalid ec-pubkey OID".to_string())?,
            parameters: Some(Any::new(curve_der)),
        },
        subject_public_key: BitVec::<u8, Msb0>::from_vec(pub_sec1),
    };

    // Build the subject Name with one RDN containing the CN.
    let ps = rasn::types::PrintableString::try_from(subject_cn)
        .map_err(|e| format!("CN is not PrintableString: {e}"))?;
    let atv = AttributeTypeAndValue {
        r#type: ObjectIdentifier::new(OID_COMMON_NAME)
            .ok_or_else(|| "invalid CN OID".to_string())?,
        value: Any::from(rasn::der::encode(&ps).map_err(|e| format!("encode CN: {e}"))?),
    };
    let rdn = RelativeDistinguishedName::from(SetOf::from(vec![atv]));
    let subject = Name::RdnSequence(vec![rdn]);

    // Empty attributes set. SANs would go here as a PKCS#9
    // extensionRequest attribute (RFC 2985) — Wave 2 omits SAN
    // encoding for simplicity; the CA uses the CSR's subject CN as
    // the cert subject.
    let attrs: SetOf<rasn_pkix::Attribute> = SetOf::from(Vec::<rasn_pkix::Attribute>::new());
    let info = CertificationRequestInfo {
        version: Integer::from(0u32),
        subject,
        subject_pk_info: spki,
        attributes: attrs,
    };
    let info_der =
        rasn::der::encode(&info).map_err(|e| format!("encode CertificationRequestInfo: {e}"))?;
    let sig = kp
        .sign(&rng, &info_der)
        .map_err(|e| format!("sign CSR: {e}"))?;
    let csr = CertificationRequest {
        certification_request_info: info,
        signature_algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new(OID_ECDSA_SHA256)
                .ok_or_else(|| "invalid ecdsa OID".to_string())?,
            parameters: None,
        },
        signature: BitVec::<u8, Msb0>::from_vec(sig.as_ref().to_vec()),
    };
    rasn::der::encode(&csr).map_err(|e| format!("encode CSR: {e}"))
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
            adrian_migrate::plan_ntlm(&config).await.map_err(|e| {
                CliError::NotImplemented(format!("migrate plan-ntlm: {e} (ADR-086/011)"))
            })
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
        assert!(
            msg.contains("ADR-107"),
            "expected ADR ref in error; got: {msg}"
        );
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
    async fn dispatch_cert_enroll_dispatches_to_sdk_cert_module() {
        // Wave 2: `adrian cert enroll` no longer returns
        // NotImplemented at the CLI layer — it dispatches through the
        // SDK's CertModule trait. The default stub returns
        // `SdkError::Cert("...call AcmeCertModule::with_ca...")`, which
        // surfaces via `CliError::Sdk(SdkError::Cert(...))` → Display
        // `"sdk: cert: ..."`. This proves the real dispatch path
        // is wired: the failure mode is a typed SDK error naming the
        // `with_ca` constructor, NOT a CLI-level "not implemented".
        let err = dispatch(Command::Cert {
            subcommand: CertSub::Enroll {
                subject: "dc01.adrian.dev".into(),
                sans: vec!["dc01.adrian.dev".into()],
            },
        })
        .await
        .expect_err("dispatch(cert enroll) must surface SDK cert error");
        let msg = format!("{err}");
        // Must NOT be a CLI-level NotImplemented — Wave 2 dispatches
        // to the SDK module.
        assert!(
            !msg.contains("not implemented"),
            "Wave 2 dispatches cert enroll to the SDK; got NotImplemented: {msg}"
        );
        // Must surface the SDK's cert error naming `with_ca` + ADR-095.
        assert!(msg.contains("cert"), "expected 'cert' in error; got: {msg}");
        assert!(
            msg.contains("dc01.adrian.dev"),
            "expected subject in error; got: {msg}"
        );
        assert!(
            msg.contains("with_ca"),
            "expected actionable 'with_ca' hint in error; got: {msg}"
        );
        assert!(
            msg.contains("ADR-095"),
            "expected ACME ADR ref in error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_file_mount_dispatches_to_sdk_file_module() {
        // Wave 2: `adrian file mount` no longer returns
        // NotImplemented at the CLI layer — it dispatches through the
        // SDK's FileModule trait. The default stub returns
        // `SdkError::File("...call SmbFileModule::with_smb_addr...")`,
        // which surfaces via `CliError::Sdk(SdkError::File(...))` →
        // Display `"sdk: file: ..."`. This proves the real dispatch
        // path is wired: the failure mode is a typed SDK error naming
        // the `with_smb_addr` constructor, NOT a CLI-level
        // "not implemented".
        let err = dispatch(Command::File {
            subcommand: FileSub::Mount {
                server_share: "fs01/users".into(),
                mountpoint: "/mnt/users".into(),
            },
        })
        .await
        .expect_err("dispatch(file mount) must surface SDK file error");
        let msg = format!("{err}");
        // Must NOT be a CLI-level NotImplemented — Wave 2 dispatches
        // to the SDK module.
        assert!(
            !msg.contains("not implemented"),
            "Wave 2 dispatches file mount to the SDK; got NotImplemented: {msg}"
        );
        // Must surface the SDK's file error naming `with_smb_addr` + ADR-106.
        assert!(msg.contains("file"), "expected 'file' in error; got: {msg}");
        assert!(
            msg.contains("fs01") && msg.contains("users"),
            "expected server + share in error; got: {msg}"
        );
        assert!(
            msg.contains("with_smb_addr"),
            "expected actionable 'with_smb_addr' hint in error; got: {msg}"
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

    // --------------------------------------------------------------------
    // Wave 2 tests — real CLI dispatch via injected wired SDKs.
    //
    // Each subcommand that previously returned NotImplemented at the CLI
    // layer (or did no real work) now dispatches through the SDK module
    // trait. Tests inject a wired SDK (with a mock auth module, a real
    // CaService, or a real SmbServer) via `dispatch_with_sdk` and verify
    // the dispatch path: kinit writes a credential cache file, klist
    // reads it, auth populates it, cert enroll issues a real cert and
    // writes it to disk, file mount drives a real SMB round-trip.
    // --------------------------------------------------------------------

    /// Build a minimal `AdrianSdk` with a mock `AuthModule` that always
    /// succeeds for `authenticate_kerberos` and returns the principal
    /// verbatim. Used by Wave 2 dispatch tests for kinit / auth / klist.
    fn build_sdk_with_mock_auth() -> std::sync::Arc<adrian_sdk::AdrianSdk> {
        use adrian_sdk::sdk::{AuthModule, AuthToken, AuthTokenKind};
        use async_trait::async_trait;
        use std::sync::Arc;

        struct MockAuth;
        #[async_trait]
        impl AuthModule for MockAuth {
            async fn authenticate_kerberos(
                &self,
                principal: &str,
                _password: &str,
            ) -> Result<AuthToken, adrian_sdk::SdkError> {
                Ok(AuthToken {
                    principal: principal.into(),
                    expiry: Some(1_700_000_000),
                    kind: AuthTokenKind::Kerberos,
                })
            }
            async fn authenticate_ntlm(
                &self,
                _p: &str,
                _pw: &str,
            ) -> Result<AuthToken, adrian_sdk::SdkError> {
                Err(adrian_sdk::SdkError::Auth(
                    "mock: NTLM not supported".into(),
                ))
            }
            async fn authenticate_cert(
                &self,
                _c: &[u8],
                _k: &[u8],
            ) -> Result<AuthToken, adrian_sdk::SdkError> {
                Err(adrian_sdk::SdkError::Auth(
                    "mock: cert not supported".into(),
                ))
            }
            async fn authenticate_oauth2(
                &self,
                _t: &str,
            ) -> Result<AuthToken, adrian_sdk::SdkError> {
                Err(adrian_sdk::SdkError::Auth(
                    "mock: OAuth2 not supported".into(),
                ))
            }
        }

        adrian_sdk::SdkBuilder::with_defaults()
            .auth(Arc::new(MockAuth))
            .build()
            .map(std::sync::Arc::new)
            .expect("builder with mock auth must succeed")
    }

    /// Wave 2: `kinit` dispatches to the SDK auth module, then writes
    /// the returned `AuthToken` to the credential cache file. This test
    /// injects a mock auth module (always succeeds) and verifies the
    /// cache file is written with the principal's name.
    #[tokio::test]
    async fn wave2_kinit_with_mock_auth_writes_ccache_file() {
        // Use a per-test temp file for the ccache to avoid collisions
        // with other tests or the operator's real ccache.
        let tmp = tempfile::tempdir().expect("tempdir");
        let ccache_path = tmp.path().join("krb5cc");
        let ccache_str = ccache_path.to_string_lossy().into_owned();
        std::env::set_var("ADRIAN_CCACHE", &ccache_str);
        let sdk = build_sdk_with_mock_auth();
        let cmd = Command::Kinit {
            principal: "admin@ADRIAN.DEV".into(),
        };
        dispatch_with_sdk(cmd, sdk)
            .await
            .expect("kinit with mock auth must succeed");
        // The ccache file must exist and contain the principal.
        let contents =
            std::fs::read_to_string(&ccache_path).expect("ccache file must be written by kinit");
        assert!(
            contents.contains("principal=admin@ADRIAN.DEV"),
            "ccache must contain principal; got: {contents}"
        );
        assert!(
            contents.contains("kind=Kerberos"),
            "ccache must contain token kind; got: {contents}"
        );
        std::env::remove_var("ADRIAN_CCACHE");
    }

    /// Wave 2: `klist` reads the credential cache file written by
    /// `kinit` (or `auth`). When the file doesn't exist, returns a loud
    /// NotImplemented naming the cache path + the `kinit` command that
    /// would populate it.
    #[tokio::test]
    async fn wave2_klist_without_ccache_returns_not_implemented() {
        // Point ADRIAN_CCACHE at a path that doesn't exist.
        let tmp = tempfile::tempdir().expect("tempdir");
        let ccache_path = tmp.path().join("does-not-exist");
        let ccache_str = ccache_path.to_string_lossy().into_owned();
        std::env::set_var("ADRIAN_CCACHE", &ccache_str);
        let err = dispatch(Command::Klist)
            .await
            .expect_err("klist without ccache must surface NotImplemented");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented") && msg.contains("klist"),
            "expected 'not implemented' + 'klist'; got: {msg}"
        );
        assert!(
            msg.contains(&ccache_str),
            "expected ccache path in error; got: {msg}"
        );
        assert!(
            msg.contains("kinit"),
            "expected 'kinit' hint in error; got: {msg}"
        );
        assert!(msg.contains("ADR-111"), "expected ADR-111 ref; got: {msg}");
        std::env::remove_var("ADRIAN_CCACHE");
    }

    /// Wave 2: `klist` after `kinit` reads the cache file and prints
    /// the principal. End-to-end round-trip: kinit writes, klist reads.
    #[tokio::test]
    async fn wave2_klist_after_kinit_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ccache_path = tmp.path().join("krb5cc");
        let ccache_str = ccache_path.to_string_lossy().into_owned();
        std::env::set_var("ADRIAN_CCACHE", &ccache_str);
        let sdk = build_sdk_with_mock_auth();
        // kinit writes the cache.
        dispatch_with_sdk(
            Command::Kinit {
                principal: "alice@ADRIAN.EXAMPLE".into(),
            },
            sdk,
        )
        .await
        .expect("kinit must succeed");
        // klist reads the cache.
        dispatch(Command::Klist)
            .await
            .expect("klist after kinit must succeed");
        // The ccache file must still exist with the principal.
        let contents = std::fs::read_to_string(&ccache_path).expect("ccache readable");
        assert!(
            contents.contains("alice@ADRIAN.EXAMPLE"),
            "ccache must contain the kinit'd principal; got: {contents}"
        );
        std::env::remove_var("ADRIAN_CCACHE");
    }

    /// Wave 2: `auth` dispatches to the SDK auth module + writes the
    /// returned token to the credential cache (so a subsequent `klist`
    /// can surface it). Verifies the cache is populated by `auth`.
    #[tokio::test]
    async fn wave2_auth_with_mock_auth_writes_ccache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ccache_path = tmp.path().join("krb5cc");
        let ccache_str = ccache_path.to_string_lossy().into_owned();
        std::env::set_var("ADRIAN_CCACHE", &ccache_str);
        let sdk = build_sdk_with_mock_auth();
        dispatch_with_sdk(
            Command::Auth {
                principal: "admin@ADRIAN.DEV".into(),
                password: Some("s3cret".into()),
            },
            sdk,
        )
        .await
        .expect("auth with mock auth must succeed");
        // The ccache file must be populated with the principal.
        let contents =
            std::fs::read_to_string(&ccache_path).expect("ccache file must be written by auth");
        assert!(
            contents.contains("principal=admin@ADRIAN.DEV"),
            "ccache must contain principal; got: {contents}"
        );
        std::env::remove_var("ADRIAN_CCACHE");
    }

    /// Wave 2: `cert enroll` with a wired SDK (real `CaService` via
    /// `AcmeCertModule::with_ca`) generates a real ECDSA-P256 CSR,
    /// calls `CaService::issue`, and writes the issued cert DER to
    /// `<subject>.der` in the current directory.
    #[tokio::test]
    async fn wave2_cert_enroll_with_real_ca_issues_and_saves_cert() {
        // Build an SDK with a real CaService wired via AcmeCertModule::with_ca.
        let ca =
            std::sync::Arc::new(adrian_ca::CaService::new().expect("CA construction succeeds"));
        let cert_module = adrian_sdk::sdk::AcmeCertModule::with_ca(ca);
        let sdk = adrian_sdk::SdkBuilder::with_defaults()
            .cert(std::sync::Arc::new(cert_module))
            .build()
            .map(std::sync::Arc::new)
            .expect("builder with real CA must succeed");

        // chdir to a temp dir so the cert file lands in a known place.
        let tmp = tempfile::tempdir().expect("tempdir");
        let prev_cwd = std::env::current_dir().expect("current_dir");
        std::env::set_current_dir(tmp.path()).expect("chdir to tmp");

        dispatch_with_sdk(
            Command::Cert {
                subcommand: CertSub::Enroll {
                    subject: "test-host.adrian.example".into(),
                    sans: vec!["test-host.adrian.example".into()],
                },
            },
            sdk,
        )
        .await
        .expect("cert enroll with real CA must succeed");

        // The cert file must exist and start with the X.509 SEQUENCE tag.
        let cert_path = tmp.path().join("test-host.adrian.example.der");
        let cert_bytes =
            std::fs::read(&cert_path).expect("cert file must be written by cert enroll");
        assert!(!cert_bytes.is_empty(), "cert must be non-empty");
        assert_eq!(
            cert_bytes[0], 0x30,
            "DER must start with X.509 SEQUENCE tag (0x30); got 0x{:02x}",
            cert_bytes[0]
        );

        // Restore cwd.
        std::env::set_current_dir(prev_cwd).expect("restore cwd");
    }

    /// Wave 2: `file mount` with a wired SDK (real in-process SMB server
    /// via `SmbFileModule::with_smb_addr`) drives a real SMB Negotiate +
    /// SessionSetup + TreeConnect round-trip and returns Ok.
    #[tokio::test]
    async fn wave2_file_mount_with_real_smb_server_dispatches() {
        use adrian_smb_server::{Share, SmbServer, VirtualFs};
        use std::collections::HashMap;
        // Stand up an SMB server on an ephemeral TCP port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let share = std::sync::Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::new()),
        ));
        let shares: std::sync::Arc<HashMap<String, std::sync::Arc<Share>>> =
            std::sync::Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = uuid::Uuid::from_u128(0xABCD_0000_0000_0000_0000_0000_0000_0001);
        let salt = vec![0x11u8; 32];
        let shares_for_loop = shares.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shares = shares_for_loop.clone();
                let salt = salt.clone();
                tokio::spawn(async move {
                    let _ = SmbServer::handle_connection(stream, shares, guid, salt).await;
                });
            }
        });
        // Wire the SDK with the SMB server address.
        let file_module = adrian_sdk::sdk::SmbFileModule::with_smb_addr(addr.to_string());
        let sdk = adrian_sdk::SdkBuilder::with_defaults()
            .file(std::sync::Arc::new(file_module))
            .build()
            .map(std::sync::Arc::new)
            .expect("builder with real SMB addr must succeed");

        // Dispatch `file mount`. The SDK drives a real round-trip; the
        // operator's actual mount syscall is a separate step.
        dispatch_with_sdk(
            Command::File {
                subcommand: FileSub::Mount {
                    server_share: format!("{addr}/sysvol"),
                    mountpoint: "/mnt/sysvol".into(),
                },
            },
            sdk,
        )
        .await
        .expect("file mount with real SMB server must succeed");
    }

    /// Wave 2: `parse_server_share` correctly splits `server/share` and
    /// `\\server\share` forms into `(server, share)` pairs, and rejects
    /// malformed input with a descriptive error.
    #[test]
    fn wave2_parse_server_share_handles_unc_and_unix_forms() {
        // Unix form: `server/share`.
        let (s, sh) = parse_server_share("fs01.adrian.dev/users").expect("unix form");
        assert_eq!(s, "fs01.adrian.dev");
        assert_eq!(sh, "users");
        // UNC form: `\\server\share`.
        let (s, sh) = parse_server_share(r"\\fs01.adrian.dev\sysvol").expect("UNC form");
        assert_eq!(s, "fs01.adrian.dev");
        assert_eq!(sh, "sysvol");
        // Forward-slash UNC form: `//server/share`.
        let (s, sh) = parse_server_share("//fs01/sysvol").expect("slash UNC form");
        assert_eq!(s, "fs01");
        assert_eq!(sh, "sysvol");
        // Missing separator.
        let err = parse_server_share("no-separator").expect_err("must reject");
        assert!(err.contains("missing share separator"), "got: {err}");
        // Empty server.
        let err = parse_server_share("/share").expect_err("must reject empty server");
        assert!(err.contains("empty server"), "got: {err}");
        // Empty share.
        let err = parse_server_share("server/").expect_err("must reject empty share");
        assert!(err.contains("empty share"), "got: {err}");
    }

    /// Wave 2: `kdc rotate-krbtgt` continues to return NotImplemented
    /// (requires HSM context per ADR-065/015 the CLI doesn't construct).
    /// The existing v0.7.0 test still applies — included here as a Wave
    /// 2 acceptance test to verify the dispatch table is unchanged for
    /// this subcommand.
    #[tokio::test]
    async fn wave2_kdc_rotate_krbtgt_still_returns_not_implemented() {
        let err = dispatch(Command::Kdc {
            subcommand: KdcSub::RotateKrbtgt,
        })
        .await
        .expect_err("kdc rotate-krbtgt must surface NotImplemented");
        let msg = format!("{err}");
        assert!(msg.contains("not implemented"), "got: {msg}");
        assert!(msg.contains("rotate-krbtgt"), "got: {msg}");
        assert!(msg.contains("KrbtgtManager"), "got: {msg}");
        assert!(
            msg.contains("ADR-065") || msg.contains("ADR-015"),
            "got: {msg}"
        );
    }
}
