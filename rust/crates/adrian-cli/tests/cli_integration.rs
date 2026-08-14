//! Wave 4 CLI integration tests — invoke the `adrian` binary as a
//! subprocess via `assert_cmd` per T-403 / T-404.
//!
//! These tests verify the binary's end-to-end behavior: argument parsing,
//! dispatch table routing, error message formatting, and exit codes. They
//! complement the unit tests in `src/lib.rs` (which call `dispatch(...)`
//! directly without spawning a subprocess).
//!
//! ## Test coverage
//!
//! Per T-404, 5 integration tests:
//! 1. `cli_help_succeeds_and_lists_subcommands` — `adrian --help` exits 0
//!    and lists subcommands.
//! 2. `cli_join_surfaces_sdk_not_joined_error` — `adrian join --domain x
//!    --user y` exits non-zero with "not joined" in stderr.
//! 3. `cli_klist_without_ccache_surfaces_not_implemented` — `adrian klist`
//!    (with no credential cache) exits non-zero with "not implemented" +
//!    "klist" + "ADR-111" in stderr.
//! 4. `cli_auth_surfaces_sdk_auth_error` — `adrian auth admin@ADRIAN.DEV
//!    --password s3cret` exits non-zero with the principal + "with_kdc"
//!    hint in stderr.
//! 5. `cli_unknown_subcommand_fails` — `adrian bogus` exits non-zero with
//!    "unrecognized subcommand" in stderr.

use assert_cmd::Command;

/// Helper: run `adrian` with the given args and return the asserted
/// command for further chaining.
fn adrian() -> Command {
    Command::cargo_bin("adrian").expect(
        "the `adrian` binary must be built before running integration tests; \
         run `cargo build -p adrian-cli` first",
    )
}

/// T-404 (1): `adrian --help` succeeds and lists the top-level subcommands.
/// This is the smoke test that the binary is built, runnable, and the
/// clap argument parser is wired correctly.
#[test]
fn cli_help_succeeds_and_lists_subcommands() {
    let output = adrian().arg("--help").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    // Verify the top-level subcommands are listed.
    for sub in [
        "join",
        "leave",
        "gpupdate",
        "klist",
        "kinit",
        "migrate",
        "gpo-translate",
        "auth",
        "policy",
        "cert",
        "file",
        "kdc",
    ] {
        assert!(
            stdout.contains(sub),
            "expected '{}' in --help output; got: {stdout}",
            sub
        );
    }
}

/// T-404 (2): `adrian join --domain x --user y` surfaces the SDK's
/// `NotJoined` error. The CLI's dispatch table routes `join` through
/// `AdrianClient::join` (the loud stub), which returns
/// `SdkError::NotJoined`. The CLI surfaces this as a non-zero exit
/// with "not joined" in stderr (via `anyhow::Error::from(CliError::Sdk(...))`
/// → `main`'s `anyhow::Result<()>`).
#[test]
fn cli_join_surfaces_sdk_not_joined_error() {
    let output = adrian()
        .args(["join", "--domain", "adrian.dev", "--user", "admin"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("not joined"),
        "expected 'not joined' in stderr; got: {stderr}"
    );
}

/// T-404 (3): `adrian klist` without a credential cache surfaces a
/// loud NotImplemented naming the cache path + the `kinit` hint +
/// ADR-111. We set `ADRIAN_CCACHE` to a non-existent path so the
/// test doesn't depend on the operator's real ccache.
#[test]
fn cli_klist_without_ccache_surfaces_not_implemented() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ccache_path = tmp.path().join("does-not-exist");
    let ccache_str = ccache_path.to_string_lossy().into_owned();
    let output = adrian()
        .arg("klist")
        .env("ADRIAN_CCACHE", &ccache_str)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("not implemented") && stderr.contains("klist"),
        "expected 'not implemented' + 'klist' in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains(&ccache_str),
        "expected ccache path in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("kinit"),
        "expected 'kinit' hint in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("ADR-111"),
        "expected ADR-111 ref in stderr; got: {stderr}"
    );
}

/// T-404 (4): `adrian auth admin@ADRIAN.DEV --password s3cret`
/// surfaces the SDK's auth error carrying the principal + the
/// actionable `with_kdc` hint. This proves the dispatch path routes
/// `auth` through `sdk.auth.authenticate_kerberos` (the default stub
/// surfaces its loud error via `CliError::Sdk(SdkError::Auth(...))`).
#[test]
fn cli_auth_surfaces_sdk_auth_error() {
    let output = adrian()
        .args(["auth", "admin@ADRIAN.DEV", "--password", "s3cret"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("admin@ADRIAN.DEV"),
        "expected principal in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("with_kdc"),
        "expected actionable 'with_kdc' hint in stderr; got: {stderr}"
    );
}

/// T-404 (5): `adrian bogus` exits non-zero with "unrecognized
/// subcommand" in stderr (clap's standard error for unknown
/// subcommands). This proves the clap parser rejects unknown
/// subcommands rather than silently succeeding.
#[test]
fn cli_unknown_subcommand_fails() {
    let output = adrian().arg("bogus").assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.to_lowercase().contains("unrecognized")
            || stderr.to_lowercase().contains("invalid")
            || stderr.to_lowercase().contains("unknown subcommand"),
        "expected an 'unrecognized/invalid subcommand' error in stderr; got: {stderr}"
    );
}

/// Wave 4 bonus: `adrian kdc rotate-krbtgt` surfaces NotImplemented
/// naming KrbtgtManager + ADR-065/015 (the one subcommand that
/// genuinely can't be wired from the CLI surface — requires HSM
/// context).
#[test]
fn cli_kdc_rotate_krbtgt_surfaces_not_implemented() {
    let output = adrian().args(["kdc", "rotate-krbtgt"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("not implemented") && stderr.contains("rotate-krbtgt"),
        "expected 'not implemented' + 'rotate-krbtgt' in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("KrbtgtManager"),
        "expected KrbtgtManager name in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("ADR-065") || stderr.contains("ADR-015"),
        "expected ADR-065 or ADR-015 ref in stderr; got: {stderr}"
    );
}

/// Wave 4 bonus: `adrian cert enroll --subject dc01.adrian.dev` surfaces
/// the SDK's cert error naming `with_ca` (proving Wave 2's real
/// dispatch through `sdk.cert.enroll`).
#[test]
fn cli_cert_enroll_surfaces_sdk_cert_error() {
    let output = adrian()
        .args(["cert", "enroll", "--subject", "dc01.adrian.dev"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("dc01.adrian.dev"),
        "expected subject in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("with_ca"),
        "expected actionable 'with_ca' hint in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("ADR-095"),
        "expected ACME ADR ref in stderr; got: {stderr}"
    );
}

/// Wave 4 bonus: `adrian file mount fs01/users /mnt/users` surfaces
/// the SDK's file error naming `with_smb_addr` (proving Wave 2's real
/// dispatch through `sdk.file.mount_share`).
#[test]
fn cli_file_mount_surfaces_sdk_file_error() {
    let output = adrian()
        .args(["file", "mount", "fs01/users", "/mnt/users"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("fs01") && stderr.contains("users"),
        "expected server + share in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("with_smb_addr"),
        "expected actionable 'with_smb_addr' hint in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("ADR-106"),
        "expected SMB client ADR ref in stderr; got: {stderr}"
    );
}
