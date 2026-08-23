//! Focused compile and constant checks for the public system/misc headers.
//!
//! The candidate and pinned musl headers are compiled with the same AArch64
//! compiler and native Linux UAPI include directory.  The fixture checks
//! representative constants, ioctl encodings, declarations, and ABI sizes.
#[path = "common/mod.rs"]
mod test_support;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn public_system_misc_headers_match_pinned_musl() {
    use std::path::Path;
    use std::process::Command;

    let manifest_dir = Path::new(test_support::REPOSITORY_ROOT);
    let fixture = manifest_dir.join("tests/fixtures/header_surface_test.c");
    let include = manifest_dir.join("include");
    let reference_include = Path::new("/opt/musl-1.2.6/include");
    assert!(
        reference_include.exists(),
        "pinned musl include directory is unavailable; run this test in scripts/dev.sh test"
    );

    let custom_bin = test_support::TempArtifact::new("header_surface_custom");
    let oracle_bin = test_support::TempArtifact::new("header_surface_musl");

    let mut custom = Command::new("musl-gcc");
    custom.args([
        "-std=c11",
        "-D_GNU_SOURCE",
        "-isystem",
        "/usr/include",
        "-fPIE",
        "-pie",
        "-I",
        include.to_str().unwrap(),
        fixture.to_str().unwrap(),
        "-o",
        custom_bin.to_str().unwrap(),
    ]);
    let status = custom
        .status()
        .expect("failed to run musl-gcc for public header probe");
    assert!(
        status.success(),
        "candidate public header probe compilation failed"
    );

    let mut oracle = Command::new("musl-gcc");
    oracle.args([
        "-std=c11",
        "-D_GNU_SOURCE",
        "-isystem",
        reference_include.to_str().unwrap(),
        "-isystem",
        "/usr/include",
        "-fPIE",
        "-pie",
        fixture.to_str().unwrap(),
        "-o",
        oracle_bin.to_str().unwrap(),
    ]);
    let status = oracle
        .status()
        .expect("failed to run musl-gcc for pinned public header probe");
    assert!(
        status.success(),
        "pinned public header probe compilation failed"
    );

    let custom_output = Command::new(&custom_bin)
        .output()
        .expect("failed to run candidate public header probe");
    assert!(
        custom_output.status.success(),
        "candidate public header probe failed: {}",
        String::from_utf8_lossy(&custom_output.stderr)
    );
    let oracle_output = Command::new(&oracle_bin)
        .output()
        .expect("failed to run pinned public header probe");
    assert!(
        oracle_output.status.success(),
        "pinned public header probe failed: {}",
        String::from_utf8_lossy(&oracle_output.stderr)
    );
    assert_eq!(
        custom_output.stdout,
        oracle_output.stdout,
        "crabc public system/misc headers diverge from pinned musl 1.2.6\ncrabc: {}musl: {}",
        String::from_utf8_lossy(&custom_output.stdout),
        String::from_utf8_lossy(&oracle_output.stdout)
    );
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[test]
fn public_system_misc_header_probe_is_native_only() {}
