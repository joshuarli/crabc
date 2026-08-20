//! AArch64 layout and constant evidence for the newly closed protocol headers.
//!
//! The fixture is compiled twice against the same musl compiler: candidate
//! public headers and the pinned musl 1.2.6 headers.  It exercises declarations
//! that are easy for a forwarding header to omit while keeping the comparison
//! independent of candidate runtime symbols.
#[path = "common/mod.rs"]
mod test_support;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn public_aarch64_network_headers_match_pinned_musl() {
    use std::path::Path;
    use std::process::Command;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir.join("tests/fixtures/aarch64_network_headers_test.c");
    let include = manifest_dir.join("include");
    let reference_include = Path::new("/opt/musl-1.2.6/include");
    assert!(
        reference_include.exists(),
        "pinned musl include directory is unavailable; run this test in scripts/dev.sh test"
    );

    let custom_bin = test_support::TempArtifact::new("aarch64_network_headers_custom");
    let oracle_bin = test_support::TempArtifact::new("aarch64_network_headers_musl");

    let mut custom = Command::new("musl-gcc");
    custom.args([
        "-std=c11",
        "-D_GNU_SOURCE",
        "-isystem",
        reference_include.to_str().unwrap(),
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
        .expect("failed to run musl-gcc for network-header ABI probe");
    assert!(status.success(), "candidate network-header probe compilation failed");

    let mut oracle = Command::new("musl-gcc");
    oracle.args([
        "-std=c11",
        "-D_GNU_SOURCE",
        "-isystem",
        reference_include.to_str().unwrap(),
        "-fPIE",
        "-pie",
        fixture.to_str().unwrap(),
        "-o",
        oracle_bin.to_str().unwrap(),
    ]);
    let status = oracle
        .status()
        .expect("failed to run musl-gcc for musl network-header ABI probe");
    assert!(status.success(), "musl network-header probe compilation failed");

    let custom_output = Command::new(&custom_bin)
        .output()
        .expect("failed to run candidate network-header ABI probe");
    assert!(
        custom_output.status.success(),
        "candidate network-header ABI probe failed: {}",
        String::from_utf8_lossy(&custom_output.stderr)
    );
    let oracle_output = Command::new(&oracle_bin)
        .output()
        .expect("failed to run musl network-header ABI probe");
    assert!(
        oracle_output.status.success(),
        "musl network-header ABI probe failed: {}",
        String::from_utf8_lossy(&oracle_output.stderr)
    );

    assert_eq!(
        custom_output.stdout,
        oracle_output.stdout,
        "crabc public network headers diverge from pinned musl 1.2.6\ncrabc: {}musl: {}",
        String::from_utf8_lossy(&custom_output.stdout),
        String::from_utf8_lossy(&oracle_output.stdout)
    );
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[test]
fn public_aarch64_network_header_probe_is_native_only() {}
