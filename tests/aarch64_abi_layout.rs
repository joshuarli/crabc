//! Public AArch64 C ABI probes compared with the pinned musl headers.
//!
//! This deliberately compiles the same fixture twice: once with crabc's
//! public headers and once with the musl 1.2.6 reference installed by the
//! native AArch64 Docker image.  The resulting runtime records make size,
//! alignment, offsets, and signal-stack constants observable to the test.

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn public_aarch64_layout_matches_pinned_musl() {
    use std::path::Path;
    use std::process::Command;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir.join("tests/fixtures/aarch64_abi_layout_test.c");
    let include = manifest_dir.join("include");
    let reference_include = Path::new("/opt/musl-1.2.6/include");
    assert!(
        reference_include.exists(),
        "pinned musl include directory is unavailable; run this test in scripts/dev.sh test"
    );

    let output_dir = manifest_dir.join("target/debug");
    let custom_bin = output_dir.join("aarch64_abi_layout_custom");
    let oracle_bin = output_dir.join("aarch64_abi_layout_musl");

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
    let status = custom.status().expect("failed to run musl-gcc for crabc ABI probe");
    assert!(status.success(), "crabc-header ABI probe compilation failed");

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
    let status = oracle.status().expect("failed to run musl-gcc for musl ABI probe");
    assert!(status.success(), "musl-header ABI probe compilation failed");

    let custom_output = Command::new(&custom_bin)
        .output()
        .expect("failed to run crabc-header ABI probe");
    assert!(
        custom_output.status.success(),
        "crabc-header ABI probe failed: {}",
        String::from_utf8_lossy(&custom_output.stderr)
    );
    let oracle_output = Command::new(&oracle_bin)
        .output()
        .expect("failed to run musl-header ABI probe");
    assert!(
        oracle_output.status.success(),
        "musl-header ABI probe failed: {}",
        String::from_utf8_lossy(&oracle_output.stderr)
    );

    assert_eq!(
        custom_output.stdout, oracle_output.stdout,
        "crabc public AArch64 layout diverges from pinned musl 1.2.6\ncrabc: {}musl: {}",
        String::from_utf8_lossy(&custom_output.stdout),
        String::from_utf8_lossy(&oracle_output.stdout)
    );
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[test]
fn public_aarch64_layout_probe_is_native_only() {
    // The probe must execute on AArch64 because the target's long and pointer
    // ABI is part of what it measures. CI runs it through scripts/dev.sh.
}
