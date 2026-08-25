#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_sets_up_tls() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let tlstest_src = fixtures.join("tlstest.c");
    let tlstest_bin = test_support::TempArtifact::new("tlstest");

    // This is a naked `_start` loader/TLS probe, not a libc/CRT candidate
    // link. Raw Clang prevents a musl compiler wrapper from contributing
    // target headers, startup objects, or compiler helper archives.
    let mut command = test_support::naked_aarch64_command();
    let status = command
        .args([
            "-fPIE",
            "-pie",
            "-nostdlib",
            "-nostartfiles",
            "-Wl,--dynamic-linker,/lib/ld-crabc-aarch64.so.1",
            tlstest_src.to_str().unwrap(),
            "-o",
            tlstest_bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile naked TLS loader probe");
    assert!(status.success(), "naked TLS loader probe compilation failed");

    let output = Command::new(&tlstest_bin)
        .output()
        .expect("failed to run tlstest");

    assert!(
        output.status.success(),
        "tlstest exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok\n");
}
