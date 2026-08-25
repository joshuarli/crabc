#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_runs_tiny_pie() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let tiny_src = fixtures.join("tiny.c");
    let tiny_bin = test_support::TempArtifact::new("tiny_ldso");

    // This is a naked `_start` loader probe, not a libc/CRT candidate link.
    // It uses raw Clang with no target headers/startup/default libraries and
    // the same canonical interpreter that ordinary owned-driver outputs use.
    let mut command = test_support::naked_aarch64_command();
    let status = command
        .args([
            "-fPIE",
            "-pie",
            "-nostdlib",
            "-nostartfiles",
            "-Wl,--dynamic-linker,/lib/ld-crabc-aarch64.so.1",
            tiny_src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-o",
            tiny_bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile naked tiny loader probe");
    assert!(status.success(), "naked tiny loader probe compilation failed");

    let output = Command::new(&tiny_bin)
        .output()
        .expect("failed to run tiny_ldso");

    assert!(
        output.status.success(),
        "tiny_ldso exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "Hello\n");
}
