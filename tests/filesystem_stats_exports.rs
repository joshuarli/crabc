#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn filesystem_stats_and_legacy_time_exports_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/filesystem_stats_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-filesystem-stats");

    assert!(target.join("libldso.so").exists(), "libldso.so not found");
    assert!(target.join("libc.so").exists(), "libc.so not found");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for filesystem_stats_exports_test");
    assert!(
        status.success(),
        "musl-gcc filesystem_stats_exports_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run filesystem_stats_exports_test");
    let _ = std::fs::remove_file(&binary);

    assert!(
        output.status.success(),
        "filesystem_stats_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi filesystem stats exports ok\n"
    );
}
