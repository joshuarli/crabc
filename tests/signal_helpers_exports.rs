#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn signal_helpers_exports_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/signal_helpers_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-signal-helpers");

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
        .expect("failed to run musl-gcc for signal_helpers_exports_test");
    assert!(
        status.success(),
        "musl-gcc signal_helpers_exports_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run signal_helpers_exports_test");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "signal_helpers_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi signal helpers ok\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "notice: User defined signal 1\n"
    );
}
