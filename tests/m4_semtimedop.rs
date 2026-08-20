#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn semtimedop_under_libldso() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/m4_semtimedop_test.c");
    let binary = test_support::TempArtifact::new("crabc-m4-semtimedop");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
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
        .expect("failed to run musl-gcc for m4_semtimedop_test");
    assert!(status.success(), "m4_semtimedop_test compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run m4_semtimedop_test");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "m4_semtimedop_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "m4 semtimedop ok\n");
}
