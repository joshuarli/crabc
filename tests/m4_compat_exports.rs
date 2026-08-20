#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn historical_compatibility_exports_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/m4_compat_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-m4-compat");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE", "-pie", "-fno-builtin", "-D_GNU_SOURCE", "-I", root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker", target.join("libldso.so").to_str().unwrap(), "-L", target.to_str().unwrap(),
            source.to_str().unwrap(), "-Wl,--allow-shlib-undefined", "-lc", "-o", binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile M4 compatibility fixture");
    assert!(status.success());
    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run M4 compatibility fixture");
    let _ = std::fs::remove_file(&binary);
    assert!(output.status.success(), "stdout: {}, stderr: {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "m4 compat exports ok\n");
}
