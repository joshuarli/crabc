#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn legacy_des_bit_array_apis_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/legacy_des_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-legacy-des");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE", "-pie", "-fno-builtin", "-I", root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker", target.join("libldso.so").to_str().unwrap(),
            "-L", target.to_str().unwrap(), source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined", "-lc", "-o", binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for legacy_des_test");
    assert!(status.success(), "legacy_des_test compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run legacy_des_test");
    assert!(
        output.status.success(),
        "legacy_des_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "c-abi legacy des unsupported\n");
}
