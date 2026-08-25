#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn dynamic_loader_introspection_reports_real_objects() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let source = root.join("tests/fixtures/dynamic_loader_introspection_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-dynamic-loader-introspection");
    let target = root.join("target/debug");
    let ldso = target.join("libldso.so");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-I",
            root.join("include").to_str().unwrap(),
            source.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile dynamic-loader introspection fixture");
    assert!(status.success(), "fixture compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", target)
        .output()
        .expect("failed to run dynamic-loader introspection fixture");
    assert!(
        output.status.success(),
        "fixture exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"ok\n");
}
