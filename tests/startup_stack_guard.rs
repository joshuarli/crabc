#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_publishes_stack_guard_before_protected_constructors() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/startup_stack_guard_test.c");
    let binary = test_support::TempArtifact::new("crabc-startup-stack-guard");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fstack-protector-strong",
            "-I",
            root.join("include").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile startup stack-guard fixture");
    assert!(status.success(), "startup stack-guard fixture compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run startup stack-guard fixture");
    assert!(
        output.status.success(),
        "startup stack-guard fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "startup stack guard ok\n");
}
