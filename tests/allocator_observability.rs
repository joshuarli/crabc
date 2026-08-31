#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn allocator_observability_matches_the_active_aarch64_runtime() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/allocator_observability_test.c");
    let binary = test_support::TempArtifact::new("allocator-observability-test");

    assert!(target.join("libldso.so").is_file(), "libldso.so not found");
    assert!(target.join("libc.so").is_file(), "libc.so not found");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-fno-stack-protector",
            "-D_GNU_SOURCE",
            "-pthread",
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
        .expect("failed to compile allocator-observability fixture");
    assert!(status.success(), "allocator-observability fixture did not compile");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("allocator-observability fixture failed to start");
    assert!(
        output.status.success(),
        "allocator-observability fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
