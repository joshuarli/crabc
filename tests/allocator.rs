#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn allocator_contract_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = root.join("tests/fixtures");
    let include = root.join("include");
    let target = root.join("target/debug");
    let ldso = target.join("libldso.so");
    let source = fixtures.join("allocator_test.c");
    let binary = test_support::TempArtifact::new("allocator_test");

    assert!(ldso.exists(), "libldso.so not found");
    assert!(target.join("libc.so").exists(), "libc.so not found");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            include.to_str().unwrap(),
            source.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("crabc-cc failed");
    assert!(status.success(), "allocator fixture compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("allocator fixture failed to start");
    assert!(
        output.status.success(),
        "allocator fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "allocator ok\n");
}
