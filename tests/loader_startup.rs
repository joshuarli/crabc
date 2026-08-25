#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn loader_startup_exports_install_bounded_state() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/loader_startup_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-loader-startup");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
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
        .expect("failed to compile loader_startup_test");
    assert!(
        status.success(),
        "crabc-cc loader_startup_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run loader_startup_test");
    let _ = std::fs::remove_file(&binary);

    assert!(
        output.status.success(),
        "loader_startup_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi loader startup ok\n"
    );
}
