#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn getopt_state_and_program_names_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/getopt_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-getopt");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
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
        .expect("failed to run crabc-cc for getopt_exports_test");
    assert!(status.success(), "getopt_exports_test compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run getopt_exports_test");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "getopt_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi getopt exports ok\n"
    );
}
