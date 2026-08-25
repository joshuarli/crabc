#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn unicode_encoders_exports_under_libc_so() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("unicode_encoders_test.c");
    let bin = test_support::TempArtifact::new("crabc-c-abi-unicode");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-std=c11",
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            include.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for unicode_encoders_test");
    assert!(
        status.success(),
        "crabc-cc unicode_encoders_test compilation failed"
    );

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run unicode_encoders_test");
    let _ = std::fs::remove_file(&bin);

    assert!(
        output.status.success(),
        "unicode_encoders_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi unicode encoders ok\n"
    );
}
