#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn iconv_utf8_errors_commit_musl_progress() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("iconv_error_progress_test.c");
    let bin = test_support::TempArtifact::new("iconv_error_progress_test");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
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
        .expect("failed to run crabc-cc for iconv_error_progress_test");
    assert!(
        status.success(),
        "crabc-cc iconv_error_progress_test compilation failed"
    );

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run iconv_error_progress_test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "iconv_error_progress_test exited with {:?}; stdout: {}; stderr: {}",
        output.status.code(),
        stdout,
        stderr
    );
    assert_eq!(stdout, "iconv error progress ok\n");
}
