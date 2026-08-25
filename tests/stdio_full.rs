#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn stdio_full_functions_under_libc_so() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");

    let ldso_path = manifest_dir.join("target/debug/libldso.so");
    let libc_path = manifest_dir.join("target/debug/libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("stdio_full_test.c");
    let bin = test_support::TempArtifact::new("stdio_full_test");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-I",
            include.to_str().unwrap(),
            "-L",
            manifest_dir.join("target/debug").to_str().unwrap(),
            src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for stdio_full_test");
    assert!(
        status.success(),
        "crabc-cc stdio_full_test compilation failed"
    );

    let output = Command::new(&bin)
        .env(
            "LD_LIBRARY_PATH",
            manifest_dir.join("target/debug").to_str().unwrap(),
        )
        .output()
        .expect("failed to run stdio_full_test");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdio_full_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("stdio full ok"),
        "expected 'stdio full ok' in stdout, got: {}",
        stdout
    );
}
