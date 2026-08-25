#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn error_reporting_exports_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/error_reporting_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-error-reporting");

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
        .expect("failed to compile error_reporting_exports_test");
    assert!(
        status.success(),
        "error_reporting_exports_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run error_reporting_exports_test");
    let _ = std::fs::remove_file(&binary);

    assert!(
        output.status.success(),
        "error_reporting_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi error reporting ok\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        concat!(
            "cabi_err: warn one: No such file or directory\n",
            "cabi_err: vwarn 2: Permission denied\n",
            "cabi_err: warnx three\n",
            "cabi_err: vwarnx 4\n",
            "signal: User defined signal 1\n",
            "cabi_err: err five: No such file or directory\n",
            "cabi_err: errx six\n",
            "cabi_err: verr seven: Permission denied\n",
            "cabi_err: verrx eight\n",
        )
    );
}
