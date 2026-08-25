#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn getdate_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/getdate_test.c");
    let artifact = test_support::TempArtifact::new("crabc-c-abi-getdate");
    let template = artifact.parent().join("datemsk");
    std::fs::write(&template, b"%Y-%m-%d %H:%M:%S\n%Y-%m-%d\n")
        .expect("failed to write getdate DATEMSK template");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-std=c11",
            "-D_XOPEN_SOURCE=700",
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            root.join("include").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            artifact.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for getdate_test");
    assert!(status.success(), "crabc-cc getdate_test compilation failed");

    let output = Command::new(&*artifact)
        .env("LD_LIBRARY_PATH", &target)
        .env("TZ", "UTC")
        .arg(&template)
        .output()
        .expect("failed to run getdate_test");
    let _ = std::fs::remove_file(&template);
    assert!(
        output.status.success(),
        "getdate_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi getdate ok\n"
    );
}
