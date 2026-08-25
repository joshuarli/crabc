#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn statvfs_under_libc_so() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");

    let ldso_path = manifest_dir.join("target/debug/libldso.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(
        manifest_dir.join("target/debug/libc.so").exists(),
        "libc.so not found"
    );

    let src = fixtures.join("statvfs_test.c");
    let bin = test_support::TempArtifact::new("statvfs_test");
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
        .expect("failed to run crabc-cc for statvfs_test");
    assert!(status.success(), "crabc-cc statvfs_test compilation failed");

    let output = Command::new(&bin)
        .env(
            "LD_LIBRARY_PATH",
            manifest_dir.join("target/debug").to_str().unwrap(),
        )
        .output()
        .expect("failed to run statvfs_test");

    assert!(
        output.status.success(),
        "statvfs_test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "statvfs ok\n");
}
