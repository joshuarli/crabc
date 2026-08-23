#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn syscall_filesystem_exports_under_libc_so() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("syscall_exports_test.c");
    // Keep generated executables out of the source tree.  The test process is
    // serialized by the workspace test configuration, so its PID is enough
    // to make this path distinct from other fixture runs.
    let bin = test_support::TempArtifact::new("crabc-c-abi-syscall-exports");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-D_GNU_SOURCE",
            "-I",
            include.to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso_path.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for syscall_exports_test");
    assert!(
        status.success(),
        "musl-gcc syscall_exports_test compilation failed"
    );

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run syscall_exports_test");
    let _ = std::fs::remove_file(&bin);

    assert!(
        output.status.success(),
        "syscall_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi syscall exports ok\n"
    );
}
