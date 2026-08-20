#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn errno_is_thread_local_and_fd_wrappers_translate_failures() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let ldso_path = manifest_dir.join("target/debug/libldso.so");
    let lib_dir = manifest_dir.join("target/debug");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(lib_dir.join("libc.so").exists(), "libc.so not found");

    let src = fixtures.join("errno_syscall_test.c");
    let bin = test_support::TempArtifact::new("errno_syscall_test");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-I",
            include.to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso_path.to_str().unwrap(),
            src.to_str().unwrap(),
            "-L",
            lib_dir.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("musl-gcc failed");
    assert!(status.success(), "errno_syscall_test compilation failed");

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", lib_dir.to_str().unwrap())
        .output()
        .expect("failed to run errno_syscall_test");
    assert!(
        output.status.success(),
        "errno_syscall_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "errno syscall ok\n");
}
