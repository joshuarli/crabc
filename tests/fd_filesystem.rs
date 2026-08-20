use std::process::Command;

#[test]
fn basic_fd_and_filesystem_contract_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("tests/fixtures");
    let include = root.join("include");
    let target = root.join("target/debug");
    let ldso = target.join("libldso.so");
    let source = fixtures.join("fd_filesystem_test.c");
    let binary = fixtures.join("fd_filesystem_test");

    assert!(ldso.exists(), "libldso.so not found");
    assert!(target.join("libc.so").exists(), "libc.so not found");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            include.to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso.to_str().unwrap(),
            source.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("musl-gcc failed");
    assert!(status.success(), "fd/filesystem fixture compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("fd/filesystem fixture failed to start");
    assert!(
        output.status.success(),
        "fd/filesystem fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "fd filesystem ok\n");
}
