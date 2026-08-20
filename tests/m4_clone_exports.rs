#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn clone_exports_under_libc_so() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let source = manifest_dir.join("tests/fixtures/m4_clone_exports_test.c");
    // TempArtifact deliberately places the executable in /tmp, matching the
    // loader-test convention and keeping the workspace free of ELF outputs.
    let binary = test_support::TempArtifact::new("crabc-m4-clone");
    assert!(binary.starts_with(std::env::temp_dir()));
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
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for m4_clone_exports_test");
    assert!(status.success(), "m4_clone_exports_test compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run m4_clone_exports_test");
    assert!(
        output.status.success(),
        "m4_clone_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "m4 clone exports ok\n"
    );
}
