#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_runs_real_printf_binary() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");

    let ldso_path = manifest_dir.join("target/debug/libldso.so");
    assert!(
        ldso_path.exists(),
        "libldso.so not found at {}",
        ldso_path.display()
    );

    let libc_path = manifest_dir.join("target/debug/libc.so");
    assert!(
        libc_path.exists(),
        "libc.so not found at {}",
        libc_path.display()
    );

    let hello_src = fixtures.join("hello.c");
    let hello_bin = test_support::TempArtifact::new("hello");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-L",
            manifest_dir.join("target/debug").to_str().unwrap(),
            hello_src.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            hello_bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run crabc-cc for hello");
    assert!(status.success(), "crabc-cc hello compilation failed");

    let output = Command::new(&hello_bin)
        .env(
            "LD_LIBRARY_PATH",
            manifest_dir.join("target/debug").to_str().unwrap(),
        )
        .output()
        .expect("failed to run hello");

    assert!(
        output.status.success(),
        "hello exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello\n");
    assert_eq!(
        output.stderr, b"",
        "a successfully started program must not receive loader diagnostics on stderr"
    );
}
