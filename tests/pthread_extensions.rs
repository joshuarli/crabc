#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;
use std::sync::Mutex;

static PTHREAD_EXTENSIONS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn pthread_extensions_under_loader() {
    let _guard = PTHREAD_EXTENSIONS_TEST_LOCK.lock();
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso = target.join("libldso.so");
    let libc = target.join("libc.so");
    assert!(ldso.exists(), "libldso.so not found");
    assert!(libc.exists(), "libc.so not found");

    let source = fixtures.join("pthread_extensions_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-pthread-extensions");
    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-I",
            include.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile c-abi pthread extension fixture");
    assert!(
        status.success(),
        "c-abi pthread extension fixture compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", target.to_str().unwrap())
        .output()
        .expect("failed to run c-abi pthread extension fixture");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "c-abi pthread extension fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi pthread extensions ok\n"
    );
}
