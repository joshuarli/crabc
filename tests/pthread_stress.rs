#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;
use std::sync::Mutex;

static PTHREAD_STRESS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn pthread_lifecycle_stress_under_libc_so() {
    let _guard = PTHREAD_STRESS_TEST_LOCK.lock().unwrap();
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");

    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("pthread_stress_test.c");
    let bin = test_support::TempArtifact::new("pthread_stress_test");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
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
        .expect("failed to run musl-gcc for pthread_stress_test");
    assert!(status.success(), "musl-gcc pthread_stress_test compilation failed");

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", target)
        .output()
        .expect("failed to run pthread_stress_test");
    assert!(
        output.status.success(),
        "pthread_stress_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "pthread stress ok\n");
}
