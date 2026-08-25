#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static PTHREAD_TEST_LOCK: Mutex<()> = Mutex::new(());

fn run_with_timeout(mut command: Command, description: &str) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to run {description}: {error}"));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed to poll {description}: {error}"))
        {
            Some(_) => {
                return child
                    .wait_with_output()
                    .unwrap_or_else(|error| panic!("failed to collect {description}: {error}"));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .unwrap_or_else(|error| panic!("failed to collect timed-out {description}: {error}"));
                panic!(
                    "{description} did not complete within 15 seconds; stdout: {}, stderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[test]
fn pthread_functions_under_libc_so() {
    let _guard = PTHREAD_TEST_LOCK.lock();
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");

    let ldso_path = manifest_dir.join("target/debug/libldso.so");
    let libc_path = manifest_dir.join("target/debug/libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("pthread_test.c");
    let bin = test_support::TempArtifact::new("pthread_test");
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
        .expect("failed to run crabc-cc for pthread_test");
    assert!(status.success(), "crabc-cc pthread_test compilation failed");

    let mut command = Command::new(&bin);
    command.env(
        "LD_LIBRARY_PATH",
        manifest_dir.join("target/debug").to_str().unwrap(),
    );
    let output = run_with_timeout(command, "pthread_test");

    assert!(
        output.status.success(),
        "pthread_test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "pthread ok\n");
}

#[test]
fn pthread_full_test() {
    let _guard = PTHREAD_TEST_LOCK.lock();
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");

    let ldso_path = manifest_dir.join("target/debug/libldso.so");
    assert!(ldso_path.exists(), "libldso.so not found");

    let src = fixtures.join("pthread_full_test.c");
    let bin = test_support::TempArtifact::new("pthread_full_test");
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
        .expect("failed to run crabc-cc for pthread_full_test");
    assert!(
        status.success(),
        "crabc-cc pthread_full_test compilation failed"
    );

    let output = Command::new(&bin)
        .env(
            "LD_LIBRARY_PATH",
            manifest_dir.join("target/debug").to_str().unwrap(),
        )
        .output()
        .expect("failed to run pthread_full_test");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pthread_full_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("pthread_full ok"),
        "unexpected output: {}",
        stdout
    );
}
