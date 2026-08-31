#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixture = root.join("tests/fixtures/native_mimalloc_initial_live_owner_exit_test.c");
    let mut command = if candidate {
        Command::new(test_support::crabc_cc())
    } else {
        Command::new("musl-gcc")
    };
    command.args(["-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
            "-I",
            root.join("include").to_str().unwrap(),
            "-L",
            root.join("target/debug").to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    command.arg(&fixture).args(["-lc", "-o"]).arg(binary);
    let status = command
        .status()
        .expect("failed to compile the native mimalloc initial-live-owner-exit fixture");
    assert!(
        status.success(),
        "native mimalloc initial-live-owner-exit fixture compilation failed"
    );
}

fn run_with_timeout(mut command: Command, description: &str) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to run {description}: {error}"));
    let deadline = Instant::now() + Duration::from_secs(5);
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
                    "{description} did not complete within 5 seconds; stdout: {}, stderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn run(binary: &std::path::Path, candidate: bool) -> Output {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let mut command = Command::new(binary);
    if candidate {
        command.env("LD_LIBRARY_PATH", root.join("target/debug"));
    }
    run_with_timeout(command, "native mimalloc initial-live-owner-exit fixture")
}

#[test]
fn native_mimalloc_initial_live_owner_exit_matches_pinned_musl() {
    let reference =
        test_support::TempArtifact::new("native-mimalloc-initial-live-owner-exit-reference");
    let candidate =
        test_support::TempArtifact::new("native-mimalloc-initial-live-owner-exit-candidate");
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, false);
    let candidate_output = run(&candidate, true);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(
        reference_output.stdout,
        b"native mimalloc initial live owner exit ok\n"
    );
    assert_eq!(
        candidate_output.status,
        reference_output.status,
        "crabc exit status differs; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
