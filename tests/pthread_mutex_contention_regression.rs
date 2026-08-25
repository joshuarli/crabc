#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let fixture = root.join("tests/fixtures/pthread_mutex_contention_regression_test.c");
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
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    command.arg(&fixture).args(["-lc", "-o"]).arg(binary);
    let status = command
        .status()
        .expect("failed to compile the pthread mutex contention regression fixture");
    assert!(
        status.success(),
        "pthread mutex contention regression fixture compilation failed"
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
    run_with_timeout(command, "pthread mutex contention regression fixture")
}

#[test]
fn pthread_mutex_contention_matches_pinned_musl() {
    let reference = test_support::TempArtifact::new("pthread-mutex-contention-reference");
    let candidate = test_support::TempArtifact::new("pthread-mutex-contention-candidate");
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, false);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(
        reference_output.stdout,
        b"pthread mutex contention contract ok\n"
    );
    // Exercise independent process lifecycles: the defect this guards against
    // requires a failed AArch64 store-exclusive retry and is schedule
    // dependent in one short handoff. Repetition makes that concurrency edge
    // an observable, bounded contract rather than a probabilistic test flake.
    for attempt in 0..8 {
        let candidate_output = run(&candidate, true);
        assert_eq!(
            candidate_output.status,
            reference_output.status,
            "crabc exit status differs on attempt {attempt}; stderr: {}",
            String::from_utf8_lossy(&candidate_output.stderr),
        );
        assert_eq!(candidate_output.stdout, reference_output.stdout);
        assert_eq!(candidate_output.stderr, reference_output.stderr);
    }
}
