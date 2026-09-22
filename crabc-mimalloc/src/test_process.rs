//! Fresh-process test boundary for fixtures that deliberately consume one
//! irreversible process-global source owner.
//!
//! A raw fork would copy any owner, lock, or environment state established by
//! earlier unit tests.  The child instead execs this exact libtest binary and
//! filter, so its fixture starts before any Rust allocator test has entered
//! the native process owner.  This module is test-only and never resets or
//! otherwise changes a production global.

use std::env;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::string::String;
use std::time::{Duration, Instant};
use std::vec::Vec;

const CHILD_MARKER: &str = "CRABC_MIMALLOC_FRESH_TEST_CHILD";
const CHILD_STARTED_PREFIX: &str = "CRABC_MIMALLOC_FRESH_TEST_CHILD_STARTED=";
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CHILD_TIMEOUT: Duration = Duration::from_secs(300);

/// Runs one process-terminal fixture in a newly exec'd instance of this exact
/// test binary.
///
/// The parent retains no lifecycle access to the child.  A child receives only
/// its exact test target, runs serially, and removes inherited mimalloc option
/// variables before the fixture sets its own source inputs.  Its output stays
/// visible to the outer test while nested libtest summaries are suppressed so
/// harness accounting observes only the outer binary's final test result.
pub(crate) fn run_in_fresh_process(test_name: &'static str, fixture: impl FnOnce()) {
    match env::var_os(CHILD_MARKER) {
        Some(marker) => {
            assert_eq!(
                marker,
                OsStr::new(test_name),
                "a fresh-process child may run only its exact marked fixture"
            );
            emit_child_started(test_name);
            fixture();
            return;
        }
        None => {}
    }

    let executable = env::current_exe().expect("the current test executable is available");
    let mut command = Command::new(executable);
    command
        .arg(test_name)
        .arg("--exact")
        .arg("--test-threads=1")
        .arg("--nocapture")
        .env(CHILD_MARKER, test_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // These source options are fixture inputs, not ambient process state.  A
    // child must not inherit a prior unit test's option image before its own
    // body selects the exact source configuration it documents.
    for (name, _) in env::vars_os() {
        if name
            .to_string_lossy()
            .starts_with("mimalloc_")
        {
            command.env_remove(name);
        }
    }

    let mut child = command.spawn().expect("spawn fresh exact test child");
    let stdout = child.stdout.take().expect("fresh child stdout is piped");
    let stderr = child.stderr.take().expect("fresh child stderr is piped");
    let stdout_reader = std::thread::spawn(move || read_child_output(stdout));
    let stderr_reader = std::thread::spawn(move || read_child_output(stderr));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("poll fresh exact test child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait().expect("reap timed out fresh test child");
                let stdout = join_child_output(stdout_reader, "stdout");
                let stderr = join_child_output(stderr_reader, "stderr");
                panic!(
                    "fresh test child {test_name} exceeded {} seconds and exited {status}; stdout:\n{}\nstderr:\n{}",
                    CHILD_TIMEOUT.as_secs(),
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr),
                );
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };
    let stdout = join_child_output(stdout_reader, "stdout");
    let stderr = join_child_output(stderr_reader, "stderr");
    if !status.success() {
        panic!(
            "fresh test child {test_name} exited {status}; stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        );
    }
    assert_child_started(test_name, &stdout);

    emit_child_stdout(test_name, &stdout);
    if !stderr.is_empty() {
        std::eprint!("{}", String::from_utf8_lossy(&stderr));
    }
}

fn emit_child_started(test_name: &str) {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    std::writeln!(stdout, "{CHILD_STARTED_PREFIX}{test_name}")
        .expect("write fresh exact test child start marker");
    stdout
        .flush()
        .expect("flush fresh exact test child start marker");
}

fn assert_child_started(test_name: &str, output: &[u8]) {
    let expected = std::format!("{CHILD_STARTED_PREFIX}{test_name}");
    assert!(
        String::from_utf8_lossy(output)
            .lines()
            .any(|line| line == expected),
        "fresh test child {test_name} exited successfully without its exact child-start marker; stdout:\n{}",
        String::from_utf8_lossy(output),
    );
}

fn read_child_output(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

fn join_child_output(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Vec<u8> {
    reader
        .join()
        .unwrap_or_else(|_| panic!("fresh test child {stream} reader panicked"))
        .unwrap_or_else(|error| panic!("read fresh test child {stream}: {error}"))
}

fn emit_child_stdout(test_name: &str, output: &[u8]) {
    let output = String::from_utf8_lossy(output);
    let test_prefix = std::format!("test {test_name} ... ");
    for line in output.lines() {
        if line.is_empty()
            || line == "running 1 test"
            || line.starts_with(CHILD_STARTED_PREFIX)
            || line.starts_with("test result: ")
        {
            continue;
        }
        std::println!("{}", line.strip_prefix(&test_prefix).unwrap_or(line));
    }
}
