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
    let test_prefix = std::format!("test {test_name} ... ");
    assert!(
        String::from_utf8_lossy(output)
            .lines()
            .any(|line| line.strip_prefix(&test_prefix).unwrap_or(line) == expected.as_str()),
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

/// Projects the isolated interpreter's environment as a live C vector.
/// Each image is retained because source option readers borrow its pointers
/// beyond one observation; later coordinated mutations produce a new image.
#[cfg(miri)]
pub(crate) fn miri_process_environment() -> *const *const core::ffi::c_char {
    use std::os::unix::ffi::OsStrExt;
    let strings = env::vars_os().map(|(name, value)| {
        let mut entry = name.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        std::ffi::CString::new(entry).expect("environment entries have no interior NUL")
    }).collect::<Vec<_>>();
    retain_miri_environment(strings)
}

#[cfg(miri)]
struct MiriEnvironmentImage {
    _strings: std::sync::Arc<[std::ffi::CString]>,
    pointers: std::sync::Arc<[*const core::ffi::c_char]>,
}

// SAFETY: each pointer refers to this image's owned immutable string buffer.
// Moving the image never grants unique access to either shared allocation. The static owner
// serializes publication and retains every image without subsequent mutation.
#[cfg(miri)]
unsafe impl Send for MiriEnvironmentImage {}

#[cfg(miri)]
fn retain_miri_environment(strings: Vec<std::ffi::CString>) -> *const *const core::ffi::c_char {
    static IMAGES: std::sync::Mutex<Vec<MiriEnvironmentImage>> = std::sync::Mutex::new(Vec::new());
    let strings: std::sync::Arc<[std::ffi::CString]> = strings.into();
    let mut pointers = strings.iter().map(|entry| entry.as_ptr()).collect::<Vec<_>>();
    pointers.push(core::ptr::null());
    let image = MiriEnvironmentImage { _strings: strings, pointers: pointers.into() };
    let pointer = image.pointers.as_ptr();
    IMAGES.lock().expect("environment image publication is not poisoned").push(image);
    pointer
}

#[cfg(miri)]
#[test]
fn isolated_environment_vectors_preserve_empty_mutated_and_previous_images() {
    use std::ffi::{CStr, CString};
    fn value(image: *const *const core::ffi::c_char, key: &[u8]) -> Option<Vec<u8>> {
        let mut next = image;
        loop {
            // SAFETY: the retained image is terminated and every string is
            // immutable and live for the complete interpreter lifetime.
            let entry = unsafe { *next };
            if entry.is_null() { return None; }
            let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
            if bytes.starts_with(key) { return Some(bytes[key.len()..].to_vec()); }
            next = unsafe { next.add(1) };
        }
    }
    let empty = retain_miri_environment(Vec::new());
    assert!(!empty.is_null());
    assert!(unsafe { *empty }.is_null());
    let fixed = retain_miri_environment(std::vec![CString::new("key=old").unwrap()]);
    assert_eq!(value(fixed, b"key="), Some(b"old".to_vec()));
    const KEY: &str = "CRABC_MIRI_ENVIRONMENT_LIFETIME_TEST";
    // SAFETY: this exact serial interpreter test owns its environment changes
    // and no source reader or concurrent thread observes the mutation.
    unsafe { env::set_var(KEY, "first") };
    let first = miri_process_environment();
    unsafe { env::set_var(KEY, "second") };
    let second = miri_process_environment();
    unsafe { env::remove_var(KEY) };
    let absent = miri_process_environment();
    let key = std::format!("{KEY}=");
    assert_eq!(value(first, key.as_bytes()), Some(b"first".to_vec()));
    assert_eq!(value(second, key.as_bytes()), Some(b"second".to_vec()));
    assert_eq!(value(absent, key.as_bytes()), None);
    assert_eq!(value(first, key.as_bytes()), Some(b"first".to_vec()));
}

#[cfg(miri)]
#[test]
fn isolated_thread_identities_are_stable_nonreserved_aligned_and_distinct() {
    fn identity() -> usize {
        let raw = crabc_core::thread::thread_pointer_identity();
        assert!(raw > 8, "a live TLS identity cannot use reserved page encodings");
        assert_eq!(raw & crate::types::PAGE_FLAG_MASK, 0);
        assert_eq!(raw, crabc_core::thread::thread_pointer_identity());
        raw
    }
    let initial = identity();
    let worker = std::thread::spawn(identity);
    let other = worker.join().unwrap();
    assert_ne!(initial, other);
    assert_eq!(initial, identity());
}
