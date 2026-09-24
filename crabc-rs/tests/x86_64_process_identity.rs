#![cfg(target_arch = "x86_64")]

use crabc_rs::process;

fn proc_status_ids() -> ([u32; 4], [u32; 4]) {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("read the current process identity oracle");
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(values) = line.strip_prefix("Uid:") {
            uid = Some(parse_id_fields(values));
        } else if let Some(values) = line.strip_prefix("Gid:") {
            gid = Some(parse_id_fields(values));
        }
    }
    (
        uid.expect("/proc status must expose Uid"),
        gid.expect("/proc status must expose Gid"),
    )
}

fn parse_id_fields(value: &str) -> [u32; 4] {
    let mut fields = [0; 4];
    for (slot, text) in value.split_whitespace().take(4).enumerate() {
        fields[slot] = text.parse().expect("/proc identity field is numeric");
    }
    fields
}

#[test]
fn x86_64_process_and_parent_ids_are_typed_and_stable() {
    let pid = process::getpid();
    assert_eq!(pid.as_raw_pid() as u32, std::process::id());
    assert_eq!(process::getpid(), pid);

    let parent = process::getppid();
    assert_eq!(process::getppid(), parent);
    if let Some(parent) = parent {
        assert!(parent.as_raw_pid() > 0);
    }
    assert_eq!(process::Pid::from_raw(0), None);
}

#[test]
fn x86_64_scalar_and_saved_identity_queries_match_proc_status() {
    let (uid, gid) = proc_status_ids();
    assert_eq!(process::getuid().as_raw(), uid[0]);
    assert_eq!(process::geteuid().as_raw(), uid[1]);
    assert_eq!(process::getgid().as_raw(), gid[0]);
    assert_eq!(process::getegid().as_raw(), gid[1]);

    let user = process::getresuid().expect("read Linux user identity triple");
    let group = process::getresgid().expect("read Linux group identity triple");
    assert_eq!(user.real.as_raw(), uid[0]);
    assert_eq!(user.effective.as_raw(), uid[1]);
    assert_eq!(user.saved.as_raw(), uid[2]);
    assert_eq!(group.real.as_raw(), gid[0]);
    assert_eq!(group.effective.as_raw(), gid[1]);
    assert_eq!(group.saved.as_raw(), gid[2]);
}

const EXIT_CHILD: &str = "CRABC_X86_64_EXIT_IMMEDIATELY_CHILD";

/// Re-executed child body: buffered output, a live `Drop` guard and a
/// sleeping worker thread are all outstanding when the thread group exits.
fn exit_immediately_child() -> ! {
    use std::io::Write;

    struct Marker;
    impl Drop for Marker {
        fn drop(&mut self) {
            let _ = std::io::stderr().write_all(b"destructor ran\n");
        }
    }
    let _marker = Marker;
    let mut stdout = std::io::BufWriter::new(std::io::stdout());
    stdout.write_all(b"buffered bytes must not be flushed\n").expect("buffer child output");
    std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(600)));
    process::exit_immediately(23)
}

#[test]
fn x86_64_exit_immediately_ends_the_thread_group_without_destructors() {
    if std::env::var_os(EXIT_CHILD).is_some() {
        exit_immediately_child();
    }
    let started = std::time::Instant::now();
    let output = std::process::Command::new(std::env::current_exe().expect("locate this test binary"))
        .args(["--exact", "x86_64_exit_immediately_ends_the_thread_group_without_destructors", "--nocapture"])
        .env(EXIT_CHILD, "1")
        .output()
        .expect("re-execute the exit child");
    // exit_group, not a single-thread exit: the sleeping worker cannot keep
    // the process alive, and no Rust or C exit path flushes or drops state.
    assert_eq!(output.status.code(), Some(23));
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("buffered bytes"), "BufWriter was flushed: {stdout:?}");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("destructor ran"));
}
