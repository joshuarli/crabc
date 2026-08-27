#![cfg(target_arch = "x86_64")]

use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

use crabc_rs::process::{self, Resource, Rlimit};
use crabc_rs::Errno;

const LIVE_CHILD_CASE: &str = "CRABC_RS_X86_64_RLIMIT_TARGETED_CHILD";
const READY_MARKER: &str = "CRABC_RLIMIT_TARGETED_READY ";

// The direct x86 slice admits read-only `process::getrlimit_for` with either
// PID zero or one explicit live target; mutation remains separately bounded.
#[test]
fn x86_64_getrlimit_for_explicit_current_pid_matches_zero() {
    let implicit = process::getrlimit_for(None, Resource::Nofile)
        .expect("read current open-file limit through implicit PID");
    let direct = process::getrlimit(Resource::Nofile).expect("read current open-file limit");
    assert_eq!(implicit, direct);

    let explicit = process::getrlimit_for(Some(process::getpid()), Resource::Nofile)
        .expect("read current open-file limit through explicit PID");
    assert_eq!(explicit, direct);
}

#[test]
fn x86_64_getrlimit_for_missing_pid_preserves_esrch() {
    let missing = process::Pid::from_raw(i32::MAX).expect("i32::MAX is non-zero");
    assert_eq!(
        process::getrlimit_for(Some(missing), Resource::Nofile),
        Err(Errno::SRCH),
    );
}

#[test]
fn x86_64_getrlimit_for_reads_a_distinct_live_child_limit() {
    if std::env::var_os(LIVE_CHILD_CASE).is_some() {
        live_child_limit_case();
        return;
    }

    let parent_limit = process::getrlimit(Resource::Nofile)
        .expect("read the parent's inherited open-file limit");
    let mut child = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_getrlimit_for_reads_a_distinct_live_child_limit",
            "--nocapture",
        ])
        .env(LIVE_CHILD_CASE, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn isolated target resource-limit child");
    let mut child_stdout = child.stdout.take().expect("target child stdout");
    let child_current = read_child_current_limit(&mut child_stdout);
    let child_pid = process::Pid::from_raw(
        i32::try_from(child.id()).expect("child PID must fit Linux pid_t"),
    )
    .expect("child PID is non-zero");
    let queried = process::getrlimit_for(Some(child_pid), Resource::Nofile);

    child
        .stdin
        .take()
        .expect("target child stdin")
        .write_all(b"release")
        .expect("release target resource-limit child");
    let status = child.wait().expect("wait for target resource-limit child");
    let mut trailing_output = Vec::new();
    child_stdout
        .read_to_end(&mut trailing_output)
        .expect("read target child trailing output");
    assert!(
        status.success(),
        "target resource-limit child failed with {:?}; trailing stdout: {}",
        status.code(),
        String::from_utf8_lossy(&trailing_output),
    );

    let queried = queried.expect("query the live target child's open-file limit");
    assert_eq!(queried.current, Some(child_current));
    assert_eq!(queried.maximum, parent_limit.maximum);
    assert_ne!(queried, parent_limit, "the child must retain a distinct limit");
}

fn read_child_current_limit(child_stdout: &mut impl Read) -> u64 {
    let marker = READY_MARKER.as_bytes();
    let mut output = Vec::new();
    loop {
        let mut byte = [0; 1];
        child_stdout
            .read_exact(&mut byte)
            .expect("wait for target child readiness");
        output.push(byte[0]);
        if output.ends_with(marker) {
            break;
        }
        assert!(
            output.len() < 16 * 1024,
            "target child did not announce its resource limit"
        );
    }

    let mut current = Vec::new();
    loop {
        let mut byte = [0; 1];
        child_stdout
            .read_exact(&mut byte)
            .expect("read target child resource limit");
        if byte[0] == b'\n' {
            break;
        }
        current.push(byte[0]);
    }
    std::str::from_utf8(&current)
        .expect("target child limit must be UTF-8 digits")
        .parse()
        .expect("target child limit must be an unsigned integer")
}

fn live_child_limit_case() {
    let inherited = process::getrlimit(Resource::Nofile)
        .expect("read inherited open-file limit in the target child");
    let changed = distinct_nofile_limit(inherited);
    process::setrlimit(Resource::Nofile, changed)
        .expect("lower or raise the target child's soft open-file limit safely");
    let observed = process::getrlimit(Resource::Nofile)
        .expect("read the target child's changed open-file limit");
    assert_eq!(observed, changed);
    let current = observed
        .current
        .expect("the target child deliberately selects a finite soft limit");
    println!("{READY_MARKER}{current}");
    std::io::stdout()
        .flush()
        .expect("publish target child readiness");

    let mut release = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut release)
        .expect("wait for parent target query");
}

fn distinct_nofile_limit(inherited: Rlimit) -> Rlimit {
    let current = match inherited.current {
        Some(0) => {
            assert_ne!(
                inherited.maximum,
                Some(0),
                "a zero hard RLIMIT_NOFILE cannot yield a distinct safe child limit",
            );
            1
        }
        Some(current) => current - 1,
        None => {
            assert_eq!(
                inherited.maximum,
                None,
                "a finite hard limit cannot have unlimited soft limit",
            );
            1
        }
    };
    Rlimit {
        current: Some(current),
        maximum: inherited.maximum,
    }
}
