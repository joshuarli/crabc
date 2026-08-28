#![cfg(target_arch = "x86_64")]

use std::ffi::CStr;

use crabc_rs::{io, pipe, process, Errno};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("test C strings include one terminal NUL")
}

#[test]
fn x86_64_prepared_child_owns_one_successful_exec_wait() {
    let prepared = process::PreparedExec::new(
        cstr(b"/bin/sh\0"),
        &[cstr(b"sh\0"), cstr(b"-c\0"), cstr(b"exit 42\0")],
        &[],
    )
    .expect("prepare an explicit shell image in the parent");

    let child = prepared.spawn().expect("spawn the prepared child");
    let status = child
        .wait(process::WaitOptions::empty())
        .expect("wait for the owned child")
        .expect("blocking wait must report the child exit");
    assert!(status.exited());
    assert_eq!(status.exit_status(), Some(42));
    assert!(!status.signaled());
}

#[test]
fn x86_64_prepared_child_applies_descriptor_actions() {
    let (reader, writer) = pipe::pipe().expect("create child-output pipe");
    let actions = [
        process::FdAction::close(&reader),
        process::FdAction::dup2(&writer, 1),
    ];
    let prepared = process::PreparedExec::new(
        cstr(b"/bin/sh\0"),
        &[cstr(b"sh\0"), cstr(b"-c\0"), cstr(b"printf child-output\0")],
        &[],
    )
    .expect("prepare descriptor-action child image")
    .with_actions(&actions);

    let child = prepared.spawn().expect("spawn descriptor-action child");
    drop(prepared);
    drop(writer);
    let mut output = [0_u8; 12];
    let read = io::read(&reader, &mut output).expect("read child stdout");
    assert_eq!(&output[..read], b"child-output");
    assert_eq!(
        child
            .wait(process::WaitOptions::empty())
            .expect("wait for descriptor-action child")
            .expect("child must report an exit status")
            .exit_status(),
        Some(0)
    );
}

#[test]
fn x86_64_prepared_child_reports_exec_failure_and_reaps_it() {
    let missing = process::PreparedExec::new(
        cstr(b"/crabc-x86-child-ownership-definitely-missing\0"),
        &[cstr(b"missing\0")],
        &[],
    )
    .expect("prepare missing executable");
    assert_eq!(missing.spawn().unwrap_err(), Errno::NOENT);

    let mut status = 0_i32;
    // SAFETY: `status` is writable Linux `int` storage. The failed prepared
    // spawn must have reaped its private child, so no child is selectable.
    assert_eq!(
        unsafe { crabc_core::process::wait4_raw(-1, &mut status, 1) }.unwrap_err(),
        Errno::CHILD
    );
}

#[test]
fn x86_64_prepared_child_preserves_the_error_pipe_across_fd_collisions() {
    let (reader, writer) = pipe::pipe().expect("create collision source pipe");
    let actions = [
        process::FdAction::dup2(&writer, 3),
        process::FdAction::dup2(&writer, 4),
        process::FdAction::dup2(&writer, 5),
        process::FdAction::dup2(&writer, 6),
        process::FdAction::dup2(&writer, 7),
        process::FdAction::dup2(&writer, 8),
        process::FdAction::dup2(&writer, 9),
        process::FdAction::dup2(&writer, 10),
        process::FdAction::dup2(&writer, 11),
        process::FdAction::dup2(&writer, 12),
        process::FdAction::dup2(&writer, 13),
        process::FdAction::dup2(&writer, 14),
        process::FdAction::dup2(&writer, 15),
        process::FdAction::dup2(&writer, 16),
    ];
    let missing = process::PreparedExec::new(
        cstr(b"/crabc-x86-child-ownership-collision-missing\0"),
        &[cstr(b"missing\0")],
        &[],
    )
    .expect("prepare collision executable")
    .with_actions(&actions);

    assert_eq!(missing.spawn().unwrap_err(), Errno::NOENT);
    drop(reader);
    drop(writer);
}

#[test]
fn x86_64_child_wait_nohang_consumes_the_owned_child() {
    let (pid_reader, pid_writer) = pipe::pipe().expect("create child PID pipe");
    let (release_reader, release_writer) = pipe::pipe().expect("create child release pipe");
    let actions = [
        process::FdAction::close(&pid_reader),
        process::FdAction::close(&release_writer),
        process::FdAction::dup2(&pid_writer, 20),
        process::FdAction::dup2(&release_reader, 21),
    ];
    let prepared = process::PreparedExec::new(
        cstr(b"/bin/sh\0"),
        &[
            cstr(b"sh\0"),
            cstr(b"-c\0"),
            cstr(b"printf '%s\\n' \"$$\" >&20; IFS= read -r _ <&21; exit 23\0"),
        ],
        &[],
    )
    .expect("prepare a synchronized child image")
    .with_actions(&actions);
    let child = prepared.spawn().expect("spawn synchronized child");
    drop(prepared);
    drop(pid_writer);
    drop(release_reader);

    let mut pid_bytes = [0_u8; 32];
    let read = io::read(&pid_reader, &mut pid_bytes).expect("read synchronized child PID");
    drop(pid_reader);
    let reported_pid = core::str::from_utf8(&pid_bytes[..read])
        .expect("shell PID report is ASCII")
        .trim()
        .parse::<i32>()
        .expect("shell PID report is a Linux PID");

    // The child cannot have exited before this point: it reported its PID, then
    // blocks reading descriptor 21. `Child::wait` consumes the owner even when
    // WNOHANG returns no status, so the test-only raw wait below performs the
    // sole later reap after the release pipe unblocks it.
    assert_eq!(
        child
            .wait(process::WaitOptions::NOHANG)
            .expect("observe the owned child without blocking"),
        None
    );
    io::write(&release_writer, b"release\n").expect("release prepared child");
    drop(release_writer);
    let mut status = 0_i32;
    // SAFETY: `status` remains writable Linux `int` storage for the final
    // blocking wait, which reaps the child after its safe owner was consumed.
    assert_eq!(
        unsafe { crabc_core::process::wait4_raw(reported_pid, &mut status, 0) }
            .expect("reap released prepared child"),
        reported_pid
    );
    assert_eq!(status, 23 << 8);
}
