#![cfg(all(target_arch = "x86_64", feature = "alloc"))]

use std::ffi::CStr;

use crabc_rs::{process, signal::Signal, Errno, Pid};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("test C strings include one terminal NUL")
}

fn sleeping_child() -> process::Child {
    process::PreparedExec::new(
        cstr(b"/bin/sh\0"),
        &[cstr(b"sh\0"), cstr(b"-c\0"), cstr(b"exec sleep 30\0")],
        &[],
    )
    .expect("prepare a sleeping child image")
    .spawn()
    .expect("spawn the sleeping child")
}

#[test]
fn x86_64_signal_zero_probes_the_caller_and_its_process_group() {
    process::test_kill_process(process::getpid()).expect("the caller accepts a signal-zero probe");
    process::test_kill_process_group(process::getpgrp())
        .expect("the caller's process group accepts a signal-zero probe");
    process::test_kill_current_process_group()
        .expect("process group zero names the caller's group");
}

#[test]
fn x86_64_kill_reports_targets_that_cannot_exist() {
    // Linux caps pid_max at 2^22, so this positive PID never names a process.
    let absent = Pid::from_raw(i32::MAX).expect("a positive PID");
    assert_eq!(process::test_kill_process(absent), Err(Errno::SRCH));
    assert_eq!(process::kill_process(absent, Signal::TERM), Err(Errno::SRCH));
    assert_eq!(process::test_kill_process_group(absent), Err(Errno::SRCH));
    assert_eq!(process::kill_process_group(absent, Signal::TERM), Err(Errno::SRCH));
}

#[test]
fn x86_64_owned_child_is_signaled_and_then_reaped_by_its_owner() {
    let child = sleeping_child();
    child.kill(Signal::KILL).expect("signal the still-owned child");
    let status = child
        .wait(process::WaitOptions::empty())
        .expect("wait for the signaled child")
        .expect("a blocking wait reports the termination");
    assert!(status.signaled());
    assert_eq!(status.terminating_signal(), Some(9));
}

#[test]
fn x86_64_kill_process_delivers_to_a_child_by_pid() {
    let child = sleeping_child();
    let pid = child.pid();
    process::kill_process(pid, Signal::TERM).expect("signal the child by PID");
    let mut status = 0;
    // SAFETY: `pid` names this test's unreaped child and `status` is writable.
    let reaped = unsafe { crabc_core::process::wait4_raw(pid.as_raw_pid(), &mut status, 0) }
        .expect("reap the PID-addressed child");
    assert_eq!(reaped, pid.as_raw_pid());
    assert_eq!(status & 0x7f, 15, "the child terminated by SIGTERM");
}
