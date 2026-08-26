#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, Pid, Priority, PriorityTarget};

fn assert_priority(priority: Priority) {
    assert!((-20..=19).contains(&priority.as_raw()));
}

#[test]
fn x86_64_priority_types_and_targets_are_closed() {
    assert_eq!(Priority::MIN.as_raw(), -20);
    assert_eq!(Priority::DEFAULT.as_raw(), 0);
    assert_eq!(Priority::MAX.as_raw(), 19);
    assert_eq!(Priority::from_raw(-21), None);
    assert_eq!(Priority::from_raw(20), None);

    assert_eq!(
        PriorityTarget::process(None).as_raw(),
        (PriorityTarget::PRIO_PROCESS, 0)
    );
    assert_eq!(
        PriorityTarget::process_group(None).as_raw(),
        (PriorityTarget::PRIO_PGRP, 0)
    );
    assert_eq!(
        PriorityTarget::user(process::Uid::ROOT).as_raw(),
        (PriorityTarget::PRIO_USER, 0)
    );
}

#[test]
fn x86_64_getpriority_translates_the_nonnegative_kernel_encoding() {
    let raw = crabc_core::process::getpriority_raw(0, 0)
        .expect("read the Linux getpriority syscall result");
    assert!((1..=40).contains(&raw));

    let priority = process::getpriority(PriorityTarget::process(None))
        .expect("read the calling process priority");
    assert_eq!(priority.as_raw(), 20 - raw);
    assert_priority(priority);
}

#[test]
fn x86_64_getpriority_supports_process_group_and_user_targets_read_only() {
    let pid = process::getpid();
    let pgid = process::getpgid(None).expect("read the current process group");
    let effective_uid = process::geteuid();

    let process_priority = process::getpriority_process(Some(pid))
        .expect("read the explicit process target");
    let process_shorthand = process::getpriority_process(None)
        .expect("read the calling process target");
    let group_priority = process::getpriority_process_group(Some(pgid))
        .expect("read the explicit process-group target");
    let group_shorthand = process::getpriority_process_group(None)
        .expect("read the calling process-group target");
    let user_priority = process::getpriority_user(effective_uid)
        .expect("read the effective-user target");
    let current_user_priority = process::getpriority_user(process::Uid::ROOT)
        .expect("read Linux's zero-selector effective-user target");

    assert_priority(process_priority);
    assert_priority(group_priority);
    assert_priority(user_priority);
    assert_eq!(user_priority, current_user_priority);
    assert_eq!(process_priority, process_shorthand);
    assert_eq!(group_priority, group_shorthand);
    // Linux reports the best (lowest nice value) member of a set. The caller
    // belongs to both sets, so neither aggregate can be less favorable.
    assert!(group_priority <= process_priority);
    assert!(user_priority <= process_priority);
    assert_eq!(
        process::getpriority_process(Some(pid)).expect("re-read process priority"),
        process_priority
    );
}

#[test]
fn x86_64_getpriority_reports_missing_process_as_srch() {
    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(
        process::getpriority_process(Some(missing)),
        Err(crabc_rs::Errno::SRCH)
    );
}
