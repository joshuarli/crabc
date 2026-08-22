use crabc_rs::process::{self, Pid, Priority, PriorityTarget};

#[test]
fn priority_type_is_closed_to_linux_nice_range() {
    assert_eq!(Priority::MIN.as_raw(), -20);
    assert_eq!(Priority::DEFAULT.as_raw(), 0);
    assert_eq!(Priority::MAX.as_raw(), 19);
    assert_eq!(Priority::from_raw(-20), Some(Priority::MIN));
    assert_eq!(Priority::from_raw(19), Some(Priority::MAX));
    assert_eq!(Priority::from_raw(-21), None);
    assert_eq!(Priority::from_raw(20), None);
}

#[test]
fn priority_target_vocabulary_matches_pinned_linux_selectors() {
    assert_eq!(
        PriorityTarget::process(None).as_raw(),
        (PriorityTarget::PRIO_PROCESS, 0),
    );
    assert_eq!(
        PriorityTarget::process_group(None).as_raw(),
        (PriorityTarget::PRIO_PGRP, 0),
    );
    assert_eq!(
        PriorityTarget::user(process::Uid::ROOT).as_raw(),
        (PriorityTarget::PRIO_USER, 0),
    );
}

#[test]
fn getpriority_translates_linux_nonnegative_syscall_encoding() {
    let raw = crabc_core::process::getpriority_raw(0, 0)
        .expect("read the Linux getpriority syscall result");
    assert!((1..=40).contains(&raw));

    let priority = process::getpriority(PriorityTarget::Process(None))
        .expect("read the calling process priority");
    assert_eq!(priority.as_raw(), 20 - raw);
    assert!((-20..=19).contains(&priority.as_raw()));
}

#[test]
fn getpriority_reads_each_closed_read_only_target() {
    let pid = process::getpid();
    let uid = process::getuid();
    let targets = [
        PriorityTarget::Process(None),
        PriorityTarget::Process(Some(pid)),
        PriorityTarget::ProcessGroup(None),
        PriorityTarget::User(uid),
    ];

    for target in targets {
        let first = process::getpriority(target).expect("read Linux process priority");
        let second = process::getpriority(target).expect("read Linux process priority again");
        assert_eq!(first, second);
        assert!((-20..=19).contains(&first.as_raw()));
    }
}

#[test]
fn getpriority_errors_are_ordinary_results_without_a_minus_one_sentinel() {
    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(
        process::getpriority(PriorityTarget::Process(Some(missing))),
        Err(crabc_rs::Errno::SRCH),
    );
}
