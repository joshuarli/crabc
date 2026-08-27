#![cfg(target_arch = "x86_64")]

use std::process::Command;

use crabc_rs::{
    process::{self, Pid, Priority, Uid},
    Errno,
};

#[test]
fn x86_64_setpriority_is_child_contained_and_keeps_targets_typed() {
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_setpriority_child_mutates_only_the_calling_process",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .expect("run isolated scheduling-priority child");
    assert!(
        output.status.success(),
        "isolated scheduling-priority child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "the parent regression invokes this test only in a subprocess"]
fn x86_64_setpriority_child_mutates_only_the_calling_process() {
    assert_eq!(
        crabc_core::process::setpriority_raw(99, 0, Priority::DEFAULT.as_raw()),
        Err(Errno::INVAL),
        "the raw x86 syscall must preserve an invalid-target-selector error",
    );

    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(
        process::setpriority_process(Some(missing), Priority::MAX),
        Err(Errno::SRCH),
        "the typed process wrapper must preserve a missing-target error",
    );
    assert_eq!(
        process::setpriority_process_group(Some(missing), Priority::MAX),
        Err(Errno::SRCH),
        "the typed process-group wrapper must preserve a missing-target error",
    );
    assert_eq!(
        process::setpriority_user(Uid::from_raw(u32::MAX), Priority::MAX),
        Err(Errno::SRCH),
        "the typed user wrapper must preserve a missing-target error",
    );

    // Moving toward nice 19 never needs CAP_SYS_NICE. The exec child owns the
    // resulting process-wide state, so no privileged restoration is required.
    process::setpriority_process(None, Priority::MAX)
        .expect("lower the isolated calling process to the least favorable nice value");
    assert_eq!(
        process::getpriority_process(None).expect("read the isolated process priority"),
        Priority::MAX,
    );
}
