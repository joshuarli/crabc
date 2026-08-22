use std::process::Command;

use crabc_rs::process::{self, Pid, Priority, PriorityTarget, Uid};
use crabc_rs::Errno;

const ISOLATED_CASE: &str = "CRABC_RS_M10_SETPRIORITY_CASE";

#[test]
fn setpriority_current_process_is_isolated() {
    if std::env::var_os(ISOLATED_CASE).is_some() {
        isolated_setpriority_case();
        return;
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args(["--exact", "setpriority_current_process_is_isolated", "--nocapture"])
        .env(ISOLATED_CASE, "1")
        .output()
        .expect("run isolated setpriority child");
    assert!(
        output.status.success(),
        "isolated setpriority child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn isolated_setpriority_case() {
    assert_eq!(
        crabc_core::process::setpriority_raw(99, 0, 0),
        Err(Errno::INVAL),
        "the raw selector must retain Linux EINVAL",
    );

    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(
        process::setpriority_process(Some(missing), Priority::MAX),
        Err(Errno::SRCH),
    );
    assert_eq!(
        process::setpriority_process_group(Some(missing), Priority::MAX),
        Err(Errno::SRCH),
    );
    assert_eq!(
        process::setpriority_user(Uid::from_raw(u32::MAX), Priority::MAX),
        Err(Errno::SRCH),
    );

    process::setpriority_process(None, Priority::MAX)
        .expect("raising niceness to Linux's maximum should be permitted");
    assert_eq!(
        process::getpriority(PriorityTarget::Process(None))
            .expect("read the changed process priority"),
        Priority::MAX,
    );
}
