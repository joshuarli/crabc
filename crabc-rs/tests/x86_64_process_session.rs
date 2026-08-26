#![cfg(target_arch = "x86_64")]

use crabc_rs::process;

#[test]
fn x86_64_process_group_and_session_observations_are_typed_and_stable() {
    let pid = process::getpid();
    assert!(pid.as_raw_pid() > 0);

    let current_group = process::getpgid(None).expect("read the current process group");
    let explicit_group =
        process::getpgid(Some(pid)).expect("read the explicit self process group");
    let shorthand_group = process::getpgrp();
    let current_session = process::getsid(None).expect("read the current session");
    let explicit_session = process::getsid(Some(pid)).expect("read the explicit self session");

    assert!(current_group.as_raw_pid() > 0);
    assert!(explicit_group.as_raw_pid() > 0);
    assert!(shorthand_group.as_raw_pid() > 0);
    assert!(current_session.as_raw_pid() > 0);
    assert!(explicit_session.as_raw_pid() > 0);
    assert_eq!(current_group, explicit_group);
    assert_eq!(shorthand_group, current_group);
    assert_eq!(current_session, explicit_session);

    assert_eq!(process::getpgid(None).expect("re-read process group"), current_group);
    assert_eq!(process::getpgrp(), shorthand_group);
    assert_eq!(process::getsid(None).expect("re-read session"), current_session);
    assert_eq!(process::getpid(), pid);
}
