use crabc_rs::process;

#[test]
fn process_ids_are_positive_stable_and_parent_option_is_typed() {
    let pid = process::getpid();
    assert!(pid.as_raw_pid() > 0, "Linux assigns a positive process ID");
    assert_eq!(process::getpid(), pid, "a process ID remains stable while it runs");

    let parent = process::getppid();
    assert_eq!(process::getppid(), parent, "the parent observation remains stable");
    match parent {
        Some(parent) => assert!(
            parent.as_raw_pid() > 0,
            "Some(parent) contains a positive typed process ID"
        ),
        None => {
            // Linux uses zero when the PID namespace exposes no parent, and
            // the public `Pid` type deliberately cannot represent zero.
            assert_eq!(process::Pid::from_raw(0), None);
        }
    }
}
