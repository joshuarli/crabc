use std::env;
use std::process::Command;

use crabc_rs::process;
use crabc_rs::thread;
use crabc_rs::Errno;

const CHILD_PROBE: &str = "CRABC_RS_NATIVE_THREAD_CREDENTIALS_CHILD";

#[test]
fn credential_setters_are_noop_and_sentinel_checked_in_a_child() {
    if env::var_os(CHILD_PROBE).is_some() {
        // The all-ones words exercise the actual Linux no-change syscall
        // path. This test deliberately runs them only in the child process;
        // the parent test process never changes its calling-thread state.
        thread::set_thread_res_uid(
            Option::<thread::Uid>::None,
            Option::<thread::Uid>::None,
            Option::<thread::Uid>::None,
        )
        .expect("Linux setresuid all-ones no-change must succeed");
        thread::set_thread_res_gid(
            Option::<thread::Gid>::None,
            Option::<thread::Gid>::None,
            Option::<thread::Gid>::None,
        )
        .expect("Linux setresgid all-ones no-change must succeed");

        let invalid_uid = process::Uid::from_raw(u32::MAX);
        let invalid_gid = process::Gid::from_raw(u32::MAX);
        assert_eq!(
            thread::set_thread_res_uid(Some(invalid_uid), Option::<thread::Uid>::None, Option::<thread::Uid>::None),
            Err(Errno::INVAL),
            "Some(all-ones UID) must not silently become None",
        );
        assert_eq!(
            thread::set_thread_res_gid(Some(invalid_gid), Option::<thread::Gid>::None, Option::<thread::Gid>::None),
            Err(Errno::INVAL),
            "Some(all-ones GID) must not silently become None",
        );
        return;
    }

    let status = Command::new(env::current_exe().expect("locate the integration test binary"))
        .arg("--exact")
        .arg("credential_setters_are_noop_and_sentinel_checked_in_a_child")
        .arg("--nocapture")
        .env(CHILD_PROBE, "1")
        .status()
        .expect("run the credential probe in a child process");
    assert!(status.success(), "child credential probe exited with {status}");
}
