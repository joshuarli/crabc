#![cfg(target_arch = "x86_64")]

use std::env;
use std::process::Command;

use crabc_rs::{process, thread, Errno};

const CHILD_PROBE: &str = "CRABC_RS_X86_64_THREAD_CREDENTIALS_CHILD";

#[test]
fn x86_64_thread_credential_setters_preserve_linux_no_change_and_typed_sentinels() {
    if env::var_os(CHILD_PROBE).is_some() {
        // The all-ones words exercise Linux's no-change operation. This runs
        // only in a child so the parent test process never changes its
        // calling-thread credentials.
        let before_uid = process::getresuid().expect("read initial user IDs");
        let before_gid = process::getresgid().expect("read initial group IDs");
        thread::set_thread_res_uid(
            Option::<thread::Uid>::None,
            Option::<thread::Uid>::None,
            Option::<thread::Uid>::None,
        )
        .expect("setresuid all-ones no-change");
        thread::set_thread_res_gid(
            Option::<thread::Gid>::None,
            Option::<thread::Gid>::None,
            Option::<thread::Gid>::None,
        )
        .expect("setresgid all-ones no-change");
        assert_eq!(
            process::getresuid().expect("read user IDs after no-change"),
            before_uid,
            "all-ones setresuid must preserve every calling-thread ID",
        );
        assert_eq!(
            process::getresgid().expect("read group IDs after no-change"),
            before_gid,
            "all-ones setresgid must preserve every calling-thread ID",
        );

        let invalid_uid = process::Uid::from_raw(u32::MAX);
        let invalid_gid = process::Gid::from_raw(u32::MAX);
        assert_eq!(
            thread::set_thread_res_uid(
                Some(invalid_uid),
                Option::<thread::Uid>::None,
                Option::<thread::Uid>::None,
            ),
            Err(Errno::INVAL),
            "a typed all-ones UID must not become Linux's no-change sentinel",
        );
        assert_eq!(
            thread::set_thread_res_gid(
                Some(invalid_gid),
                Option::<thread::Gid>::None,
                Option::<thread::Gid>::None,
            ),
            Err(Errno::INVAL),
            "a typed all-ones GID must not become Linux's no-change sentinel",
        );
        return;
    }

    let output = Command::new(env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_thread_credential_setters_preserve_linux_no_change_and_typed_sentinels",
            "--nocapture",
        ])
        .env(CHILD_PROBE, "1")
        .output()
        .expect("run isolated credential child");
    assert!(
        output.status.success(),
        "isolated credential child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
