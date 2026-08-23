use std::env;
use std::process::Command;

use crabc_rs::process;
use crabc_rs::Errno;

const CHILD_PROBE: &str = "CRABC_RS_NATIVE_FS_CREDENTIALS_CHILD";

#[test]
fn filesystem_credentials_are_typed_and_changed_only_in_a_child() {
    if env::var_os(CHILD_PROBE).is_some() {
        // The typed facade reserves all-ones for None's query meaning. These
        // checks happen before the child performs any credential transition.
        assert_eq!(
            unsafe { process::set_fs_uid(Some(process::Uid::from_raw(u32::MAX))) },
            Err(Errno::INVAL),
            "an all-ones UID must not silently become the query sentinel",
        );
        assert_eq!(
            unsafe { process::set_fs_gid(Some(process::Gid::from_raw(u32::MAX))) },
            Err(Errno::INVAL),
            "an all-ones GID must not silently become the query sentinel",
        );

        // None queries the current filesystem identity without changing it.
        let original_uid = unsafe { process::set_fs_uid(None) }
            .expect("Linux setfsuid query must return the previous filesystem UID");
        let original_gid = unsafe { process::set_fs_gid(None) }
            .expect("Linux setfsgid query must return the previous filesystem GID");

        // The effective IDs are always valid targets for an unprivileged
        // caller. This exercises the actual mutation paths without relying on
        // a privileged or alternate identity, and the child exits immediately
        // afterward so the test runner's credentials cannot be changed.
        let effective_uid = process::geteuid();
        let effective_gid = process::getegid();
        assert_eq!(
            unsafe { process::set_fs_uid(Some(effective_uid)) }
                .expect("setfsuid to the effective UID must return the old value"),
            original_uid,
        );
        assert_eq!(
            unsafe { process::set_fs_gid(Some(effective_gid)) }
                .expect("setfsgid to the effective GID must return the old value"),
            original_gid,
        );
        assert_eq!(
            unsafe { process::set_fs_uid(None) }.expect("query changed filesystem UID"),
            effective_uid,
        );
        assert_eq!(
            unsafe { process::set_fs_gid(None) }.expect("query changed filesystem GID"),
            effective_gid,
        );
        return;
    }

    let status = Command::new(env::current_exe().expect("locate the integration test binary"))
        .arg("--exact")
        .arg("filesystem_credentials_are_typed_and_changed_only_in_a_child")
        .arg("--nocapture")
        .env(CHILD_PROBE, "1")
        .status()
        .expect("run the filesystem-credential probe in a child process");
    assert!(
        status.success(),
        "child filesystem-credential probe exited with {status}"
    );
}
