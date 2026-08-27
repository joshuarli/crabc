#![cfg(target_arch = "x86_64")]

use std::process::Command;

use crabc_rs::{
    process::{self, Gid, Uid},
    Errno,
};

#[test]
fn x86_64_fs_credentials_are_child_contained_and_keep_the_query_sentinel_typed() {
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_fs_credentials_child_queries_and_requests_current_identity",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .expect("run isolated filesystem-credential child");
    assert!(
        output.status.success(),
        "isolated filesystem-credential child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "the parent regression invokes this test only in a subprocess"]
fn x86_64_fs_credentials_child_queries_and_requests_current_identity() {
    assert_eq!(
        unsafe { process::set_fs_uid(Some(Uid::from_raw(u32::MAX))) },
        Err(Errno::INVAL),
        "an all-ones UID must not silently become the query sentinel",
    );
    assert_eq!(
        unsafe { process::set_fs_gid(Some(Gid::from_raw(u32::MAX))) },
        Err(Errno::INVAL),
        "an all-ones GID must not silently become the query sentinel",
    );

    // Querying is the only way this typed API forwards Linux's all-ones word.
    // It returns the prior filesystem identity without changing it.
    let original_uid = unsafe { process::set_fs_uid(None) }
        .expect("Linux setfsuid query must return the previous filesystem UID");
    let original_gid = unsafe { process::set_fs_gid(None) }
        .expect("Linux setfsgid query must return the previous filesystem GID");

    // An effective identity is an allowed unprivileged target. The return is
    // still the *previous* filesystem identity, not a success indicator. The
    // child exits immediately so no caller credential state can escape.
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
}
