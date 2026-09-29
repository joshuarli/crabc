#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;
use std::process::Command;

use crabc_rs::process::{self, Gid};
use crabc_rs::Errno;

fn proc_supplementary_groups() -> Vec<u32> {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("read the current process group oracle");
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .expect("/proc status must expose Groups");
    groups
        .split_whitespace()
        .map(|value| value.parse().expect("/proc group ID is numeric"))
        .collect()
}

#[test]
fn x86_64_getgroups_query_and_fill_match_the_current_credential_snapshot() {
    let expected = proc_supplementary_groups();
    let count = process::getgroups_count().expect("query Linux supplementary-group count");
    assert_eq!(count, expected.len());

    let mut groups = vec![Gid::ROOT; count];
    let filled = process::getgroups(&mut groups[..]).expect("fill caller-owned group storage");
    assert_eq!(filled, count);
    assert_eq!(
        groups
            .iter()
            .map(|group| group.as_raw())
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn x86_64_getgroups_reports_only_the_initialized_maybe_uninit_prefix() {
    let count = process::getgroups_count().expect("query Linux supplementary-group count");
    let mut groups = vec![MaybeUninit::<Gid>::uninit(); count];
    let untouched_sentinel = Gid::from_raw(u32::MAX);
    groups.push(MaybeUninit::new(untouched_sentinel));
    let (initialized, untouched) =
        process::getgroups(&mut groups[..]).expect("fill MaybeUninit group storage");

    assert_eq!(initialized.len(), count);
    assert_eq!(untouched.len(), 1);
    // SAFETY: this trailing value was initialized before the syscall, and a
    // successful Linux getgroups fill initializes only its returned prefix.
    assert_eq!(unsafe { untouched[0].assume_init() }, untouched_sentinel);
}

#[test]
fn x86_64_getgroups_rejects_an_undersized_buffer_without_changing_credentials() {
    let count = process::getgroups_count().expect("query Linux supplementary-group count");
    if count == 0 {
        return;
    }

    let mut groups = vec![Gid::ROOT; count - 1];
    assert_eq!(process::getgroups(&mut groups[..]), Err(Errno::INVAL));
    assert_eq!(
        process::getgroups_count().expect("re-query group count"),
        count
    );
}

#[test]
fn x86_64_getgroups_empty_fill_keeps_the_count_query_out_of_buffer_results() {
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_getgroups_empty_fill_child_checks_nonempty_and_empty_lists",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .expect("run isolated supplementary-group child");
    assert!(
        output.status.success(),
        "isolated supplementary-group child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn set_child_groups(groups: &[u32]) {
    let result: isize;
    // SAFETY: Linux x86-64 setgroups reads exactly this live u32 slice. This
    // fixture runs only in the isolated child, so credential changes cannot
    // affect the test runner or its other tests.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 116usize => result,
            in("rdi") groups.len(),
            in("rsi") groups.as_ptr(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    assert_eq!(result, 0, "the credential fixture requires CAP_SETGID");
}

#[test]
#[ignore = "the parent regression invokes this test only in a subprocess"]
fn x86_64_getgroups_empty_fill_child_checks_nonempty_and_empty_lists() {
    set_child_groups(&[0]);
    assert_eq!(process::getgroups_count(), Ok(1));

    let mut initialized: [Gid; 0] = [];
    assert_eq!(process::getgroups(&mut initialized), Err(Errno::INVAL));
    let mut uninitialized: [MaybeUninit<Gid>; 0] = [];
    assert!(matches!(
        process::getgroups(&mut uninitialized),
        Err(Errno::INVAL),
    ));

    #[cfg(feature = "alloc")]
    {
        let mut groups = Vec::<Gid>::new();
        assert_eq!(
            process::getgroups(crabc_rs::buffer::spare_capacity(&mut groups)),
            Err(Errno::INVAL),
        );
        assert_eq!(groups.len(), 0);
    }

    set_child_groups(&[]);
    assert_eq!(process::getgroups_count(), Ok(0));
    assert_eq!(process::getgroups(&mut initialized), Ok(0));
    let (filled, untouched) = process::getgroups(&mut uninitialized)
        .expect("an empty group list initializes an empty prefix");
    assert!(filled.is_empty());
    assert!(untouched.is_empty());

    #[cfg(feature = "alloc")]
    {
        let mut groups = Vec::<Gid>::new();
        assert_eq!(
            process::getgroups(crabc_rs::buffer::spare_capacity(&mut groups)),
            Ok(0),
        );
        assert_eq!(groups.len(), 0);
    }
}
