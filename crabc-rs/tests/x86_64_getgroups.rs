#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;

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
