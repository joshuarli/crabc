use core::mem::MaybeUninit;

use crabc_rs::process::{self, Gid};

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
fn query_and_fill_match_linux_supplementary_group_snapshot() {
    let expected = proc_supplementary_groups();
    let count = process::getgroups_count().expect("query Linux supplementary-group count");
    assert_eq!(count, expected.len());

    let mut groups = vec![Gid::ROOT; count];
    let filled = process::getgroups(&mut groups).expect("fill caller-owned group storage");
    assert_eq!(filled, count);
    assert_eq!(groups.iter().map(|group| group.as_raw()).collect::<Vec<_>>(), expected);
}

#[test]
fn maybe_uninit_fill_reports_only_the_initialized_prefix() {
    let count = process::getgroups_count().expect("query Linux supplementary-group count");
    let mut groups = vec![MaybeUninit::<Gid>::uninit(); count];
    let (initialized, untouched) =
        process::getgroups(&mut groups).expect("fill MaybeUninit group storage");

    assert_eq!(initialized.len(), count);
    assert!(untouched.is_empty());
    for group in initialized {
        assert_ne!(group.as_raw(), u32::MAX);
    }
}

#[test]
fn undersized_fill_reports_einval_without_changing_credentials() {
    let count = process::getgroups_count().expect("query Linux supplementary-group count");
    if count == 0 {
        return;
    }

    let mut groups = vec![Gid::ROOT; count - 1];
    assert_eq!(process::getgroups(&mut groups), Err(crabc_rs::Errno::INVAL));
    assert_eq!(process::getgroups_count().expect("re-query group count"), count);
}
