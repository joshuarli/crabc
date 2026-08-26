#![cfg(target_arch = "x86_64")]

use crabc_rs::process;

fn proc_status_ids() -> ([u32; 4], [u32; 4]) {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("read the current process identity oracle");
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(values) = line.strip_prefix("Uid:") {
            uid = Some(parse_id_fields(values));
        } else if let Some(values) = line.strip_prefix("Gid:") {
            gid = Some(parse_id_fields(values));
        }
    }
    (
        uid.expect("/proc status must expose Uid"),
        gid.expect("/proc status must expose Gid"),
    )
}

fn parse_id_fields(value: &str) -> [u32; 4] {
    let mut fields = [0; 4];
    for (slot, text) in value.split_whitespace().take(4).enumerate() {
        fields[slot] = text.parse().expect("/proc identity field is numeric");
    }
    fields
}

#[test]
fn x86_64_process_and_parent_ids_are_typed_and_stable() {
    let pid = process::getpid();
    assert_eq!(pid.as_raw_pid() as u32, std::process::id());
    assert_eq!(process::getpid(), pid);

    let parent = process::getppid();
    assert_eq!(process::getppid(), parent);
    if let Some(parent) = parent {
        assert!(parent.as_raw_pid() > 0);
    }
    assert_eq!(process::Pid::from_raw(0), None);
}

#[test]
fn x86_64_scalar_and_saved_identity_queries_match_proc_status() {
    let (uid, gid) = proc_status_ids();
    assert_eq!(process::getuid().as_raw(), uid[0]);
    assert_eq!(process::geteuid().as_raw(), uid[1]);
    assert_eq!(process::getgid().as_raw(), gid[0]);
    assert_eq!(process::getegid().as_raw(), gid[1]);

    let user = process::getresuid().expect("read Linux user identity triple");
    let group = process::getresgid().expect("read Linux group identity triple");
    assert_eq!(user.real.as_raw(), uid[0]);
    assert_eq!(user.effective.as_raw(), uid[1]);
    assert_eq!(user.saved.as_raw(), uid[2]);
    assert_eq!(group.real.as_raw(), gid[0]);
    assert_eq!(group.effective.as_raw(), gid[1]);
    assert_eq!(group.saved.as_raw(), gid[2]);
}
