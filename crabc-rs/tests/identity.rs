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
fn typed_identity_syscalls_match_linux_real_and_effective_ids() {
    let (uid, gid) = proc_status_ids();
    let real_uid = process::getuid();
    let effective_uid = process::geteuid();
    let real_gid = process::getgid();
    let effective_gid = process::getegid();

    assert_eq!(real_uid.as_raw(), uid[0]);
    assert_eq!(effective_uid.as_raw(), uid[1]);
    assert_eq!(real_gid.as_raw(), gid[0]);
    assert_eq!(effective_gid.as_raw(), gid[1]);
    assert_eq!(real_uid, process::Uid::from_raw(real_uid.as_raw()));
    assert_eq!(real_gid, process::Gid::from_raw(real_gid.as_raw()));
    assert_eq!(real_uid.is_root(), real_uid.as_raw() == 0);
    assert_eq!(real_gid.is_root(), real_gid.as_raw() == 0);
}

#[test]
fn typed_identity_triples_match_linux_real_effective_saved_ids() {
    let (uid, gid) = proc_status_ids();
    let user_ids = process::getresuid().expect("read Linux real/effective/saved user IDs");
    let group_ids = process::getresgid().expect("read Linux real/effective/saved group IDs");

    assert_eq!(user_ids.real.as_raw(), uid[0]);
    assert_eq!(user_ids.effective.as_raw(), uid[1]);
    assert_eq!(user_ids.saved.as_raw(), uid[2]);
    assert_eq!(group_ids.real.as_raw(), gid[0]);
    assert_eq!(group_ids.effective.as_raw(), gid[1]);
    assert_eq!(group_ids.saved.as_raw(), gid[2]);
    assert_eq!(user_ids.real, process::getuid());
    assert_eq!(user_ids.effective, process::geteuid());
    assert_eq!(group_ids.real, process::getgid());
    assert_eq!(group_ids.effective, process::getegid());
}

#[test]
fn typed_identity_triples_are_read_only_and_stable() {
    let first_uid = process::getresuid().expect("read Linux user identity triple");
    let first_gid = process::getresgid().expect("read Linux group identity triple");
    let second_uid = process::getresuid().expect("read Linux user identity triple again");
    let second_gid = process::getresgid().expect("read Linux group identity triple again");

    assert_eq!(first_uid, second_uid);
    assert_eq!(first_gid, second_gid);
}
