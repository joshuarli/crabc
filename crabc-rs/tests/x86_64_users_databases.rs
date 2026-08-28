#![cfg(all(target_arch = "x86_64", feature = "alloc"))]

//! Native x86-64 contract for strict, owned conventional account snapshots.
//!
//! This exercises supplied local-file bytes independently from the host's
//! account configuration, then proves the separately loaded system snapshots
//! retain calling identity lookup. It deliberately does not select libc's
//! passwd/group APIs or NSS provider behavior.

use crabc_rs::process::{Gid, Uid};
use crabc_rs::users::{Database, DatabaseError, GroupDatabase, UserDatabase};

#[test]
fn x86_64_local_account_snapshots_keep_source_order_and_first_lookup() {
    let passwd = b"# local fixture\r\n\
first:x:1000:100:First User:/home/first:/bin/sh\r\n\
second:!:1001:100:Second User:/srv/second:/usr/bin/false\n\
first:x:2000:200:Later Duplicate:/home/later:/bin/bash\n";
    let group = b"staff:x:100:first,second\n\
staff:x:200:later\r\n\
empty:x:201:\n";

    let database = Database::from_bytes(passwd, group).expect("well-formed local snapshots");

    let users = database.users();
    assert_eq!(users.len(), 3);
    assert_eq!(users.entries()[2].gecos(), "Later Duplicate");
    let first = users.by_name("first").expect("first source record wins");
    assert_eq!(first.uid(), Uid::from_raw(1000));
    assert_eq!(first.home(), "/home/first");
    assert_eq!(users.by_uid(Uid::from_raw(1001)).unwrap().name(), "second");

    let groups = database.groups();
    assert_eq!(groups.len(), 3);
    let staff = groups.by_name("staff").expect("first source record wins");
    assert_eq!(staff.gid(), Gid::from_raw(100));
    assert_eq!(staff.members(), ["first", "second"]);
    assert!(groups
        .by_gid(Gid::from_raw(201))
        .expect("empty members are valid")
        .members()
        .is_empty());
}

#[test]
fn x86_64_local_account_snapshots_own_their_input_bytes() {
    let mut passwd = b"owned:x:1000:100:Owned User:/home/owned:/bin/sh\n".to_vec();
    let users = UserDatabase::from_bytes(&passwd).expect("well-formed local snapshot");

    passwd[0] = b'X';

    let owned = users.by_name("owned").expect("parser owns record fields");
    assert_eq!(owned.name(), "owned");
    assert_eq!(owned.gecos(), "Owned User");
}

#[test]
fn x86_64_malformed_local_account_records_are_rejected() {
    assert_eq!(
        UserDatabase::from_bytes(b"broken:x:1000:100:only:five\n"),
        Err(DatabaseError::InvalidInput),
    );
    assert_eq!(
        UserDatabase::from_bytes(b"name:x:not-a-number:100::/:/bin/sh\n"),
        Err(DatabaseError::InvalidInput),
    );
    assert_eq!(
        UserDatabase::from_bytes(b"name:x:1000:100:\xff:/:/bin/sh\n"),
        Err(DatabaseError::InvalidInput),
    );
    assert_eq!(
        GroupDatabase::from_bytes(b"staff:x:100:member,,other\n"),
        Err(DatabaseError::InvalidInput),
    );
    assert_eq!(
        GroupDatabase::from_bytes(b"staff:x:4294967296:member\n"),
        Err(DatabaseError::Overflow),
    );
}

#[test]
fn x86_64_system_account_snapshots_are_owned_and_match_calling_ids() {
    let users = UserDatabase::from_system().expect("test container supplies /etc/passwd");
    let groups = GroupDatabase::from_system().expect("test container supplies /etc/group");

    assert!(!users.is_empty());
    assert!(!groups.is_empty());
    assert!(users.by_uid(crabc_rs::process::getuid()).is_some());
    assert!(groups.by_gid(crabc_rs::process::getgid()).is_some());
}
