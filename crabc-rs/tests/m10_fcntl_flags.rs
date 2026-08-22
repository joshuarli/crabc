use crabc_rs::{fs, io, pipe};

#[test]
fn native_fcntl_status_flags_are_shared_by_duplicate_descriptors() {
    let (reader, _writer) = pipe::pipe().expect("create fcntl status-flags fixture");
    let duplicate = io::dup(&reader).expect("duplicate fcntl status-flags fixture");
    let initial = fs::fcntl_getfl(&reader).expect("read initial open-file flags");

    assert!(!initial.contains(fs::OFlags::NONBLOCK));
    fs::fcntl_setfl(&reader, initial | fs::OFlags::NONBLOCK)
        .expect("set open-file nonblocking status flag");
    assert!(
        fs::fcntl_getfl(&duplicate)
            .expect("read duplicated open-file flags")
            .contains(fs::OFlags::NONBLOCK),
        "F_SETFL must update the shared open-file description",
    );

    fs::fcntl_setfl(&duplicate, initial).expect("restore open-file status flags");
    assert!(
        !fs::fcntl_getfl(&reader)
            .expect("read restored open-file flags")
            .contains(fs::OFlags::NONBLOCK),
        "restoring through a duplicate must be visible through the original",
    );
}
