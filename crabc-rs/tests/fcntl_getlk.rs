use crabc_rs::{fs, process, Errno, OwnedFd};

fn child_observes_parent_lock(fd: &OwnedFd, parent: process::Pid) -> ! {
    let query = process::Flock::from(process::FlockType::WriteLock);
    let observed = match process::fcntl_getlk(fd, &query) {
        Ok(Some(lock)) => lock,
        Ok(None) | Err(_) => process::exit_immediately(1),
    };
    if observed.typ != process::FlockType::WriteLock
        || observed.offset_type != process::FlockOffsetType::Set
        || observed.start != 0
        || observed.length != 0
        || observed.pid != Some(parent)
    {
        process::exit_immediately(2);
    }
    process::exit_immediately(0)
}

#[test]
fn fcntl_getlk_reports_unlocked_and_parent_process_lock() {
    let file = fs::memfd_create(&b"crabc-native-fcntl-getlk"[..], fs::MemfdFlags::CLOEXEC)
        .expect("create fcntl_getlk memfd");
    let query = process::Flock::from(process::FlockType::WriteLock);

    assert_eq!(
        process::fcntl_getlk(&file, &query).expect("query unlocked memfd"),
        None,
    );
    fs::fcntl_lock(&file, fs::FlockOperation::LockExclusive)
        .expect("acquire parent-associated record lock");

    let parent = process::getpid();
    let child = match unsafe { process::fork_raw() }.expect("fork lock observer") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => child_observes_parent_lock(&file, parent),
    };
    let (_, status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("wait for lock observer")
        .expect("lock observer changed state");
    assert_eq!(status.exit_status(), Some(0));
    fs::fcntl_lock(&file, fs::FlockOperation::Unlock).expect("release parent lock");
    assert_eq!(
        process::fcntl_getlk(&file, &query).expect("query unlocked memfd"),
        None
    );
}

#[test]
fn fcntl_getlk_rejects_undefined_input_and_unrepresentable_offsets() {
    let file = fs::memfd_create(
        &b"crabc-native-fcntl-getlk-errors"[..],
        fs::MemfdFlags::CLOEXEC,
    )
    .expect("create fcntl_getlk error memfd");

    let unlocked = process::Flock::from(process::FlockType::Unlocked);
    assert_eq!(
        process::fcntl_getlk(&file, &unlocked).err(),
        Some(Errno::INVAL),
    );

    let oversized = process::Flock {
        start: u64::MAX,
        length: 0,
        pid: None,
        typ: process::FlockType::ReadLock,
        offset_type: process::FlockOffsetType::Set,
    };
    assert_eq!(
        process::fcntl_getlk(&file, &oversized).err(),
        Some(Errno::RANGE),
    );
}
