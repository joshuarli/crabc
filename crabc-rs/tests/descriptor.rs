use core::num::NonZeroU64;

use crabc_rs::{fs, io, pipe, process, Errno, OwnedFd};

#[test]
fn owned_close_consumes_and_releases_descriptor() {
    let file = fs::memfd_create(
        &b"crabc-native-posix-close"[..],
        fs::MemfdFlags::CLOEXEC,
    )
    .expect("create close fixture");
    let raw = file.as_raw_fd();

    file.close().expect("close owned descriptor");
    // The raw value is intentionally used only as a direct kernel argument;
    // no borrowed descriptor is created after ownership has been consumed.
    let closed = unsafe {
        crabc_core::io::fcntl_raw(raw, crabc_core::io::F_GETFD, core::ptr::null_mut())
    };
    assert_eq!(closed, Err(Errno::BADF));
}

#[test]
fn splice_transfers_with_an_explicit_offset_without_moving_file_position() {
    let file = fs::memfd_create(
        &b"crabc-native-splice"[..],
        fs::MemfdFlags::CLOEXEC,
    )
    .expect("create splice source");
    io::write(&file, b"splice-payload").expect("write splice source");
    fs::seek(&file, fs::SeekFrom::Start(0)).expect("rewind splice source");

    let (reader, writer) = pipe::pipe().expect("create splice pipe");
    let mut offset = 2_u64;
    assert_eq!(
        pipe::splice(
            &file,
            Some(&mut offset),
            &writer,
            None,
            6,
            pipe::SpliceFlags::empty(),
        )
        .expect("splice source range into pipe"),
        6,
    );
    assert_eq!(offset, 8);
    assert_eq!(fs::tell(&file).expect("tell source after positioned splice"), 0);

    let mut received = [0_u8; 6];
    assert_eq!(io::read(&reader, &mut received).expect("read spliced bytes"), 6);
    assert_eq!(&received, b"lice-p");

    let mut invalid_offset = i64::MAX as u64;
    assert_eq!(
        pipe::splice(
            &file,
            Some(&mut invalid_offset),
            &writer,
            None,
            1,
            pipe::SpliceFlags::empty(),
        ),
        Err(Errno::INVAL),
    );
    assert_eq!(invalid_offset, i64::MAX as u64);
}

#[test]
fn vmsplice_transfers_an_immutable_source_iovec() {
    let (reader, writer) = pipe::pipe().expect("create vmsplice pipe");
    let source = [pipe::IoSliceRaw::from_slice(b"vmsplice")];
    assert_eq!(
        unsafe { pipe::vmsplice(&writer, &source, pipe::SpliceFlags::empty()) }
            .expect("vmsplice source bytes"),
        8,
    );

    let mut received = [0_u8; 8];
    assert_eq!(io::read(&reader, &mut received).expect("read vmspliced bytes"), 8);
    assert_eq!(&received, b"vmsplice");
}

fn child_lockf_test(fd: &OwnedFd) -> ! {
    match fs::lock_from_current(
        fd,
        fs::CurrentLockOperation::TestExclusive,
        fs::CurrentLockRange::ToEnd,
    ) {
        Err(Errno::ACCESS) => process::exit_immediately(0),
        Ok(()) => process::exit_immediately(1),
        Err(_) => process::exit_immediately(2),
    }
}

#[test]
fn lockf_uses_current_offset_and_reports_conflicts() {
    let file = fs::memfd_create(
        &b"crabc-native-lockf"[..],
        fs::MemfdFlags::CLOEXEC,
    )
    .expect("create lockf fixture");
    io::write(&file, b"lockf-range").expect("write lockf fixture");
    fs::seek(&file, fs::SeekFrom::Start(3)).expect("position lockf fixture");

    fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::LockExclusive,
        fs::CurrentLockRange::Forward(NonZeroU64::new(4).unwrap()),
    )
    .expect("take current-offset range lock");
    assert_eq!(fs::tell(&file).expect("tell after lockf"), 3);

    let child = match unsafe { process::fork_raw() }.expect("fork lockf observer") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => child_lockf_test(&file),
    };
    let (_, status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("wait for lockf observer")
        .expect("lockf observer changed state");
    assert_eq!(status.exit_status(), Some(0));

    fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::Unlock,
        fs::CurrentLockRange::Forward(NonZeroU64::new(4).unwrap()),
    )
    .expect("release current-offset range lock");
    fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::TestExclusive,
        fs::CurrentLockRange::ToEnd,
    )
    .expect("test unlocked current-offset range");
    fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::TryExclusive,
        fs::CurrentLockRange::Backward(NonZeroU64::new(1).unwrap()),
    )
    .expect("take nonblocking backward lock");
    fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::Unlock,
        fs::CurrentLockRange::Backward(NonZeroU64::new(1).unwrap()),
    )
    .expect("release nonblocking backward lock");
    assert_eq!(
        fs::lock_from_current(
            &file,
            fs::CurrentLockOperation::LockExclusive,
            fs::CurrentLockRange::Forward(NonZeroU64::new(i64::MAX as u64 + 1).unwrap()),
        ),
        Err(Errno::RANGE),
    );
}
