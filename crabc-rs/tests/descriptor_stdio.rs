use crabc_rs::{fs, io, stdio};

fn scratch_path() -> String {
    format!(
        "/tmp/crabc-rs-descriptor-descriptor-stdio-{}",
        std::process::id()
    )
}

#[test]
fn duplication_and_descriptor_flags_preserve_ownership_contracts() {
    let path = scratch_path();
    let _ = fs::unlink(&path);
    let source = fs::open(
        &path,
        fs::OFlags::RDWR | fs::OFlags::CREATE | fs::OFlags::EXCL,
        fs::Mode::RUSR | fs::Mode::WUSR,
    )
    .expect("create descriptor fixture");

    crabc_core::io::dup2(source.as_raw_fd(), source.as_raw_fd())
        .expect("dup2 must preserve its equal-descriptor no-op contract");
    assert_eq!(
        crabc_core::io::dup3(source.as_raw_fd(), source.as_raw_fd(), 0)
            .expect_err("dup3 must reject equal descriptors")
            .raw(),
        22,
    );

    assert_eq!(
        io::fcntl_getfd(&source).expect("get initial fd flags"),
        io::FdFlags::empty()
    );
    io::fcntl_setfd(&source, io::FdFlags::CLOEXEC).expect("set close-on-exec");
    assert!(io::fcntl_getfd(&source)
        .expect("read close-on-exec")
        .contains(io::FdFlags::CLOEXEC));

    let duplicate = io::dup(&source).expect("dup source");
    assert_ne!(duplicate.as_raw_fd(), source.as_raw_fd());
    assert_eq!(
        io::fcntl_getfd(&duplicate).expect("read dup flags"),
        io::FdFlags::empty(),
        "dup does not copy FD_CLOEXEC"
    );

    let fcntl_duplicate =
        io::fcntl_dupfd(&source, duplicate.as_raw_fd() + 1).expect("duplicate through F_DUPFD");
    assert!(fcntl_duplicate.as_raw_fd() > duplicate.as_raw_fd());
    let cloexec_duplicate = io::fcntl_dupfd_cloexec(&source, fcntl_duplicate.as_raw_fd() + 1)
        .expect("duplicate through F_DUPFD_CLOEXEC");
    assert!(io::fcntl_getfd(&cloexec_duplicate)
        .expect("read F_DUPFD_CLOEXEC flags")
        .contains(io::FdFlags::CLOEXEC));

    let mut target = fs::open(&path, fs::OFlags::RDWR, fs::Mode::empty()).expect("open target");
    io::dup2(&source, &mut target).expect("dup2 target");
    assert_eq!(
        io::fcntl_getfd(&target).expect("read dup2 flags"),
        io::FdFlags::empty(),
        "dup2 clears the target descriptor's close-on-exec flag"
    );
    io::dup3(&source, &mut target, io::DupFlags::CLOEXEC).expect("dup3 target");
    assert!(io::fcntl_getfd(&target)
        .expect("read dup3 flags")
        .contains(io::FdFlags::CLOEXEC));

    drop(target);
    drop(cloexec_duplicate);
    drop(fcntl_duplicate);
    drop(duplicate);
    drop(source);
    fs::unlink(&path).expect("remove descriptor fixture");
}

#[test]
fn stdio_handles_have_stable_linux_descriptor_numbers_and_restore_stdin() {
    assert_eq!(stdio::raw_stdin(), 0);
    assert_eq!(stdio::raw_stdout(), 1);
    assert_eq!(stdio::raw_stderr(), 2);
    assert_eq!(stdio::stdin().as_raw_fd(), 0);
    assert_eq!(stdio::stdout().as_raw_fd(), 1);
    assert_eq!(stdio::stderr().as_raw_fd(), 2);

    let saved = io::dup(stdio::stdin()).expect("save stdin");
    stdio::dup2_stdin(&saved).expect("dup2 stdin onto itself's standard slot");
    assert_eq!(
        io::fcntl_getfd(stdio::stdin()).expect("read restored stdin flags"),
        io::FdFlags::empty()
    );
    drop(saved);
}
