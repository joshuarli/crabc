#[allow(unused_imports)]
use api::fd::AsRawFd;

use api::{
    fs::{self, Mode, OFlags},
    io::{self, DupFlags, FdFlags},
    stdio,
};

fn main() {
    let path = format!("/tmp/crabc-rustix-m5-descriptor-stdio-{}", std::process::id());
    let _ = fs::unlink(&path);
    let source = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create descriptor fixture");
    io::fcntl_setfd(&source, FdFlags::CLOEXEC).expect("set close-on-exec");
    let duplicate = io::dup(&source).expect("dup source");
    let cloexec_duplicate = io::fcntl_dupfd_cloexec(&source, duplicate.as_raw_fd() + 1)
        .expect("duplicate through F_DUPFD_CLOEXEC");
    assert!(
        io::fcntl_getfd(&cloexec_duplicate)
            .expect("read F_DUPFD_CLOEXEC flags")
            .contains(FdFlags::CLOEXEC)
    );

    let mut target = fs::open(&path, OFlags::RDWR, Mode::empty()).expect("open target");
    io::dup2(&source, &mut target).expect("dup2 target");
    io::dup3(&source, &mut target, DupFlags::CLOEXEC).expect("dup3 target");
    assert_eq!(stdio::raw_stdin(), 0);
    assert_eq!(stdio::raw_stdout(), 1);
    assert_eq!(stdio::raw_stderr(), 2);
    assert_eq!(stdio::stdin().as_raw_fd(), 0);
    assert_eq!(stdio::stdout().as_raw_fd(), 1);
    assert_eq!(stdio::stderr().as_raw_fd(), 2);

    drop(target);
    drop(cloexec_duplicate);
    drop(duplicate);
    drop(source);
    fs::unlink(&path).expect("remove descriptor fixture");
    println!("m5-descriptor-stdio ok");
}
