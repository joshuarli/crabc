use api::fs::{self, FlockOperation, Mode, OFlags, CWD};

fn main() {
    let path = format!("/tmp/crabc-rustix-fs-locks-{}", std::process::id());
    let file = fs::openat(
        CWD,
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RWXU,
    )
    .expect("create lock fixture");

    fs::flock(&file, FlockOperation::LockExclusive).expect("take flock lock");
    fs::flock(&file, FlockOperation::Unlock).expect("release flock lock");
    fs::fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive)
        .expect("take fcntl lock");
    fs::fcntl_lock(&file, FlockOperation::NonBlockingUnlock)
        .expect("release fcntl lock");

    drop(file);
    fs::unlink(&path).expect("remove lock fixture");
    println!("fs-locks ok");
}
