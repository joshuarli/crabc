use api::fs::{self, AtFlags, Mode, OFlags, XattrFlags, CWD};

fn unavailable(error: api::io::Errno) -> bool {
    error == api::io::Errno::OPNOTSUPP || error == api::io::Errno::NOSYS
}

fn xattr_list_contains(list: &[u8], name: &[u8]) -> bool {
    list.split(|byte| *byte == 0).any(|entry| entry == name)
}

fn main() {
    let root = format!("/tmp/crabc-rustix-fs-xattr-{}", std::process::id());
    match fs::rmdir(&root) {
        Ok(()) | Err(api::io::Errno::NOENT) => {}
        Err(error) => panic!("remove stale fixture root: {error}"),
    }
    fs::mkdir(&root, Mode::RWXU).expect("mkdir");
    let directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open root");
    let file = fs::openat(
        &directory,
        "record",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create record");
    let path = format!("{root}/record");

    if let Err(error) = fs::setxattr(&path, "user.crabc-rs", b"path", XattrFlags::CREATE) {
        if unavailable(error) {
            drop(file);
            fs::unlinkat(&directory, "record", AtFlags::empty()).expect("unlink record");
            drop(directory);
            fs::rmdir(&root).expect("remove root");
            println!("fs-xattr unavailable");
            return;
        }
        panic!("set path xattr: {error}");
    }
    assert_eq!(fs::getxattr(&path, "user.crabc-rs", &mut [0_u8; 0]).unwrap(), 4);
    let mut get = [0_u8; 32];
    let get_length = fs::getxattr(&path, "user.crabc-rs", &mut get).unwrap();
    assert_eq!(&get[..get_length], b"path");
    let mut lget = [0_u8; 32];
    let lget_length = fs::lgetxattr(&path, "user.crabc-rs", &mut lget).unwrap();
    assert_eq!(&lget[..lget_length], b"path");
    let mut fget = [0_u8; 32];
    let fget_length = fs::fgetxattr(&file, "user.crabc-rs", &mut fget).unwrap();
    assert_eq!(&fget[..fget_length], b"path");

    fs::lsetxattr(&path, "user.crabc-rs-link", b"link", XattrFlags::CREATE).unwrap();
    fs::fsetxattr(&file, "user.crabc-rs-fd", b"fd", XattrFlags::CREATE).unwrap();
    let mut listed = [0_u8; 128];
    for list_length in [
        fs::listxattr(&path, &mut listed).unwrap(),
        fs::llistxattr(&path, &mut listed).unwrap(),
        fs::flistxattr(&file, &mut listed).unwrap(),
    ] {
        assert!(xattr_list_contains(&listed[..list_length], b"user.crabc-rs"));
    }

    fs::removexattr(&path, "user.crabc-rs").unwrap();
    fs::lremovexattr(&path, "user.crabc-rs-link").unwrap();
    fs::fremovexattr(&file, "user.crabc-rs-fd").unwrap();
    assert_eq!(
        fs::getxattr(&path, "user.crabc-rs", &mut [0_u8; 0]).unwrap_err(),
        api::io::Errno::NODATA,
    );

    drop(file);
    fs::unlinkat(&directory, "record", AtFlags::empty()).expect("unlink record");
    drop(directory);
    fs::rmdir(&root).expect("remove root");
    println!("fs-xattr ok");
}
