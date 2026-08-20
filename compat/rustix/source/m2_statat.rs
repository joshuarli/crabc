use api::fs::{self, AtFlags, FileType, Mode, OFlags, ABS, CWD};

fn main() {
    let root = format!("/tmp/crabc-rustix-m2-{}", std::process::id());
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
    api::io::write(&file, b"m2").expect("write record");

    let by_fd = fs::fstat(&file).expect("fstat");
    assert_eq!(by_fd.st_size, 2);
    assert_eq!(FileType::from_raw_mode(by_fd.st_mode), FileType::RegularFile);
    let by_path = fs::statat(&directory, "record", AtFlags::empty()).expect("statat");
    assert_eq!(by_path.st_ino, by_fd.st_ino);
    let absolute = format!("{root}/record");
    assert_eq!(fs::stat(&absolute).unwrap().st_ino, by_fd.st_ino);
    assert_eq!(fs::statat(ABS, &absolute, AtFlags::empty()).unwrap().st_ino, by_fd.st_ino);
    assert_eq!(fs::statat(ABS, "record", AtFlags::empty()).unwrap_err(), api::io::Errno::BADF);

    fs::mkdirat(&directory, "child", Mode::RWXU).expect("mkdirat child");
    fs::unlinkat(&directory, "child", AtFlags::REMOVEDIR).expect("remove child");

    drop(file);
    fs::unlinkat(&directory, "record", AtFlags::empty()).expect("unlink record");
    drop(directory);
    fs::rmdir(&root).expect("remove root");
    println!("m2-statat ok");
}
