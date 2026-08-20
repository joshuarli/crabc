use api::fs::{self, AtFlags, Mode, OFlags, Timespec, Timestamps, CWD};

fn main() {
    let root = format!("/tmp/crabc-rustix-m2-metadata-{}", std::process::id());
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
        Mode::RWXU,
    )
    .expect("create record");

    fs::chmodat(&directory, "record", Mode::empty(), AtFlags::empty()).expect("chmodat");
    assert_eq!(fs::statat(&directory, "record", AtFlags::empty()).unwrap().st_mode & 0o700, 0);
    fs::fchmod(&file, Mode::RWXU).expect("fchmod");
    fs::chmod(format!("{root}/record"), Mode::RUSR).expect("chmod");
    assert_eq!(fs::stat(format!("{root}/record")).unwrap().st_mode & 0o700, 0o400);
    fs::fchmod(&file, Mode::RWXU).expect("restore fchmod");

    fs::symlinkat("record", &directory, "symbolic").expect("symlinkat");
    assert_eq!(
        fs::chmodat(
            &directory,
            "symbolic",
            Mode::empty(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap_err(),
        api::io::Errno::OPNOTSUPP,
    );
    assert_eq!(
        fs::chmodat(&directory, "record", Mode::empty(), AtFlags::EACCESS).unwrap_err(),
        api::io::Errno::INVAL,
    );

    let times = Timestamps {
        last_access: Timespec { tv_sec: 44_000, tv_nsec: 45_000 },
        last_modification: Timespec { tv_sec: 46_000, tv_nsec: 47_000 },
    };
    fs::utimensat(&directory, "record", &times, AtFlags::empty()).expect("utimensat");
    let by_path = fs::statat(&directory, "record", AtFlags::empty()).unwrap();
    assert_eq!((by_path.st_mtime, by_path.st_mtime_nsec), (46_000, 47_000));

    let by_fd_times = Timestamps {
        last_access: Timespec { tv_sec: 48_000, tv_nsec: 49_000 },
        last_modification: Timespec { tv_sec: 50_000, tv_nsec: 51_000 },
    };
    fs::futimens(&file, &by_fd_times).expect("futimens");
    let by_fd = fs::fstat(&file).unwrap();
    assert_eq!((by_fd.st_mtime, by_fd.st_mtime_nsec), (50_000, 51_000));

    drop(file);
    for name in ["record", "symbolic"] {
        fs::unlinkat(&directory, name, AtFlags::empty()).expect("unlink fixture path");
    }
    drop(directory);
    fs::rmdir(&root).expect("remove root");
    println!("m2-metadata ok");
}
