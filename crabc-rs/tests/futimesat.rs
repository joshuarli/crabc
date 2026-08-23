use crabc_rs::fs::{self, Mode, OFlags, Timeval};

const ROOT_PATH: &[u8] = b"/tmp/crabc-rs-native-futimesat";

#[test]
fn futimesat_resolves_relative_paths_and_updates_the_target() {
    let _ = fs::rmdir(ROOT_PATH);
    fs::mkdir(ROOT_PATH, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .expect("create futimesat directory");
    let directory = fs::open(
        ROOT_PATH,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open futimesat directory");
    let target = fs::openat(
        &directory,
        "target",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create futimesat target");
    fs::symlinkat("target", &directory, "link").expect("create futimesat symlink");

    let target_times = [
        Timeval {
            tv_sec: 11,
            tv_usec: 111_111,
        },
        Timeval {
            tv_sec: 12,
            tv_usec: 222_222,
        },
    ];
    fs::futimesat(&directory, "link", Some(&target_times))
        .expect("set timestamps through directory-relative symlink");
    let target_stat = fs::fstat(&target).expect("observe target timestamps");
    assert_eq!(target_stat.st_atime, 11);
    assert_eq!(target_stat.st_atime_nsec, 111_111_000);
    assert_eq!(target_stat.st_mtime, 12);
    assert_eq!(target_stat.st_mtime_nsec, 222_222_000);

    let invalid = [
        Timeval {
            tv_sec: 11,
            tv_usec: -1,
        },
        Timeval {
            tv_sec: 12,
            tv_usec: 1_000_000,
        },
    ];
    assert_eq!(
        fs::futimesat(&directory, "link", Some(&invalid)),
        Err(crabc_rs::Errno::INVAL)
    );
    let unchanged = fs::fstat(&target).expect("observe target after rejected input");
    assert_eq!(unchanged.st_atime, target_stat.st_atime);
    assert_eq!(unchanged.st_atime_nsec, target_stat.st_atime_nsec);
    assert_eq!(unchanged.st_mtime, target_stat.st_mtime);
    assert_eq!(unchanged.st_mtime_nsec, target_stat.st_mtime_nsec);

    fs::futimesat(&directory, "link", None).expect("set target timestamps to current time");
    let current = fs::fstat(&target).expect("observe current target timestamps");
    assert!(
        current.st_atime > 12
            || current.st_atime == 12 && current.st_atime_nsec > 222_222_000
    );
    assert!(
        current.st_mtime > 12
            || current.st_mtime == 12 && current.st_mtime_nsec > 222_222_000
    );

    drop(target);
    fs::unlinkat(&directory, "link", fs::AtFlags::empty()).expect("remove futimesat link");
    fs::unlinkat(&directory, "target", fs::AtFlags::empty()).expect("remove futimesat target");
    drop(directory);
    fs::rmdir(ROOT_PATH).expect("remove futimesat directory");
}
