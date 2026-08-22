use crabc_rs::fs::{self, Access, AtFlags, Mode, OFlags};

const ROOT_PATH: &[u8] = b"/tmp/crabc-rs-m10-accessat";

#[test]
fn accessat_resolves_relative_paths_and_supports_final_symlink_no_follow() {
    let _ = fs::rmdir(ROOT_PATH);
    fs::mkdir(ROOT_PATH, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .expect("create accessat directory");
    let directory = fs::open(
        ROOT_PATH,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open accessat directory");
    let target = fs::openat(
        &directory,
        "target",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create accessat target");
    fs::symlinkat("target", &directory, "link").expect("create accessat symlink");
    fs::symlinkat("missing-target", &directory, "dangling")
        .expect("create accessat dangling symlink");

    fs::accessat(&directory, "target", Access::EXISTS, AtFlags::empty())
        .expect("empty flags use directory-relative faccessat");
    assert_eq!(
        fs::accessat(
            &directory,
            "missing",
            Access::EXISTS,
            AtFlags::empty(),
        ),
        Err(crabc_rs::Errno::NOENT)
    );

    fs::accessat(
        &directory,
        "dangling",
        Access::EXISTS,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("faccessat2 checks a dangling final symlink itself");
    assert_eq!(
        fs::accessat(&directory, "dangling", Access::EXISTS, AtFlags::empty()),
        Err(crabc_rs::Errno::NOENT)
    );
    fs::accessat(
        &directory,
        "target",
        Access::EXISTS,
        AtFlags::EACCESS,
    )
    .expect("faccessat2 accepts effective-credential checks");
    fs::accessat(
        &directory,
        "target",
        Access::EXISTS,
        AtFlags::REMOVEDIR,
    )
    .expect("the shared REMOVEDIR/EACCESS bit is interpreted as EACCESS");

    assert_eq!(
        fs::accessat(
            &directory,
            "target",
            Access::EXISTS,
            AtFlags::SYMLINK_FOLLOW,
        ),
        Err(crabc_rs::Errno::INVAL)
    );
    assert_eq!(
        fs::accessat(
            &directory,
            "target",
            Access::from_bits_retain(0x8),
            AtFlags::empty(),
        ),
        Err(crabc_rs::Errno::INVAL)
    );

    drop(target);
    fs::unlinkat(&directory, "dangling", fs::AtFlags::empty())
        .expect("remove accessat dangling link");
    fs::unlinkat(&directory, "link", fs::AtFlags::empty()).expect("remove accessat link");
    fs::unlinkat(&directory, "target", fs::AtFlags::empty()).expect("remove accessat target");
    drop(directory);
    fs::rmdir(ROOT_PATH).expect("remove accessat directory");
}
