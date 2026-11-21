use crabc_rs::fs::AccessAtFlags as AccessFlags;
const UNLINK_FILE: crabc_rs::fs::UnlinkAtFlags = crabc_rs::fs::UnlinkAtFlags::empty();
const ACCESS_REMOVEDIR: AccessFlags = AccessFlags::EACCESS;
const ACCESS_SYMLINK_FOLLOW: AccessFlags = AccessFlags::from_bits_retain(0x400);

use crabc_rs::fs::{self, Access, Mode, OFlags};

const ROOT_PATH: &[u8] = b"/tmp/crabc-rs-native-accessat";

#[test]
fn accessat_resolves_relative_paths_and_supports_final_symlink_no_follow() {
    let _ = fs::rmdir(ROOT_PATH);
    fs::mkdir(ROOT_PATH, Mode::RUSR | Mode::WUSR | Mode::XUSR).expect("create accessat directory");
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

    fs::accessat(&directory, "target", Access::EXISTS, AccessFlags::empty())
        .expect("empty flags use directory-relative faccessat");
    assert_eq!(
        fs::accessat(&directory, "missing", Access::EXISTS, AccessFlags::empty(),),
        Err(crabc_rs::Errno::NOENT)
    );

    fs::accessat(
        &directory,
        "dangling",
        Access::EXISTS,
        AccessFlags::SYMLINK_NOFOLLOW,
    )
    .expect("faccessat2 checks a dangling final symlink itself");
    assert_eq!(
        fs::accessat(&directory, "dangling", Access::EXISTS, AccessFlags::empty()),
        Err(crabc_rs::Errno::NOENT)
    );
    fs::accessat(&directory, "target", Access::EXISTS, AccessFlags::EACCESS)
        .expect("faccessat2 accepts effective-credential checks");
    fs::accessat(&directory, "target", Access::EXISTS, ACCESS_REMOVEDIR)
        .expect("the shared REMOVEDIR/EACCESS bit is interpreted as EACCESS");

    assert_eq!(
        fs::accessat(
            &directory,
            "target",
            Access::EXISTS,
            ACCESS_SYMLINK_FOLLOW,
        ),
        Err(crabc_rs::Errno::INVAL)
    );
    assert_eq!(
        fs::accessat(
            &directory,
            "target",
            Access::from_bits_retain(0x8),
            AccessFlags::empty(),
        ),
        Err(crabc_rs::Errno::INVAL)
    );

    drop(target);
    fs::unlinkat(&directory, "dangling", UNLINK_FILE)
        .expect("remove accessat dangling link");
    fs::unlinkat(&directory, "link", UNLINK_FILE).expect("remove accessat link");
    fs::unlinkat(&directory, "target", UNLINK_FILE).expect("remove accessat target");
    drop(directory);
    fs::rmdir(ROOT_PATH).expect("remove accessat directory");
}
