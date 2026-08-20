use core::mem::MaybeUninit;

use api::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, CWD};

fn main() {
    let root = format!("/tmp/crabc-rustix-m2-links-{}", std::process::id());
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
    let record = fs::fstat(&file).expect("stat record");

    fs::linkat(&directory, "record", &directory, "hard", AtFlags::empty()).expect("linkat");
    assert_eq!(fs::statat(&directory, "hard", AtFlags::empty()).unwrap().st_ino, record.st_ino);
    fs::symlinkat("record", &directory, "symbolic").expect("symlinkat");
    assert_eq!(
        FileType::from_raw_mode(
            fs::statat(&directory, "symbolic", AtFlags::SYMLINK_NOFOLLOW)
                .unwrap()
                .st_mode,
        ),
        FileType::Symlink,
    );
    assert_eq!(
        FileType::from_raw_mode(fs::lstat(format!("{root}/symbolic")).unwrap().st_mode),
        FileType::Symlink,
    );
    let mut raw = [MaybeUninit::uninit(); 16];
    let (target, _) = fs::readlinkat_raw(&directory, "symbolic", &mut raw).expect("raw readlinkat");
    assert_eq!(target, b"record");
    assert_eq!(
        fs::readlinkat(&directory, "symbolic", Vec::new()).unwrap().as_bytes(),
        b"record",
    );

    fs::renameat(&directory, "hard", &directory, "renamed").expect("renameat");
    assert_eq!(
        fs::renameat_with(
            &directory,
            "renamed",
            &directory,
            "record",
            RenameFlags::NOREPLACE,
        )
        .unwrap_err(),
        api::io::Errno::EXIST,
    );
    drop(file);
    for name in ["record", "renamed", "symbolic"] {
        fs::unlinkat(&directory, name, AtFlags::empty()).expect("unlink fixture path");
    }
    drop(directory);
    fs::rmdir(&root).expect("remove root");
    println!("m2-links ok");
}
