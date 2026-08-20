use api::fs::{self, AtFlags, Mode, OFlags, ResolveFlags, CWD};

fn main() {
    let root = format!("/tmp/crabc-rustix-m2-openat2-{}", std::process::id());
    match fs::rmdir(&root) {
        Ok(()) | Err(api::io::Errno::NOENT) => {}
        Err(error) => panic!("remove stale fixture root: {error}"),
    }
    fs::mkdir(&root, Mode::RWXU).expect("mkdir");
    let directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open root");
    drop(
        fs::openat(
            &directory,
            "record",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
    )
    .expect("create record"),
    );
    drop(fs::open(format!("{root}/record"), OFlags::RDONLY, Mode::empty()).expect("open record"));
    fs::symlinkat("record", &directory, "symbolic").expect("symlinkat");

    assert_eq!(
        fs::openat(
            &directory,
            "symbolic",
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap_err(),
        api::io::Errno::LOOP,
    );
    drop(
        fs::openat2(
            &directory,
            "record",
            OFlags::RDONLY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .expect("constrained openat2"),
    );
    assert_eq!(
        fs::openat2(
            &directory,
            "symbolic",
            OFlags::RDONLY,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )
        .unwrap_err(),
        api::io::Errno::LOOP,
    );

    for name in ["record", "symbolic"] {
        fs::unlinkat(&directory, name, AtFlags::empty()).expect("unlink fixture path");
    }
    drop(directory);
    fs::rmdir(&root).expect("remove root");
    println!("m2-openat2 ok");
}
