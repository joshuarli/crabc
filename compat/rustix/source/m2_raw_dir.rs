use core::mem::MaybeUninit;

use api::fs::{self, AtFlags, Mode, OFlags, RawDir, CWD};

fn main() {
    let root = format!("/tmp/crabc-rustix-m2-raw-dir-{}", std::process::id());
    match fs::rmdir(&root) {
        Ok(()) | Err(api::io::Errno::NOENT) => {}
        Err(error) => panic!("remove stale fixture root: {error}"),
    }
    fs::mkdir(&root, Mode::RWXU).expect("mkdir");
    let directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open root");
    let long_name = "n".repeat(255);
    for name in ["short", long_name.as_str()] {
        drop(
            fs::openat(
                &directory,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )
            .expect("create entry"),
        );
    }

    let iteration_directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open iterator");
    let mut unaligned = [MaybeUninit::uninit(); 4097];
    let mut entries = RawDir::new(&iteration_directory, &mut unaligned[1..]);
    let mut names = Vec::new();
    while let Some(entry) = entries.next() {
        names.push(entry.unwrap().file_name().to_bytes().to_vec());
    }
    assert!(names.iter().any(|name| name == b"short"));
    assert!(names.iter().any(|name| name == long_name.as_bytes()));
    drop(entries);
    drop(iteration_directory);

    let small_directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open undersized iterator");
    let mut too_small = [MaybeUninit::uninit(); 1];
    let mut too_small_iter = RawDir::new(&small_directory, &mut too_small);
    assert_eq!(
        too_small_iter.next().unwrap().unwrap_err(),
        api::io::Errno::INVAL,
    );
    drop(too_small_iter);
    drop(small_directory);

    for name in ["short", long_name.as_str()] {
        fs::unlinkat(&directory, name, AtFlags::empty()).expect("unlink fixture path");
    }
    drop(directory);
    fs::rmdir(&root).expect("remove root");
    println!("m2-raw-dir ok");
}
