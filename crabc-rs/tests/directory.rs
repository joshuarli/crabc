use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Dir, Mode, OFlags, CWD};
use crabc_rs::{io, Errno};

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn scratch_path() -> String {
    format!(
        "/tmp/crabc-rs-native-dir-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

#[test]
fn dir_owns_close_on_exec_descriptor_and_preserves_byte_names() {
    let root = scratch_path();
    let _ = fs::rmdir(&root);
    fs::mkdir(&root, Mode::RWXU).expect("create directory fixture");
    let directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("open fixture directory");
    let byte_name = b"entry-\xff";
    let file = fs::openat(
        &directory,
        &byte_name[..],
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create non-UTF-8 directory entry");
    drop(file);
    drop(directory);

    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut stream = Dir::open(&root, &mut storage).expect("open owned directory stream");
    assert!(
        io::fcntl_getfd(&stream)
            .expect("read directory stream descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "Dir::open must set close-on-exec",
    );

    let mut found = false;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("validated getdents record");
        if entry.name_bytes() == byte_name {
            found = true;
        }
    }
    assert!(found, "directory entry names must remain byte-oriented");
    assert!(stream.next().is_none(), "end-of-directory is represented by None");

    drop(stream);
    let directory = fs::openat(CWD, &root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .expect("reopen fixture directory for cleanup");
    fs::unlinkat(&directory, &byte_name[..], fs::AtFlags::empty()).expect("remove byte entry");
    drop(directory);
    fs::rmdir(&root).expect("remove directory fixture");
}

#[test]
fn dir_reports_small_buffer_error_once_and_then_stops() {
    let root = scratch_path();
    let _ = fs::rmdir(&root);
    fs::mkdir(&root, Mode::RWXU).expect("create directory fixture");

    let mut storage = [MaybeUninit::uninit(); 1];
    let mut stream = Dir::open(&root, &mut storage).expect("open owned directory stream");
    assert_eq!(stream.next().expect("small buffer must report an error").unwrap_err(), Errno::INVAL);
    assert!(stream.next().is_none(), "a failed stream must not silently continue");
    drop(stream);

    fs::rmdir(&root).expect("remove directory fixture");
}
