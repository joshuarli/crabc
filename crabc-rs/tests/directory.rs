const UNLINK_FILE: crabc_rs::fs::UnlinkAtFlags = crabc_rs::fs::UnlinkAtFlags::empty();

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Dir, Mode, OFlags, CWD};
use crabc_rs::{io, Errno};

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "linux")]
const BYTE_NAME: &[u8] = b"entry-\xff";
// APFS stores names as UTF-8 and rejects other byte sequences.
#[cfg(target_os = "macos")]
const BYTE_NAME: &[u8] = "entry-\u{e9}".as_bytes();

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
    let directory = fs::openat(
        CWD,
        &root,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .expect("open fixture directory");
    let byte_name = BYTE_NAME;
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
    assert!(
        stream.next().is_none(),
        "end-of-directory is represented by None"
    );

    drop(stream);
    let directory = fs::openat(
        CWD,
        &root,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .expect("reopen fixture directory for cleanup");
    fs::unlinkat(&directory, &byte_name[..], UNLINK_FILE).expect("remove byte entry");
    drop(directory);
    fs::rmdir(&root).expect("remove directory fixture");
}

#[cfg(target_os = "linux")]
#[test]
fn dir_reports_small_buffer_error_once_and_then_stops() {
    let root = scratch_path();
    let _ = fs::rmdir(&root);
    fs::mkdir(&root, Mode::RWXU).expect("create directory fixture");

    let mut storage = [MaybeUninit::uninit(); 1];
    let mut stream = Dir::open(&root, &mut storage).expect("open owned directory stream");
    assert_eq!(
        stream
            .next()
            .expect("small buffer must report an error")
            .unwrap_err(),
        Errno::INVAL
    );
    assert!(
        stream.next().is_none(),
        "a failed stream must not silently continue"
    );
    drop(stream);

    fs::rmdir(&root).expect("remove directory fixture");
}

// libSystem's directory stream owns its record storage, so the caller buffer
// does not bound the entries Darwin can return.
#[cfg(target_os = "macos")]
#[test]
fn dir_iterates_with_an_empty_caller_buffer_on_darwin() {
    let root = scratch_path();
    let _ = fs::rmdir(&root);
    fs::mkdir(&root, Mode::RWXU).expect("create directory fixture");
    fs::mkdir(format!("{root}/child"), Mode::RWXU).expect("create child directory");

    let mut storage: [MaybeUninit<u8>; 0] = [];
    let mut stream = Dir::open(&root, &mut storage).expect("open owned directory stream");
    let mut names = Vec::new();
    while let Some(entry) = stream.next() {
        let entry = entry.expect("libSystem directory record");
        names.push((entry.name_bytes().to_vec(), entry.file_type()));
    }
    names.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        names,
        [
            (b".".to_vec(), fs::FileType::Directory),
            (b"..".to_vec(), fs::FileType::Directory),
            (b"child".to_vec(), fs::FileType::Directory),
        ]
    );
    drop(stream);

    let file = fs::open(
        format!("{root}/child/file"),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create non-directory fixture");
    let mut stream = Dir::from_owned_fd(file, &mut storage);
    assert_eq!(
        stream.next().expect("adopting a non-directory reports an error").unwrap_err(),
        Errno::NOTDIR
    );
    assert!(stream.next().is_none(), "a failed stream must not silently continue");
    drop(stream);

    fs::unlink(format!("{root}/child/file")).expect("remove non-directory fixture");
    fs::rmdir(format!("{root}/child")).expect("remove child directory");
    fs::rmdir(&root).expect("remove directory fixture");
}
