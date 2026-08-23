use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::path::Arg;
use crabc_rs::{Errno, Result};

const PATH: &[u8] = b"/tmp/crabc-rs-native-truncate";

fn remove_if_present() {
    match fs::unlink(PATH) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale truncate fixture: {error}"),
    }
}

#[test]
fn truncate_changes_the_named_file_and_rejects_unrepresentable_lengths() {
    remove_if_present();
    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create disposable truncate fixture");
    io::write(&file, b"truncate").expect("write disposable truncate fixture");

    fs::truncate(PATH, 3).expect("truncate through the pathname syscall");
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("read size after truncate"),
        3,
    );

    assert_eq!(
        fs::truncate(PATH, i64::MAX as u64 + 1),
        Err(Errno::INVAL),
        "the unsigned API must reject values outside Linux loff_t",
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("read size after rejected truncate"),
        3,
        "an invalid length must not mutate the file",
    );

    drop(file);
    fs::unlink(PATH).expect("remove disposable truncate fixture");
}

struct CallbackMustNotRun;

impl Arg for CallbackMustNotRun {
    fn into_with_c_str<T, F>(self, _: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&core::ffi::CStr) -> Result<T>,
    {
        panic!("pathname conversion must not run for an invalid length");
    }
}

#[test]
fn truncate_validates_length_before_crossing_the_path_boundary() {
    assert_eq!(
        fs::truncate(CallbackMustNotRun, i64::MAX as u64 + 1),
        Err(Errno::INVAL),
    );
}
