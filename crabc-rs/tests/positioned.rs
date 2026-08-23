use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn scratch_path(prefix: &str) -> String {
    format!(
        "/tmp/crabc-rs-native-{}-{}-{}",
        prefix,
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

#[test]
fn positioned_reads_and_writes_do_not_change_file_position() {
    let path = scratch_path("positioned");
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create positioned-I/O fixture");

    assert_eq!(io::write(&file, b"abcdef").expect("write fixture"), 6);
    assert_eq!(fs::seek(&file, SeekFrom::Start(2)).expect("set descriptor position"), 2);

    assert_eq!(io::pwrite(&file, b"XY", 4).expect("positioned write"), 2);
    assert_eq!(
        fs::tell(&file).expect("position after positioned write"),
        2,
        "pwrite must not update the shared descriptor offset"
    );

    let mut positioned = [0_u8; 2];
    assert_eq!(
        io::pread(&file, &mut positioned, 4).expect("positioned read"),
        2
    );
    assert_eq!(&positioned, b"XY");
    assert_eq!(
        fs::tell(&file).expect("position after positioned read"),
        2,
        "pread must not update the shared descriptor offset"
    );

    fs::seek(&file, SeekFrom::Start(0)).expect("rewind fixture");
    let mut whole = [0_u8; 6];
    assert_eq!(io::read(&file, &mut whole).expect("read final fixture"), 6);
    assert_eq!(&whole, b"abcdXY");

    drop(file);
    fs::unlink(&path).expect("remove positioned-I/O fixture");
}

#[test]
fn positioned_read_supports_uninitialized_storage() {
    let path = scratch_path("positioned-uninit");
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create uninitialized positioned-I/O fixture");
    io::write(&file, b"kernel-buffer").expect("write uninitialized fixture");

    let mut buffer = [core::mem::MaybeUninit::<u8>::uninit(); 6];
    let (initialized, remaining) = io::pread(&file, &mut buffer, 6).expect("pread into spare storage");
    assert_eq!(initialized, b"-buffe" as &[u8]);
    assert!(remaining.is_empty());

    drop(file);
    fs::unlink(&path).expect("remove uninitialized positioned-I/O fixture");
}
