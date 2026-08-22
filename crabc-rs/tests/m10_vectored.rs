use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::{io, pipe};

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn scratch_path(prefix: &str) -> String {
    format!(
        "/tmp/crabc-rs-m10-vectored-{}-{}-{}",
        prefix,
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

#[test]
fn vectored_pipe_io_preserves_order_and_reports_short_reads() {
    let (reader, writer) = pipe::pipe().expect("create vectored-I/O pipe");

    let no_writes: [io::IoSlice<'static>; 0] = [];
    assert_eq!(io::writev(&writer, &no_writes).expect("empty writev"), 0);

    let writes = [
        io::IoSlice::new(b""),
        io::IoSlice::new(b"abc"),
        io::IoSlice::new(b"defgh"),
        io::IoSlice::new(b""),
    ];
    assert_eq!(io::writev(&writer, &writes).expect("writev pipe payload"), 8);

    let mut no_reads: [io::IoSliceMut<'static>; 0] = [];
    assert_eq!(io::readv(&reader, &mut no_reads).expect("empty readv"), 0);

    let mut first = [0xcc; 4];
    let mut second = [0xdd; 6];
    let read = {
        let mut leading_empty = [];
        let mut trailing_empty = [];
        let mut reads = [
            io::IoSliceMut::new(&mut leading_empty),
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
            io::IoSliceMut::new(&mut trailing_empty),
        ];
        io::readv(&reader, &mut reads).expect("readv pipe payload")
    };

    assert_eq!(read, 8);
    assert_eq!(&first, b"abcd");
    assert_eq!(&second[..4], b"efgh");
    assert_eq!(&second[4..], &[0xdd; 2]);
}

#[test]
fn vectored_slice_helpers_allow_zero_advance_without_touching_empty_pointers() {
    let mut immutable = io::IoSlice::new(b"payload");
    immutable.advance(0);
    assert_eq!(immutable.as_slice(), b"payload");

    let mut empty = [];
    let mut mutable = io::IoSliceMut::new(&mut empty);
    mutable.advance(0);
    assert!(mutable.as_slice().is_empty());
}

#[test]
fn vectored_file_io_uses_each_segment_and_updates_file_position() {
    let path = scratch_path("file");
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create vectored-I/O file");

    let writes = [io::IoSlice::new(b"head"), io::IoSlice::new(b"-tail")];
    assert_eq!(io::writev(&file, &writes).expect("writev file payload"), 9);
    assert_eq!(fs::tell(&file).expect("position after writev"), 9);

    fs::seek(&file, SeekFrom::Start(0)).expect("rewind vectored-I/O file");
    let mut first = [0_u8; 4];
    let mut second = [0_u8; 5];
    let read = {
        let mut reads = [io::IoSliceMut::new(&mut first), io::IoSliceMut::new(&mut second)];
        io::readv(&file, &mut reads).expect("readv file payload")
    };

    assert_eq!(read, 9);
    assert_eq!(&first, b"head");
    assert_eq!(&second, b"-tail");
    assert_eq!(fs::tell(&file).expect("position after readv"), 9);

    drop(file);
    fs::unlink(&path).expect("remove vectored-I/O file");
}
