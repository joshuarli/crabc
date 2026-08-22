use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn scratch_path() -> String {
    format!(
        "/tmp/crabc-rs-m10-positioned-vectored-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

#[test]
fn positioned_vectored_io_preserves_file_position_and_segment_order() {
    let path = scratch_path();
    let _ = fs::unlink(&path);
    let file = fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create positioned-vectored fixture");

    assert_eq!(io::write(&file, b"0123456789").expect("write fixture"), 10);
    fs::seek(&file, SeekFrom::Start(2)).expect("set shared file position");

    let no_writes: [io::IoSlice<'static>; 0] = [];
    assert_eq!(
        io::pwritev(&file, &no_writes, 4).expect("empty positional writev"),
        0
    );
    assert_eq!(fs::tell(&file).expect("position after empty pwritev"), 2);

    let writes = [
        io::IoSlice::new(b""),
        io::IoSlice::new(b"ab"),
        io::IoSlice::new(b"CD"),
        io::IoSlice::new(b""),
    ];
    assert_eq!(
        io::pwritev(&file, &writes, 4).expect("positional writev"),
        4
    );
    assert_eq!(
        fs::tell(&file).expect("position after positional writev"),
        2,
        "pwritev must not update the descriptor offset"
    );

    let mut first = [0xcc; 2];
    let mut second = [0xdd; 2];
    let read = {
        let mut leading_empty = [];
        let mut trailing_empty = [];
        let mut reads = [
            io::IoSliceMut::new(&mut leading_empty),
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
            io::IoSliceMut::new(&mut trailing_empty),
        ];
        io::preadv(&file, &mut reads, 4).expect("positional readv")
    };
    assert_eq!(read, 4);
    assert_eq!(&first, b"ab");
    assert_eq!(&second, b"CD");
    assert_eq!(
        fs::tell(&file).expect("position after positional readv"),
        2,
        "preadv must not update the descriptor offset"
    );

    // A positional read shorter than the destination vectors only initializes
    // the bytes returned by Linux; the remaining initialized bytes are kept.
    let mut partial_first = [0xee; 3];
    let mut partial_second = [0xef; 3];
    let partial = {
        let mut reads = [
            io::IoSliceMut::new(&mut partial_first),
            io::IoSliceMut::new(&mut partial_second),
        ];
        io::preadv(&file, &mut reads, 8).expect("short positional readv")
    };
    assert_eq!(partial, 2);
    assert_eq!(&partial_first[..2], b"89");
    assert_eq!(partial_first[2], 0xee);
    assert_eq!(&partial_second, &[0xef; 3]);
    assert_eq!(fs::tell(&file).expect("position after short preadv"), 2);

    // Linux/AArch64 passes the positioned-vector offset as distinct low and
    // high 32-bit syscall arguments. A sparse write above 4 GiB exercises the
    // high word without allocating the intervening hole and proves that the
    // native wrapper does not truncate a valid `u64` offset to 32 bits.
    let high_offset = (1_u64 << 32) + 7;
    let high_writes = [io::IoSlice::new(b"hi"), io::IoSlice::new(b"GH")];
    assert_eq!(
        io::pwritev(&file, &high_writes, high_offset).expect("high-offset pwritev"),
        4
    );
    let mut high_first = [0_u8; 2];
    let mut high_second = [0_u8; 2];
    let high_read = {
        let mut reads = [
            io::IoSliceMut::new(&mut high_first),
            io::IoSliceMut::new(&mut high_second),
        ];
        io::preadv(&file, &mut reads, high_offset).expect("high-offset preadv")
    };
    assert_eq!(high_read, 4);
    assert_eq!(&high_first, b"hi");
    assert_eq!(&high_second, b"GH");
    assert_eq!(
        fs::tell(&file).expect("position after high-offset positioned I/O"),
        2,
        "high-word positioned I/O must not update the descriptor offset"
    );

    let mut no_reads: [io::IoSliceMut<'static>; 0] = [];
    assert_eq!(
        io::preadv(&file, &mut no_reads, 4).expect("empty positional readv"),
        0
    );
    assert_eq!(fs::tell(&file).expect("position after empty preadv"), 2);

    let mut invalid_read = [0_u8; 1];
    let invalid_read_error = {
        let mut reads = [io::IoSliceMut::new(&mut invalid_read)];
        io::preadv(&file, &mut reads, u64::MAX).expect_err("negative off_t must be rejected")
    };
    assert_eq!(invalid_read_error.raw(), 22, "EINVAL");

    let invalid_write_error = io::pwritev(
        &file,
        &[io::IoSlice::new(b"x")],
        u64::MAX,
    )
    .expect_err("negative off_t must be rejected");
    assert_eq!(invalid_write_error.raw(), 22, "EINVAL");
    assert_eq!(fs::tell(&file).expect("position after invalid positional I/O"), 2);

    drop(file);
    fs::unlink(&path).expect("remove positioned-vectored fixture");
}
