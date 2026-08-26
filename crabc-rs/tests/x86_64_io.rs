#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;

use crabc_rs::{io, pipe, Errno, OwnedFd};

fn anonymous_regular_file() -> OwnedFd {
    let name = CStr::from_bytes_with_nul(b"crabc-rs-x86-64-io\0")
        .expect("fixed anonymous-file name is NUL-terminated");
    let raw = crabc_core::fs::memfd_create(name, 0).expect("create anonymous regular file");
    // SAFETY: `memfd_create` returned one newly-open descriptor and this
    // helper transfers its unique ownership into the facade owner.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn file_offset(file: &OwnedFd) -> u64 {
    let offset = crabc_core::fs::lseek(file.as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
        .expect("query anonymous file position");
    u64::try_from(offset).expect("Linux successful file positions are nonnegative")
}

#[test]
fn x86_64_readv_writev_preserve_segment_order_and_short_read_tails() {
    let (reader, writer) = pipe::pipe().expect("create vector-I/O pipe");

    let writes = [
        io::IoSlice::new(b""),
        io::IoSlice::new(b"ab"),
        io::IoSlice::new(b"CD"),
        io::IoSlice::new(b""),
    ];
    assert_eq!(io::writev(&writer, &writes).expect("write vector segments"), 4);

    let mut first = [0xcc; 2];
    let mut second = [0xdd; 2];
    let count = {
        let mut leading_empty = [];
        let mut trailing_empty = [];
        let mut reads = [
            io::IoSliceMut::new(&mut leading_empty),
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
            io::IoSliceMut::new(&mut trailing_empty),
        ];
        io::readv(&reader, &mut reads).expect("read vector segments")
    };
    assert_eq!(count, 4);
    assert_eq!(first, *b"ab");
    assert_eq!(second, *b"CD");

    assert_eq!(io::writev(&writer, &[io::IoSlice::new(b"89")]).expect("write short read"), 2);
    let mut partial_first = [0xee; 3];
    let mut partial_second = [0xef; 3];
    let partial = {
        let mut reads = [
            io::IoSliceMut::new(&mut partial_first),
            io::IoSliceMut::new(&mut partial_second),
        ];
        io::readv(&reader, &mut reads).expect("short vector read")
    };
    assert_eq!(partial, 2);
    assert_eq!(&partial_first[..2], b"89");
    assert_eq!(partial_first[2], 0xee);
    assert_eq!(partial_second, [0xef; 3]);

    let no_writes: [io::IoSlice<'static>; 0] = [];
    assert_eq!(io::writev(&writer, &no_writes).expect("empty writev"), 0);
}

#[test]
fn x86_64_vectored_positioned_io_preserves_segments_offsets_and_guards() {
    let file = anonymous_regular_file();
    assert_eq!(io::write(&file, b"0123456789").expect("seed anonymous file"), 10);
    assert_eq!(
        crabc_core::fs::lseek(file.as_raw_fd(), 2, crabc_core::fs::SEEK_SET)
            .expect("set shared file position"),
        2,
    );

    let no_writes: [io::IoSlice<'static>; 0] = [];
    assert_eq!(
        io::pwritev(&file, &no_writes, 4).expect("empty positioned writev"),
        0
    );
    assert_eq!(file_offset(&file), 2, "pwritev must not move the file position");

    let writes = [
        io::IoSlice::new(b""),
        io::IoSlice::new(b"ab"),
        io::IoSlice::new(b"CD"),
        io::IoSlice::new(b""),
    ];
    assert_eq!(
        io::pwritev(&file, &writes, 4).expect("positioned vector write"),
        4
    );
    assert_eq!(file_offset(&file), 2, "pwritev must not move the file position");

    let mut first = [0xcc; 2];
    let mut second = [0xdd; 2];
    let count = {
        let mut leading_empty = [];
        let mut trailing_empty = [];
        let mut reads = [
            io::IoSliceMut::new(&mut leading_empty),
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
            io::IoSliceMut::new(&mut trailing_empty),
        ];
        io::preadv(&file, &mut reads, 4).expect("positioned vector read")
    };
    assert_eq!(count, 4);
    assert_eq!(first, *b"ab");
    assert_eq!(second, *b"CD");
    assert_eq!(file_offset(&file), 2, "preadv must not move the file position");

    let mut partial_first = [0xee; 3];
    let mut partial_second = [0xef; 3];
    let partial = {
        let mut reads = [
            io::IoSliceMut::new(&mut partial_first),
            io::IoSliceMut::new(&mut partial_second),
        ];
        io::preadv(&file, &mut reads, 8).expect("short positioned vector read")
    };
    assert_eq!(partial, 2);
    assert_eq!(&partial_first[..2], b"89");
    assert_eq!(partial_first[2], 0xee);
    assert_eq!(partial_second, [0xef; 3]);

    // Linux/x86-64 passes preadv/pwritev's offset as low and high 32-bit
    // words. A sparse write above 4 GiB proves the safe facade does not
    // accidentally truncate its u64 offset to the low word.
    const HIGH_OFFSET: u64 = 0x0000_0001_0000_0007;
    let high_writes = [io::IoSlice::new(b"hi"), io::IoSlice::new(b"GH")];
    assert_eq!(
        io::pwritev(&file, &high_writes, HIGH_OFFSET).expect("high-offset vector write"),
        4
    );
    let mut high_first = [0_u8; 2];
    let mut high_second = [0_u8; 2];
    let high_count = {
        let mut reads = [
            io::IoSliceMut::new(&mut high_first),
            io::IoSliceMut::new(&mut high_second),
        ];
        io::preadv(&file, &mut reads, HIGH_OFFSET).expect("high-offset vector read")
    };
    assert_eq!(high_count, 4);
    assert_eq!(high_first, *b"hi");
    assert_eq!(high_second, *b"GH");

    let mut low_word = [0_u8; 1];
    let low_count = {
        let mut reads = [io::IoSliceMut::new(&mut low_word)];
        io::preadv(&file, &mut reads, 7).expect("low-offset vector read")
    };
    assert_eq!(low_count, 1);
    assert_eq!(low_word, *b"D", "high offset must not alias its low word");

    let mut invalid_read = [0_u8; 1];
    let invalid_read = {
        let mut reads = [io::IoSliceMut::new(&mut invalid_read)];
        io::preadv(&file, &mut reads, u64::MAX)
            .expect_err("preadv must reject an invalid signed file offset")
    };
    assert_eq!(invalid_read, Errno::INVAL);
    assert_eq!(
        io::pwritev(&file, &[io::IoSlice::new(b"x")], u64::MAX),
        Err(Errno::INVAL),
    );
    assert_eq!(file_offset(&file), 2, "failed positioned I/O must not move the file position");
}

#[test]
fn x86_64_preadv2_pwritev2_preserve_current_offset_sentinel_and_validate_flags() {
    let file = anonymous_regular_file();
    assert_eq!(io::write(&file, b"A").expect("seed anonymous file"), 1);

    // `RWF_APPEND` reaches x86-64's sixth syscall argument. Despite the
    // supplied zero offset, the byte must be appended after the initial one.
    assert_eq!(
        io::pwritev2(
            &file,
            &[io::IoSlice::new(b"B")],
            0,
            io::ReadWriteFlags::APPEND,
        )
        .expect("pwritev2 RWF_APPEND"),
        1,
    );
    let mut appended = [0_u8; 2];
    let appended_count = {
        let mut reads = [io::IoSliceMut::new(&mut appended)];
        io::preadv2(&file, &mut reads, 0, io::ReadWriteFlags::empty())
            .expect("preadv2 appended bytes")
    };
    assert_eq!(appended_count, 2);
    assert_eq!(appended, *b"AB");

    assert_eq!(
        crabc_core::fs::lseek(file.as_raw_fd(), 1, crabc_core::fs::SEEK_SET)
            .expect("set current file position"),
        1,
    );
    assert_eq!(
        io::pwritev2(
            &file,
            &[io::IoSlice::new(b"C")],
            u64::MAX,
            io::ReadWriteFlags::empty(),
        )
        .expect("pwritev2 current-offset sentinel"),
        1,
    );
    assert_eq!(file_offset(&file), 2, "the pwritev2 sentinel must advance the position");

    assert_eq!(
        crabc_core::fs::lseek(file.as_raw_fd(), 0, crabc_core::fs::SEEK_SET)
            .expect("rewind for preadv2 sentinel"),
        0,
    );
    let mut current = [0_u8; 1];
    let current_count = {
        let mut reads = [io::IoSliceMut::new(&mut current)];
        io::preadv2(&file, &mut reads, u64::MAX, io::ReadWriteFlags::empty())
            .expect("preadv2 current-offset sentinel")
    };
    assert_eq!(current_count, 1);
    assert_eq!(current, *b"A");
    assert_eq!(file_offset(&file), 1, "the preadv2 sentinel must advance the position");

    let unadmitted = io::ReadWriteFlags::from_bits_retain(0x8000_0000);
    assert_eq!(
        io::pwritev2(&file, &[io::IoSlice::new(b"X")], 0, unadmitted),
        Err(Errno::INVAL),
        "unknown RWF bits must be rejected before the direct syscall",
    );
    let mut unchanged = [0_u8; 2];
    let unchanged_count = {
        let mut reads = [io::IoSliceMut::new(&mut unchanged)];
        io::preadv(&file, &mut reads, 0).expect("read after rejected RWF bits")
    };
    assert_eq!(unchanged_count, 2);
    assert_eq!(unchanged, *b"AC");
}

#[test]
fn x86_64_duplication_and_fcntl_keep_descriptor_and_pipe_contracts() {
    let (source, writer) = pipe::pipe().expect("create source pipe");
    io::fcntl_setfd(&source, io::FdFlags::CLOEXEC).expect("set source close-on-exec");

    let duplicate = io::dup(&source).expect("duplicate source pipe descriptor");
    assert_eq!(
        io::fcntl_getfd(&duplicate).expect("read dup descriptor flags"),
        io::FdFlags::empty(),
        "dup must not copy FD_CLOEXEC",
    );

    let fcntl_duplicate = io::fcntl_dupfd(&source, duplicate.as_raw_fd() + 1)
        .expect("duplicate through F_DUPFD");
    assert!(fcntl_duplicate.as_raw_fd() > duplicate.as_raw_fd());
    let cloexec_duplicate = io::fcntl_dupfd_cloexec(&source, fcntl_duplicate.as_raw_fd() + 1)
        .expect("duplicate through F_DUPFD_CLOEXEC");
    assert!(
        io::fcntl_getfd(&cloexec_duplicate)
            .expect("read F_DUPFD_CLOEXEC descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
    );

    let (mut target, _target_writer) = pipe::pipe().expect("create replacement target pipe");
    io::fcntl_setfd(&target, io::FdFlags::CLOEXEC).expect("set target close-on-exec");
    io::dup2(&source, &mut target).expect("replace target through dup2");
    assert_eq!(
        io::fcntl_getfd(&target).expect("read dup2 descriptor flags"),
        io::FdFlags::empty(),
        "dup2 must clear the target descriptor's close-on-exec flag",
    );
    io::dup3(&source, &mut target, io::DupFlags::CLOEXEC).expect("replace target through dup3");
    assert!(
        io::fcntl_getfd(&target)
            .expect("read dup3 descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
    );

    assert_eq!(io::write(&writer, b"fd").expect("write source pipe"), 2);
    let mut observed = [0_u8; 2];
    assert_eq!(io::read(&target, &mut observed).expect("read duplicated pipe"), 2);
    assert_eq!(observed, *b"fd");
}
