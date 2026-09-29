#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;

use crabc_rs::{io, pipe, AsFd, Errno, OwnedFd};

#[test]
fn x86_64_dup2_validates_equal_invalid_descriptors() {
    assert_eq!(
        crabc_core::io::dup2(-1, -1)
            .expect_err("dup2 must validate an equal invalid descriptor")
            .raw(),
        Errno::BADF.raw(),
    );

    let source = anonymous_regular_file();
    let mut target = anonymous_regular_file();
    assert_eq!(io::write(&source, b"dup2").expect("seed source"), 4);
    crabc_core::io::dup2(source.as_raw_fd(), source.as_raw_fd())
        .expect("equal open descriptor remains valid");
    io::dup2(&source, &mut target).expect("replace target descriptor");
    let mut bytes = [0; 4];
    assert_eq!(io::pread(&target, &mut bytes[..], 0).expect("read replacement"), 4);
    assert_eq!(&bytes, b"dup2");
}

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

#[test]
fn x86_64_scalar_reads_expose_only_the_received_prefix_on_short_read_and_eof() {
    use core::mem::MaybeUninit;

    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::NONBLOCK).expect("nonblocking pipe");
    let mut guarded = [MaybeUninit::new(0xcc); 8];
    assert_eq!(io::read(&reader, &mut guarded).expect_err("empty live pipe"), Errno::AGAIN);
    // SAFETY: Every element was initialized before the failed read.
    assert!(guarded.iter().all(|byte| unsafe { byte.assume_init() } == 0xcc));

    assert_eq!(io::write(&writer, b"abc"), Ok(3));
    let mut storage = [MaybeUninit::<u8>::uninit(); 8];
    let (received, remaining) = io::read(reader.as_fd(), &mut storage).expect("short scalar read");
    assert_eq!(received, b"abc");
    assert_eq!(remaining.len(), 5);
    let (received, remaining) = io::read(&reader, &mut guarded[..0]).expect("empty scalar read");
    assert!(received.is_empty());
    assert!(remaining.is_empty());
    drop(writer);
    let (received, remaining) = io::read(&reader, &mut storage).expect("pipe EOF");
    assert!(received.is_empty());
    assert_eq!(remaining.len(), 8);
    io::fcntl_getfd(&reader).expect("borrowing I/O retains the descriptor owner");
}

#[test]
fn x86_64_nonblocking_writes_return_one_partial_transfer_and_preserve_vector_order() {
    for vectored in [false, true] {
        let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::NONBLOCK).expect("nonblocking pipe");
        let capacity = pipe::fcntl_getpipe_size(&writer).expect("query pipe capacity");
        let split = capacity / 2 + 1;
        let mut payload = vec![b'a'; capacity + pipe::PIPE_BUF];
        payload[split..].fill(b'b');
        let count = if vectored {
            io::writev(&writer, &[io::IoSlice::new(&payload[..split]), io::IoSlice::new(&payload[split..])])
        } else {
            io::write(&writer, &payload)
        }.expect("one nonblocking partial write");
        assert_eq!(count, capacity);
        assert_eq!(io::write(&writer, b"x"), Err(Errno::AGAIN));
        assert_eq!(io::writev(&writer, &[io::IoSlice::new(b"x")]), Err(Errno::AGAIN));
        let mut received = vec![0; payload.len()];
        assert_eq!(io::read(&reader, &mut received[..]), Ok(count));
        assert_eq!(&received[..count], &payload[..count]);
        assert!(received[count..].iter().all(|byte| *byte == 0));
    }
}

#[test]
fn x86_64_readv_short_count_crosses_segments_and_errors_leave_destinations_unchanged() {
    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::NONBLOCK).expect("nonblocking pipe");
    let mut first = [0xcc; 2];
    let mut second = [0xdd; 4];
    {
        let mut vectors = [io::IoSliceMut::new(&mut first), io::IoSliceMut::new(&mut second)];
        assert_eq!(io::readv(&reader, &mut vectors), Err(Errno::AGAIN));
    }
    assert_eq!(first, [0xcc; 2]);
    assert_eq!(second, [0xdd; 4]);
    assert_eq!(io::write(&writer, b"abcde"), Ok(5));
    {
        let mut vectors = [io::IoSliceMut::new(&mut first), io::IoSliceMut::new(&mut second)];
        assert_eq!(io::readv(&reader, &mut vectors), Ok(5));
        vectors[1].advance(3);
        assert_eq!(vectors[1].as_slice(), &[0xdd]);
    }
    assert_eq!(first, *b"ab");
    assert_eq!(second, [b'c', b'd', b'e', 0xdd]);
    drop(writer);
    let mut vectors = [io::IoSliceMut::new(&mut first), io::IoSliceMut::new(&mut second)];
    assert_eq!(io::readv(&reader, &mut vectors), Ok(0));
    assert_eq!(vectors[0].as_slice(), b"ab");
    assert_eq!(vectors[1].as_slice(), &[b'c', b'd', b'e', 0xdd]);
}

#[test]
fn x86_64_iov_max_and_empty_vectors_follow_kernel_validation() {
    let file = anonymous_regular_file();
    for count in [0, 1024, 1025] {
        let writes = vec![io::IoSlice::new(b""); count];
        let mut storage = vec![[0_u8; 0]; count];
        let mut reads: Vec<_> = storage.iter_mut().map(|bytes| io::IoSliceMut::new(bytes)).collect();
        let expected = if count <= 1024 { Ok(0) } else { Err(Errno::INVAL) };
        assert_eq!(io::writev(&file, &writes), expected);
        assert_eq!(io::readv(&file, &mut reads), expected);
        assert_eq!(io::pwritev(&file, &writes, 0), expected);
        assert_eq!(io::preadv(&file, &mut reads, 0), expected);
    }
    assert_eq!(file_offset(&file), 0);
}

#[test]
fn x86_64_scalar_positioned_offsets_reject_negative_signed_values_without_initialization() {
    use core::mem::MaybeUninit;

    let file = anonymous_regular_file();
    assert_eq!(io::write(&file, b"abc"), Ok(3));
    let duplicate = io::dup(file.as_fd()).expect("duplicate shares the file position");
    for offset in [i64::MAX as u64 + 1, u64::MAX] {
        let mut storage = [MaybeUninit::new(0xcc); 2];
        assert_eq!(io::pread(&file, &mut storage, offset).expect_err("negative signed offset"), Errno::INVAL);
        // SAFETY: All elements were initialized before the rejected operation.
        assert!(storage.iter().all(|byte| unsafe { byte.assume_init() } == 0xcc));
        assert_eq!(io::pwrite(&file, b"x", offset), Err(Errno::INVAL));
        assert_eq!(io::pwrite(&file, b"", offset), Err(Errno::INVAL));
        assert_eq!(file_offset(&duplicate), 3);
    }
    let mut storage = [MaybeUninit::<u8>::uninit(); 6];
    let (received, remaining) = io::pread(&file, &mut storage, 1).expect("positioned partial prefix");
    assert_eq!(received, b"bc");
    assert_eq!(remaining.len(), 4);
    assert_eq!(file_offset(&duplicate), 3);
    assert_eq!(io::pread(&file, &mut storage, i64::MAX as u64).expect_err("offset plus count exceeds signed range"), Errno::INVAL);
    let (received, remaining) = io::pread(&file, &mut storage[..0], i64::MAX as u64).expect("empty read at signed maximum");
    assert!(received.is_empty());
    assert!(remaining.is_empty());
    assert_eq!(io::pwrite(&file, b"", i64::MAX as u64), Ok(0));
    const HIGH_OFFSET: u64 = (1_u64 << 32) + 7;
    assert_eq!(io::pwrite(&file, b"hi", HIGH_OFFSET), Ok(2));
    let (received, remaining) = io::pread(&file, &mut storage, HIGH_OFFSET).expect("high scalar offset");
    assert_eq!(received, b"hi");
    assert_eq!(remaining.len(), 4);
    let mut low_word = [0xcc; 2];
    assert_eq!(io::pread(&file, &mut low_word, 7), Ok(2));
    assert_eq!(low_word, [0; 2], "high scalar offset must not alias the low word");
    assert_eq!(file_offset(&duplicate), 3);
}

#[test]
fn x86_64_consuming_io_closes_its_owned_argument_after_the_single_transfer() {
    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::NONBLOCK).expect("nonblocking pipe");
    let raw = writer.as_raw_fd();
    assert_eq!(io::write(writer, b"owner"), Ok(5));
    assert_eq!(crabc_core::io::fcntl_getfd(raw), Err(Errno::BADF));
    let mut bytes = [0; 8];
    assert_eq!(io::read(reader.as_fd(), &mut bytes), Ok(5));
    assert_eq!(&bytes[..5], b"owner");
    assert_eq!(io::read(&reader, &mut bytes), Ok(0));
}

static IO_SIGNAL_SEEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

unsafe extern "C" fn io_signal_handler(_: crabc_rs::signal::Signal) {
    IO_SIGNAL_SEEN.store(true, core::sync::atomic::Ordering::Relaxed);
}

struct RestoreIoSignal {
    action: crabc_rs::signal::SigAction,
    mask: u64,
}

impl Drop for RestoreIoSignal {
    fn drop(&mut self) {
        // SAFETY: The guard restores the live thread's original kernel mask
        // and the disposition copied before installing the static handler.
        unsafe {
            crabc_core::signal::rt_sigprocmask_raw(2, &self.mask, core::ptr::null_mut())
                .expect("restore I/O test signal mask");
            crabc_rs::signal::sigaction(crabc_rs::signal::Signal::USR1, Some(&self.action))
                .expect("restore I/O test signal action");
        }
    }
}

#[test]
fn x86_64_read_and_readv_expose_eintr_without_retry_or_initializing_storage() {
    use core::mem::MaybeUninit;
    use core::sync::atomic::Ordering;
    use crabc_rs::signal::{self, SigAction, SigActionFlags, SigHandler, Signal};

    let action = SigAction::new(SigHandler::Simple(io_signal_handler), SigActionFlags::empty());
    let mut original_mask = 0_u64;
    // SAFETY: The static handler only stores a lock-free atomic flag. It
    // remains installed through both blocking calls and their helper joins.
    let original_action = unsafe { signal::sigaction(Signal::USR1, Some(&action)) }
        .expect("install non-restarting handler");
    // SAFETY: Query and replace this thread's one-word Linux kernel mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(2, core::ptr::null(), &mut original_mask)
            .expect("query I/O test mask");
    }
    let _restore = RestoreIoSignal { action: original_action, mask: original_mask };
    let unblocked = original_mask & !(1 << (Signal::USR1.as_raw() - 1));
    // SAFETY: `unblocked` is a complete initialized kernel mask word.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(2, &unblocked, core::ptr::null_mut())
            .expect("unblock targeted test signal");
    }
    let pid = crabc_rs::process::getpid().as_raw_pid();
    let tid = crabc_rs::thread::gettid().as_raw_pid();
    for vectored in [false, true] {
        let (reader, writer) = pipe::pipe().expect("blocking interruption pipe");
        let descriptor = reader.as_raw_fd();
        let expected_syscall = if vectored { 19 } else { 0 };
        IO_SIGNAL_SEEN.store(false, Ordering::Relaxed);
        let returned = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let observer_returned = returned.clone();
        let sender = std::thread::spawn(move || {
            let path = format!("/proc/self/task/{tid}/syscall");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                let record = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
                let mut fields = record.split_whitespace();
                let number = fields.next().and_then(|word| word.parse::<i32>().ok());
                let fd = fields.next().and_then(|word| i32::from_str_radix(word.trim_start_matches("0x"), 16).ok());
                if number == Some(expected_syscall) && fd == Some(descriptor) {
                    let result: isize;
                    // SAFETY: Linux/x86-64 tgkill=234 targets the still-live
                    // blocked test thread; no user pointers cross this syscall.
                    unsafe {
                        core::arch::asm!("syscall", inlateout("rax") 234_isize => result,
                            in("rdi") pid, in("rsi") tid, in("rdx") Signal::USR1.as_raw(),
                            lateout("rcx") _, lateout("r11") _, options(nostack));
                    }
                    if result != 0 {
                        return Err(format!("targeted signal syscall returned {result}"));
                    }
                    // Keep EOF from racing the signal, but release the writer
                    // if an unexpected hidden retry keeps the call blocked.
                    while !observer_returned.load(Ordering::Acquire) {
                        if std::time::Instant::now() >= deadline {
                            return Err("I/O did not return after the targeted signal".to_owned());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    return Ok(writer);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // Failure drops the final writer and unblocks the test as EOF;
            // the join then reports an invalid setup rather than an I/O pass.
            Err("blocking read was not observed before the setup deadline".to_owned())
        });
        let mut storage = [MaybeUninit::new(0xcc); 4];
        let mut initialized = [0xdd; 4];
        let result = if vectored {
            io::readv(&reader, &mut [io::IoSliceMut::new(&mut initialized)])
        } else {
            io::read(&reader, &mut storage).map(|(prefix, _)| prefix.len())
        };
        returned.store(true, Ordering::Release);
        let writer = sender.join().expect("signal observer thread").expect("observed blocked I/O");
        assert_eq!(result, Err(Errno::INTR));
        assert!(IO_SIGNAL_SEEN.load(Ordering::Relaxed));
        // SAFETY: Every element was initialized before the interrupted read.
        assert!(storage.iter().all(|byte| unsafe { byte.assume_init() } == 0xcc));
        assert_eq!(initialized, [0xdd; 4]);
        assert_eq!(io::write(&writer, b"x"), Ok(1));
        assert_eq!(io::read(&reader, &mut initialized), Ok(1));
        assert_eq!(initialized[0], b'x');
    }
}

#[cfg(feature = "alloc")]
#[test]
fn x86_64_spare_capacity_commits_only_successful_received_bytes() {
    use crabc_rs::buffer;

    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::NONBLOCK).expect("nonblocking pipe");
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(b"head");
    let capacity = bytes.capacity();
    assert_eq!(io::read(&reader, buffer::spare_capacity(&mut bytes)), Err(Errno::AGAIN));
    assert_eq!(&bytes, b"head");
    assert_eq!(bytes.capacity(), capacity);
    assert_eq!(io::write(&writer, b"xy"), Ok(2));
    assert_eq!(io::read(&reader, buffer::spare_capacity(&mut bytes)), Ok(2));
    assert_eq!(&bytes, b"headxy");
    assert_eq!(bytes.capacity(), capacity);
    drop(writer);
    assert_eq!(io::read(&reader, buffer::spare_capacity(&mut bytes)), Ok(0));
    assert_eq!(&bytes, b"headxy");
    assert_eq!(bytes.capacity(), capacity);
}

#[test]
fn x86_64_descriptor_io_composes_with_socketpair_borrows_and_peer_eof() {
    use core::mem::MaybeUninit;
    use crabc_rs::net::{self, AddressFamily, SocketFlags, SocketType};

    let (first, second) = net::socketpair(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::NONBLOCK, None)
        .expect("nonblocking local stream socketpair");
    assert_eq!(io::writev(first.as_fd(), &[io::IoSlice::new(b"ab"), io::IoSlice::new(b"cde")]), Ok(5));
    let mut bytes = [MaybeUninit::<u8>::uninit(); 8];
    let (received, remaining) = io::read(second.as_fd(), &mut bytes).expect("short socket read");
    assert_eq!(received, b"abcde");
    assert_eq!(remaining.len(), 3);
    assert_eq!(io::read(&second, &mut bytes).expect_err("live empty socket"), Errno::AGAIN);
    drop(first);
    let (received, remaining) = io::read(&second, &mut bytes).expect("peer EOF");
    assert!(received.is_empty());
    assert_eq!(remaining.len(), 8);
    io::fcntl_getfd(&second).expect("socket descriptor remains owned after borrowed reads");
}
