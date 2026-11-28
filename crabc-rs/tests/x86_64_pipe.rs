
use crabc_rs::{io, pipe, Errno};

#[cfg(target_os = "linux")]
#[test]
fn x86_64_direct_pipe_uses_the_native_packet_mode_flag() {
    // Linux/x86-64's `O_DIRECT` is 0x4000. 0x10000 is the AArch64 value and
    // would be an unrelated x86 open flag rather than a packet-mode request.
    #[cfg(target_arch = "x86_64")]
    assert_eq!(pipe::PipeFlags::DIRECT.bits(), 0x0000_4000);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(pipe::PipeFlags::DIRECT.bits(), 0x0001_0000);

    let flags = pipe::PipeFlags::DIRECT | pipe::PipeFlags::NONBLOCK | pipe::PipeFlags::CLOEXEC;
    let (reader, writer) = pipe::pipe_with(flags).expect("create x86-64 packet-mode pipe");

    for descriptor in [&reader, &writer] {
        assert!(
            io::fcntl_getfd(descriptor)
                .expect("read pipe descriptor flags")
                .contains(io::FdFlags::CLOEXEC),
            "pipe2 must set close-on-exec on both descriptors",
        );
    }

    assert_eq!(
        io::write(&writer, b"packet").expect("write one packet-mode record"),
        6
    );

    let mut prefix = [0_u8; 3];
    assert_eq!(
        io::read(&reader, &mut prefix).expect("read packet prefix"),
        prefix.len()
    );
    assert_eq!(prefix, *b"pac");

    // Packet-mode pipes discard a record's unread tail when the read buffer
    // is too short. Nonblocking mode turns the following empty-pipe read into
    // a deterministic observation instead of a block.
    let mut remainder = [0_u8; 1];
    assert_eq!(io::read(&reader, &mut remainder), Err(Errno::AGAIN));
}

// Darwin has no packet-mode pipes; `pipe2` applies only the descriptor and
// status flags, and the pipe keeps ordinary byte-stream semantics.
#[cfg(target_os = "macos")]
#[test]
fn darwin_pipe2_sets_flags_atomically_and_keeps_stream_semantics() {
    let (reader, writer) = pipe::pipe().expect("create default pipe");
    for descriptor in [&reader, &writer] {
        assert!(!io::fcntl_getfd(descriptor)
            .expect("read default pipe descriptor flags")
            .contains(io::FdFlags::CLOEXEC));
    }
    drop((reader, writer));

    let flags = pipe::PipeFlags::NONBLOCK | pipe::PipeFlags::CLOEXEC;
    let (reader, writer) = pipe::pipe_with(flags).expect("create flagged pipe");
    for descriptor in [&reader, &writer] {
        assert!(
            io::fcntl_getfd(descriptor)
                .expect("read pipe descriptor flags")
                .contains(io::FdFlags::CLOEXEC),
            "pipe2 must set close-on-exec on both descriptors",
        );
        assert!(crabc_rs::fs::fcntl_getfl(descriptor)
            .expect("read pipe status flags")
            .contains(crabc_rs::fs::OFlags::NONBLOCK));
    }

    assert_eq!(io::write(&writer, b"stream").expect("write stream bytes"), 6);
    let mut prefix = [0_u8; 3];
    assert_eq!(io::read(&reader, &mut prefix).expect("read stream prefix"), 3);
    assert_eq!(prefix, *b"str");
    let mut rest = [0_u8; 8];
    assert_eq!(io::read(&reader, &mut rest).expect("read stream tail"), 3);
    assert_eq!(&rest[..3], b"eam");
    assert_eq!(io::read(&reader, &mut rest), Err(Errno::AGAIN));

    drop(writer);
    assert_eq!(io::read(&reader, &mut rest).expect("read end of stream"), 0);

    assert_eq!(
        pipe::pipe_with(pipe::PipeFlags::from_bits_retain(0x0001_0000)).unwrap_err(),
        Errno::INVAL,
        "pipe2 rejects flags outside its vocabulary",
    );
}
