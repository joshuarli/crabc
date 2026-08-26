#![cfg(target_arch = "x86_64")]

use crabc_rs::{io, pipe, Errno};

#[test]
fn x86_64_direct_pipe_uses_the_native_packet_mode_flag() {
    // Linux/x86-64's `O_DIRECT` is 0x4000. 0x10000 is the AArch64 value and
    // would be an unrelated x86 open flag rather than a packet-mode request.
    assert_eq!(pipe::PipeFlags::DIRECT.bits(), 0x0000_4000);

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
