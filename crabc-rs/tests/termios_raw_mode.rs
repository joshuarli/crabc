use crabc_rs::{io, pty, termios, BorrowedFd};

fn pair() -> pty::PtyPair {
    pty::PtyPair::open(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)
        .expect("open PTY pair")
}

fn read_exactly(fd: BorrowedFd<'_>, length: usize) -> Vec<u8> {
    let mut received = Vec::new();
    while received.len() < length {
        let mut chunk = [0_u8; 64];
        let wanted = (length - received.len()).min(chunk.len());
        let count = io::read(fd, &mut chunk[..wanted]).expect("read from PTY");
        assert!(count > 0, "PTY reported end of file after {received:?}");
        received.extend_from_slice(&chunk[..count]);
    }
    received
}

#[test]
fn cooked_and_raw_modes_shape_pty_data_in_both_directions() {
    let pair = pair();
    let original = termios::tcgetattr(pair.slave()).expect("read PTY attributes");

    assert_eq!(io::write(pair.slave(), b"x\n").expect("write cooked output"), 2);
    assert_eq!(read_exactly(pair.master(), 3), b"x\r\n", "cooked output maps NL to CR NL");

    let mut raw = original.clone();
    raw.make_raw();
    termios::tcsetattr(pair.slave(), termios::OptionalActions::Now, &raw)
        .expect("apply raw mode");

    assert_eq!(io::write(pair.master(), b"a\rb\x03").expect("write raw input"), 4);
    assert_eq!(
        read_exactly(pair.slave(), 4),
        b"a\rb\x03",
        "raw input keeps CR and the interrupt byte and needs no newline",
    );

    assert_eq!(io::write(pair.slave(), b"y\n").expect("write raw output"), 2);
    assert_eq!(
        read_exactly(pair.master(), 2),
        b"y\n",
        "raw output is not echoed input and keeps NL unexpanded",
    );

    termios::tcsetattr(pair.slave(), termios::OptionalActions::Now, &original)
        .expect("restore PTY attributes");
    assert_eq!(io::write(pair.slave(), b"z\n").expect("write restored output"), 2);
    assert_eq!(read_exactly(pair.master(), 3), b"z\r\n", "restored mode cooks output again");
}
