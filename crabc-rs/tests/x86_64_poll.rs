#![cfg(target_arch = "x86_64")]

use crabc_rs::{event, io, pipe, time::Timespec, Errno};

#[test]
fn x86_64_poll_observes_pipe_readiness_and_preserves_requested_events() {
    let (reader, writer) = pipe::pipe().expect("create poll fixture pipe");
    let mut fds = [event::PollFd::new(&reader, event::PollFlags::IN)];
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };

    assert_eq!(event::poll(&mut fds, Some(&zero)), Ok(0));
    assert!(fds[0].revents().is_empty());

    io::write(&writer, b"x").expect("seed readable pipe");
    assert_eq!(event::poll(&mut fds, Some(&zero)), Ok(1));
    assert!(fds[0].revents().contains(event::PollFlags::IN));

    let mut byte = [0_u8; 1];
    assert_eq!(io::read(&reader, &mut byte), Ok(1));
    drop(writer);
    fds[0].clear_revents();
    assert_eq!(event::poll(&mut fds, Some(&zero)), Ok(1));
    assert!(fds[0].revents().contains(event::PollFlags::HUP));
}

#[test]
fn x86_64_poll_rejects_timeout_that_cannot_fit_linux_milliseconds() {
    let (_, writer) = pipe::pipe().expect("create timeout fixture pipe");
    let mut fds = [event::PollFd::new(&writer, event::PollFlags::OUT)];
    let too_large = Timespec { tv_sec: i64::from(i32::MAX), tv_nsec: 0 };
    assert_eq!(
        event::poll(&mut fds, Some(&too_large)),
        Err(Errno::INVAL)
    );

    let invalid_nanoseconds = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
    assert_eq!(
        event::poll(&mut fds, Some(&invalid_nanoseconds)),
        Err(Errno::INVAL)
    );
}

#[test]
fn x86_64_poll_flags_match_musl_x86_values() {
    assert_eq!(event::PollFlags::IN.bits(), 0x0001);
    assert_eq!(event::PollFlags::PRI.bits(), 0x0002);
    assert_eq!(event::PollFlags::OUT.bits(), 0x0004);
    assert_eq!(event::PollFlags::ERR.bits(), 0x0008);
    assert_eq!(event::PollFlags::HUP.bits(), 0x0010);
    assert_eq!(event::PollFlags::NVAL.bits(), 0x0020);
    assert_eq!(event::PollFlags::RDHUP.bits(), 0x2000);
}
