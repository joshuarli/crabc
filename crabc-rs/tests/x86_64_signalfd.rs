#![cfg(target_arch = "x86_64")]

use core::mem::{size_of, MaybeUninit};
use crabc_rs::{event, io, pipe, signal, time::Timespec, AsFd, Errno};

#[test]
fn x86_64_signalfd_record_and_flags_match_linux() {
    if let Some(raw) = std::env::var_os("CRABC_SIGNALFD_CLOEXEC_CHECK") {
        let raw: i32 = raw.to_str().unwrap().parse().unwrap();
        assert_eq!(crabc_core::io::fcntl_getfd(raw).unwrap_err(), Errno::BADF);
        return;
    }
    assert_eq!(size_of::<signal::SignalFdInfo>(), 128);
    assert_eq!(signal::SignalFdFlags::NONBLOCK.bits(), 0x800);
    assert_eq!(signal::SignalFdFlags::CLOEXEC.bits(), 0x80000);
    let mut selected = signal::SignalSet::EMPTY;
    selected.insert(signal::Signal::USR1);
    let mut before = 0_u64;
    let mut after = 0_u64;
    // SAFETY: A null input queries the calling thread's mask into one live word.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(2, core::ptr::null(), &mut before).unwrap();
    }
    let fd = signal::signalfd(&selected, signal::SignalFdFlags::empty()).unwrap();
    // SAFETY: The writable word remains valid for the query.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(2, core::ptr::null(), &mut after).unwrap();
    }
    assert_eq!(before, after, "creating a signal descriptor must not block signals");
    assert!(!io::fcntl_getfd(&fd).unwrap().contains(io::FdFlags::CLOEXEC));
    assert_eq!(crabc_core::io::fcntl_getfl(fd.as_fd().as_raw_fd()).unwrap() & 0x800, 0);
    let invalid = signal::SignalFdFlags::from_bits_retain(1);
    assert_eq!(
        signal::signalfd(&signal::SignalSet::EMPTY, invalid).unwrap_err(), Errno::INVAL,
    );
}

#[test]
fn x86_64_signalfd_read_rejects_incomplete_foreign_records() {
    let (reader, writer) = pipe::pipe().unwrap();
    io::write(&writer, &[0_u8; 127]).unwrap();
    assert_eq!(signal::read_signalfd(&reader).unwrap_err(), Errno::IO);
    drop(writer);
    assert_eq!(signal::read_signalfd(&reader).unwrap_err(), Errno::IO);
    assert_eq!(
        signal::signalfd_update(&reader, &signal::SignalSet::EMPTY).unwrap_err(), Errno::INVAL,
    );
}

#[test]
fn x86_64_signalfd_isolated_blocked_signal_composition() {
    const CHILD: &str = "CRABC_SIGNALFD_TEST_CHILD";
    let bits = 1_u64 << (signal::Signal::USR1.as_raw() - 1);
    let mut previous = 0_u64;
    // SAFETY: Both pointers retain one live kernel-sized signal-set word.
    // Blocking before exec makes every child harness thread inherit the mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(0, &bits, &mut previous).unwrap();
    }
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("x86_64_signalfd_isolated_blocked_signal_composition")
            .arg("--test-threads=1").env(CHILD, "1").status().unwrap();
        // SAFETY: The child owns signal delivery; this thread has no pending
        // test signal and restores its exact mask after the inherited-mask exec.
        unsafe {
            crabc_core::signal::rt_sigprocmask_raw(2, &previous, core::ptr::null_mut()).unwrap();
        }
        assert!(status.success(), "isolated signal descriptor child: {status}");
        return;
    }
    let mut selected = signal::SignalSet::EMPTY;
    selected.insert(signal::Signal::USR1);
    let fd = signal::signalfd(
        &selected,
        signal::SignalFdFlags::NONBLOCK | signal::SignalFdFlags::CLOEXEC,
    ).unwrap();
    let raw = fd.as_fd().as_raw_fd();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact").arg("x86_64_signalfd_record_and_flags_match_linux")
        .arg("--test-threads=1")
        .env("CRABC_SIGNALFD_CLOEXEC_CHECK", raw.to_string()).status().unwrap();
    assert!(status.success(), "signal descriptor must close across successful exec");
    assert!(io::fcntl_getfd(&fd).unwrap().contains(io::FdFlags::CLOEXEC));
    assert_ne!(crabc_core::io::fcntl_getfl(raw).unwrap() & 0x800, 0);
    assert_eq!(signal::read_signalfd(&fd).unwrap_err(), Errno::AGAIN);
    let epoll = event::epoll::create(event::epoll::CreateFlags::CLOEXEC).unwrap();
    let token = 0xfeed_face_dead_beef;
    event::epoll::add(
        &epoll, &fd, event::epoll::EventData::new_u64(token), event::epoll::EventFlags::IN,
    ).unwrap();
    let timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut events = [MaybeUninit::uninit(); 1];
    let mut poll = [event::PollFd::new(&fd, event::PollFlags::IN)];
    assert_eq!(event::poll(&mut poll, Some(&timeout)).unwrap(), 0);
    signal::raise(signal::Signal::USR1).unwrap();
    assert_eq!(event::poll(&mut poll, Some(&timeout)).unwrap(), 1);
    assert_eq!(poll[0].revents(), event::PollFlags::IN);
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout)).unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].data().u64(), token);
    let mut short = [0_u8; 127];
    assert_eq!(io::read(&fd, &mut short).unwrap_err(), Errno::INVAL);
    let info = signal::read_signalfd(&fd).unwrap();
    assert_eq!(info.signal(), Some(signal::Signal::USR1));
    assert_eq!(info.raw_errno(), 0);
    assert_eq!(info.raw_code(), -6);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), crabc_core::process::getpid());
    assert_eq!(info.sender_uid(), crabc_core::process::getuid());
    assert_eq!(event::poll(&mut poll, Some(&timeout)).unwrap(), 0);
    let mut queued = crabc_core::signal::SigInfo::zeroed();
    queued.bytes[0..4].copy_from_slice(&signal::Signal::USR1.as_raw().to_ne_bytes());
    queued.bytes[8..12].copy_from_slice(&(-1_i32).to_ne_bytes());
    queued.bytes[16..20].copy_from_slice(&crabc_core::process::getpid().to_ne_bytes());
    queued.bytes[20..24].copy_from_slice(&crabc_core::process::getuid().to_ne_bytes());
    queued.bytes[24..28].copy_from_slice(&(-1234567_i32).to_ne_bytes());
    // SAFETY: The zeroed 128-byte x86 siginfo record carries SI_QUEUE with the
    // process sender and integer payload at the kernel ABI's fixed offsets.
    unsafe {
        crabc_core::signal::rt_sigqueueinfo_raw(
            crabc_core::process::getpid(), signal::Signal::USR1.as_raw(), &queued,
        ).unwrap();
    }
    let info = signal::read_signalfd(&fd).unwrap();
    assert_eq!(info.raw_code(), -1);
    assert_eq!(info.queued_i32(), -1234567);
    assert_eq!(info.status(), 0);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), crabc_core::process::getpid());
    assert_eq!(info.sender_uid(), crabc_core::process::getuid());
    signal::signalfd_update(&fd, &signal::SignalSet::EMPTY).unwrap();
    signal::raise(signal::Signal::USR1).unwrap();
    assert_eq!(event::poll(&mut poll, Some(&timeout)).unwrap(), 0);
    assert_eq!(signal::read_signalfd(&fd).unwrap_err(), Errno::AGAIN);
    signal::signalfd_update(&fd, &selected).unwrap();
    assert_eq!(event::poll(&mut poll, Some(&timeout)).unwrap(), 1);
    signal::read_signalfd(&fd).unwrap();
    assert!(io::fcntl_getfd(&fd).unwrap().contains(io::FdFlags::CLOEXEC));
    assert_ne!(crabc_core::io::fcntl_getfl(raw).unwrap() & 0x800, 0);
    drop(poll);
    let duplicate = io::dup(&fd).unwrap();
    drop(fd);
    assert_eq!(crabc_core::io::fcntl_getfd(raw).unwrap_err(), Errno::BADF);
    signal::raise(signal::Signal::USR1).unwrap();
    assert_eq!(
        signal::read_signalfd(&duplicate).unwrap().signal(), Some(signal::Signal::USR1),
    );
    drop(duplicate);
    assert!(event::epoll::wait(&epoll, &mut events, Some(&timeout)).unwrap().0.is_empty());
    // SAFETY: All pending test signals were consumed before restoring the exact entry mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(2, &previous, core::ptr::null_mut()).unwrap();
    }
}
