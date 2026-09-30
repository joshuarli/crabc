#![cfg(target_arch = "x86_64")]

use crabc_rs::{signal, time::Timespec, Errno};

unsafe extern "C" { fn __errno_location() -> *mut i32; }

fn pid(raw: i32) -> signal::Pid { signal::Pid::from_raw(raw).unwrap() }
fn selected(member: signal::Signal) -> signal::SignalSet {
    let mut set = signal::SignalSet::EMPTY;
    set.insert(member);
    set
}
fn isolated(name: &str) -> bool {
    let mut set = selected(signal::Signal::USR1);
    set.insert(signal::Signal::RTMIN);
    set.insert(signal::Signal::RTMAX);
    let previous = signal::block(&set).unwrap();
    if std::env::var_os("CRABC_SIGNAL_QUEUE_CHILD").is_some() { return true; }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact").arg(name).arg("--test-threads=1")
        .env("CRABC_SIGNAL_QUEUE_CHILD", "1").status().unwrap();
    signal::set_mask(&previous).unwrap();
    assert!(status.success(), "isolated queued signal child: {status}");
    false
}
fn queue(target: signal::Pid, member: signal::Signal, value: i32) {
    // SAFETY: The musl test runtime owns writable calling-thread errno storage.
    unsafe { *__errno_location() = 1234; }
    signal::queue_process(target, member, value).unwrap();
    // SAFETY: This thread retains its live errno storage throughout the call.
    assert_eq!(unsafe { *__errno_location() }, 1234);
}
fn check(info: signal::SigInfo, member: signal::Signal, sender: i32, value: i32) {
    assert_eq!(info.signal(), Some(member));
    assert_eq!(info.raw_errno(), 0);
    assert_eq!(info.raw_code(), -1);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), sender);
    assert_eq!(info.queued_i32(), value);
}

#[test]
fn x86_64_signal_queue_payload_metadata_coalescing_and_errors() {
    if !isolated("x86_64_signal_queue_payload_metadata_coalescing_and_errors") { return; }
    let mask = signal::current_mask().unwrap();
    let own = crabc_core::process::getpid();
    assert_eq!(core::mem::size_of::<signal::SigInfo>(), 128);
    assert_eq!(core::mem::align_of::<signal::SigInfo>(), 8);
    assert!(signal::Pid::from_raw(0).is_none());
    assert!(signal::Pid::from_raw(-1).is_none());
    let usr1 = selected(signal::Signal::USR1);
    let fd = signal::signalfd(&usr1, signal::SignalFdFlags::NONBLOCK | signal::SignalFdFlags::CLOEXEC).unwrap();
    queue(pid(own), signal::Signal::USR1, 11);
    queue(pid(own), signal::Signal::USR1, 22);
    let info = signal::read_signalfd(&fd).unwrap();
    assert_eq!(info.raw_code(), -1);
    assert_eq!(info.raw_errno(), 0);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), own);
    assert_eq!(info.sender_uid(), crabc_core::process::getuid());
    assert_eq!(info.queued_i32(), 11);
    assert_eq!(signal::read_signalfd(&fd).unwrap_err(), Errno::AGAIN);
    for value in [i32::MAX, i32::MIN, -1234567] { queue(pid(own), signal::Signal::RTMIN, value); }
    for value in [i32::MAX, i32::MIN, -1234567] {
        let (received, info) = signal::wait_info(&selected(signal::Signal::RTMIN)).unwrap();
        assert_eq!(received, signal::Signal::RTMIN);
        check(info, received, own, value);
    }
    let rtmax = selected(signal::Signal::RTMAX);
    let rtfd = signal::signalfd(&rtmax, signal::SignalFdFlags::NONBLOCK).unwrap();
    queue(pid(own), signal::Signal::RTMAX, i32::MIN);
    let rtinfo = signal::read_signalfd(&rtfd).unwrap();
    assert_eq!(rtinfo.queued_i32(), i32::MIN);
    assert_eq!(rtinfo.sender_uid(), crabc_core::process::getuid());
    assert_eq!(rtinfo.raw_code(), -1);
    // SAFETY: The test runtime owns this thread's writable errno storage.
    // Linux PID allocation is bounded far below i32::MAX; this cannot target a live process.
    unsafe { *__errno_location() = 1234; }
    assert_eq!(signal::queue_process(pid(i32::MAX), signal::Signal::USR1, 0).unwrap_err(), Errno::SRCH);
    // SAFETY: The test runtime's calling-thread errno remains live.
    assert_eq!(unsafe { *__errno_location() }, 1234);
    assert_eq!(signal::current_mask().unwrap(), mask);
    assert!(!signal::pending().unwrap().contains(signal::Signal::RTMIN));
}

#[test]
fn x86_64_signal_queue_process_and_owned_thread_delivery() {
    if !isolated("x86_64_signal_queue_process_and_owned_thread_delivery") { return; }
    let mask = signal::current_mask().unwrap();
    let own = crabc_core::process::getpid();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        assert_eq!(signal::current_mask().unwrap(), mask);
        ready_tx.send(crabc_core::thread::gettid()).unwrap();
        release_rx.recv().unwrap();
        let pending = signal::pending().unwrap();
        assert!(pending.contains(signal::Signal::RTMIN));
        assert!(pending.contains(signal::Signal::RTMAX));
        let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
        let (_, info) = signal::timed_wait(&selected(signal::Signal::RTMIN), Some(&zero)).unwrap();
        check(info, signal::Signal::RTMIN, own, 101);
        let (received, info) = signal::timed_wait(&selected(signal::Signal::RTMAX), Some(&zero)).unwrap();
        assert_eq!(received, signal::Signal::RTMAX);
        assert_eq!(info.raw_code(), -6);
        assert_eq!(info.sender_pid().unwrap().as_raw_pid(), own);
        assert_eq!(signal::current_mask().unwrap(), mask);
    });
    let tid = ready_rx.recv().unwrap();
    assert_ne!(tid, own);
    queue(pid(tid), signal::Signal::USR1, 7);
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let (_, info) = signal::timed_wait(&selected(signal::Signal::USR1), Some(&zero)).unwrap();
    check(info, signal::Signal::USR1, own, 7);
    queue(pid(own), signal::Signal::RTMIN, 101);
    signal::kill_thread(pid(tid), signal::Signal::RTMAX).unwrap();
    assert!(signal::pending().unwrap().contains(signal::Signal::RTMIN));
    assert!(!signal::pending().unwrap().contains(signal::Signal::RTMAX));
    release_tx.send(()).unwrap();
    worker.join().unwrap();
    assert!(!signal::pending().unwrap().contains(signal::Signal::RTMIN));
    assert_eq!(signal::kill_thread(pid(i32::MAX), signal::Signal::USR1).unwrap_err(), Errno::SRCH);
    assert_eq!(signal::current_mask().unwrap(), mask);
}

#[test]
fn x86_64_signal_queue_owned_child_process_delivery() {
    if !isolated("x86_64_signal_queue_owned_child_process_delivery") { return; }
    let set = selected(signal::Signal::RTMIN);
    let mask = signal::current_mask().unwrap();
    if let Some(raw) = std::env::var_os("CRABC_SIGNAL_QUEUE_READY_FD") {
        let fd: i32 = raw.to_str().unwrap().parse().unwrap();
        let sender: i32 = std::env::var("CRABC_SIGNAL_QUEUE_SENDER").unwrap().parse().unwrap();
        assert_eq!(crabc_core::io::write(fd, b"r").unwrap(), 1);
        let timeout = Timespec { tv_sec: 5, tv_nsec: 0 };
        let (received, info) = signal::timed_wait(&set, Some(&timeout)).unwrap();
        assert_eq!(received, signal::Signal::RTMIN);
        check(info, received, sender, -1234);
        assert_eq!(signal::current_mask().unwrap(), mask);
        return;
    }
    let (reader, writer) = crabc_rs::pipe::pipe().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact").arg("x86_64_signal_queue_owned_child_process_delivery")
        .arg("--test-threads=1")
        .env("CRABC_SIGNAL_QUEUE_READY_FD", writer.as_raw_fd().to_string())
        .env("CRABC_SIGNAL_QUEUE_SENDER", crabc_core::process::getpid().to_string())
        .spawn().unwrap();
    drop(writer);
    let mut ready = [0];
    assert_eq!(crabc_core::io::read(reader.as_raw_fd(), &mut ready).unwrap(), 1);
    assert_eq!(ready, *b"r");
    let target = pid(child.id() as i32);
    assert_eq!(signal::kill_thread(target, signal::Signal::RTMIN).unwrap_err(), Errno::SRCH);
    queue(target, signal::Signal::RTMIN, -1234);
    assert!(child.wait().unwrap().success());
    assert_eq!(signal::current_mask().unwrap(), mask);
    assert!(!signal::pending().unwrap().contains(signal::Signal::RTMIN));
}
