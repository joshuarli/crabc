use std::ffi::CStr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crabc_rs::{io, pipe, process, signal, Errno};

static ATFORK_LOG: AtomicU64 = AtomicU64::new(0);
static ATFORK_LEN: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn atfork_a_prepare() {
    atfork_push(b'A');
}
unsafe extern "C" fn atfork_a_parent() {
    atfork_push(b'a');
}
unsafe extern "C" fn atfork_a_child() {
    atfork_push(b'a');
}
unsafe extern "C" fn atfork_b_prepare() {
    atfork_push(b'B');
}
unsafe extern "C" fn atfork_b_parent() {
    atfork_push(b'b');
}
unsafe extern "C" fn atfork_b_child() {
    atfork_push(b'b');
}
unsafe extern "C" fn atfork_c_prepare() {
    atfork_push(b'C');
}
unsafe extern "C" fn atfork_c_parent() {
    atfork_push(b'c');
}
unsafe extern "C" fn atfork_c_child() {
    atfork_push(b'c');
}

unsafe extern "C" fn usr2_handler(_: process::Signal) {
    ATFORK_LOG.store(u64::from_le_bytes(*b"handler!"), Ordering::SeqCst);
}

unsafe extern "C" fn usr2_info_handler(
    _: process::Signal,
    _: *mut signal::SigInfo,
    _: *mut core::ffi::c_void,
) {
}

fn atfork_push(byte: u8) {
    let offset = ATFORK_LEN.fetch_add(1, Ordering::SeqCst);
    assert!(offset < 8, "atfork test log exceeded fixed capacity");
    ATFORK_LOG.fetch_or((byte as u64) << (offset * 8), Ordering::SeqCst);
}

fn atfork_log() -> Vec<u8> {
    let length = ATFORK_LEN.load(Ordering::SeqCst);
    ATFORK_LOG.load(Ordering::SeqCst).to_le_bytes()[..length].to_vec()
}

#[test]
fn signal_process() {
    if let Ok(case) = std::env::var("CRABC_RS_SIGNAL_PROCESS_CASE") {
        match case.as_str() {
            "signals" => signal_case(),
            "signal-fd" => signal_fd_case(),
            "realtime" => realtime_case(),
            "process-control" => process_control_case(),
            "fork-wait" => fork_wait_case(),
            "atfork" => atfork_case(),
            "spawn" => spawn_case(),
            "waitid" => waitid_case(),
            other => panic!("unknown child case {other}"),
        }
        return;
    }

    for case in [
        "signals",
        "signal-fd",
        "realtime",
        "process-control",
        "fork-wait",
        "atfork",
        "spawn",
        "waitid",
    ] {
        let output = Command::new(std::env::current_exe().expect("locate test binary"))
            .args(["--exact", "signal_process", "--nocapture"])
            .env("CRABC_RS_SIGNAL_PROCESS_CASE", case)
            .output()
            .expect("run isolated child case");
        assert!(
            output.status.success(),
            "{case} subprocess failed with {:?}, stdout: {}, stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

fn signal_case() {
    let mut set = signal::SignalSet::EMPTY;
    set.insert(process::Signal::USR1);
    assert!(set.contains(process::Signal::USR1));
    assert!(!set.contains(process::Signal::USR2));
    assert!(!signal::SignalSet::full().contains(unsafe { process::Signal::from_raw_unchecked(32) }));
    assert!(!signal::SignalSet::full().contains(unsafe { process::Signal::from_raw_unchecked(33) }));
    assert!(!signal::SignalSet::full().contains(unsafe { process::Signal::from_raw_unchecked(34) }));
    assert_eq!(process::Signal::from_named_raw(32), None);
    assert_eq!(process::Signal::from_named_raw(33), None);
    assert_eq!(process::Signal::from_named_raw(34), None);
    assert_eq!(
        process::Signal::from_named_raw(35),
        Some(process::Signal::RTMIN)
    );
    assert!(process::Signal::RTMIN.is_realtime());

    let (ready_reader, ready_writer) = pipe::pipe().expect("create signal readiness pipe");
    let (result_reader, result_writer) = pipe::pipe().expect("create signal result pipe");
    let child = match unsafe { process::fork_raw() }.expect("fork isolated signal waiter") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => {
            let old_mask = signal::block(&set).expect("block SIGUSR1 in isolated child");
            crabc_core::io::write(ready_writer.as_raw_fd(), b"r").expect("announce signal waiter");
            assert!(signal::pending()
                .expect("read initial pending set")
                .is_empty());
            let (received, info) = signal::wait_info(&set).expect("receive queued signal");
            assert_eq!(received, process::Signal::USR1);
            assert_eq!(info.signal(), Some(process::Signal::USR1));
            assert_eq!(
                info.sender_pid(),
                Some(process::getppid().expect("visible parent"))
            );
            crabc_core::io::write(result_writer.as_raw_fd(), &info.queued_i32().to_ne_bytes())
                .expect("report queued signal value");
            signal::set_mask(&old_mask).expect("restore child mask");
            process::exit_immediately(0)
        }
    };
    let mut ready = [0_u8; 1];
    assert_eq!(
        io::read(&ready_reader, &mut ready[..]).expect("wait for signal child"),
        1
    );
    signal::queue_process(child, process::Signal::USR1, 0x1a2b_3c4d)
        .expect("queue signal to isolated blocked child");
    let mut queued = [0_u8; 4];
    assert_eq!(
        io::read(&result_reader, &mut queued[..]).expect("read queued value"),
        4
    );
    assert_eq!(i32::from_ne_bytes(queued), 0x1a2b_3c4d);
    assert_eq!(
        process::waitpid(Some(child), process::WaitOptions::empty())
            .expect("reap signal child")
            .expect("signal child status")
            .1
            .exit_status(),
        Some(0),
    );

    let action = signal::SigAction::new(
        signal::SigHandler::Simple(usr2_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::SIGINFO,
    );
    assert!(
        !action.flags().contains(signal::SigActionFlags::SIGINFO),
        "a one-argument handler cannot use the SA_SIGINFO calling convention",
    );
    let old = unsafe { signal::sigaction(process::Signal::USR2, Some(&action)) }
        .expect("install direct handler");
    signal::raise(process::Signal::USR2).expect("raise on current thread");
    assert_eq!(
        ATFORK_LOG.load(Ordering::SeqCst).to_le_bytes(),
        *b"handler!"
    );
    unsafe { signal::sigaction(process::Signal::USR2, Some(&old)) }
        .expect("restore direct handler");

    let info_action = signal::SigAction::new(
        signal::SigHandler::SigInfo(usr2_info_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    assert!(info_action
        .flags()
        .contains(signal::SigActionFlags::SIGINFO));

    let mut storage = vec![0_u128; 1024];
    let stack = signal::Stack::new(
        storage.as_mut_ptr().cast(),
        storage.len() * core::mem::size_of::<u128>(),
    );
    let previous = unsafe { signal::sigaltstack(Some(&stack)) }.expect("install alternate stack");
    let observed = unsafe { signal::sigaltstack(None) }.expect("read alternate stack");
    assert_eq!(observed.as_mut_ptr(), stack.as_mut_ptr());
    assert_eq!(observed.size(), stack.size());
    unsafe { signal::sigaltstack(Some(&previous)) }.expect("restore alternate stack");

    let realtime_set = set_for(process::Signal::RTMIN);
    assert_eq!(
        signal::timed_wait(&realtime_set, Some(&crabc_rs::time::Timespec::default())).unwrap_err(),
        Errno::AGAIN,
    );
}

fn signal_fd_case() {
    let mut set = signal::SignalSet::EMPTY;
    set.insert(process::Signal::USR1);
    let (ready_reader, ready_writer) = pipe::pipe().expect("create signalfd readiness pipe");
    let (result_reader, result_writer) = pipe::pipe().expect("create signalfd result pipe");
    let child = match unsafe { process::fork_raw() }.expect("fork isolated signalfd reader") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => {
            let old_mask = signal::block(&set).expect("block signalfd signal in child");
            let descriptor = signal::signalfd(&set, signal::SignalFdFlags::CLOEXEC)
                .expect("create native signalfd");
            crabc_core::io::write(ready_writer.as_raw_fd(), b"r")
                .expect("announce signalfd reader");
            let info = signal::read_signalfd(&descriptor).expect("read queued signalfd event");
            assert_eq!(info.signal(), Some(process::Signal::USR1));
            assert_eq!(
                info.sender_pid(),
                Some(process::getppid().expect("visible parent"))
            );
            crabc_core::io::write(result_writer.as_raw_fd(), &info.queued_i32().to_ne_bytes())
                .expect("report signalfd queue value");
            signal::set_mask(&old_mask).expect("restore signalfd child mask");
            process::exit_immediately(0)
        }
    };
    let mut ready = [0_u8; 1];
    assert_eq!(
        io::read(&ready_reader, &mut ready[..]).expect("wait for signalfd child"),
        1
    );
    signal::queue_process(child, process::Signal::USR1, 0x4d3c_2b1a)
        .expect("queue signal for signalfd child");
    let mut queued = [0_u8; 4];
    assert_eq!(
        io::read(&result_reader, &mut queued[..]).expect("read signalfd value"),
        4
    );
    assert_eq!(i32::from_ne_bytes(queued), 0x4d3c_2b1a);
    assert_eq!(
        process::waitpid(Some(child), process::WaitOptions::empty())
            .expect("reap signalfd child")
            .expect("signalfd child status")
            .1
            .exit_status(),
        Some(0),
    );
}

fn realtime_case() {
    let realtime = process::Signal::RTMIN;
    let set = set_for(realtime);
    let (ready_reader, ready_writer) = pipe::pipe().expect("create realtime readiness pipe");
    let (result_reader, result_writer) = pipe::pipe().expect("create realtime result pipe");
    let child = match unsafe { process::fork_raw() }.expect("fork realtime waiter") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => {
            let old_mask = signal::block(&set).expect("block realtime signal");
            crabc_core::io::write(ready_writer.as_raw_fd(), b"r")
                .expect("announce realtime waiter");
            let (received, info) = signal::wait_info(&set).expect("receive realtime signal");
            assert_eq!(received, realtime);
            assert_eq!(info.signal(), Some(realtime));
            assert_eq!(info.raw_code(), -1, "queued realtime signal uses SI_QUEUE");
            crabc_core::io::write(result_writer.as_raw_fd(), &info.queued_i32().to_ne_bytes())
                .expect("report realtime value");
            signal::set_mask(&old_mask).expect("restore realtime mask");
            process::exit_immediately(0)
        }
    };
    let mut ready = [0_u8; 1];
    assert_eq!(
        io::read(&ready_reader, &mut ready[..]).expect("wait for realtime child"),
        1
    );
    signal::queue_process(child, realtime, 0x1234_5678).expect("queue realtime child signal");
    let mut queued = [0_u8; 4];
    assert_eq!(
        io::read(&result_reader, &mut queued[..]).expect("read realtime value"),
        4
    );
    assert_eq!(i32::from_ne_bytes(queued), 0x1234_5678);
    assert_eq!(
        process::waitpid(Some(child), process::WaitOptions::empty())
            .expect("reap realtime child")
            .expect("realtime child status")
            .1
            .exit_status(),
        Some(0),
    );
}

fn process_control_case() {
    let child = match unsafe { process::fork_raw() }.expect("fork process-control child") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => {
            let pid = process::getpid();
            assert_eq!(
                process::getpgid(None).expect("read initial process group"),
                process::getpgrp()
            );
            assert!(
                process::getsid(None)
                    .expect("read initial session")
                    .as_raw_pid()
                    > 0
            );
            assert_eq!(process::setsid().expect("create isolated session"), pid);
            assert_eq!(
                process::getpgid(None).expect("read session process group"),
                pid
            );
            assert_eq!(process::getsid(None).expect("read isolated session"), pid);
            process::test_kill_process_group(pid).expect("signal-zero isolated process group");
            process::exit_immediately(0)
        }
    };
    assert_eq!(
        process::waitpid(Some(child), process::WaitOptions::empty())
            .expect("reap process-control child")
            .expect("process-control child status")
            .1
            .exit_status(),
        Some(0),
    );
}

fn fork_wait_case() {
    let child = match unsafe { process::fork_raw() }.expect("raw direct fork") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => process::exit_immediately(42),
    };
    let (_, status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("wait for raw-fork child")
        .expect("raw-fork child must report a status");
    assert!(status.exited());
    assert_eq!(status.exit_status(), Some(42));
    assert!(!status.signaled());

    assert_eq!(
        process::wait(process::WaitOptions::NOHANG).unwrap_err(),
        Errno::CHILD
    );
}

fn atfork_case() {
    ATFORK_LOG.store(0, Ordering::SeqCst);
    ATFORK_LEN.store(0, Ordering::SeqCst);
    unsafe {
        process::register_atfork(
            Some(atfork_a_prepare),
            Some(atfork_a_parent),
            Some(atfork_a_child),
        )
        .expect("register first atfork callback");
        process::register_atfork(
            Some(atfork_b_prepare),
            Some(atfork_b_parent),
            Some(atfork_b_child),
        )
        .expect("register second atfork callback");
        process::register_atfork(
            Some(atfork_c_prepare),
            Some(atfork_c_parent),
            Some(atfork_c_child),
        )
        .expect("register third atfork callback");
    }
    let (reader, writer) = pipe::pipe().expect("create atfork observation pipe");
    let child = match unsafe { process::fork() }.expect("native atfork fork") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => {
            let bytes = atfork_log();
            let _ = crabc_core::io::write(writer.as_raw_fd(), &bytes);
            process::exit_immediately(0)
        }
    };
    assert_eq!(atfork_log(), b"CBAabc");
    drop(writer);
    let mut child_log = [0_u8; 6];
    let read = io::read(&reader, &mut child_log[..]).expect("read child atfork log");
    assert_eq!(read, child_log.len());
    assert_eq!(&child_log, b"CBAabc");
    let (_, status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("reap atfork child")
        .expect("atfork child status");
    assert_eq!(status.exit_status(), Some(0));
}

fn spawn_case() {
    let (reader, writer) = pipe::pipe().expect("create spawn output pipe");
    let path = cstr(b"/bin/sh\0");
    let shell = cstr(b"sh\0");
    let dash_c = cstr(b"-c\0");
    let command = cstr(b"printf sig-proc\0");
    let actions = [
        process::FdAction::close(&reader),
        process::FdAction::dup2(&writer, 1),
    ];
    let prepared = process::PreparedExec::new(path, &[shell, dash_c, command], &[])
        .expect("prepare path argv and env in parent")
        .with_actions(&actions);
    let child = prepared
        .spawn()
        .expect("exec shell through prepared error-pipe spawn");
    drop(prepared);
    drop(writer);
    let mut output = [0_u8; 8];
    let read = io::read(&reader, &mut output[..]).expect("read prepared child stdout");
    assert_eq!(&output[..read], b"sig-proc");
    assert_eq!(
        child
            .wait(process::WaitOptions::empty())
            .unwrap()
            .unwrap()
            .exit_status(),
        Some(0)
    );

    let missing = process::PreparedExec::new(
        cstr(b"/crabc-rs-signal-process-definitely-missing\0"),
        &[cstr(b"missing\0")],
        &[],
    )
    .expect("prepare missing executable");
    assert_eq!(missing.spawn().unwrap_err(), Errno::NOENT);

    // The private error pipe is allocated after the public action list. Cover
    // every likely low descriptor target so a failed exec proves that spawn
    // relocates its writer rather than mistaking a clobbered writer for an
    // exec-success EOF.
    let (collision_reader, collision_writer) = pipe::pipe().expect("create collision source pipe");
    let collision_actions = [
        process::FdAction::dup2(&collision_writer, 3),
        process::FdAction::dup2(&collision_writer, 4),
        process::FdAction::dup2(&collision_writer, 5),
        process::FdAction::dup2(&collision_writer, 6),
        process::FdAction::dup2(&collision_writer, 7),
        process::FdAction::dup2(&collision_writer, 8),
        process::FdAction::dup2(&collision_writer, 9),
        process::FdAction::dup2(&collision_writer, 10),
        process::FdAction::dup2(&collision_writer, 11),
        process::FdAction::dup2(&collision_writer, 12),
        process::FdAction::dup2(&collision_writer, 13),
        process::FdAction::dup2(&collision_writer, 14),
        process::FdAction::dup2(&collision_writer, 15),
        process::FdAction::dup2(&collision_writer, 16),
    ];
    let collision_missing = process::PreparedExec::new(
        cstr(b"/crabc-rs-signal-process-collision-missing\0"),
        &[cstr(b"missing\0")],
        &[],
    )
    .expect("prepare missing collision executable")
    .with_actions(&collision_actions);
    assert_eq!(collision_missing.spawn().unwrap_err(), Errno::NOENT);
    drop(collision_reader);
    drop(collision_writer);
}

fn waitid_case() {
    let child = match unsafe { process::fork_raw() }.expect("fork waitid child") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => process::exit_immediately(19),
    };
    let status = process::waitid(process::WaitId::Pid(child), process::WaitIdOptions::EXITED)
        .expect("waitid child exit")
        .expect("waitid must report child status");
    assert_eq!(status.pid(), Some(child));
    assert!(status.exited());
    assert_eq!(status.status(), 19);
}

fn set_for(signal: process::Signal) -> signal::SignalSet {
    let mut set = signal::SignalSet::EMPTY;
    set.insert(signal);
    set
}

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("static C string")
}
