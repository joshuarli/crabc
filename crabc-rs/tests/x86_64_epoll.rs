#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, size_of, MaybeUninit};
use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::{event, io, pipe, signal, time::Timespec, Errno};

static EPOLL_MASK_SIGNAL_SEEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn epoll_mask_signal_handler(_: signal::Signal) {
    EPOLL_MASK_SIGNAL_SEEN.store(true, Ordering::SeqCst);
}

#[test]
fn x86_64_epoll_event_uses_the_packed_kernel_layout_and_exact_tokens() {
    assert_eq!(size_of::<event::epoll::Event>(), 12);
    assert_eq!(align_of::<event::epoll::Event>(), 1);
    assert_eq!(
        event::epoll::CreateFlags::CLOEXEC.bits(),
        0x0008_0000
    );
    assert_eq!(event::epoll::EventFlags::IN.bits(), 0x0000_0001);
    assert_eq!(event::epoll::EventFlags::NVAL.bits(), 0x0000_0020);
    let future_create = event::epoll::CreateFlags::from_bits(0x0000_0800)
        .expect("unknown creation bits must remain representable for Linux");
    assert_eq!(future_create.bits(), 0x0000_0800);
    let future_event = event::epoll::EventFlags::from_bits(1 << 11)
        .expect("unknown event bits must remain representable for Linux");
    assert_eq!(future_event.bits(), 1 << 11);

    let token = 0xfeed_face_dead_beef;
    let data = event::epoll::EventData::new_u64(token);
    assert_eq!(data.u64(), token);
    assert_eq!(
        event::epoll::EventData::new_ptr(token as *mut core::ffi::c_void).u64(),
        token
    );
}

#[test]
fn x86_64_epoll_create_and_legacy_constructor_honor_their_contracts() {
    assert!(matches!(
        event::epoll::create_legacy(0),
        Err(Errno::INVAL)
    ));
    let future_create = event::epoll::CreateFlags::from_bits(0x0000_0800)
        .expect("unknown creation bits must remain representable for Linux");
    assert!(
        matches!(
            event::epoll::create(future_create),
            Err(Errno::INVAL)
        ),
        "unknown creation bits must reach Linux unchanged",
    );

    let cloexec = event::epoll::create(event::epoll::CreateFlags::CLOEXEC)
        .expect("create close-on-exec epoll descriptor");
    assert!(io::fcntl_getfd(&cloexec)
        .expect("read epoll descriptor flags")
        .contains(io::FdFlags::CLOEXEC));

    let legacy = event::epoll::create_legacy(1).expect("create legacy epoll descriptor");
    assert!(!io::fcntl_getfd(&legacy)
        .expect("read legacy descriptor flags")
        .contains(io::FdFlags::CLOEXEC));
}

#[test]
fn x86_64_epoll_wait_initializes_only_the_result_prefix() {
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll descriptor");
    let timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut events = [MaybeUninit::uninit(); 2];
    let (ready, remaining) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("empty epoll wait");
    assert!(ready.is_empty());
    assert_eq!(remaining.len(), 2);
}

#[test]
fn x86_64_epoll_pipe_lifecycle_preserves_flags_and_tokens() {
    let (reader, writer) = pipe::pipe().expect("create pipe");
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll descriptor");
    let first = 0x1234_5678_9abc_def0;
    let future_event = event::epoll::EventFlags::from_bits(0x0000_0800)
        .expect("unknown event bits must remain representable for Linux");
    let first_flags = event::epoll::EventFlags::IN | future_event;
    assert_eq!(
        event::epoll::Event::new(first_flags, event::epoll::EventData::new_u64(first)).flags(),
        first_flags,
        "the packed event record must retain future bits until the syscall",
    );
    event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(first),
        first_flags,
    )
    .expect("forward unknown event bits through epoll registration");

    let timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut empty = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut empty, Some(&timeout))
        .expect("empty epoll set should return immediately");
    assert!(ready.is_empty());

    assert_eq!(io::write(&writer, b"x").expect("seed readable pipe"), 1);
    let untouched = event::epoll::Event::new(
        event::epoll::EventFlags::OUT,
        event::epoll::EventData::new_u64(0xface_cafe_dead_beef),
    );
    let mut result = [MaybeUninit::uninit(), MaybeUninit::new(untouched)];
    let (ready, remaining) = event::epoll::wait(&epoll, &mut result, Some(&timeout))
        .expect("wait for readable pipe");
    assert_eq!(ready.len(), 1);
    assert!(ready[0].flags().contains(event::epoll::EventFlags::IN));
    assert_eq!(ready[0].data().u64(), first);
    assert_eq!(remaining.len(), 1);
    // SAFETY: this suffix was initialized before the syscall and Linux
    // reported exactly one initialized event, so the facade must leave it
    // untouched behind the returned initialized prefix.
    assert_eq!(unsafe { remaining[0].assume_init() }, untouched);

    let second = 0x0bad_f00d_cafe_babe;
    event::epoll::modify(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(second),
        event::epoll::EventFlags::IN,
    )
    .expect("modify pipe registration");
    let mut modified = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut modified, Some(&timeout))
        .expect("modified registration remains readable");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].data().u64(), second);

    event::epoll::delete(&epoll, &reader).expect("delete pipe registration");
    let mut deleted = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut deleted, Some(&timeout))
        .expect("deleted registration should not report readiness");
    assert!(ready.is_empty());
}

#[test]
fn x86_64_epoll_masked_wait_reports_pipe_readiness_without_mutating_timeout() {
    let (reader, writer) = pipe::pipe().expect("create epoll pipe");
    let epoll = event::epoll::create_legacy(1).expect("create legacy epoll descriptor");
    event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(0xfeed),
        event::epoll::EventFlags::IN,
    )
    .expect("register epoll pipe reader");

    let mask = signal::SignalSet::EMPTY;
    let mut events = [MaybeUninit::uninit(); 1];
    let empty_timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
    let (ready, _) = event::epoll::wait_with_mask(
        &epoll,
        &mut events,
        Some(&empty_timeout),
        Some(&mask),
    )
        .expect("masked empty epoll wait");
    assert!(ready.is_empty());
    assert_eq!(empty_timeout, Timespec { tv_sec: 0, tv_nsec: 0 });

    assert_eq!(io::write(&writer, b"m").expect("write epoll byte"), 1);
    let timeout = Timespec {
        tv_sec: 1,
        tv_nsec: 234_567_890,
    };
    let original_timeout = timeout;
    let (ready, _) = event::epoll::wait_with_mask(&epoll, &mut events, Some(&timeout), Some(&mask))
        .expect("masked epoll wait for readable pipe");
    assert_eq!(ready.len(), 1);
    assert!(ready[0].flags().contains(event::epoll::EventFlags::IN));
    assert_eq!(ready[0].data().u64(), 0xfeed);
    assert_eq!(timeout, original_timeout);
}

#[test]
fn x86_64_epoll_masked_wait_temporarily_installs_and_restores_the_signal_mask() {
    const SIG_SETMASK: i32 = 2;
    let selected_signal = signal::Signal::USR1;
    let signal_bit = 1_u64 << (selected_signal.as_raw() - 1);

    let old_action =
        unsafe { signal::sigaction(selected_signal, None) }.expect("query SIGUSR1 action");
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(epoll_mask_signal_handler),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is a static function with the x86-64 restorer owned
    // by crabc-rs and remains installed only for this test.
    unsafe { signal::sigaction(selected_signal, Some(&action)) }
        .expect("install SIGUSR1 handler");

    let mut old_mask = 0_u64;
    // SAFETY: A null input queries this thread's one-word kernel mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut old_mask,
        )
        .expect("query signal mask");
    }
    let blocked_mask = old_mask | signal_bit;
    // SAFETY: `blocked_mask` is one initialized x86-64 kernel mask word.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            &blocked_mask,
            core::ptr::null_mut(),
        )
        .expect("block SIGUSR1");
    }

    EPOLL_MASK_SIGNAL_SEEN.store(false, Ordering::SeqCst);
    let target_pid = crabc_core::process::getpid();
    let target_tid = crabc_core::thread::gettid();
    let target_signal = selected_signal.as_raw();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(10));
        crabc_core::process::tgkill(target_pid, target_tid, target_signal)
    });
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll descriptor");
    let timeout = Timespec { tv_sec: 1, tv_nsec: 0 };
    let empty = signal::SignalSet::EMPTY;
    let mut events = [MaybeUninit::uninit(); 1];
    let wait = event::epoll::wait_with_mask(&epoll, &mut events, Some(&timeout), Some(&empty));
    let sender = sender.join().expect("join delayed SIGUSR1 sender");

    let mut observed_mask = 0_u64;
    // SAFETY: A null input queries the mask restored by epoll_pwait.
    let observed = unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut observed_mask,
        )
    };

    // SAFETY: Restore the caller's signal state and the prior disposition.
    let restored_mask = unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            &old_mask,
            core::ptr::null_mut(),
        )
    };
    let restored_action = unsafe { signal::sigaction(selected_signal, Some(&old_action)) };

    sender.expect("send SIGUSR1 while epoll_pwait temporarily unmasks it");
    observed.expect("query restored signal mask");
    restored_mask.expect("restore signal mask");
    restored_action.expect("restore SIGUSR1 action");
    assert!(matches!(wait, Err(Errno::INTR)));
    assert!(EPOLL_MASK_SIGNAL_SEEN.load(Ordering::SeqCst));
    assert_ne!(observed_mask & signal_bit, 0);
}

#[test]
fn x86_64_epoll_rejects_invalid_timeout_values() {
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll descriptor");
    let mut events = [MaybeUninit::uninit(); 1];

    let negative = Timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };
    assert!(matches!(
        event::epoll::wait(&epoll, &mut events, Some(&negative)),
        Err(Errno::INVAL)
    ));

    let invalid_nanoseconds = Timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    assert!(matches!(
        event::epoll::wait(&epoll, &mut events, Some(&invalid_nanoseconds)),
        Err(Errno::INVAL)
    ));

    let too_large = Timespec {
        tv_sec: i64::from(i32::MAX),
        tv_nsec: 0,
    };
    assert!(matches!(
        event::epoll::wait(&epoll, &mut events, Some(&too_large)),
        Err(Errno::INVAL)
    ));
}
