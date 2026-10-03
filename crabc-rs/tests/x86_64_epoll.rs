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


fn immediate_event_tokens(epoll: &crabc_rs::OwnedFd) -> Vec<u64> {
    let mut storage = [MaybeUninit::uninit(); 4];
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let (ready, _) = event::epoll::wait(epoll, &mut storage, Some(&zero))
        .expect("observe current epoll readiness");
    let mut tokens: Vec<_> = ready.iter().map(|record| record.data().u64()).collect();
    tokens.sort_unstable();
    tokens
}

#[test]
fn x86_64_poll_and_epoll_track_eventfd_saturation_and_drain() {
    let counter = event::eventfd(0, event::EventfdFlags::NONBLOCK).unwrap();
    let epoll = event::epoll::create(event::epoll::CreateFlags::CLOEXEC).unwrap();
    event::epoll::add(&epoll, &counter, event::epoll::EventData::new_u64(0x1234),
        event::epoll::EventFlags::IN | event::epoll::EventFlags::OUT).unwrap();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut polled = [event::PollFd::new(&counter, event::PollFlags::IN | event::PollFlags::OUT)];
    assert_eq!(event::poll(&mut polled, Some(&zero)), Ok(1));
    assert_eq!(polled[0].revents(), event::PollFlags::OUT);
    event::eventfd_write(&counter, u64::MAX - 2).unwrap();
    event::eventfd_write(&counter, 1).unwrap();
    assert_eq!(event::eventfd_write(&counter, 1), Err(Errno::AGAIN));
    assert_eq!(event::poll(&mut polled, Some(&zero)), Ok(1));
    assert_eq!(polled[0].revents(), event::PollFlags::IN);
    let mut storage = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut storage, Some(&zero)).unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].flags(), event::epoll::EventFlags::IN);
    assert_eq!(ready[0].data().u64(), 0x1234);
    assert_eq!(event::eventfd_read(&counter), Ok(u64::MAX - 1));
    assert_eq!(event::eventfd_read(&counter), Err(Errno::AGAIN));
    assert_eq!(event::poll(&mut polled, Some(&zero)), Ok(1));
    assert_eq!(polled[0].revents(), event::PollFlags::OUT);
    let (ready, _) = event::epoll::wait(&epoll, &mut storage, Some(&zero)).unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].flags(), event::epoll::EventFlags::OUT);
}

#[test]
fn x86_64_epoll_oneshot_rearm_observes_still_readable_semaphore() {
    let counter = event::eventfd(2, event::EventfdFlags::NONBLOCK | event::EventfdFlags::SEMAPHORE).unwrap();
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty()).unwrap();
    let flags = event::epoll::EventFlags::IN | event::epoll::EventFlags::ONESHOT;
    event::epoll::add(&epoll, &counter, event::epoll::EventData::new_u64(11), flags).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [11]);
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert!(immediate_event_tokens(&epoll).is_empty());
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut polled = [event::PollFd::new(&counter, event::PollFlags::IN)];
    assert_eq!(event::poll(&mut polled, Some(&zero)), Ok(1));
    event::epoll::modify(&epoll, &counter, event::epoll::EventData::new_u64(22), flags).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [22]);
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert_eq!(event::eventfd_read(&counter), Err(Errno::AGAIN));
    event::epoll::modify(&epoll, &counter, event::epoll::EventData::new_u64(33), flags).unwrap();
    assert!(immediate_event_tokens(&epoll).is_empty());
    event::eventfd_write(&counter, 1).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [33]);
}

#[test]
fn x86_64_epoll_edge_trigger_reports_once_then_reports_increment_after_drain() {
    let counter = event::eventfd(2, event::EventfdFlags::NONBLOCK | event::EventfdFlags::SEMAPHORE).unwrap();
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty()).unwrap();
    event::epoll::add(&epoll, &counter, event::epoll::EventData::new_u64(44),
        event::epoll::EventFlags::IN | event::epoll::EventFlags::ET).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [44]);
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert!(immediate_event_tokens(&epoll).is_empty());
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert_eq!(event::eventfd_read(&counter), Err(Errno::AGAIN));
    assert!(immediate_event_tokens(&epoll).is_empty());
    event::eventfd_write(&counter, 1).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [44]);
}

#[test]
fn x86_64_epoll_registration_survives_original_close_until_last_duplicate_closes() {
    let original = event::eventfd(1, event::EventfdFlags::NONBLOCK).unwrap();
    let duplicate = io::dup(&original).unwrap();
    let epoll = event::epoll::create(event::epoll::CreateFlags::empty()).unwrap();
    let flags = event::epoll::EventFlags::IN;
    event::epoll::add(&epoll, &original, event::epoll::EventData::new_u64(51), flags).unwrap();
    drop(original);
    assert_eq!(immediate_event_tokens(&epoll), [51]);
    assert_eq!(event::epoll::modify(&epoll, &duplicate, event::epoll::EventData::new_u64(52), flags),
        Err(Errno::NOENT));
    event::epoll::add(&epoll, &duplicate, event::epoll::EventData::new_u64(52), flags).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [51, 52]);
    assert_eq!(event::eventfd_read(&duplicate), Ok(1));
    assert!(immediate_event_tokens(&epoll).is_empty());
    event::eventfd_write(&duplicate, 1).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [51, 52]);
    drop(duplicate);
    assert!(immediate_event_tokens(&epoll).is_empty());
}

#[test]
fn x86_64_epoll_reused_descriptor_slot_keeps_file_descriptions_distinct() {
    let mut slot = event::eventfd(1, event::EventfdFlags::NONBLOCK | event::EventfdFlags::CLOEXEC)
        .expect("create the original registered file description");
    let retained = io::dup(&slot).expect("retain the original file description");
    let replacement = event::eventfd(2, event::EventfdFlags::NONBLOCK | event::EventfdFlags::CLOEXEC)
        .expect("create the replacement file description");
    let epoll = event::epoll::create(event::epoll::CreateFlags::CLOEXEC).unwrap();
    let slot_number = slot.as_raw_fd();
    let flags = event::epoll::EventFlags::IN;
    event::epoll::add(&epoll, &slot, event::epoll::EventData::new_u64(61), flags).unwrap();

    // The registration key includes the open file description. Replacing the
    // owned slot preserves its number while the duplicate retains the old key.
    io::dup2(&replacement, &mut slot).expect("replace the owned descriptor slot");
    assert_eq!(slot.as_raw_fd(), slot_number);
    assert!(!io::fcntl_getfd(&slot).unwrap().contains(io::FdFlags::CLOEXEC));
    assert!(io::fcntl_getfd(&replacement).unwrap().contains(io::FdFlags::CLOEXEC));
    event::epoll::add(&epoll, &slot, event::epoll::EventData::new_u64(62), flags).unwrap();
    assert_eq!(immediate_event_tokens(&epoll), [61, 62]);

    assert_eq!(event::eventfd_read(&retained), Ok(1));
    assert_eq!(immediate_event_tokens(&epoll), [62]);
    event::eventfd_write(&retained, 3).unwrap();
    event::epoll::delete(&epoll, &slot).expect("delete only the replacement key");
    assert_eq!(immediate_event_tokens(&epoll), [61]);
    assert_eq!(event::eventfd_read(&replacement), Ok(2));
    event::eventfd_write(&slot, 4).unwrap();
    assert_eq!(event::eventfd_read(&replacement), Ok(4));
    drop(retained);
    assert!(immediate_event_tokens(&epoll).is_empty());
    assert!(io::fcntl_getfd(&epoll).unwrap().contains(io::FdFlags::CLOEXEC));
}

#[test]
fn x86_64_epoll_packed_results_copy_tokens_without_owning_their_sources() {
    let counters = [
        event::eventfd(1, event::EventfdFlags::NONBLOCK).unwrap(),
        event::eventfd(1, event::EventfdFlags::NONBLOCK).unwrap(),
    ];
    let mut token_storage = Box::new([71_u64, 72]);
    let pointers = [
        core::ptr::addr_of_mut!(token_storage[0]).cast::<core::ffi::c_void>(),
        core::ptr::addr_of_mut!(token_storage[1]).cast::<core::ffi::c_void>(),
    ];
    let epoll = event::epoll::create(event::epoll::CreateFlags::CLOEXEC).unwrap();
    for (counter, pointer) in counters.iter().zip(pointers) {
        event::epoll::add(&epoll, counter, event::epoll::EventData::new_ptr(pointer),
            event::epoll::EventFlags::IN).unwrap();
    }
    let sentinel = event::epoll::Event::new(event::epoll::EventFlags::OUT,
        event::epoll::EventData::new_u64(0xdead_beef));
    let mut records = [sentinel; 4];
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let count = event::epoll::wait(&epoll, &mut records, Some(&zero)).unwrap();
    assert_eq!(count, 2);
    assert_eq!(records[2], sentinel);
    assert_eq!(records[3], sentinel);
    let copied = [records[0], records[1]];
    let mut observed: Vec<_> = copied.iter().map(|record| {
        assert_eq!(record.flags(), event::epoll::EventFlags::IN);
        record.data().ptr() as usize
    }).collect();
    observed.sort_unstable();
    let mut expected = pointers.map(|pointer| pointer as usize);
    expected.sort_unstable();
    assert_eq!(observed, expected);
    for counter in &counters {
        event::epoll::delete(&epoll, counter).unwrap();
    }
    drop(counters);
    drop(epoll);

    // Packed record methods copy fields before borrowing them for formatting,
    // equality or hashing. A copied result owns token bits, not its source fd.
    for record in copied {
        let pointer = pointers.iter().copied().find(|pointer| *pointer == record.data().ptr())
            .expect("the copied result keeps a caller-provided token");
        let expected = event::epoll::Event::new(event::epoll::EventFlags::IN,
            event::epoll::EventData::new_ptr(pointer));
        assert_eq!(record, expected);
        let mut first = std::collections::hash_map::DefaultHasher::new();
        let mut second = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&record, &mut first);
        std::hash::Hash::hash(&expected, &mut second);
        assert_eq!(std::hash::Hasher::finish(&first), std::hash::Hasher::finish(&second));
        assert_eq!(format!("{record:?}"), format!("{expected:?}"));
    }
    assert_eq!(*token_storage, [71, 72]);
}
