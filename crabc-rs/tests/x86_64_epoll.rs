#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, size_of, MaybeUninit};

use crabc_rs::{event, io, pipe, time::Timespec, Errno};

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
    assert!(event::epoll::CreateFlags::from_bits(1).is_none());
    assert!(event::epoll::EventFlags::from_bits(1 << 11).is_none());

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
    event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(first),
        event::epoll::EventFlags::IN,
    )
    .expect("register pipe reader");

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
