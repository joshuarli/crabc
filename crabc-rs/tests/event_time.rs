use core::mem::MaybeUninit;

use crabc_rs::{event, io, pipe, time};

#[test]
fn epoll_register_modify_delete_and_wait_preserve_event_data() {
    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::CLOEXEC)
        .expect("create a close-on-exec pipe through the direct kernel seam");
    let epoll = event::epoll::create(event::epoll::CreateFlags::CLOEXEC)
        .expect("create an epoll descriptor through the direct kernel seam");

    event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(0x1234),
        event::epoll::EventFlags::IN,
    )
    .expect("register the pipe reader");

    let timeout = time::Timespec::default();
    let mut events = [MaybeUninit::uninit(); 4];
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("an empty epoll set should return immediately");
    assert!(ready.is_empty());

    assert_eq!(io::write(&writer, b"e").expect("write readiness byte"), 1);
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("wait for the readable pipe");
    assert_eq!(ready.len(), 1);
    assert!(ready[0].flags.contains(event::epoll::EventFlags::IN));
    assert_eq!(ready[0].data.u64(), 0x1234);

    event::epoll::modify(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(0x5678),
        event::epoll::EventFlags::IN,
    )
    .expect("modify the pipe registration");
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("modified registration remains readable");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].data.u64(), 0x5678);

    event::epoll::delete(&epoll, &reader).expect("delete the pipe registration");
    let mut byte = [0_u8; 1];
    assert_eq!(io::read(&reader, &mut byte).expect("drain pipe"), 1);
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("deleted registration should not report readiness");
    assert!(ready.is_empty());
}

#[test]
fn timerfd_set_get_and_epoll_wait_use_direct_linux_layouts() {
    let timer = time::timerfd_create(
        time::TimerfdClockId::Monotonic,
        time::TimerfdFlags::CLOEXEC | time::TimerfdFlags::NONBLOCK,
    )
    .expect("create a nonblocking timerfd through the direct kernel seam");
    let initial = time::Itimerspec::default();
    let previous = time::timerfd_settime(
        &timer,
        time::TimerfdTimerFlags::empty(),
        &time::Itimerspec {
            it_interval: time::Timespec::default(),
            it_value: time::Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            },
        },
    )
    .expect("arm a one-shot timerfd");
    assert_eq!(previous, initial);

    let current = time::timerfd_gettime(&timer).expect("read timerfd state");
    assert!(current.it_value.tv_sec >= 0);
    assert!((0..1_000_000_000).contains(&current.it_value.tv_nsec));

    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll for timer readiness");
    event::epoll::add(
        &epoll,
        &timer,
        event::epoll::EventData::new_u64(0xa11),
        event::epoll::EventFlags::IN,
    )
    .expect("register timerfd readiness");

    let timeout = time::Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let mut events = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("timerfd should become readable before the timeout");
    assert_eq!(ready.len(), 1);
    assert!(ready[0].flags.contains(event::epoll::EventFlags::IN));
    assert_eq!(ready[0].data.u64(), 0xa11);

    let mut expirations = [0_u8; 8];
    assert_eq!(
        io::read(&timer, &mut expirations).expect("consume timer expiration"),
        8
    );
    assert!(u64::from_ne_bytes(expirations) >= 1);
}
