use core::mem::MaybeUninit;

use api::{event, io, pipe, time};

fn main() {
    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::CLOEXEC).expect("pipe2");
    let epoll = event::epoll::create(event::epoll::CreateFlags::CLOEXEC).expect("epoll_create1");
    event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(0x1234),
        event::epoll::EventFlags::IN,
    )
    .expect("epoll_ctl add");

    let timeout = time::Timespec::default();
    let mut events = [MaybeUninit::uninit(); 2];
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout)).expect("epoll wait");
    assert!(ready.is_empty());
    assert_eq!(io::write(&writer, b"e").expect("write"), 1);
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout)).expect("epoll wait");
    assert_eq!(ready.len(), 1);
    assert!(ready[0].flags.contains(event::epoll::EventFlags::IN));
    assert_eq!(ready[0].data.u64(), 0x1234);
    event::epoll::modify(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(0x5678),
        event::epoll::EventFlags::IN,
    )
    .expect("epoll_ctl modify");
    event::epoll::delete(&epoll, &reader).expect("epoll_ctl delete");

    let timer = time::timerfd_create(
        time::TimerfdClockId::Monotonic,
        time::TimerfdFlags::CLOEXEC | time::TimerfdFlags::NONBLOCK,
    )
    .expect("timerfd_create");
    let old = time::timerfd_settime(
        &timer,
        time::TimerfdTimerFlags::empty(),
        &time::Itimerspec {
            it_interval: time::Timespec::default(),
            it_value: time::Timespec { tv_sec: 0, tv_nsec: 1_000_000 },
        },
    )
    .expect("timerfd_settime");
    assert_eq!(old.it_value, time::Timespec::default());
    let current = time::timerfd_gettime(&timer).expect("timerfd_gettime");
    assert!(current.it_value.tv_sec >= 0);
    println!("m5-event-time ok");
}
