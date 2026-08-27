#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, offset_of, size_of, MaybeUninit};

use crabc_rs::{event, io, pipe, time, Errno};

fn one_shot(nanoseconds: i64) -> time::Itimerspec {
    time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: time::Timespec {
            tv_sec: 0,
            tv_nsec: nanoseconds,
        },
    }
}

fn deadline_after(now: time::Timespec, nanoseconds: i64) -> time::Timespec {
    let mut seconds = now.tv_sec;
    let mut nanoseconds = now.tv_nsec + nanoseconds;
    if nanoseconds >= i64::from(time::NANOS_PER_SECOND) {
        seconds += 1;
        nanoseconds -= i64::from(time::NANOS_PER_SECOND);
    }
    time::Timespec {
        tv_sec: seconds,
        tv_nsec: nanoseconds,
    }
}

#[test]
fn x86_64_timerfd_records_and_constants_match_linux() {
    assert_eq!(size_of::<time::Itimerspec>(), 32);
    assert_eq!(align_of::<time::Itimerspec>(), 8);
    assert_eq!(offset_of!(time::Itimerspec, it_interval), 0);
    assert_eq!(offset_of!(time::Itimerspec, it_value), 16);
    assert_eq!(time::TimerfdFlags::NONBLOCK.bits(), 0x0000_0800);
    assert_eq!(time::TimerfdFlags::CLOEXEC.bits(), 0x0008_0000);
    assert_eq!(time::TimerfdTimerFlags::ABSTIME.bits(), 0x0000_0001);
    assert_eq!(time::TimerfdTimerFlags::CANCEL_ON_SET.bits(), 0x0000_0002);
    assert_eq!(time::TimerfdClockId::Realtime as i32, 0);
    assert_eq!(time::TimerfdClockId::Monotonic as i32, 1);
    assert_eq!(time::TimerfdClockId::Boottime as i32, 7);
    assert_eq!(time::TimerfdClockId::RealtimeAlarm as i32, 8);
    assert_eq!(time::TimerfdClockId::BoottimeAlarm as i32, 9);
    assert!(time::TimerfdFlags::from_bits(1).is_some());
    assert!(time::TimerfdTimerFlags::from_bits(4).is_some());
    assert_eq!(time::Itimerspec::default(), time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: time::Timespec { tv_sec: 0, tv_nsec: 0 },
    });
}

#[test]
fn x86_64_timerfd_forwards_unknown_flags_and_exposes_linux_clock_selection() {
    let future_create = time::TimerfdFlags::from_bits(0x0000_0001)
        .expect("unknown creation bits must remain representable for Linux");
    assert!(matches!(
        time::timerfd_create(time::TimerfdClockId::Monotonic, future_create),
        Err(Errno::INVAL)
    ));

    for clock in [
        time::TimerfdClockId::Realtime,
        time::TimerfdClockId::Monotonic,
        time::TimerfdClockId::Boottime,
    ] {
        time::timerfd_create(clock, time::TimerfdFlags::CLOEXEC)
            .expect("ordinary Linux timerfd clock must create a descriptor");
    }

    for clock in [
        time::TimerfdClockId::RealtimeAlarm,
        time::TimerfdClockId::BoottimeAlarm,
    ] {
        match time::timerfd_create(clock, time::TimerfdFlags::CLOEXEC) {
            Ok(_) | Err(Errno::PERM) => {}
            Err(error) => panic!("unexpected alarm-clock timerfd error: {error:?}"),
        }
    }

    let timer = time::timerfd_create(time::TimerfdClockId::Monotonic, time::TimerfdFlags::empty())
        .expect("create timerfd for future settime flags");
    let future_settime = time::TimerfdTimerFlags::from_bits(0x0000_0004)
        .expect("unknown settime bits must remain representable for Linux");
    assert_eq!(
        time::timerfd_settime(&timer, future_settime, &time::Itimerspec::default()),
        Err(Errno::INVAL),
    );
}

#[test]
fn x86_64_timerfd_create_applies_descriptor_flags_and_starts_disarmed() {
    let timer = time::timerfd_create(
        time::TimerfdClockId::Monotonic,
        time::TimerfdFlags::NONBLOCK | time::TimerfdFlags::CLOEXEC,
    )
    .expect("create nonblocking close-on-exec timerfd");
    assert!(io::fcntl_getfd(&timer)
        .expect("read timerfd descriptor flags")
        .contains(io::FdFlags::CLOEXEC));

    assert_eq!(
        time::timerfd_gettime(&timer).expect("read disarmed timer setting"),
        time::Itimerspec::default(),
    );
    let mut expirations = [0_u8; 8];
    assert_eq!(io::read(&timer, &mut expirations), Err(Errno::AGAIN));
}

#[test]
fn x86_64_timerfd_relative_arm_epoll_read_and_disarm_preserve_the_lifecycle() {
    let timer = time::timerfd_create(
        time::TimerfdClockId::Monotonic,
        time::TimerfdFlags::NONBLOCK,
    )
    .expect("create nonblocking timerfd");
    let armed = one_shot(1_000_000);
    assert_eq!(
        time::timerfd_settime(&timer, time::TimerfdTimerFlags::empty(), &armed)
            .expect("arm one-shot timer"),
        time::Itimerspec::default(),
    );

    let current = time::timerfd_gettime(&timer).expect("read armed timer setting");
    assert_eq!(current.it_interval, time::Timespec { tv_sec: 0, tv_nsec: 0 });
    assert!(current.it_value.tv_sec >= 0);
    assert!((0..i64::from(time::NANOS_PER_SECOND)).contains(&current.it_value.tv_nsec));

    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll descriptor");
    event::epoll::add(
        &epoll,
        &timer,
        event::epoll::EventData::new_u64(0x71e7_f00d),
        event::epoll::EventFlags::IN,
    )
    .expect("register timerfd readiness");
    let timeout = time::Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let mut events = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("timerfd should become readable");
    assert_eq!(ready.len(), 1);
    assert!(ready[0].flags().contains(event::epoll::EventFlags::IN));
    assert_eq!(ready[0].data().u64(), 0x71e7_f00d);

    let mut expirations = [0_u8; 8];
    assert_eq!(io::read(&timer, &mut expirations).expect("consume expiration"), 8);
    assert!(u64::from_ne_bytes(expirations) >= 1);
    assert_eq!(io::read(&timer, &mut expirations), Err(Errno::AGAIN));

    let previous = time::timerfd_settime(
        &timer,
        time::TimerfdTimerFlags::empty(),
        &time::Itimerspec::default(),
    )
    .expect("disarm timer");
    assert_eq!(previous.it_interval, time::Timespec { tv_sec: 0, tv_nsec: 0 });
    assert_eq!(
        time::timerfd_gettime(&timer).expect("read disarmed timer setting"),
        time::Itimerspec::default(),
    );
}

#[test]
fn x86_64_timerfd_accepts_monotonic_absolute_deadlines() {
    let timer = time::timerfd_create(time::TimerfdClockId::Monotonic, time::TimerfdFlags::empty())
        .expect("create timerfd");
    let now = time::clock_gettime(time::ClockId::Monotonic).expect("read monotonic clock");
    let deadline = time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: deadline_after(now, 1_000_000),
    };
    time::timerfd_settime(&timer, time::TimerfdTimerFlags::ABSTIME, &deadline)
        .expect("arm monotonic absolute timer");

    let epoll = event::epoll::create(event::epoll::CreateFlags::empty())
        .expect("create epoll descriptor");
    event::epoll::add(
        &epoll,
        &timer,
        event::epoll::EventData::new_u64(0xa851_1e),
        event::epoll::EventFlags::IN,
    )
    .expect("register absolute timer readiness");
    let timeout = time::Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let mut events = [MaybeUninit::uninit(); 1];
    let (ready, _) = event::epoll::wait(&epoll, &mut events, Some(&timeout))
        .expect("absolute timerfd should become readable");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].data().u64(), 0xa851_1e);

    let mut expirations = [0_u8; 8];
    assert_eq!(io::read(&timer, &mut expirations).expect("consume expiration"), 8);
    assert!(u64::from_ne_bytes(expirations) >= 1);
}

#[test]
fn x86_64_timerfd_preserves_periodic_settings_and_accepts_realtime_cancel_on_set() {
    let periodic_timer = time::timerfd_create(
        time::TimerfdClockId::Monotonic,
        time::TimerfdFlags::empty(),
    )
    .expect("create periodic timerfd");
    let periodic = time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 2, tv_nsec: 0 },
        it_value: time::Timespec { tv_sec: 5, tv_nsec: 0 },
    };
    assert_eq!(
        time::timerfd_settime(
            &periodic_timer,
            time::TimerfdTimerFlags::empty(),
            &periodic,
        )
        .expect("arm periodic timer"),
        time::Itimerspec::default(),
    );
    let current = time::timerfd_gettime(&periodic_timer).expect("read periodic timer");
    assert_eq!(current.it_interval, periodic.it_interval);
    assert!(current.it_value.tv_sec >= 0);
    assert!((0..i64::from(time::NANOS_PER_SECOND)).contains(&current.it_value.tv_nsec));

    let realtime_timer = time::timerfd_create(
        time::TimerfdClockId::Realtime,
        time::TimerfdFlags::empty(),
    )
    .expect("create realtime timerfd");
    let now = time::clock_gettime(time::ClockId::Realtime).expect("read realtime clock");
    let absolute = time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: deadline_after(now, 1_000_000_000),
    };
    time::timerfd_settime(
        &realtime_timer,
        time::TimerfdTimerFlags::ABSTIME | time::TimerfdTimerFlags::CANCEL_ON_SET,
        &absolute,
    )
    .expect("arm realtime absolute cancellation-aware timer");
    let previous = time::timerfd_settime(
        &realtime_timer,
        time::TimerfdTimerFlags::empty(),
        &time::Itimerspec::default(),
    )
    .expect("disarm realtime timer");
    assert_eq!(previous.it_interval, time::Timespec { tv_sec: 0, tv_nsec: 0 });
    assert!(previous.it_value.tv_sec >= 0);
    assert!((0..i64::from(time::NANOS_PER_SECOND)).contains(&previous.it_value.tv_nsec));
}

#[test]
fn x86_64_timerfd_rejects_invalid_records_and_descriptor_kinds() {
    let timer = time::timerfd_create(time::TimerfdClockId::Monotonic, time::TimerfdFlags::empty())
        .expect("create timerfd");
    let invalid_nanoseconds = time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: time::Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(time::NANOS_PER_SECOND),
        },
    };
    assert_eq!(
        time::timerfd_settime(&timer, time::TimerfdTimerFlags::empty(), &invalid_nanoseconds),
        Err(Errno::INVAL),
    );
    let negative_seconds = time::Itimerspec {
        it_interval: time::Timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: time::Timespec { tv_sec: -1, tv_nsec: 0 },
    };
    assert_eq!(
        time::timerfd_settime(&timer, time::TimerfdTimerFlags::empty(), &negative_seconds),
        Err(Errno::INVAL),
    );
    let (reader, _writer) = pipe::pipe().expect("create non-timer descriptor");
    assert_eq!(time::timerfd_gettime(&reader), Err(Errno::INVAL));
}
