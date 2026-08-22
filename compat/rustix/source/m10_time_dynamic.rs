use api::{io, pipe, time};
use api::fd::AsFd;

fn main() {
    let before = time::clock_gettime_dynamic(time::DynamicClockId::Known(time::ClockId::Monotonic))
        .expect("known monotonic clock query");
    let after = time::clock_gettime_dynamic(time::DynamicClockId::Known(time::ClockId::Monotonic))
        .expect("known monotonic clock query");
    assert!((0..1_000_000_000).contains(&before.tv_nsec));
    assert!((0..1_000_000_000).contains(&after.tv_nsec));
    assert!((after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec));

    let (reader, _writer) = pipe::pipe().expect("pipe");
    let error = time::clock_gettime_dynamic(time::DynamicClockId::Dynamic(reader.as_fd()))
        .expect_err("a pipe is not a dynamic clock descriptor");
    assert_eq!(error, io::Errno::INVAL);
    println!("m10-time-dynamic ok");
}
