use crabc_rs::pipe;
use crabc_rs::time::{clock_gettime_dynamic, ClockId, DynamicClockId, NANOS_PER_SECOND};
use crabc_rs::{AsFd, Errno};

#[test]
fn dynamic_known_clock_is_monotonic_and_normalized() {
    let before = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))
        .expect("known monotonic clock query");
    let after = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))
        .expect("known monotonic clock query");

    assert!((0..NANOS_PER_SECOND as i64).contains(&before.tv_nsec));
    assert!((0..NANOS_PER_SECOND as i64).contains(&after.tv_nsec));
    assert!((after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec));
}

#[test]
fn dynamic_non_clock_descriptor_preserves_kernel_error() {
    let (reader, _writer) = pipe::pipe().expect("pipe");
    let error = clock_gettime_dynamic(DynamicClockId::Dynamic(reader.as_fd()))
        .expect_err("a pipe is not a dynamic clock descriptor");

    assert_eq!(error, Errno::INVAL);
}
