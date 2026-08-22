use crabc_rs::process;
use crabc_rs::time::{self, DynamicClockId};

#[test]
fn process_clock_id_resolves_current_process() {
    let by_zero = time::clock_getcpuclockid(None).expect("current process CPU clock");
    let by_pid = time::clock_getcpuclockid(Some(process::getpid()))
        .expect("current process CPU clock by pid");

    assert_eq!(by_zero.as_raw(), -6);
    assert_ne!(by_pid, by_zero);
    assert_eq!(
        by_pid.as_raw(),
        ((-(process::getpid().as_raw_pid() as i64) - 1) * 8 + 2) as i32,
    );
}

#[test]
fn process_clock_id_maps_unknown_process_to_srch() {
    // This value cannot encode a negative Linux process clock ID without
    // wrapping to the ordinary current-process clock. The typed resolver must
    // reject it instead of validating an aliased clock for the wrong process.
    let pid = process::Pid::from_raw(i32::MAX).expect("positive test PID");
    assert_eq!(time::clock_getcpuclockid(Some(pid)), Err(crabc_rs::Errno::SRCH));
}

#[test]
fn process_clock_id_can_read_cpu_time_through_dynamic_clock() {
    let id = time::clock_getcpuclockid(None).expect("current process CPU clock");
    let before = time::clock_gettime_dynamic(DynamicClockId::Process(id))
        .expect("process CPU clock query");

    let mut checksum = 0u64;
    for value in 0..500_000u64 {
        checksum = checksum.wrapping_add(value.rotate_left((value & 31) as u32));
        std::hint::black_box(checksum);
    }

    let after = time::clock_gettime_dynamic(DynamicClockId::Process(id))
        .expect("process CPU clock query");
    assert_ne!(checksum, 0);
    assert!((0..1_000_000_000).contains(&before.tv_nsec));
    assert!((0..1_000_000_000).contains(&after.tv_nsec));
    assert!((after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec));
}
