use crabc_rs::process::{self, ClockTicks, ProcessTimes};

fn ticks(value: ClockTicks) -> i64 {
    value.as_raw()
}

fn assert_structurally_sound(observation: ProcessTimes) {
    assert!(ticks(observation.user_time()) >= 0);
    assert!(ticks(observation.system_time()) >= 0);
    assert!(ticks(observation.children_user_time()) >= 0);
    assert!(ticks(observation.children_system_time()) >= 0);
}

#[test]
fn times_reads_validated_tick_accounting_without_a_clock_rate() {
    let first = process::times().expect("Linux times syscall");
    assert_structurally_sound(first);

    // Keep the observation deterministic: work may consume zero or more
    // accounting ticks, so the invariant is monotonicity rather than a
    // sleep-dependent minimum delta.
    let mut checksum = 0_u64;
    for value in 0..100_000_u64 {
        checksum = checksum.wrapping_add(value);
    }
    assert_ne!(checksum, 0);

    let second = process::times().expect("Linux times syscall again");
    assert_structurally_sound(second);
    assert!(ticks(second.user_time()) >= ticks(first.user_time()));
    assert!(ticks(second.system_time()) >= ticks(first.system_time()));
    assert!(ticks(second.children_user_time()) >= ticks(first.children_user_time()));
    assert!(ticks(second.children_system_time()) >= ticks(first.children_system_time()));
    assert!(ticks(second.elapsed_ticks()) >= ticks(first.elapsed_ticks()));
}
