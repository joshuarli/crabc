use crabc_rs::time::process_cpu_time;

#[test]
fn process_cpu_time_is_a_monotonic_canonical_duration() {
    let before = process_cpu_time();
    let mut checksum = 0u64;
    for value in 0..2_000_000u64 {
        checksum = checksum.wrapping_add(value.rotate_left((value & 31) as u32));
        std::hint::black_box(checksum);
    }
    let after = process_cpu_time();

    assert_ne!(checksum, 0);
    assert!(after >= before, "process CPU clock moved backwards");
    assert!(after.subsec_nanos() < 1_000_000_000);
}
