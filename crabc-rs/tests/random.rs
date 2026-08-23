use crabc_rs::rand::{random_u32, RandomState};

#[test]
fn native_random_state_is_owned_and_reproducible() {
    let mut first = RandomState::new(0x0123_4567_89ab_cdef);
    let mut second = RandomState::new(0x0123_4567_89ab_cdef);

    let expected = [0xa48f_aa9d_u32, 0x34a1_d093, 0x996d_ccbe, 0x4c46_67ec];
    for expected in expected {
        assert_eq!(random_u32(&mut first), expected);
        assert_eq!(random_u32(&mut second), expected);
    }

    let mut different = RandomState::new(0x0123_4567_89ab_cdf0);
    assert_ne!(first.next_u64(), different.next_u64());
}

#[test]
fn native_random_state_supports_checkpointing_by_value() {
    let mut state = RandomState::new(7);
    let _ = state.next_u32();
    let mut checkpoint = state;

    assert_eq!(state.next_u64(), checkpoint.next_u64());
    assert_eq!(state.next_u32(), checkpoint.next_u32());
}

#[test]
fn native_random_state_can_be_seeded_from_kernel_entropy() {
    let mut state = RandomState::from_entropy().expect("Linux getrandom seeds the state");
    let _ = state.next_u64();
}
