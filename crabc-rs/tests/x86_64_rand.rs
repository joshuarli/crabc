#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;

use crabc_rs::rand::{self, GetRandomFlags, RandomState, GETENTROPY_MAX_LENGTH};
use crabc_rs::Errno;

#[test]
fn x86_64_getrandom_uses_linux_flags_and_initializes_only_received_bytes() {
    assert_eq!(GetRandomFlags::NONBLOCK.bits(), 0x1);
    assert_eq!(GetRandomFlags::RANDOM.bits(), 0x2);
    assert_eq!(GetRandomFlags::INSECURE.bits(), 0x4);

    let mut empty = [MaybeUninit::<u8>::uninit(); 0];
    let (initialized, remaining) =
        rand::getrandom(&mut empty, GetRandomFlags::NONBLOCK).expect("accept nonblocking flag");
    assert!(initialized.is_empty());
    assert!(remaining.is_empty());

    let mut bytes = [MaybeUninit::<u8>::uninit(); 64];
    let (initialized, remaining) =
        rand::getrandom(&mut bytes, GetRandomFlags::empty()).expect("get x86-64 entropy");

    assert!(!initialized.is_empty());
    assert_eq!(initialized.len() + remaining.len(), bytes.len());
}

#[test]
fn x86_64_getentropy_preserves_the_musl_size_boundary() {
    let mut accepted = [0_u8; GETENTROPY_MAX_LENGTH];
    assert_eq!(rand::getentropy(&mut accepted), Ok(GETENTROPY_MAX_LENGTH));

    let mut rejected = [0xa5_u8; GETENTROPY_MAX_LENGTH + 1];
    assert_eq!(rand::getentropy(&mut rejected), Err(Errno::IO));
    assert!(rejected.iter().all(|&byte| byte == 0xa5));
}

#[test]
fn x86_64_owned_random_state_is_reproducible_and_can_be_entropy_seeded() {
    let mut first = RandomState::new(0x0123_4567_89ab_cdef);
    let mut second = RandomState::new(0x0123_4567_89ab_cdef);

    for _ in 0..4 {
        assert_eq!(first.next_u64(), second.next_u64());
    }

    let mut seeded = RandomState::from_entropy().expect("seed from x86-64 getrandom");
    assert_ne!(seeded.next_u64(), seeded.next_u64());
}
