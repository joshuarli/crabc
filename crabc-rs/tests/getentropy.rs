use core::mem::MaybeUninit;

use crabc_rs::rand::{getentropy, GETENTROPY_MAX_LENGTH};
use crabc_rs::Errno;

#[test]
fn native_getentropy_rejects_oversized_requests_before_kernel_access() {
    let mut bytes = [0xa5_u8; GETENTROPY_MAX_LENGTH + 1];

    assert_eq!(getentropy(&mut bytes), Err(Errno::IO));
    assert!(bytes.iter().all(|&byte| byte == 0xa5));
}

#[test]
fn native_getentropy_accepts_the_musl_limit_and_initializes_success() {
    let mut bytes = [0_u8; GETENTROPY_MAX_LENGTH];

    assert_eq!(getentropy(&mut bytes), Ok(GETENTROPY_MAX_LENGTH));
}

#[test]
fn native_getentropy_marks_maybe_uninit_output_initialized_only_on_success() {
    let mut bytes = [MaybeUninit::<u8>::uninit(); 32];

    let (initialized, remaining) = getentropy(&mut bytes).expect("getentropy fills 32 bytes");

    assert_eq!(initialized.len(), 32);
    assert!(remaining.is_empty());
}

#[test]
fn native_getentropy_zero_length_succeeds_without_a_kernel_request() {
    let mut bytes: [u8; 0] = [];

    assert_eq!(getentropy(&mut bytes), Ok(0));
}
