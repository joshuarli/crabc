use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, Access};
use crabc_rs::Errno;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn access_uses_the_current_directory_for_existing_and_missing_paths() {
    fs::access(".", Access::EXISTS).expect("the current directory must exist");

    let missing = format!(
        "/tmp/crabc-rs-m10-access-missing-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    );
    assert_eq!(fs::access(&missing, Access::EXISTS).unwrap_err(), Errno::NOENT);
}

#[test]
fn access_mode_and_path_inputs_are_validated_before_the_kernel_boundary() {
    assert!(
        Access::from_bits(0x8).is_none(),
        "unknown access mode bits must not enter the safe API",
    );
    assert_eq!(
        fs::access(".", Access::from_bits_retain(0x8)).unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(fs::access(b"bad\0path".as_slice(), Access::EXISTS).unwrap_err(), Errno::INVAL);
}
