use core::num::NonZeroU64;

use crabc_rs::fs::{Advice, Mode, OFlags};
use crabc_rs::{fs, io};

#[test]
fn native_fadvise_policies_succeed_without_moving_position() {
    const PATH: &[u8] = b"crabc-rs-native-fadvise";

    match fs::unlink(PATH) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale fadvise fixture: {error}"),
    }

    let file = fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create disposable fadvise fixture");
    io::write(&file, b"fadvise").expect("dirty disposable fadvise fixture");
    let before = fs::tell(&file).expect("read position before fadvise");
    let bounded_length = NonZeroU64::new(7).expect("non-zero fadvise length");
    let policies = [
        Advice::Normal,
        Advice::Sequential,
        Advice::Random,
        Advice::NoReuse,
        Advice::WillNeed,
        Advice::DontNeed,
    ];

    for (index, advice) in policies.into_iter().enumerate() {
        let length = if index == 0 {
            None
        } else {
            Some(bounded_length)
        };
        fs::fadvise(&file, 0, length, advice).expect("apply direct fadvise policy");
    }

    assert_eq!(
        fs::tell(&file).expect("read position after fadvise"),
        before
    );
    let oversized_offset = i64::MAX as u64 + 1;
    let range_error = fs::fadvise(&file, oversized_offset, None, Advice::Normal);
    drop(file);
    fs::unlink(PATH).expect("remove disposable fadvise fixture");

    assert_eq!(range_error, Err(crabc_rs::Errno::INVAL));
}
