use api::thread::futex::{self, Flags, Timespec};
use core::sync::atomic::AtomicU32;

fn main() {
    let word = AtomicU32::new(7);
    assert_eq!(
        futex::wait(&word, Flags::PRIVATE, 8, None),
        Err(api::io::Errno::AGAIN)
    );
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        futex::wait(&word, Flags::PRIVATE, 8, Some(&timeout)),
        Err(api::io::Errno::AGAIN)
    );
    assert_eq!(futex::wake(&word, Flags::PRIVATE, 1), Ok(0));
    println!("native-futex ok");
}
