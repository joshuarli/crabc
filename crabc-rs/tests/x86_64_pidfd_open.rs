#![cfg(target_arch = "x86_64")]

use crabc_rs::process::{self, Pid, PidfdFlags};
use crabc_rs::Errno;

#[test]
fn x86_64_pidfd_open_owns_a_descriptor_and_applies_nonblock() {
    assert_eq!(PidfdFlags::NONBLOCK.bits(), 0x0000_0800);

    let pidfd = match process::pidfd_open(process::getpid(), PidfdFlags::NONBLOCK) {
        Ok(pidfd) => pidfd,
        Err(Errno::NOSYS) => {
            eprintln!("skipping x86 pidfd test: kernel lacks pidfd_open");
            return;
        }
        Err(error) => panic!("open a nonblocking pidfd for the current process: {error:?}"),
    };

    assert!(pidfd.as_raw_fd() >= 0);
    let status_flags = crabc_core::io::fcntl_getfl(pidfd.as_raw_fd())
        .expect("read pidfd open-file status flags");
    assert_ne!(status_flags & 0x0000_0800, 0, "PIDFD_NONBLOCK must set O_NONBLOCK");
}

#[test]
fn x86_64_pidfd_open_preserves_kernel_errors() {
    match process::pidfd_open(process::getpid(), PidfdFlags::empty()) {
        Ok(pidfd) => drop(pidfd),
        Err(Errno::NOSYS) => {
            eprintln!("skipping x86 pidfd error checks: kernel lacks pidfd_open");
            return;
        }
        Err(error) => panic!("probe pidfd_open support: {error:?}"),
    }

    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(
        process::pidfd_open(missing, PidfdFlags::empty()).err(),
        Some(Errno::SRCH),
    );

    let invalid_flags = PidfdFlags::from_bits_retain(u32::MAX);
    assert_eq!(
        process::pidfd_open(process::getpid(), invalid_flags).err(),
        Some(Errno::INVAL),
    );
}
