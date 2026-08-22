use crabc_rs::process::{self, Pid, PidfdFlags};
use crabc_rs::Errno;

#[test]
fn pidfd_open_owns_a_descriptor_for_the_current_process() {
    let pid = process::getpid();
    let pidfd = match process::pidfd_open(pid, PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(Errno::NOSYS) => {
            eprintln!("skipping pidfd test: kernel lacks pidfd_open");
            return;
        }
        Err(error) => panic!("open a pidfd for the current process: {error:?}"),
    };

    assert!(pidfd.as_raw_fd() >= 0);
}

#[test]
fn pidfd_open_preserves_bounded_kernel_errors() {
    match process::pidfd_open(process::getpid(), PidfdFlags::empty()) {
        Ok(pidfd) => drop(pidfd),
        Err(Errno::NOSYS) => {
            eprintln!("skipping pidfd error checks: kernel lacks pidfd_open");
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
