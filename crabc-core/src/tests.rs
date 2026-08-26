//! Cross-domain structural tests for crabc-core.

use crate::{param, process, system, thread, Errno};
use crate::syscall::decode_i32;

#[test]
fn errno_accepts_only_linux_syscall_values() {
    assert_eq!(Errno::from_raw(0), None);
    assert_eq!(Errno::from_raw(4096), None);
    assert_eq!(Errno::from_raw(2).unwrap().raw(), 2);
}

#[test]
fn system_layouts_match_linux_64_bit_kernel_abis() {
    assert_eq!(core::mem::size_of::<system::UtsName>(), 390);
    assert_eq!(core::mem::size_of::<system::Sysinfo>(), 112);
}

#[test]
fn resource_usage_layout_matches_linux_64_bit_initialized_prefix() {
    assert_eq!(core::mem::size_of::<process::KernelRusageTimeval>(), 16);
    assert_eq!(core::mem::size_of::<process::KernelRusage>(), 144);
}

#[test]
fn ioctl_result_keeps_negative_non_errno_successes() {
    assert_eq!(decode_i32(0), Ok(0));
    assert_eq!(decode_i32(-1), Err(Errno::from_raw(1).unwrap()));
    assert_eq!(decode_i32(-4095), Err(Errno::from_raw(4095).unwrap()));
    assert_eq!(decode_i32(-4096), Ok(-4096));
}

#[test]
fn at_random_keeps_the_linux_auxv_tag_without_dereferencing_it() {
    assert_eq!(param::AT_RANDOM, 25);
}

#[test]
fn thread_pointer_identity_is_stable_for_the_calling_thread() {
    let first = thread::thread_pointer_identity();
    let second = thread::thread_pointer_identity();

    assert_ne!(first, 0, "Linux thread pointer must identify the calling thread");
    assert_eq!(second, first, "thread pointer changed within one thread");
}

#[test]
fn getcpu_preserves_the_cpu_observation_used_by_sched_getcpu() {
    let location = thread::getcpu().expect("getcpu with private output storage");

    // `sched_getcpu` remains the CPU-only view of the same syscall seam. Do
    // not compare two observations: Linux may migrate this thread between
    // the calls.
    let cpu_only = thread::sched_getcpu();
    let _numa_node = location.numa_node;
    assert!(u32::try_from(cpu_only).is_ok());
}

#[test]
fn prctl_raw_preserves_invalid_kernel_argument_errors() {
    // An unknown option has no pointer arguments, so this exercises the raw
    // five-word syscall result without introducing process policy.
    assert_eq!(
        unsafe { process::prctl_raw(-1, 0, 0, 0, 0) },
        Err(Errno::INVAL)
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_openat_mode_and_direct_io_follow_the_kernel_abi() {
    use core::ffi::CStr;

    const O_RDWR: i32 = 0x0002;
    const O_CREAT: i32 = 0x0040;
    const O_EXCL: i32 = 0x0080;
    const STATX_MODE: u32 = 0x0002;
    const MODE_OFFSET: usize = 28;
    let path = CStr::from_bytes_with_nul(b"/tmp/crabc-core-x86_64-openat-evidence\0")
        .expect("fixed test path is NUL-terminated");

    // A stale file can only come from an interrupted earlier test process.
    // `unlinkat` is deliberately ignored here because ENOENT is expected for
    // a clean start and every later result remains checked explicitly.
    let _ = crate::fs::unlinkat(crate::AT_FDCWD, path, 0);

    // `openat` has four Linux syscall arguments. Its nonzero mode reaches
    // x86-64's required fourth syscall register (`r10`), so a successful
    // `statx` observation below is a direct behavior proof rather than a
    // compile-only register assertion.
    let old_umask = crate::process::umask_raw(0);
    struct RestoreUmask(u32);
    impl Drop for RestoreUmask {
        fn drop(&mut self) {
            let _ = crate::process::umask_raw(self.0);
        }
    }
    let _restore_umask = RestoreUmask(old_umask);

    let fd = crate::fs::openat(
        crate::AT_FDCWD,
        path,
        O_RDWR | O_CREAT | O_EXCL,
        0o600,
    )
    .expect("x86 openat creates the evidence file");

    let operation = (|| -> crate::Result<(usize, i64, usize, [u8; 3], u16)> {
        let written = crate::io::write(fd, b"x86")?;
        let offset = crate::fs::lseek(fd, 0, crate::fs::SEEK_SET)?;
        let mut bytes = [0u8; 3];
        let read = crate::io::read(fd, &mut bytes)?;
        let mut statx = [0u8; 256];
        // SAFETY: `path` is a live NUL-terminated C string and `statx` owns
        // the complete 256-byte Linux output record for this syscall.
        unsafe {
            crate::fs::statx_raw(
                crate::AT_FDCWD,
                path.as_ptr().cast(),
                0,
                STATX_MODE,
                statx.as_mut_ptr(),
            )?;
        }
        let mode = u16::from_le_bytes([statx[MODE_OFFSET], statx[MODE_OFFSET + 1]]) & 0o777;
        Ok((written, offset, read, bytes, mode))
    })();

    let close = crate::io::close(fd);
    let remove = crate::fs::unlinkat(crate::AT_FDCWD, path, 0);
    let (written, offset, read, bytes, mode) = operation.expect("direct x86 file sequence");
    close.expect("close evidence descriptor");
    remove.expect("remove evidence file");

    assert_eq!(written, 3);
    assert_eq!(offset, 0);
    assert_eq!(read, 3);
    assert_eq!(bytes, *b"x86");
    assert_eq!(mode, 0o600);
    assert_eq!(crate::io::close(-1), Err(Errno::BADF));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_futex_wait_and_wake_preserve_the_six_word_kernel_call() {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    let word = Arc::new(AtomicU32::new(0));
    let entered_wait_loop = Arc::new(AtomicBool::new(false));
    let worker_word = Arc::clone(&word);
    let worker_entered_wait_loop = Arc::clone(&entered_wait_loop);
    let worker = std::thread::spawn(move || {
        worker_entered_wait_loop.store(true, Ordering::Release);
        while worker_word.load(Ordering::Acquire) == 0 {
            // SAFETY: `AtomicU32` supplies one aligned, live kernel futex
            // word. The null timeout and secondary pointers select the exact
            // `FUTEX_WAIT` form, and the zero sixth argument remains part of
            // the Linux six-word syscall ABI.
            match unsafe {
                crate::thread::futex_wait(
                    worker_word.as_ptr(),
                    0,
                    true,
                    core::ptr::null(),
                )
            } {
                Ok(()) => {}
                Err(error) if error == Errno::AGAIN || error == Errno::INTR => {}
                Err(error) => panic!("x86 futex wait failed: {}", error.raw()),
            }
        }
    });

    while !entered_wait_loop.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    word.store(1, Ordering::Release);
    // SAFETY: `word` remains aligned and live until after the worker joins.
    let woken = unsafe { crate::thread::futex_wake(word.as_ptr(), 1, true) }
        .expect("x86 futex wake");
    assert!(woken <= 1, "one waiter cannot wake more than once");
    worker.join().expect("futex waiter returns after publication");
}
