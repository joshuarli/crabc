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
fn x86_64_gettimeofday_writes_one_normalized_private_record() {
    #[repr(C)]
    struct GuardedWallClock {
        value: crate::time::KernelWallClockParts,
        trailing_guard: [u8; 32],
    }

    let mut output = GuardedWallClock {
        value: crate::time::KernelWallClockParts {
            seconds: 0,
            microseconds: 0,
        },
        trailing_guard: [0xa5; 32],
    };

    // SAFETY: `value` is one aligned, live private timeval record. The guard
    // makes the direct x86 syscall's exact output-record boundary observable.
    unsafe { crate::time::gettimeofday_raw(core::ptr::addr_of_mut!(output.value)) }
        .expect("direct x86 gettimeofday initializes the private timeval record");

    assert!(
        (0..1_000_000).contains(&output.value.microseconds),
        "Linux normalizes successful timeval microseconds"
    );
    assert_eq!(output.trailing_guard, [0xa5; 32]);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_posix_timer_writes_exact_id_and_old_setting_records() {
    #[repr(C)]
    struct KernelSigevent {
        value: usize,
        signal: i32,
        notify: i32,
        padding: [i32; 12],
    }

    #[repr(C)]
    struct GuardedTimerId {
        value: i32,
        trailing_guard: [u8; 32],
    }

    #[repr(C)]
    struct GuardedTimerSpec {
        value: crate::time::KernelItimerspec,
        trailing_guard: [u8; 32],
    }

    const _: () = assert!(core::mem::size_of::<KernelSigevent>() == 64);
    const _: () = assert!(core::mem::align_of::<KernelSigevent>() == 8);

    let event = KernelSigevent {
        value: 0,
        signal: 0,
        // `SIGEV_NONE`: create a timer with no signal or callback side effect.
        notify: 1,
        padding: [0; 12],
    };
    let mut timer_id = GuardedTimerId {
        value: -1,
        trailing_guard: [0xa5; 32],
    };

    // SAFETY: `event` is one initialized private 64-byte x86-64 sigevent,
    // and `timer_id.value` is aligned writable storage for the kernel's i32
    // output. Its guard makes that output boundary observable.
    let status = unsafe {
        crate::time::timer_create_raw(
            1,
            core::ptr::addr_of!(event).cast(),
            core::ptr::addr_of_mut!(timer_id.value),
        )
    }
    .expect("direct x86 timer_create initializes a private timer ID");
    assert_eq!(status, 0);
    assert!(timer_id.value >= 0);
    assert_eq!(timer_id.trailing_guard, [0xa5; 32]);

    let disarmed = crate::time::KernelItimerspec {
        it_interval: crate::time::KernelTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: crate::time::KernelTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let mut old = GuardedTimerSpec {
        value: disarmed,
        trailing_guard: [0x5a; 32],
    };

    // `timer_settime` has four x86-64 syscall arguments. A successful old
    // setting proves that its fourth pointer reached the required `r10`
    // register, while the guard proves Linux wrote exactly one itimerspec.
    let operation = unsafe {
        crate::time::timer_settime_raw(
            timer_id.value,
            0,
            core::ptr::addr_of!(disarmed),
            core::ptr::addr_of_mut!(old.value),
        )
    };
    let delete = crate::time::timer_delete_raw(timer_id.value);
    operation.expect("direct x86 timer_settime returns the old private record");
    delete.expect("delete direct x86 SIGEV_NONE evidence timer");

    assert_eq!(old.value, disarmed);
    assert_eq!(old.trailing_guard, [0x5a; 32]);
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

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_preadv2_pwritev2_preserve_split_offsets_and_sixth_flags() {
    use core::ffi::CStr;

    // `memfd_create` gives this ABI test a private anonymous regular file:
    // no fixed pathname can collide with another test process, and closing
    // the descriptor releases it even if an assertion below panics.
    let name = CStr::from_bytes_with_nul(b"crabc-core-x86-64-preadv2\0")
        .expect("fixed memfd name is NUL-terminated");
    let fd = crate::fs::memfd_create(name, 0).expect("create anonymous I/O evidence file");

    let operation = (|| -> crate::Result<()> {
        // Linux `pwritev2` takes six raw syscall words. `RWF_APPEND` must
        // arrive in x86-64's sixth word (`r9`): despite the positioned zero
        // offset, the second byte must appear after this initial byte.
        crate::io::write(fd, b"A")?;
        let appended = b"B";
        let append_iovec = [crate::io::Iovec {
            iov_base: appended.as_ptr().cast_mut(),
            iov_len: appended.len(),
        }];
        // SAFETY: The iovec and its byte slice remain live and readable for
        // this synchronous kernel call.
        assert_eq!(
            unsafe { crate::io::pwritev2_raw(fd, append_iovec.as_ptr(), 1, 0, 0x10) }?,
            1,
        );

        let mut beginning = [0u8; 2];
        let beginning_iovec = [crate::io::Iovec {
            iov_base: beginning.as_mut_ptr(),
            iov_len: beginning.len(),
        }];
        // SAFETY: The iovec and its output buffer remain live and writable
        // for this synchronous kernel call.
        assert_eq!(
            unsafe { crate::io::preadv2_raw(fd, beginning_iovec.as_ptr(), 1, 0, 0) }?,
            2,
        );
        assert_eq!(beginning, *b"AB");

        // A nonzero high word distinguishes the raw split-offset ABI from a
        // superficially plausible four-word positioned-I/O call. The low
        // offset is deliberately a hole: a misplaced high word would change
        // this byte instead of the sparse location below.
        const HIGH_OFFSET: u64 = 0x0000_0001_0000_0007;
        let high_byte = b"H";
        let high_iovec = [crate::io::Iovec {
            iov_base: high_byte.as_ptr().cast_mut(),
            iov_len: high_byte.len(),
        }];
        // SAFETY: The iovec and its byte slice remain live and readable for
        // this synchronous kernel call.
        assert_eq!(
            unsafe { crate::io::pwritev2_raw(fd, high_iovec.as_ptr(), 1, HIGH_OFFSET, 0) }?,
            1,
        );

        let mut low_byte = [0xff];
        let low_iovec = [crate::io::Iovec {
            iov_base: low_byte.as_mut_ptr(),
            iov_len: low_byte.len(),
        }];
        // SAFETY: The iovec and its output buffer remain live and writable
        // for this synchronous kernel call.
        assert_eq!(
            unsafe { crate::io::preadv2_raw(fd, low_iovec.as_ptr(), 1, 7, 0) }?,
            1,
        );
        assert_eq!(low_byte, [0], "high offset was truncated to its low word");

        let mut high_read = [0u8];
        let high_read_iovec = [crate::io::Iovec {
            iov_base: high_read.as_mut_ptr(),
            iov_len: high_read.len(),
        }];
        // SAFETY: The iovec and its output buffer remain live and writable
        // for this synchronous kernel call.
        assert_eq!(
            unsafe { crate::io::preadv2_raw(fd, high_read_iovec.as_ptr(), 1, HIGH_OFFSET, 0) }?,
            1,
        );
        assert_eq!(high_read, *b"H");
        Ok(())
    })();

    let close = crate::io::close(fd);
    operation.expect("x86 preadv2/pwritev2 argument sequence");
    close.expect("close anonymous I/O evidence descriptor");
}
