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
fn system_layouts_match_linux_aarch64_kernel_abis() {
    assert_eq!(core::mem::size_of::<system::UtsName>(), 390);
    assert_eq!(core::mem::size_of::<system::Sysinfo>(), 112);
}

#[test]
fn resource_usage_layout_matches_linux_aarch64_initialized_prefix() {
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
