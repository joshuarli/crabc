//! Cross-domain structural tests for crabc-core.

use crate::{process, system, Errno};
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
