//! Bounded Linux/x86-64 mount and unmount requests.
//!
//! This private facade owns only checked non-null source, target, and
//! filesystem-type pathname conversion plus optional borrowed C-string data.
//! It preserves direct Linux `mount(2)` and `umount2(2)` errors without a C
//! ABI or thread-local `errno` boundary. Successful mount-namespace mutation,
//! null source/type forms, arbitrary data pointers, propagation policy, and
//! newer filesystem-descriptor mount APIs are not provided.

use bitflags::bitflags;
use core::ffi::CStr;

use crate::fs::PathArg;
use crate::Result;

bitflags! {
    /// Linux `MS_*` mount flags.
    ///
    /// These direct Linux bits are retained for the existing mount request
    /// vocabulary. Bind, remount, propagation, and mount-namespace policy
    /// are left to the kernel and the caller.
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct MountFlags: u64 {
        const RDONLY = 1;
        const NOSUID = 2;
        const NODEV = 4;
        const NOEXEC = 8;
        const SYNCHRONOUS = 16;
        const REMOUNT = 32;
        const MANDLOCK = 64;
        const DIRSYNC = 128;
        const NOATIME = 1024;
        const NODIRATIME = 2048;
        const BIND = 4096;
        const MOVE = 8192;
        const REC = 16384;
        const SILENT = 32768;
        const POSIXACL = 1 << 16;
        const UNBINDABLE = 1 << 17;
        const PRIVATE = 1 << 18;
        const SLAVE = 1 << 19;
        const SHARED = 1 << 20;
        const RELATIME = 1 << 21;
        const KERNMOUNT = 1 << 22;
        const I_VERSION = 1 << 23;
        const STRICTATIME = 1 << 24;
        const LAZYTIME = 1 << 25;
        const _ = !0;
    }
}

bitflags! {
    /// Linux `MNT_*` unmount flags.
    ///
    /// Detachment and namespace effects are whatever the kernel does for the
    /// direct request.
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct UnmountFlags: i32 {
        const FORCE = 1;
        const DETACH = 2;
        const EXPIRE = 4;
        const NOFOLLOW = 8;
        const _ = !0;
    }
}

/// Requests a Linux filesystem mount.
///
/// All three mandatory pathname-like arguments are non-null, byte-oriented,
/// and checked for interior NUL bytes before the direct syscall. `data` is
/// either null or a borrowed NUL-terminated C string. A successful request
/// changes the calling process's mount namespace and is deliberately not a
/// sandbox or namespace-management API.
#[inline]
pub fn mount<'a, Source: PathArg, Target: PathArg, Fs: PathArg>(
    source: Source,
    target: Target,
    file_system_type: Fs,
    flags: MountFlags,
    data: Option<&'a CStr>,
) -> Result<()> {
    source.into_with_c_str(|source| {
        target.into_with_c_str(|target| {
            file_system_type.into_with_c_str(|file_system_type| {
                crabc_core::mount::mount(Some(source), target, Some(file_system_type), flags.bits(), data)
            })
        })
    })
}

/// Requests a Linux unmount.
///
/// `target` is byte-oriented and checked for interior NUL bytes before the
/// direct syscall. A successful request changes the calling process's mount
/// namespace.
#[inline]
pub fn unmount<Target: PathArg>(target: Target, flags: UnmountFlags) -> Result<()> {
    target.into_with_c_str(|target| crabc_core::mount::umount2(target, flags.bits()))
}
