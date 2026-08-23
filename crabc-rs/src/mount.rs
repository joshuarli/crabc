//! Linux mount and unmount operations.

use bitflags::bitflags;
use core::ffi::CStr;

use crate::path::{option_into_with_c_str, Arg};
use crate::Result;

bitflags! {
    /// Linux `MS_*` mount flags.
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

/// Mounts a filesystem.
#[inline]
pub fn mount<'a, Source: Arg, Target: Arg, Fs: Arg, Data: Into<Option<&'a CStr>>>(
    source: Source,
    target: Target,
    file_system_type: Fs,
    flags: MountFlags,
    data: Data,
) -> Result<()> {
    source.into_with_c_str(|source| {
        target.into_with_c_str(|target| {
            file_system_type.into_with_c_str(|file_system_type| {
                option_into_with_c_str(data.into(), |data| {
                    crabc_core::mount::mount(
                        Some(source),
                        target,
                        Some(file_system_type),
                        flags.bits(),
                        data,
                    )
                })
            })
        })
    })
}

/// Unmounts a filesystem.
#[inline]
pub fn unmount<Target: Arg>(target: Target, flags: UnmountFlags) -> Result<()> {
    target.into_with_c_str(|target| crabc_core::mount::umount2(target, flags.bits()))
}
