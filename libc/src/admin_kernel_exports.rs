// filesystem ownership and identity exports.
//
// These entry points intentionally pass through to Linux.  In particular,
// ownership changes are not made to appear successful when the caller lacks
// the kernel's permission (CAP_CHOWN); syscall_result preserves that errno
// boundary for the C ABI.  The generic 64-bit targets use fchownat for the
// path-only variants because their kernel ABI does not provide the legacy
// chown/lchown syscall numbers used by x86_64.

#[cfg(target_arch = "x86_64")]
const CABI_SYS_CHOWN: i64 = 92;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_FCHOWN: i64 = 93;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_LCHOWN: i64 = 94;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_FCHOWNAT: i64 = 260;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_CHROOT: i64 = 161;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SETFSUID: i64 = 122;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_SETFSGID: i64 = 123;

// AArch64 and RISC-V use the asm-generic syscall ABI.  chown and lchown are
// represented by fchownat here so their follow/no-follow behavior remains
// explicit at the syscall boundary.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_FCHOWN: i64 = 55;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_FCHOWNAT: i64 = 54;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_CHROOT: i64 = 51;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SETFSUID: i64 = 151;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_SETFSGID: i64 = 152;

#[inline]
unsafe fn cabi_chown(path: *const c_char, owner: c_uint, group: c_uint) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        <Arch as Syscalls>::syscall3(CABI_SYS_CHOWN, path as i64, owner as i64, group as i64)
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        <Arch as Syscalls>::syscall5(
            CABI_SYS_FCHOWNAT,
            AT_FDCWD as i64,
            path as i64,
            owner as i64,
            group as i64,
            0,
        )
    }
}

#[inline]
unsafe fn cabi_fchown(fd: c_int, owner: c_uint, group: c_uint) -> i64 {
    <Arch as Syscalls>::syscall3(CABI_SYS_FCHOWN, fd as i64, owner as i64, group as i64)
}

#[inline]
unsafe fn cabi_fchownat(
    dirfd: c_int,
    path: *const c_char,
    owner: c_uint,
    group: c_uint,
    flags: c_int,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        CABI_SYS_FCHOWNAT,
        dirfd as i64,
        path as i64,
        owner as i64,
        group as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn cabi_lchown(path: *const c_char, owner: c_uint, group: c_uint) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        <Arch as Syscalls>::syscall3(CABI_SYS_LCHOWN, path as i64, owner as i64, group as i64)
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        <Arch as Syscalls>::syscall5(
            CABI_SYS_FCHOWNAT,
            AT_FDCWD as i64,
            path as i64,
            owner as i64,
            group as i64,
            AT_SYMLINK_NOFOLLOW as i64,
        )
    }
}

#[inline]
unsafe fn cabi_chroot(path: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall1(CABI_SYS_CHROOT, path as i64)
}

#[inline]
unsafe fn cabi_setfsuid(uid: c_uint) -> i64 {
    <Arch as Syscalls>::syscall1(CABI_SYS_SETFSUID, uid as i64)
}

#[inline]
unsafe fn cabi_setfsgid(gid: c_uint) -> i64 {
    <Arch as Syscalls>::syscall1(CABI_SYS_SETFSGID, gid as i64)
}

#[no_mangle]
pub unsafe extern "C" fn chown(path: *const c_char, owner: c_uint, group: c_uint) -> c_int {
    syscall_result(cabi_chown(path, owner, group)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fchown(fd: c_int, owner: c_uint, group: c_uint) -> c_int {
    syscall_result(cabi_fchown(fd, owner, group)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fchownat(
    dirfd: c_int,
    path: *const c_char,
    owner: c_uint,
    group: c_uint,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_fchownat(dirfd, path, owner, group, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lchown(path: *const c_char, owner: c_uint, group: c_uint) -> c_int {
    syscall_result(cabi_lchown(path, owner, group)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    syscall_result(cabi_chroot(path)) as c_int
}

// Linux returns the previous filesystem UID/GID rather than a conventional
// zero-on-success result.  Keep that value intact while still translating a
// true syscall failure into -1/errno.
#[no_mangle]
pub unsafe extern "C" fn setfsuid(uid: c_uint) -> c_int {
    syscall_result(cabi_setfsuid(uid)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setfsgid(gid: c_uint) -> c_int {
    syscall_result(cabi_setfsgid(gid)) as c_int
}

// Linux capability queries and updates use a deliberately small, fixed ABI:
// the versioned header carries a 32-bit version and a signed pid, while each
// data word contains three 32-bit capability sets.  Keep the wrappers as raw
// syscalls so the kernel remains authoritative for both validation and
// permission checks; syscall_result translates only the public errno boundary.
#[repr(C)]
pub struct CabiCapUserHeader {
    pub version: u32,
    pub pid: c_int,
}

#[repr(C)]
pub struct CabiCapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[cfg(target_arch = "x86_64")]
const CABI_SYS_CAPGET: i64 = 125;
#[cfg(target_arch = "x86_64")]
const CABI_SYS_CAPSET: i64 = 126;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_CAPGET: i64 = 90;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const CABI_SYS_CAPSET: i64 = 91;

#[inline]
unsafe fn cabi_capget(header: *mut CabiCapUserHeader, data: *mut CabiCapUserData) -> i64 {
    <Arch as Syscalls>::syscall2(CABI_SYS_CAPGET, header as i64, data as i64)
}

#[inline]
unsafe fn cabi_capset(header: *const CabiCapUserHeader, data: *const CabiCapUserData) -> i64 {
    <Arch as Syscalls>::syscall2(CABI_SYS_CAPSET, header as i64, data as i64)
}

#[no_mangle]
pub unsafe extern "C" fn capget(
    header: *mut CabiCapUserHeader,
    data: *mut CabiCapUserData,
) -> c_int {
    syscall_result(cabi_capget(header, data)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn capset(
    header: *const CabiCapUserHeader,
    data: *const CabiCapUserData,
) -> c_int {
    syscall_result(cabi_capset(header, data)) as c_int
}
