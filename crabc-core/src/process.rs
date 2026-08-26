//! Stateless Linux process operations.
//!
//! The full source surface is used by Linux/AArch64; staged Linux/x86-64
//! facades admit only individually evidenced operations from this module.

use core::{ffi::CStr, mem::MaybeUninit};

use crate::{RawFd, Result};
use crate::syscall::{decode, decode_i32, decode_i64, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, SYS_BRK, SYS_CHDIR, SYS_CHROOT, SYS_CLONE, SYS_EXECVE, SYS_EXIT_GROUP, SYS_FCHDIR, SYS_GETCWD, SYS_GETEGID, SYS_GETEUID, SYS_GETGID, SYS_GETGROUPS, SYS_GETPGID, SYS_GETPID, SYS_GETPPID, SYS_GETPRIORITY, SYS_GETRESGID, SYS_GETRESUID, SYS_GETRUSAGE, SYS_GETSID, SYS_GETUID, SYS_KILL, SYS_PIDFD_OPEN, SYS_PRCTL, SYS_PRLIMIT64, SYS_SCHED_GET_PRIORITY_MAX, SYS_SCHED_GET_PRIORITY_MIN, SYS_SETFSGID, SYS_SETFSUID, SYS_SETPGID, SYS_SETPRIORITY, SYS_SETSID, SYS_TGKILL, SYS_TIMES, SYS_UMASK, SYS_WAIT4, SYS_WAITID};

/// Linux's process-associated `struct flock` record used by
/// `fcntl(F_GETLK)`.
///
/// This is the fixed Linux record on both admitted 64-bit little-endian
/// targets. It remains a raw core record: the native facade validates its
/// fields before exposing them as typed Rust values.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelFlock {
    /// Requested or observed lock kind (`F_RDLCK`, `F_WRLCK`, or `F_UNLCK`).
    pub l_type: i16,
    /// Byte-offset origin (`SEEK_SET`, `SEEK_CUR`, or `SEEK_END`).
    pub l_whence: i16,
    /// Starting byte offset.
    pub l_start: i64,
    /// Number of bytes, with zero extending through end of file.
    pub l_len: i64,
    /// Process holding an observed conflicting lock.
    pub l_pid: i32,
}

const _: [(); 32] = [(); core::mem::size_of::<KernelFlock>()];
const _: [(); 8] = [(); core::mem::align_of::<KernelFlock>()];

/// Queries the first process-associated record lock that would block the
/// supplied lock through Linux's direct `fcntl(F_GETLK)` seam.
///
/// The record is initialized by the caller and overwritten by Linux on
/// success. The raw lock kind, offset origin, range, and PID remain
/// unvalidated so the native facade can enforce its typed vocabulary.
#[inline]
pub fn fcntl_getlk_raw(fd: RawFd, lock: &mut KernelFlock) -> Result<()> {
    const F_GETLK: i32 = 5;

    // SAFETY: `lock` is live writable storage for the complete Linux
    // `struct flock` record for the duration of this direct query.
    unsafe {
        crate::io::fcntl_raw(fd, F_GETLK, (lock as *mut KernelFlock).cast())
    }
    .map(|_| ())
}

/// Invokes Linux's five-word `prctl` syscall ABI directly.
///
/// Linux receives `option` followed by its four option-specific `unsigned
/// long` argument words. This raw seam deliberately owns no `PR_*` constant
/// set, VMA name, transparent-huge-page setting, default, fallback, or
/// process policy. Successful `PR_GET_*` operations retain their raw scalar
/// result, while failures remain direct [`Errno`] values.
///
/// # Safety
///
/// The caller must uphold the complete Linux contract for `option` and all
/// four argument words. In particular, every word interpreted by the selected
/// option as a pointer must have the required alignment, validity, mutability,
/// and lifetime for the syscall. The caller must also coordinate any selected
/// operation's process-wide or calling-thread state transition with code that
/// depends on that state.
#[inline]
pub unsafe fn prctl_raw(
    option: i32,
    argument2: usize,
    argument3: usize,
    argument4: usize,
    argument5: usize,
) -> Result<usize> {
    // SAFETY: The caller owns the selected prctl option's complete pointer
    // and state-transition contract; the raw words otherwise map one-to-one
    // onto x0 through x4 in Linux's AArch64 syscall ABI.
    decode(unsafe {
        syscall5(
            SYS_PRCTL,
            option as usize,
            argument2,
            argument3,
            argument4,
            argument5,
        )
    })
}

/// Queries or requests Linux's current program break.
///
/// Linux's `brk` syscall does not use the ordinary `-errno` return
/// convention: it returns the resulting current break, including the
/// unchanged break when a requested increase cannot be satisfied.  The
/// C `brk` and `sbrk` adapters compare this value with their request and
/// provide their respective sentinel/`errno` contracts.  Native callers
/// receive the kernel value directly and must perform any policy or
/// comparison themselves.
///
/// # Safety
///
/// `address` is passed directly to Linux.  It may be null to query the
/// current break; otherwise the caller must obey the Linux program-break
/// address contract and coordinate with any allocator owning the heap.
#[inline]
pub unsafe fn brk_raw(address: *mut u8) -> *mut u8 {
    // SAFETY: The caller owns the Linux program-break contract.  Unlike
    // ordinary syscalls, `brk` returns a valid pointer on allocation
    // failure rather than a negative errno encoding.
    unsafe { syscall1(SYS_BRK, address as usize) as usize as *mut u8 }
}

/// Opens a Linux process file descriptor through `pidfd_open`.
///
/// `pid` is a non-zero Linux process or thread ID and `flags` retains the
/// kernel's `PIDFD_*` bit representation. Linux validates unknown flags
/// and target lifetime; those errors remain ordinary [`Errno`] values.
#[inline]
pub fn pidfd_open_raw(pid: i32, flags: u32) -> Result<RawFd> {
    // SAFETY: Both arguments are immediate Linux syscall values.
    // A successful pidfd_open result is a newly allocated descriptor.
    decode_i32(unsafe { syscall2(SYS_PIDFD_OPEN, pid as usize, flags as usize) })
}

/// The Linux `struct rlimit64` returned by `prlimit64` on the admitted
/// 64-bit targets.
///
/// This is the exact two-word kernel ABI record. It remains separate from
/// the safe facade's infinity-aware `Rlimit` mapping.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelRlimit64 {
    /// Soft/current limit, or Linux `RLIM64_INFINITY`.
    pub rlim_cur: u64,
    /// Hard/maximum limit, or Linux `RLIM64_INFINITY`.
    pub rlim_max: u64,
}

const _: () = assert!(core::mem::size_of::<KernelRlimit64>() == 16);
const _: () = assert!(core::mem::align_of::<KernelRlimit64>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelRlimit64, rlim_cur) == 0);
const _: () = assert!(core::mem::offset_of!(KernelRlimit64, rlim_max) == 8);

/// Reads one target process's resource limit through Linux `prlimit64`
/// without libc or TLS `errno`.
///
/// This is a raw core seam: `pid` is the Linux `pid_t` selector and
/// `resource` is the Linux `RLIMIT_*` number. PID zero asks the kernel for
/// the calling process; null `new_limit` makes this query read-only. The
/// public facade supplies the typed process and resource vocabulary.
#[inline]
pub fn getrlimit_for_raw(pid: i32, resource: u32) -> Result<KernelRlimit64> {
    let mut result = MaybeUninit::<KernelRlimit64>::uninit();
    // SAFETY: Linux writes the complete `rlimit64` record on success;
    // `new_limit = NULL` makes this a read-only query and the output
    // storage remains live for the syscall.
    decode(unsafe {
        syscall4(
            SYS_PRLIMIT64,
            pid as usize,
            resource as usize,
            0,
            result.as_mut_ptr() as usize,
        )
    })?;
    // SAFETY: Successful prlimit64 initialized both ABI words above.
    Ok(unsafe { result.assume_init() })
}

/// Reads the calling process's resource limit through Linux `prlimit64`.
#[inline]
pub fn getrlimit_raw(resource: u32) -> Result<KernelRlimit64> {
    getrlimit_for_raw(0, resource)
}

/// Changes the calling process's resource limit through Linux `prlimit64`.
///
/// This core seam deliberately targets PID zero, passes a fully
/// initialized kernel `rlimit64`, and requests no old-limit output. The
/// typed facade performs any infinity/value validation before crossing
/// this boundary.
#[inline]
pub fn setrlimit_raw(resource: u32, limit: &KernelRlimit64) -> Result<()> {
    // SAFETY: `limit` remains readable for this syscall and is an exact
    // Linux `struct rlimit64` record on the admitted 64-bit targets.
    decode(unsafe {
        syscall4(
            SYS_PRLIMIT64,
            0,
            resource as usize,
            limit as *const KernelRlimit64 as usize,
            0,
        )
    })
    .map(|_| ())
}

/// Changes the calling process's file-creation mask and returns the old
/// mask. Linux's `umask` syscall always returns the previous mask.
#[inline]
pub fn umask_raw(mask: u32) -> u32 {
    // SAFETY: `mask` is an immediate Linux mode word and the syscall's
    // return value is the previous mask rather than an errno encoding.
    unsafe { syscall1(SYS_UMASK, mask as usize) as u32 }
}

/// One Linux/AArch64 `struct timeval` as embedded in `struct rusage`.
///
/// The pinned musl target uses 64-bit `time_t` and `suseconds_t`, and the
/// Linux kernel ABI uses the same two signed 64-bit words for its old
/// timeval record. This is the kernel record only; it is not a public C
/// `timeval` alias.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelRusageTimeval {
    /// Whole seconds of CPU time.
    pub tv_sec: i64,
    /// Microseconds within the second.
    pub tv_usec: i64,
}

/// The initialized Linux/AArch64 portion of `struct rusage`.
///
/// Linux's `getrusage` syscall writes these 144 bytes: two old timeval
/// records followed by fourteen signed `long` counters. Musl's public
/// `struct rusage` appends sixteen reserved `long` words for source
/// compatibility; the kernel does not initialize that tail, so this
/// direct seam deliberately omits it. The native facade exposes only the
/// named initialized observations below.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelRusage {
    /// User CPU time.
    pub ru_utime: KernelRusageTimeval,
    /// System CPU time.
    pub ru_stime: KernelRusageTimeval,
    /// Maximum resident-set size in KiB on Linux.
    pub ru_maxrss: i64,
    /// Integral shared-memory size (historical Linux field).
    pub ru_ixrss: i64,
    /// Integral unshared-data size (historical Linux field).
    pub ru_idrss: i64,
    /// Integral unshared-stack size (historical Linux field).
    pub ru_isrss: i64,
    /// Number of minor page faults.
    pub ru_minflt: i64,
    /// Number of major page faults.
    pub ru_majflt: i64,
    /// Number of swaps (historical Linux field).
    pub ru_nswap: i64,
    /// Block input operations.
    pub ru_inblock: i64,
    /// Block output operations.
    pub ru_oublock: i64,
    /// IPC messages sent (historical Linux field).
    pub ru_msgsnd: i64,
    /// IPC messages received (historical Linux field).
    pub ru_msgrcv: i64,
    /// Signals received (historical Linux field).
    pub ru_nsignals: i64,
    /// Voluntary context switches.
    pub ru_nvcsw: i64,
    /// Involuntary context switches.
    pub ru_nivcsw: i64,
}

/// Reads one Linux resource-usage record through `getrusage`.
///
/// `who` is the raw Linux `RUSAGE_*` selector. The typed facade supplies
/// the closed selector vocabulary; this core seam keeps the kernel token
/// explicit and does not accept a caller-provided output pointer. Linux
/// initializes only [`KernelRusage`]'s 144-byte record; the reserved tail
/// present in musl's public C struct is intentionally not represented.
#[inline]
pub fn getrusage_raw(who: i32) -> Result<KernelRusage> {
    let mut result = MaybeUninit::<KernelRusage>::uninit();
    // SAFETY: `result` is writable storage for exactly the initialized
    // Linux/AArch64 getrusage record, and Linux writes all fields on a
    // successful call. `who` is an immediate selector value.
    decode(unsafe { syscall2(SYS_GETRUSAGE, who as usize, result.as_mut_ptr() as usize) })?;
    // SAFETY: Successful getrusage initialized every field in the
    // kernel-sized record above; no reserved musl tail is read.
    Ok(unsafe { result.assume_init() })
}

/// The four initialized Linux/AArch64 words written by `times(2)`.
///
/// Linux's native `struct tms` uses four signed 64-bit `clock_t` words on
/// AArch64. This is an internal kernel record rather than a public C ABI
/// type; the native facade validates the non-negative process-accounting
/// values before exposing them as Rust tick values.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelProcessTimes {
    /// User CPU time consumed by the calling process, in clock ticks.
    pub user_ticks: i64,
    /// System CPU time consumed by the calling process, in clock ticks.
    pub system_ticks: i64,
    /// User CPU time of waited-for terminated children, in clock ticks.
    pub children_user_ticks: i64,
    /// System CPU time of waited-for terminated children, in clock ticks.
    pub children_system_ticks: i64,
}

/// The process-accounting record and independent elapsed-tick result of
/// one Linux `times(2)` query.
///
/// Linux's syscall return is not another `struct tms` field: it is the
/// number of clock ticks since a kernel-defined arbitrary point. It is
/// retained separately so callers cannot confuse elapsed system ticks
/// with this process's CPU-accounting fields.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelProcessTimesObservation {
    /// The four words written to the caller's `struct tms` storage.
    pub process: KernelProcessTimes,
    /// The syscall's independent elapsed-tick return value.
    pub elapsed_ticks: i64,
}

/// Reads Linux process accounting through the native `times` syscall.
///
/// A caller-owned pointer is deliberately not exposed here: this seam
/// provides private initialized storage for the exact AArch64 record and
/// returns it by value. The kernel's signed `clock_t` return is decoded as
/// an ordinary syscall result; the four process-accounting words are
/// checked for their documented non-negative range. No C ABI, allocator,
/// vDSO, or TLS `errno` is involved.
#[inline]
pub fn times_raw() -> Result<KernelProcessTimesObservation> {
    let mut process = MaybeUninit::<KernelProcessTimes>::uninit();
    // SAFETY: `process` is writable storage for Linux/AArch64's exact
    // four-word `struct tms`; the kernel initializes all words on success.
    let elapsed_ticks =
        decode_i64(unsafe { syscall1(SYS_TIMES, process.as_mut_ptr() as usize) })?;
    // SAFETY: A successful times syscall initializes all four words.
    let process = unsafe { process.assume_init() };
    if process.user_ticks < 0
        || process.system_ticks < 0
        || process.children_user_ticks < 0
        || process.children_system_ticks < 0
    {
        // A conforming Linux kernel reports non-negative process times;
        // never reinterpret a malformed record as a valid Rust value.
        return Err(crate::Errno::RANGE);
    }
    Ok(KernelProcessTimesObservation {
        process,
        elapsed_ticks,
    })
}

/// Reads one Linux scheduling-priority observation through the native
/// `getpriority` syscall.
///
/// Linux deliberately does not return the usual nice value here. To keep
/// every successful result non-negative, the kernel encodes nice values
/// `[-20, 19]` as `[(19 - nice) + 1]`, or `[40, 1]`; musl and Rustix both
/// translate that value with `20 - raw`. This core seam preserves the
/// kernel's encoded success value so the native facade can make that
/// translation at its typed boundary. A negative syscall result in
/// Linux's `-errno` range is decoded into the ordinary [`Errno`] result.
#[inline]
pub fn getpriority_raw(which: i32, who: u32) -> Result<i32> {
    // SAFETY: `which` and `who` are immediate Linux scalar arguments. The
    // public facade supplies the closed selector and identifier types.
    decode_i32(unsafe { syscall2(SYS_GETPRIORITY, which as usize, who as usize) })
}

/// Reads one Linux scheduler policy's maximum and minimum priority.
///
/// The raw policy remains an integer so Linux can report `EINVAL`; the
/// native facade supplies its closed policy vocabulary and validates the
/// returned ordering. The two calls are read-only scalar observations.
#[inline]
pub fn scheduler_priority_bounds_raw(policy: i32) -> Result<(i32, i32)> {
    let maximum = decode_i32(unsafe { syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as usize) })?;
    let minimum = decode_i32(unsafe { syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as usize) })?;
    Ok((minimum, maximum))
}

/// Sets one Linux scheduling-priority target through `setpriority`.
///
/// `which` and `who` retain the Linux `PRIO_*` selector encoding while the
/// native facade supplies the closed target and priority types. Kernel
/// permission and target errors remain ordinary [`Errno`] values; this
/// seam does not translate through libc's TLS `errno` channel.
#[inline]
pub fn setpriority_raw(which: i32, who: u32, priority: i32) -> Result<()> {
    // SAFETY: All arguments are immediate Linux scalar values.
    decode(unsafe {
        syscall3(
            SYS_SETPRIORITY,
            which as usize,
            who as usize,
            priority as usize,
        )
    })
    .map(|_| ())
}

/// The low-byte clone exit signal used by Linux's fork-equivalent clone.
pub const CLONE_FORK_FLAGS: u64 = 17;

/// Returns the caller's Linux process ID.
#[inline]
pub fn getpid() -> i32 {
    // Linux guarantees that this syscall succeeds and returns a positive
    // process ID for a running task.
    unsafe { syscall0(SYS_GETPID) as i32 }
}

/// Returns the caller's Linux parent process ID, or zero for namespace init.
#[inline]
pub fn getppid() -> i32 {
    // Linux guarantees that this syscall succeeds. A zero parent is the
    // documented namespace-init/no-visible-parent representation.
    unsafe { syscall0(SYS_GETPPID) as i32 }
}

/// The Linux real, effective, and saved user IDs returned by
/// `getresuid`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelUidTriple {
    /// The process's real user ID.
    pub real: u32,
    /// The process's effective user ID.
    pub effective: u32,
    /// The process's saved-set user ID.
    pub saved: u32,
}

/// The Linux real, effective, and saved group IDs returned by
/// `getresgid`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KernelGidTriple {
    /// The process's real group ID.
    pub real: u32,
    /// The process's effective group ID.
    pub effective: u32,
    /// The process's saved-set group ID.
    pub saved: u32,
}

/// Reads the calling process's real, effective, and saved user IDs
/// through Linux's native `getresuid` syscall.
///
/// The output pointers are private caller-owned storage, so this seam is
/// read-only and does not expose C ABI pointers or TLS `errno` semantics.
#[inline]
pub fn getresuid_raw() -> Result<KernelUidTriple> {
    let mut real = MaybeUninit::<u32>::uninit();
    let mut effective = MaybeUninit::<u32>::uninit();
    let mut saved = MaybeUninit::<u32>::uninit();
    // SAFETY: Each pointer addresses live, writable storage for one
    // Linux/AArch64 uid_t, and Linux initializes all three words on
    // success. The syscall has no process-mutating arguments.
    decode(unsafe {
        syscall3(
            SYS_GETRESUID,
            real.as_mut_ptr() as usize,
            effective.as_mut_ptr() as usize,
            saved.as_mut_ptr() as usize,
        )
    })?;
    // SAFETY: Successful getresuid initialized each output above.
    Ok(KernelUidTriple {
        real: unsafe { real.assume_init() },
        effective: unsafe { effective.assume_init() },
        saved: unsafe { saved.assume_init() },
    })
}

/// Reads the calling process's real, effective, and saved group IDs
/// through Linux's native `getresgid` syscall.
///
/// The output pointers are private caller-owned storage, so this seam is
/// read-only and does not expose C ABI pointers or TLS `errno` semantics.
#[inline]
pub fn getresgid_raw() -> Result<KernelGidTriple> {
    let mut real = MaybeUninit::<u32>::uninit();
    let mut effective = MaybeUninit::<u32>::uninit();
    let mut saved = MaybeUninit::<u32>::uninit();
    // SAFETY: Each pointer addresses live, writable storage for one
    // Linux/AArch64 gid_t, and Linux initializes all three words on
    // success. The syscall has no process-mutating arguments.
    decode(unsafe {
        syscall3(
            SYS_GETRESGID,
            real.as_mut_ptr() as usize,
            effective.as_mut_ptr() as usize,
            saved.as_mut_ptr() as usize,
        )
    })?;
    // SAFETY: Successful getresgid initialized each output above.
    Ok(KernelGidTriple {
        real: unsafe { real.assume_init() },
        effective: unsafe { effective.assume_init() },
        saved: unsafe { saved.assume_init() },
    })
}

/// Sets or queries the calling task's Linux filesystem user ID through
/// `setfsuid`.
///
/// Linux returns the previous filesystem user ID on both a successful and
/// an unsuccessful requested change. The all-ones input is the kernel's
/// query form and is therefore retained by this raw seam; the typed
/// facade owns its `Option<Uid>` conversion and rejects an explicit
/// all-ones value before reaching the syscall.
#[inline]
pub fn setfsuid_raw(uid: u32) -> Result<u32> {
    // SAFETY: `uid` is an immediate Linux uid_t word. Linux applies this
    // credential operation to the calling kernel task and returns the
    // previous filesystem UID as a scalar.
    decode(unsafe { syscall1(SYS_SETFSUID, uid as usize) }).map(|previous| previous as u32)
}

/// Sets or queries the calling task's Linux filesystem group ID through
/// `setfsgid`.
///
/// Linux returns the previous filesystem group ID on both a successful and
/// an unsuccessful requested change. The all-ones input is the kernel's
/// query form and is therefore retained by this raw seam; the typed
/// facade owns its `Option<Gid>` conversion and rejects an explicit
/// all-ones value before reaching the syscall.
#[inline]
pub fn setfsgid_raw(gid: u32) -> Result<u32> {
    // SAFETY: `gid` is an immediate Linux gid_t word. Linux applies this
    // credential operation to the calling kernel task and returns the
    // previous filesystem GID as a scalar.
    decode(unsafe { syscall1(SYS_SETFSGID, gid as usize) }).map(|previous| previous as u32)
}

/// Queries or fills the calling process's supplementary group IDs through
/// Linux's native `getgroups` syscall.
///
/// `groups` must be null when `length` is zero, which performs the Linux
/// count query. Otherwise it must point to writable storage for `length`
/// Linux/AArch64 `gid_t` values. Linux returns `EINVAL` when the storage
/// is too small; the caller may query again and retry because credentials
/// can change between the two syscalls.
///
/// # Safety
///
/// When `length` is non-zero, `groups` must be aligned and writable for
/// `length` `u32` values for the duration of the call. When `length` is
/// zero, `groups` must be null. The pointed-to storage is initialized only
/// for the number of groups returned by a successful fill.
#[inline]
pub unsafe fn getgroups_raw(groups: *mut u32, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies the output-storage contract; Linux
    // validates the requested count and supplementary-group snapshot.
    decode(unsafe { syscall2(SYS_GETGROUPS, length, groups as usize) })
}

/// Queries the current number of supplementary group IDs.
#[inline]
pub fn getgroups_count_raw() -> Result<usize> {
    // SAFETY: A zero-size Linux getgroups query requires a null list and
    // writes no caller memory.
    unsafe { getgroups_raw(core::ptr::null_mut(), 0) }
}

/// Copies the calling process's current working directory through Linux's
/// native `getcwd` syscall.
///
/// On success Linux initializes exactly the returned number of bytes and
/// includes the terminating NUL in that count. The caller must provide
/// writable storage for `length` bytes; the path pointer may be null only
/// when `length` is zero. A successful call always writes a NUL at the end
/// of the initialized prefix. Linux reports [`Errno::RANGE`] when the
/// supplied storage is too small.
///
/// # Safety
///
/// When `length` is non-zero, `buffer` must be aligned and writable for
/// `length` bytes for the duration of this call. A successful call
/// initializes only the returned prefix, including its trailing NUL.
#[inline]
pub unsafe fn getcwd_raw(buffer: *mut u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies writable output storage for the exact
    // requested length; Linux validates the pathname and size.
    decode(unsafe { syscall2(SYS_GETCWD, buffer as usize, length) })
}

/// Changes the calling process's current working directory through
/// Linux's native `chdir` syscall.
///
/// The CWD is process-global on Linux. This direct seam performs no
/// synchronization, and callers must coordinate concurrent pathname work
/// when using it through a native facade.
#[inline]
pub fn chdir(path: &CStr) -> Result<()> {
    // SAFETY: `CStr` keeps a readable, NUL-terminated pathname alive for
    // the syscall; Linux validates the path and directory permissions.
    decode(unsafe { syscall1(SYS_CHDIR, path.as_ptr() as usize) }).map(|_| ())
}

/// Changes the calling process's current working directory to the
/// directory referenced by `fd` through Linux's native `fchdir` syscall.
///
/// The CWD is process-global on Linux. This direct seam performs no
/// synchronization, and callers must coordinate concurrent pathname work
/// when using it through a native facade.
#[inline]
pub fn fchdir(fd: RawFd) -> Result<()> {
    // SAFETY: The descriptor is an immediate scalar; Linux validates that
    // it is open and references a directory accessible to the caller.
    decode(unsafe { syscall1(SYS_FCHDIR, fd as usize) }).map(|_| ())
}

/// Changes the calling process's root directory through Linux's native
/// `chroot` syscall.
///
/// This direct seam reports the kernel's permission, pathname, and
/// filesystem errors as [`Errno`] values. It does not change the current
/// working directory, and it does not close or otherwise preserve any
/// descriptor the caller may need after the root change.
#[inline]
pub fn chroot(path: &CStr) -> Result<()> {
    // SAFETY: `CStr` keeps a readable, NUL-terminated pathname alive for
    // the syscall; Linux validates the path and caller privilege.
    decode(unsafe { syscall1(SYS_CHROOT, path.as_ptr() as usize) }).map(|_| ())
}

/// Returns the caller's real Linux user ID.
#[inline]
pub fn getuid() -> u32 {
    // Linux guarantees that `getuid` succeeds and returns a `uid_t`.
    unsafe { syscall0(SYS_GETUID) as u32 }
}

/// Returns the caller's effective Linux user ID.
#[inline]
pub fn geteuid() -> u32 {
    // Linux guarantees that `geteuid` succeeds and returns a `uid_t`.
    unsafe { syscall0(SYS_GETEUID) as u32 }
}

/// Returns the caller's real Linux group ID.
#[inline]
pub fn getgid() -> u32 {
    // Linux guarantees that `getgid` succeeds and returns a `gid_t`.
    unsafe { syscall0(SYS_GETGID) as u32 }
}

/// Returns the caller's effective Linux group ID.
#[inline]
pub fn getegid() -> u32 {
    // Linux guarantees that `getegid` succeeds and returns a `gid_t`.
    unsafe { syscall0(SYS_GETEGID) as u32 }
}

/// Sends `signal` to the raw Linux process target `pid`.
#[inline]
pub fn kill(pid: i32, signal: i32) -> Result<()> {
    // SAFETY: Both arguments are immediate Linux scalar values.
    decode(unsafe { syscall2(SYS_KILL, pid as usize, signal as usize) }).map(|_| ())
}

/// Sends a signal to one exact thread in a process.
#[inline]
pub fn tgkill(tgid: i32, tid: i32, signal: i32) -> Result<()> {
    // SAFETY: All arguments are immediate Linux scalar values.
    decode(unsafe { syscall3(SYS_TGKILL, tgid as usize, tid as usize, signal as usize) })
        .map(|_| ())
}

/// Creates a child process using the raw Linux fork-equivalent clone.
///
/// This is deliberately only a kernel primitive. It does not run libc or
/// facade atfork handlers, repair runtime state, or make arbitrary Rust
/// execution in a multithreaded child safe.
#[inline]
pub fn fork_raw() -> Result<i32> {
    // SAFETY: `SIGCHLD` and a null child stack form Linux's documented
    // fork-equivalent `clone` invocation. No parent/child TID, TLS, or
    // namespace flags are requested, so their ignored argument registers
    // are immaterial.
    decode_i32(unsafe { syscall2(SYS_CLONE, CLONE_FORK_FLAGS as usize, 0) })
}

/// Executes a new program image through Linux `execve`.
///
/// On success this syscall does not return. A successful `Ok(())` is kept
/// in the type solely to model the direct syscall seam consistently.
///
/// # Safety
///
/// `path` must name a readable NUL-terminated pathname. `argv` and `envp`
/// must be null-terminated arrays of readable NUL-terminated strings (or
/// a null `envp` only where the kernel ABI permits it).
#[inline]
pub unsafe fn execve_raw(
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> Result<()> {
    // SAFETY: The caller owns every pointer/array/string contract.
    decode(unsafe { syscall3(SYS_EXECVE, path as usize, argv as usize, envp as usize) })
        .map(|_| ())
}

/// Waits for a child process state change through Linux `wait4`.
///
/// `pid` and `options` retain the Linux `waitpid` encoding. A successful
/// zero means `WNOHANG` found no waitable child.
///
/// # Safety
///
/// `status` must be null or point to writable Linux `int` storage.
#[inline]
pub unsafe fn wait4_raw(pid: i32, status: *mut i32, options: u32) -> Result<i32> {
    // SAFETY: This convenience form explicitly declines rusage output.
    unsafe { wait4_with_rusage_raw(pid, status, options, core::ptr::null_mut()) }
}

/// Waits for a child process state change through Linux `wait4`, with an
/// optional caller-owned kernel `struct rusage` output record.
///
/// # Safety
///
/// `status` and `rusage` must each be null or point to writable storage
/// for their exact Linux/AArch64 records.
#[inline]
pub unsafe fn wait4_with_rusage_raw(
    pid: i32,
    status: *mut i32,
    options: u32,
    rusage: *mut u8,
) -> Result<i32> {
    // SAFETY: The caller owns the optional status-output storage; the
    // optional rusage output has the same caller-owned ABI contract.
    decode_i32(unsafe {
        syscall4(
            SYS_WAIT4,
            pid as usize,
            status as usize,
            options as usize,
            rusage as usize,
        )
    })
}

/// Waits through Linux `waitid` and fills a 128-byte `siginfo_t` record.
///
/// # Safety
///
/// `info` must point to writable, eight-byte-aligned Linux `siginfo_t`
/// storage. `id_type`, `id`, and `options` must use Linux `waitid`
/// encodings.
#[inline]
pub unsafe fn waitid_raw(
    id_type: u32,
    id: u32,
    info: *mut crate::signal::SigInfo,
    options: u32,
) -> Result<()> {
    // SAFETY: The caller owns the output-record contract and supplies
    // Linux scalar encodings for the remaining immediate arguments.
    decode(unsafe {
        syscall5(
            SYS_WAITID,
            id_type as usize,
            id as usize,
            info as usize,
            options as usize,
            0,
        )
    })
    .map(|_| ())
}

/// Terminates the current Linux thread group without invoking Rust destructors
/// or the public C ABI.
#[inline]
pub fn exit_immediately(status: i32) -> ! {
    // SAFETY: `exit_group` has one immediate scalar argument and cannot
    // return after a successful kernel entry.
    unsafe { syscall1(SYS_EXIT_GROUP, status as usize) };
    // Linux cannot return from a successful exit syscall. If a hostile or
    // non-Linux execution environment did, continuing would be unsound.
    panic!("Linux exit_group syscall returned")
}

/// Returns a process group ID. `pid == 0` denotes the calling process.
#[inline]
pub fn getpgid(pid: i32) -> Result<i32> {
    // SAFETY: `pid` is an immediate Linux scalar value.
    decode_i32(unsafe { syscall1(SYS_GETPGID, pid as usize) })
}

/// Assigns a process group. Zero values retain Linux's calling-process meaning.
#[inline]
pub fn setpgid(pid: i32, pgid: i32) -> Result<()> {
    // SAFETY: Both arguments are immediate Linux scalar values.
    decode(unsafe { syscall2(SYS_SETPGID, pid as usize, pgid as usize) }).map(|_| ())
}

/// Returns a session ID. `pid == 0` denotes the calling process.
#[inline]
pub fn getsid(pid: i32) -> Result<i32> {
    // SAFETY: `pid` is an immediate Linux scalar value.
    decode_i32(unsafe { syscall1(SYS_GETSID, pid as usize) })
}

/// Creates a session and returns its process ID.
#[inline]
pub fn setsid() -> Result<i32> {
    // SAFETY: `setsid` has no user-memory arguments.
    decode_i32(unsafe { syscall0(SYS_SETSID) })
}
