//! Stateless Linux/AArch64 signal operations.

use crate::Result;
use crate::syscall::{decode, decode_i32, syscall2, syscall3, syscall4, SYS_RT_SIGACTION, SYS_RT_SIGPENDING, SYS_RT_SIGPROCMASK, SYS_RT_SIGQUEUEINFO, SYS_RT_SIGSUSPEND, SYS_RT_SIGTIMEDWAIT, SYS_SIGALTSTACK, SYS_SIGNALFD4};

/// The Linux/AArch64 signal-set width passed to every `rt_*` syscall.
///
/// Linux's kernel ABI deliberately accepts one 64-bit word here, even
/// though musl's public `sigset_t` has more storage for source ABI
/// compatibility.
pub const KERNEL_SIGSET_SIZE: usize = core::mem::size_of::<u64>();

/// Linux/AArch64's compact `rt_sigaction` record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigAction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

/// Linux's fixed-size `siginfo_t` transport record.
///
/// The kernel fills only the fields meaningful for the triggering signal.
/// Consumers must interpret it according to `si_code`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct SigInfo {
    pub bytes: [u8; 128],
}

impl SigInfo {
    /// A zeroed record suitable for kernel output.
    #[inline]
    pub const fn zeroed() -> Self {
        Self { bytes: [0; 128] }
    }
}

/// Linux/AArch64's `stack_t` layout for `sigaltstack`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalStack {
    pub sp: *mut u8,
    pub flags: i32,
    _padding: i32,
    pub size: usize,
}

impl SignalStack {
    /// Builds a kernel signal-stack record with the required AArch64
    /// padding initialized to zero.
    #[inline]
    pub const fn new(sp: *mut u8, flags: i32, size: usize) -> Self {
        Self {
            sp,
            flags,
            _padding: 0,
            size,
        }
    }
}

/// Installs or queries a signal action without libc or TLS `errno`.
///
/// # Safety
///
/// `action` and `old_action` must be null or point to valid compact
/// Linux/AArch64 records for the duration of the call. A non-null handler
/// and restorer must satisfy the kernel's asynchronous signal ABI.
#[inline]
pub unsafe fn rt_sigaction_raw(
    signal: i32,
    action: *const KernelSigAction,
    old_action: *mut KernelSigAction,
) -> Result<()> {
    // SAFETY: The caller owns the compact-kernel-record pointer and
    // handler/restorer contracts; the other arguments are scalar values.
    decode(unsafe {
        syscall4(
            SYS_RT_SIGACTION,
            signal as usize,
            action as usize,
            old_action as usize,
            KERNEL_SIGSET_SIZE,
        )
    })
    .map(|_| ())
}

/// Changes or queries the calling thread's kernel signal mask.
///
/// # Safety
///
/// `set` and `old_set` must be null or point to one readable/writable
/// kernel-sized signal-set word, respectively.
#[inline]
pub unsafe fn rt_sigprocmask_raw(how: i32, set: *const u64, old_set: *mut u64) -> Result<()> {
    // SAFETY: The caller owns the kernel signal-set pointer contracts.
    decode(unsafe {
        syscall4(
            SYS_RT_SIGPROCMASK,
            how as usize,
            set as usize,
            old_set as usize,
            KERNEL_SIGSET_SIZE,
        )
    })
    .map(|_| ())
}

/// Queries the calling thread's pending signal set.
///
/// # Safety
///
/// `set` must point to writable storage for one kernel-sized signal-set
/// word.
#[inline]
pub unsafe fn rt_sigpending_raw(set: *mut u64) -> Result<()> {
    // SAFETY: The caller owns the kernel signal-set output storage.
    decode(unsafe { syscall2(SYS_RT_SIGPENDING, set as usize, KERNEL_SIGSET_SIZE) }).map(|_| ())
}

/// Atomically swaps in `set` while waiting for an unblocked signal.
///
/// A successful wait never returns; Linux reports `EINTR` after a handler
/// runs. The returned error is intentionally preserved as an ordinary
/// result value rather than being translated through TLS `errno`.
///
/// # Safety
///
/// `set` must point to one readable kernel-sized signal-set word.
#[inline]
pub unsafe fn rt_sigsuspend_raw(set: *const u64) -> Result<()> {
    // SAFETY: The caller owns the kernel signal-set input storage.
    decode(unsafe { syscall2(SYS_RT_SIGSUSPEND, set as usize, KERNEL_SIGSET_SIZE) }).map(|_| ())
}

/// Waits for one signal in `set` and returns its signal number.
///
/// # Safety
///
/// `set` must point to one readable kernel-sized signal-set word.
/// `info` must be null or point to writable 128-byte Linux `siginfo_t`
/// storage. `timeout` must be null or point to one Linux/AArch64
/// `timespec` record.
#[inline]
pub unsafe fn rt_sigtimedwait_raw(
    set: *const u64,
    info: *mut SigInfo,
    timeout: *const u8,
) -> Result<i32> {
    // SAFETY: The caller owns every pointed-to kernel ABI record.
    decode_i32(unsafe {
        syscall4(
            SYS_RT_SIGTIMEDWAIT,
            set as usize,
            info as usize,
            timeout as usize,
            KERNEL_SIGSET_SIZE,
        )
    })
}

/// Queues the supplied Linux `siginfo_t` record to a process.
///
/// # Safety
///
/// `info` must point to a fully initialized Linux signal-information
/// record whose fields satisfy `rt_sigqueueinfo`'s ABI contract.
#[inline]
pub unsafe fn rt_sigqueueinfo_raw(pid: i32, signal: i32, info: *const SigInfo) -> Result<()> {
    // SAFETY: The caller owns the signal-info input record contract.
    decode(unsafe {
        syscall3(
            SYS_RT_SIGQUEUEINFO,
            pid as usize,
            signal as usize,
            info as usize,
        )
    })
    .map(|_| ())
}

/// Installs or queries an alternate signal stack.
///
/// # Safety
///
/// `stack` and `old_stack` must be null or point to valid Linux/AArch64
/// `stack_t` records. Any enabled stack memory must remain valid while the
/// kernel may dispatch a signal on it.
#[inline]
pub unsafe fn sigaltstack_raw(
    stack: *const SignalStack,
    old_stack: *mut SignalStack,
) -> Result<()> {
    // SAFETY: The caller owns both `stack_t` pointer contracts.
    decode(unsafe { syscall2(SYS_SIGALTSTACK, stack as usize, old_stack as usize) }).map(|_| ())
}

/// Creates or updates a Linux `signalfd4` descriptor.
///
/// # Safety
///
/// `mask` must point to one readable Linux kernel-sized signal-set word.
/// When `fd` is non-negative it must designate an existing signalfd
/// descriptor. `flags` uses Linux's `SFD_*` bit representation.
#[inline]
pub unsafe fn signalfd4_raw(fd: i32, mask: *const u64, flags: u32) -> Result<i32> {
    // SAFETY: The caller owns the mask pointer and descriptor contracts.
    decode_i32(unsafe {
        syscall4(
            SYS_SIGNALFD4,
            fd as usize,
            mask as usize,
            KERNEL_SIGSET_SIZE,
            flags as usize,
        )
    })
}
