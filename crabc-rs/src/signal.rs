//! Native Linux/AArch64 signal facilities.
//!
//! Signal masks and synchronous waiting are ordinary typed operations. Handler
//! installation and alternate-stack replacement are unsafe because the kernel
//! can later enter the supplied code or memory at an arbitrary interruption
//! point. This module uses `crabc-core`'s direct kernel seams exclusively; it
//! never calls the public C ABI or reads TLS `errno`.

use core::arch::global_asm;
use core::convert::Infallible;
use core::ffi::c_void;
use core::fmt;
use core::mem::MaybeUninit;
use core::ptr;

use bitflags::bitflags;

use crate::process::{self, Pid};
use crate::time::Timespec;
use crate::{AsFd, Errno, OwnedFd, Result};

pub use crate::process::Signal;

const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_SIGINFO: u64 = 0x0000_0004;
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const SI_QUEUE: i32 = -1;
const SIGINFO_SIGNO_OFFSET: usize = 0;
const SIGINFO_ERRNO_OFFSET: usize = 4;
const SIGINFO_CODE_OFFSET: usize = 8;
const SIGINFO_PID_OFFSET: usize = 16;
const SIGINFO_UID_OFFSET: usize = 20;
const SIGINFO_VALUE_OFFSET: usize = 24;
const SIGNALFD_SIGNO_OFFSET: usize = 0;
const SIGNALFD_ERRNO_OFFSET: usize = 4;
const SIGNALFD_CODE_OFFSET: usize = 8;
const SIGNALFD_PID_OFFSET: usize = 12;
const SIGNALFD_UID_OFFSET: usize = 16;
const SIGNALFD_STATUS_OFFSET: usize = 40;
const SIGNALFD_VALUE_OFFSET: usize = 44;

// This is intentionally private and uniquely named so a program may link
// crabc-rs alongside crabc's C facade, whose public C restorer has another
// symbol. Linux/AArch64's rt_sigaction record must carry a restorer for the
// kernel to return from a user handler.
global_asm!(
    ".global crabc_rs_signal_restorer",
    ".type crabc_rs_signal_restorer, %function",
    "crabc_rs_signal_restorer:",
    "mov x8, #139",
    "svc #0",
);

unsafe extern "C" {
    fn crabc_rs_signal_restorer();
}

/// A set of Linux signal numbers represented in the kernel's 64-bit signal
/// mask form.
///
/// Safe constructors exclude signals 32, 33, and 34, which musl reserves for its
/// internal runtime. The raw kernel bit pattern is intentionally not exposed
/// for construction, so ordinary Rust code cannot accidentally perturb them.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct SignalSet(u64);

impl SignalSet {
    /// The empty signal set.
    pub const EMPTY: Self = Self(0);

    /// Returns a set containing every signal safe for application use.
    #[inline]
    #[must_use]
    pub const fn full() -> Self {
        // musl keeps 32, 33, and 34 outside application-visible sets.
        Self(u64::MAX & !(1_u64 << 31) & !(1_u64 << 32) & !(1_u64 << 33))
    }

    /// Adds `signal` to this set.
    #[inline]
    pub fn insert(&mut self, signal: Signal) {
        self.0 |= signal_bit(signal);
    }

    /// Removes `signal` from this set.
    #[inline]
    pub fn remove(&mut self, signal: Signal) {
        self.0 &= !signal_bit(signal);
    }

    /// Returns whether `signal` is a member of this set.
    #[inline]
    #[must_use]
    pub fn contains(self, signal: Signal) -> bool {
        self.0 & signal_bit(signal) != 0
    }

    /// Returns whether no signal is in this set.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub(crate) const fn kernel_bits(&self) -> &u64 {
        &self.0
    }
}

bitflags! {
    /// Flags accepted by Linux `signalfd4`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SignalFdFlags: u32 {
        /// Return `EAGAIN` rather than blocking when no selected signal is pending.
        const NONBLOCK = 0x0000_0800;
        /// Close the descriptor during a successful `execve`.
        const CLOEXEC = 0x0008_0000;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// One fixed-width signal event read from a Linux signal file descriptor.
///
/// This is intentionally distinct from [`SigInfo`]: Linux `signalfd4`
/// presents a stable descriptor record, not the in-memory `siginfo_t` passed
/// to handlers and synchronous waits.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SignalFdInfo([u8; 128]);

impl SignalFdInfo {
    /// Returns the raw signal number reported by the descriptor.
    #[inline]
    #[must_use]
    pub fn raw_signal(self) -> i32 {
        self.read_i32(SIGNALFD_SIGNO_OFFSET)
    }

    /// Returns a safe named signal when this record carries one.
    #[inline]
    #[must_use]
    pub fn signal(self) -> Option<Signal> {
        Signal::from_named_raw(self.raw_signal())
    }

    /// Returns the kernel-provided errno field.
    #[inline]
    #[must_use]
    pub fn raw_errno(self) -> i32 {
        self.read_i32(SIGNALFD_ERRNO_OFFSET)
    }

    /// Returns the kernel signal-code discriminator.
    #[inline]
    #[must_use]
    pub fn raw_code(self) -> i32 {
        self.read_i32(SIGNALFD_CODE_OFFSET)
    }

    /// Returns the sending process ID when the record carries one.
    #[inline]
    #[must_use]
    pub fn sender_pid(self) -> Option<Pid> {
        Pid::from_raw(self.read_i32(SIGNALFD_PID_OFFSET))
    }

    /// Returns the sending user ID for process-originated signals.
    #[inline]
    #[must_use]
    pub fn sender_uid(self) -> u32 {
        self.read_i32(SIGNALFD_UID_OFFSET) as u32
    }

    /// Returns the child-status field when the record describes `SIGCHLD`.
    #[inline]
    #[must_use]
    pub fn status(self) -> i32 {
        self.read_i32(SIGNALFD_STATUS_OFFSET)
    }

    /// Returns the queued integer value for a queued signal record.
    #[inline]
    #[must_use]
    pub fn queued_i32(self) -> i32 {
        self.read_i32(SIGNALFD_VALUE_OFFSET)
    }

    #[inline]
    fn read_i32(self, offset: usize) -> i32 {
        // SAFETY: Each accessor names an in-bounds, fixed-width field in
        // Linux's 128-byte `signalfd_siginfo` descriptor record.
        unsafe { ptr::read_unaligned(self.0.as_ptr().add(offset).cast()) }
    }
}

impl fmt::Debug for SignalFdInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalFdInfo")
            .field("signal", &self.raw_signal())
            .field("errno", &self.raw_errno())
            .field("code", &self.raw_code())
            .finish()
    }
}

impl fmt::Debug for SignalSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SignalSet").field(&self.0).finish()
    }
}

/// Selects how a signal set changes the calling thread's mask.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum SigmaskHow {
    /// Add the set's signals to the current mask.
    Block = SIG_BLOCK,
    /// Remove the set's signals from the current mask.
    Unblock = SIG_UNBLOCK,
    /// Replace the current mask with the supplied set.
    SetMask = SIG_SETMASK,
}

bitflags! {
    /// Signal-action flags accepted by Linux/AArch64.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SigActionFlags: u64 {
        /// Do not report child stops through `SIGCHLD`.
        const NOCLDSTOP = 0x0000_0001;
        /// Do not leave terminated children as zombies.
        const NOCLDWAIT = 0x0000_0002;
        /// Enter the three-argument signal-handler ABI.
        const SIGINFO = SA_SIGINFO;
        /// Run the handler on an enabled alternate signal stack.
        const ONSTACK = 0x0800_0000;
        /// Restart selected interrupted syscalls where Linux permits it.
        const RESTART = 0x1000_0000;
        /// Do not automatically mask this signal while its handler runs.
        const NODEFER = 0x4000_0000;
        /// Restore the default disposition on entry to the handler.
        const RESETHAND = 0x8000_0000;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// A signal disposition.
///
/// Calling either handler form is inherently kernel-driven asynchronous Rust
/// execution. Handlers must satisfy the documented async-signal-safe and
/// reentrancy restrictions for every thread they can interrupt.
#[derive(Clone, Copy)]
pub enum SigHandler {
    /// Ask the kernel to apply the default disposition.
    Default,
    /// Ask the kernel to ignore the signal.
    Ignore,
    /// A one-argument C-ABI signal handler.
    Simple(unsafe extern "C" fn(Signal)),
    /// A three-argument `SA_SIGINFO` C-ABI signal handler.
    SigInfo(unsafe extern "C" fn(Signal, *mut SigInfo, *mut c_void)),
}

impl fmt::Debug for SigHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => formatter.write_str("SigHandler::Default"),
            Self::Ignore => formatter.write_str("SigHandler::Ignore"),
            Self::Simple(_) => formatter.write_str("SigHandler::Simple(..)"),
            Self::SigInfo(_) => formatter.write_str("SigHandler::SigInfo(..)"),
        }
    }
}

/// A complete kernel signal-action configuration.
#[derive(Clone, Copy, Debug)]
pub struct SigAction {
    handler: SigHandler,
    mask: SignalSet,
    flags: SigActionFlags,
}

impl SigAction {
    /// Creates a signal action. A `SigInfo` handler automatically requests the
    /// matching `SA_SIGINFO` kernel ABI.
    #[inline]
    #[must_use]
    pub fn new(handler: SigHandler, mask: SignalSet, flags: SigActionFlags) -> Self {
        // A one-argument handler must never be entered with the three-argument
        // `SA_SIGINFO` calling convention. The handler variant, rather than a
        // caller-supplied flag, owns that ABI decision.
        let flags = match handler {
            SigHandler::SigInfo(_) => flags | SigActionFlags::SIGINFO,
            SigHandler::Default | SigHandler::Ignore | SigHandler::Simple(_) => {
                SigActionFlags::from_bits_retain(flags.bits() & !SA_SIGINFO)
            }
        };
        Self { handler, mask, flags }
    }

    /// Returns this action's configured handler.
    #[inline]
    #[must_use]
    pub const fn handler(self) -> SigHandler {
        self.handler
    }

    /// Returns the signals masked while this handler runs.
    #[inline]
    #[must_use]
    pub const fn mask(self) -> SignalSet {
        self.mask
    }

    /// Returns this action's kernel flags.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> SigActionFlags {
        self.flags
    }

    #[inline]
    fn kernel(self) -> crabc_core::signal::KernelSigAction {
        let (handler, siginfo) = match self.handler {
            SigHandler::Default => (SIG_DFL, false),
            SigHandler::Ignore => (SIG_IGN, false),
            SigHandler::Simple(handler) => (handler as usize, false),
            SigHandler::SigInfo(handler) => (handler as usize, true),
        };
        let mut flags = self.flags.bits() | SA_RESTORER;
        if siginfo {
            flags |= SA_SIGINFO;
        }
        crabc_core::signal::KernelSigAction {
            handler,
            flags,
            restorer: crabc_rs_signal_restorer as *const () as usize,
            mask: self.mask.0,
        }
    }

    #[inline]
    unsafe fn from_kernel(action: crabc_core::signal::KernelSigAction) -> Self {
        let handler = match action.handler {
            SIG_DFL => SigHandler::Default,
            SIG_IGN => SigHandler::Ignore,
            address if action.flags & SA_SIGINFO != 0 => {
                // SAFETY: The kernel returned a previously installed handler
                // pointer. Invoking it remains unsafe and is represented by
                // the `SigHandler::SigInfo` contract.
                SigHandler::SigInfo(unsafe { core::mem::transmute(address) })
            }
            address => {
                // SAFETY: As above, the pointer is opaque until an unsafe
                // caller elects to invoke the handler.
                SigHandler::Simple(unsafe { core::mem::transmute(address) })
            }
        };
        Self {
            handler,
            mask: SignalSet(action.mask & !(1_u64 << 31) & !(1_u64 << 32) & !(1_u64 << 33)),
            flags: SigActionFlags::from_bits_retain(action.flags & !SA_RESTORER),
        }
    }
}

/// The kernel's 128-byte signal-information record.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SigInfo(crabc_core::signal::SigInfo);

impl SigInfo {
    /// Returns the raw `si_signo` value.
    #[inline]
    #[must_use]
    pub fn raw_signal(self) -> i32 {
        self.read_i32(SIGINFO_SIGNO_OFFSET)
    }

    /// Returns the signal number when it is a safe named Linux signal.
    #[inline]
    #[must_use]
    pub fn signal(self) -> Option<Signal> {
        Signal::from_named_raw(self.raw_signal())
    }

    /// Returns the raw `si_errno` value.
    #[inline]
    #[must_use]
    pub fn raw_errno(self) -> i32 {
        self.read_i32(SIGINFO_ERRNO_OFFSET)
    }

    /// Returns the raw `si_code` value.
    #[inline]
    #[must_use]
    pub fn raw_code(self) -> i32 {
        self.read_i32(SIGINFO_CODE_OFFSET)
    }

    /// Returns the sender process ID for queueable process-originated signals.
    #[inline]
    #[must_use]
    pub fn sender_pid(self) -> Option<Pid> {
        Pid::from_raw(self.read_i32(SIGINFO_PID_OFFSET))
    }

    /// Returns the queued integer value when this record originated from
    /// `queue_process` or a compatible `sigqueue` sender.
    #[inline]
    #[must_use]
    pub fn queued_i32(self) -> i32 {
        self.read_i32(SIGINFO_VALUE_OFFSET)
    }

    /// Returns the child status field for `SIGCHLD` information records.
    #[inline]
    #[must_use]
    pub fn status(self) -> i32 {
        self.read_i32(SIGINFO_VALUE_OFFSET)
    }

    #[inline]
    fn read_i32(self, offset: usize) -> i32 {
        // SAFETY: All read offsets above refer to fixed initialized prefix
        // fields of the 128-byte kernel record, and unaligned reads preserve
        // the Linux/AArch64 byte representation.
        unsafe { ptr::read_unaligned(self.0.bytes.as_ptr().add(offset).cast()) }
    }

    #[inline]
    fn queue(signal: Signal, value: i32) -> Self {
        let mut info = crabc_core::signal::SigInfo::zeroed();
        write_i32(&mut info.bytes, SIGINFO_SIGNO_OFFSET, signal.as_raw());
        write_i32(&mut info.bytes, SIGINFO_CODE_OFFSET, SI_QUEUE);
        write_i32(&mut info.bytes, SIGINFO_PID_OFFSET, process::getpid().as_raw_pid());
        write_i32(
            &mut info.bytes,
            SIGINFO_UID_OFFSET,
            process::getuid().as_raw() as i32,
        );
        write_i32(&mut info.bytes, SIGINFO_VALUE_OFFSET, value);
        Self(info)
    }

    #[inline]
    pub(crate) const fn from_core(info: crabc_core::signal::SigInfo) -> Self {
        Self(info)
    }
}

impl fmt::Debug for SigInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigInfo")
            .field("signal", &self.raw_signal())
            .field("errno", &self.raw_errno())
            .field("code", &self.raw_code())
            .finish()
    }
}

bitflags! {
    /// Flags reported by or supplied to `sigaltstack`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StackFlags: i32 {
        /// The caller is currently executing on this alternate stack.
        const ONSTACK = SS_ONSTACK;
        /// Disable alternate-stack delivery.
        const DISABLE = SS_DISABLE;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// An alternate signal-stack configuration.
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    sp: *mut u8,
    size: usize,
    flags: StackFlags,
}

impl Stack {
    /// Builds an enabled alternate stack over caller-owned memory.
    ///
    /// Installing this stack is unsafe because the memory must remain valid
    /// until a later replacement or disable operation succeeds.
    #[inline]
    #[must_use]
    pub const fn new(sp: *mut u8, size: usize) -> Self {
        Self { sp, size, flags: StackFlags::empty() }
    }

    /// Builds the disabled-stack representation.
    #[inline]
    #[must_use]
    pub const fn disabled() -> Self {
        Self { sp: ptr::null_mut(), size: 0, flags: StackFlags::DISABLE }
    }

    /// Returns the stack base pointer.
    #[inline]
    #[must_use]
    pub const fn as_mut_ptr(self) -> *mut u8 {
        self.sp
    }

    /// Returns the stack byte length.
    #[inline]
    #[must_use]
    pub const fn size(self) -> usize {
        self.size
    }

    /// Returns the kernel stack flags.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> StackFlags {
        self.flags
    }

    #[inline]
    const fn kernel(self) -> crabc_core::signal::SignalStack {
        crabc_core::signal::SignalStack::new(self.sp, self.flags.bits(), self.size)
    }

    #[inline]
    fn from_kernel(stack: crabc_core::signal::SignalStack) -> Self {
        Self {
            sp: stack.sp,
            size: stack.size,
            flags: StackFlags::from_bits_retain(stack.flags),
        }
    }
}

/// Changes the calling thread's signal mask and returns the previous mask.
#[inline]
pub fn sigprocmask(how: SigmaskHow, set: Option<&SignalSet>) -> Result<SignalSet> {
    let mut old = MaybeUninit::<u64>::uninit();
    let set = set.map_or(ptr::null(), |set| &set.0);
    // SAFETY: `set` is null or points to one `SignalSet` word. `old` provides
    // writable output storage which Linux initializes on a successful call.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(how as i32, set, old.as_mut_ptr())?;
        Ok(SignalSet(old.assume_init() & !(1_u64 << 31) & !(1_u64 << 32) & !(1_u64 << 33)))
    }
}

/// Returns the calling thread's signal mask.
#[inline]
pub fn current_mask() -> Result<SignalSet> {
    sigprocmask(SigmaskHow::SetMask, None)
}

/// Blocks all signals in `set` and returns the previous mask.
#[inline]
pub fn block(set: &SignalSet) -> Result<SignalSet> {
    sigprocmask(SigmaskHow::Block, Some(set))
}

/// Unblocks all signals in `set` and returns the previous mask.
#[inline]
pub fn unblock(set: &SignalSet) -> Result<SignalSet> {
    sigprocmask(SigmaskHow::Unblock, Some(set))
}

/// Replaces the calling thread's mask and returns its previous mask.
#[inline]
pub fn set_mask(set: &SignalSet) -> Result<SignalSet> {
    sigprocmask(SigmaskHow::SetMask, Some(set))
}

/// Returns signals pending for the calling thread.
#[inline]
pub fn pending() -> Result<SignalSet> {
    let mut set = MaybeUninit::<u64>::uninit();
    // SAFETY: `set` is writable storage for the one kernel signal-set word.
    unsafe {
        crabc_core::signal::rt_sigpending_raw(set.as_mut_ptr())?;
        Ok(SignalSet(set.assume_init() & !(1_u64 << 31) & !(1_u64 << 32) & !(1_u64 << 33)))
    }
}

/// Atomically installs `mask` while waiting for an unblocked signal.
///
/// Linux returns `EINTR` after a signal handler runs, so the normal result is
/// `Err(Errno::INTR)`.
#[inline]
pub fn suspend(mask: &SignalSet) -> Result<Infallible> {
    // SAFETY: `mask` provides one readable kernel signal-set word.
    match unsafe { crabc_core::signal::rt_sigsuspend_raw(&mask.0) } {
        Err(error) => Err(error),
        Ok(()) => panic!("Linux rt_sigsuspend unexpectedly returned success"),
    }
}

/// Waits indefinitely for one member of `set`, returning its signal metadata.
#[inline]
pub fn wait_info(set: &SignalSet) -> Result<(Signal, SigInfo)> {
    timed_wait(set, None)
}

/// Waits for one member of `set` until the optional relative timeout expires.
#[inline]
pub fn timed_wait(set: &SignalSet, timeout: Option<&Timespec>) -> Result<(Signal, SigInfo)> {
    let mut info = MaybeUninit::<crabc_core::signal::SigInfo>::uninit();
    let timeout = timeout.map_or(ptr::null(), |timeout| (timeout as *const Timespec).cast());
    // SAFETY: `set`, `info`, and optional `Timespec` each use the exact
    // Linux/AArch64 kernel ABI layout expected by `rt_sigtimedwait`.
    let raw = unsafe {
        crabc_core::signal::rt_sigtimedwait_raw(&set.0, info.as_mut_ptr(), timeout)?
    };
    let signal = Signal::from_named_raw(raw).ok_or(Errno::INVAL)?;
    // SAFETY: Linux initialized `info` because the syscall returned a signal.
    Ok((signal, SigInfo(unsafe { info.assume_init() })))
}

/// Queues an integer-valued signal for `pid` using Linux `rt_sigqueueinfo`.
#[inline]
pub fn queue_process(pid: Pid, signal: Signal, value: i32) -> Result<()> {
    let info = SigInfo::queue(signal, value);
    // SAFETY: `SigInfo::queue` initialized the exact Linux queued-signal
    // layout, including the sender identity and `SI_QUEUE` discriminator.
    unsafe {
        crabc_core::signal::rt_sigqueueinfo_raw(pid.as_raw_pid(), signal.as_raw(), &info.0)
    }
}

/// Sends `signal` to a known thread in the current process.
#[inline]
pub fn kill_thread(tid: Pid, signal: Signal) -> Result<()> {
    crabc_core::process::tgkill(process::getpid().as_raw_pid(), tid.as_raw_pid(), signal.as_raw())
}

/// Sends `signal` to the current thread.
#[inline]
pub fn raise(signal: Signal) -> Result<()> {
    kill_thread(crate::thread::gettid(), signal)
}

/// Creates a Linux signal descriptor for signals already blocked in every
/// thread which could otherwise receive them.
///
/// A signal file descriptor does not block the selected signals itself; use
/// [`block`] or [`set_mask`] before relying on descriptor delivery. The
/// returned descriptor is an owned native resource and never crosses the C
/// ABI.
#[inline]
pub fn signalfd(mask: &SignalSet, flags: SignalFdFlags) -> Result<OwnedFd> {
    // SAFETY: `mask` owns the one kernel signal-set word for this invocation;
    // `-1` asks Linux to allocate a new descriptor.
    let fd = unsafe { crabc_core::signal::signalfd4_raw(-1, &mask.0, flags.bits())? };
    // SAFETY: Linux returned a fresh non-negative descriptor with unique
    // ownership transferred to the caller.
    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Replaces the selected mask of an existing Linux signal descriptor.
///
/// As with [`signalfd`], callers must arrange signal masks for all relevant
/// threads before expecting descriptor delivery.
#[inline]
pub fn signalfd_update<Fd: AsFd>(fd: Fd, mask: &SignalSet) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: `fd` is borrowed for the call and `mask` owns its kernel word.
    unsafe { crabc_core::signal::signalfd4_raw(fd.as_raw_fd(), &mask.0, 0)? };
    Ok(())
}

/// Reads one complete Linux signal-descriptor record.
#[inline]
pub fn read_signalfd<Fd: AsFd>(fd: Fd) -> Result<SignalFdInfo> {
    let fd = fd.as_fd();
    let mut info = MaybeUninit::<SignalFdInfo>::uninit();
    // SAFETY: `info` is writable storage for exactly one 128-byte kernel
    // descriptor record and is only assumed initialized after a full read.
    let read = unsafe {
        crabc_core::io::read_raw(
            fd.as_raw_fd(),
            info.as_mut_ptr().cast(),
            core::mem::size_of::<SignalFdInfo>(),
        )?
    };
    if read != core::mem::size_of::<SignalFdInfo>() {
        return Err(Errno::IO);
    }
    // SAFETY: Linux initialized the whole fixed-width record on this full read.
    Ok(unsafe { info.assume_init() })
}

/// Installs or queries a signal action.
///
/// # Safety
///
/// Any installed handler must remain valid until a later successful action
/// replacement. It may run on any interrupted thread and must obey the
/// async-signal-safety, reentrancy, unwind, and foreign-call restrictions of
/// the target program. In particular, it must not allocate, lock ordinary
/// Rust synchronization primitives, or access data that another thread may
/// be mutating without signal-safe coordination.
#[inline]
pub unsafe fn sigaction(signal: Signal, action: Option<&SigAction>) -> Result<SigAction> {
    let kernel = action.map(|action| action.kernel());
    let action = kernel.as_ref().map_or(ptr::null(), |action| action);
    let mut old = MaybeUninit::<crabc_core::signal::KernelSigAction>::uninit();
    // SAFETY: `action` is null or points to a compact kernel record retained
    // through the call; `old` provides writable output storage.
    unsafe {
        crabc_core::signal::rt_sigaction_raw(signal.as_raw(), action, old.as_mut_ptr())?;
        Ok(SigAction::from_kernel(old.assume_init()))
    }
}

/// Installs or queries the alternate signal stack.
///
/// # Safety
///
/// An enabled `stack` must remain allocated, writable, correctly aligned for
/// signal frames, and otherwise unused for its entire installed lifetime. It
/// must not be replaced or freed while a handler can execute on it.
#[inline]
pub unsafe fn sigaltstack(stack: Option<&Stack>) -> Result<Stack> {
    let kernel = stack.map(|stack| stack.kernel());
    let stack = kernel.as_ref().map_or(ptr::null(), |stack| stack);
    let mut old = MaybeUninit::<crabc_core::signal::SignalStack>::uninit();
    // SAFETY: `stack` is null or points to a valid stack record retained for
    // the call; `old` is writable output storage initialized on success.
    unsafe {
        crabc_core::signal::sigaltstack_raw(stack, old.as_mut_ptr())?;
        Ok(Stack::from_kernel(old.assume_init()))
    }
}

#[inline]
const fn signal_bit(signal: Signal) -> u64 {
    1_u64 << (signal.as_raw() - 1)
}

#[inline]
fn write_i32(bytes: &mut [u8; 128], offset: usize, value: i32) {
    // SAFETY: Every caller uses a fixed field wholly within the 128-byte
    // Linux `siginfo_t` transport record. Unaligned storage is intentional.
    unsafe { ptr::write_unaligned(bytes.as_mut_ptr().add(offset).cast(), value) }
}
