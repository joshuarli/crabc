//! Native Linux signal facilities for the staged supported targets.
//!
//! Linux/AArch64 exposes the complete typed mask, waiting, queue, descriptor,
//! and alternate-stack families. The staged x86-64 surface is deliberately
//! narrower: one-argument handler actions and delivery to the current thread.
//! Handler installation is unsafe because the kernel can later enter supplied
//! code at an arbitrary interruption point. This module uses `crabc-core`'s
//! direct kernel seams exclusively; it never calls the public C ABI or reads
//! TLS `errno`.

use core::arch::global_asm;
#[cfg(target_arch = "aarch64")]
use core::convert::Infallible;
#[cfg(target_arch = "aarch64")]
use core::ffi::c_void;
use core::fmt;
use core::mem::MaybeUninit;
use core::num::NonZeroI32;
use core::ptr;

use bitflags::bitflags;

#[cfg(target_arch = "aarch64")]
use crate::process::{self, Pid};
#[cfg(target_arch = "aarch64")]
use crate::time::Timespec;
#[cfg(target_arch = "aarch64")]
use crate::{AsFd, Errno, OwnedFd};
use crate::Result;

#[cfg(target_arch = "aarch64")]
pub use crate::process::Signal;

/// A non-zero Linux process or thread identifier used by the staged x86-64
/// signal facade.
///
/// This narrow type exists here rather than admitting `process` wholesale:
/// that larger facade still contains AArch64-only kernel records. It is only
/// the typed selector needed by direct signal observation and delivery.
#[cfg(target_arch = "x86_64")]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pid(NonZeroI32);

#[cfg(target_arch = "x86_64")]
impl Pid {
    /// The Linux init process.
    pub const INIT: Self = Self(unsafe { NonZeroI32::new_unchecked(1) });

    /// Converts a positive raw Linux process or thread identifier.
    #[inline]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        if raw > 0 {
            // SAFETY: The comparison proves that `raw` is non-zero.
            Some(Self(unsafe { NonZeroI32::new_unchecked(raw) }))
        } else {
            None
        }
    }

    /// Converts a known positive raw Linux process or thread identifier.
    ///
    /// # Safety
    ///
    /// `raw` must be positive.
    #[inline]
    pub const unsafe fn from_raw_unchecked(raw: i32) -> Self {
        Self(unsafe { NonZeroI32::new_unchecked(raw) })
    }

    /// Returns the raw Linux process or thread identifier.
    #[inline]
    pub const fn as_raw_pid(self) -> i32 {
        self.0.get()
    }
}

#[cfg(target_arch = "x86_64")]
impl fmt::Display for Pid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A non-zero application-visible Linux signal number on staged x86-64.
///
/// Musl 1.2.6 reserves 32, 33, and 34 for its runtime; safe construction
/// covers the standard range 1–31 and the 35–64 realtime range only.
#[cfg(target_arch = "x86_64")]
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Signal(NonZeroI32);

#[cfg(target_arch = "x86_64")]
impl Signal {
    /// `SIGHUP`.
    pub const HUP: Self = Self(unsafe { NonZeroI32::new_unchecked(1) });
    /// `SIGINT`.
    pub const INT: Self = Self(unsafe { NonZeroI32::new_unchecked(2) });
    /// `SIGQUIT`.
    pub const QUIT: Self = Self(unsafe { NonZeroI32::new_unchecked(3) });
    /// `SIGILL`.
    pub const ILL: Self = Self(unsafe { NonZeroI32::new_unchecked(4) });
    /// `SIGTRAP`.
    pub const TRAP: Self = Self(unsafe { NonZeroI32::new_unchecked(5) });
    /// `SIGABRT` / `SIGIOT`.
    pub const ABORT: Self = Self(unsafe { NonZeroI32::new_unchecked(6) });
    /// `SIGBUS`.
    pub const BUS: Self = Self(unsafe { NonZeroI32::new_unchecked(7) });
    /// `SIGFPE`.
    pub const FPE: Self = Self(unsafe { NonZeroI32::new_unchecked(8) });
    /// `SIGKILL`.
    pub const KILL: Self = Self(unsafe { NonZeroI32::new_unchecked(9) });
    /// `SIGUSR1`.
    pub const USR1: Self = Self(unsafe { NonZeroI32::new_unchecked(10) });
    /// `SIGSEGV`.
    pub const SEGV: Self = Self(unsafe { NonZeroI32::new_unchecked(11) });
    /// `SIGUSR2`.
    pub const USR2: Self = Self(unsafe { NonZeroI32::new_unchecked(12) });
    /// `SIGPIPE`.
    pub const PIPE: Self = Self(unsafe { NonZeroI32::new_unchecked(13) });
    /// `SIGALRM`.
    pub const ALARM: Self = Self(unsafe { NonZeroI32::new_unchecked(14) });
    /// `SIGTERM`.
    pub const TERM: Self = Self(unsafe { NonZeroI32::new_unchecked(15) });
    /// `SIGSTKFLT`.
    pub const STKFLT: Self = Self(unsafe { NonZeroI32::new_unchecked(16) });
    /// `SIGCHLD`.
    pub const CHILD: Self = Self(unsafe { NonZeroI32::new_unchecked(17) });
    /// `SIGCONT`.
    pub const CONT: Self = Self(unsafe { NonZeroI32::new_unchecked(18) });
    /// `SIGSTOP`.
    pub const STOP: Self = Self(unsafe { NonZeroI32::new_unchecked(19) });
    /// `SIGTSTP`.
    pub const TSTP: Self = Self(unsafe { NonZeroI32::new_unchecked(20) });
    /// `SIGTTIN`.
    pub const TTIN: Self = Self(unsafe { NonZeroI32::new_unchecked(21) });
    /// `SIGTTOU`.
    pub const TTOU: Self = Self(unsafe { NonZeroI32::new_unchecked(22) });
    /// `SIGURG`.
    pub const URG: Self = Self(unsafe { NonZeroI32::new_unchecked(23) });
    /// `SIGXCPU`.
    pub const XCPU: Self = Self(unsafe { NonZeroI32::new_unchecked(24) });
    /// `SIGXFSZ`.
    pub const XFSZ: Self = Self(unsafe { NonZeroI32::new_unchecked(25) });
    /// `SIGVTALRM`.
    pub const VTALARM: Self = Self(unsafe { NonZeroI32::new_unchecked(26) });
    /// `SIGPROF`.
    pub const PROF: Self = Self(unsafe { NonZeroI32::new_unchecked(27) });
    /// `SIGWINCH`.
    pub const WINCH: Self = Self(unsafe { NonZeroI32::new_unchecked(28) });
    /// `SIGIO` / `SIGPOLL`.
    pub const IO: Self = Self(unsafe { NonZeroI32::new_unchecked(29) });
    /// `SIGPWR`.
    pub const POWER: Self = Self(unsafe { NonZeroI32::new_unchecked(30) });
    /// `SIGSYS`.
    pub const SYS: Self = Self(unsafe { NonZeroI32::new_unchecked(31) });
    /// The first musl application-visible realtime signal.
    pub const RTMIN: Self = Self(unsafe { NonZeroI32::new_unchecked(35) });
    /// The last Linux realtime signal.
    pub const RTMAX: Self = Self(unsafe { NonZeroI32::new_unchecked(64) });

    /// Converts an application-visible Linux/musl signal number into a typed
    /// signal.
    #[inline]
    pub const fn from_named_raw(raw: i32) -> Option<Self> {
        if (raw >= 1 && raw <= 31) || (raw >= Self::RTMIN.as_raw() && raw <= Self::RTMAX.as_raw()) {
            // SAFETY: The range check proves that `raw` is non-zero.
            Some(Self(unsafe { NonZeroI32::new_unchecked(raw) }))
        } else {
            None
        }
    }

    /// Constructs an arbitrary non-zero Linux signal number.
    ///
    /// # Safety
    ///
    /// `raw` must be valid for the intended kernel operation and must not be
    /// one of musl's reserved 32, 33, or 34 values unless the caller owns the
    /// runtime consequences.
    #[inline]
    pub const unsafe fn from_raw_unchecked(raw: i32) -> Self {
        Self(unsafe { NonZeroI32::new_unchecked(raw) })
    }

    /// Returns the raw Linux signal number.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0.get()
    }

    /// Returns whether this is an application-visible realtime signal.
    #[inline]
    #[must_use]
    pub const fn is_realtime(self) -> bool {
        self.as_raw() >= Self::RTMIN.as_raw() && self.as_raw() <= Self::RTMAX.as_raw()
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn calling_pid_raw() -> i32 {
    process::getpid().as_raw_pid()
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn calling_pid_raw() -> i32 {
    crabc_core::process::getpid()
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn calling_uid_raw() -> u32 {
    process::getuid().as_raw()
}

#[cfg(target_arch = "aarch64")]
const SIG_BLOCK: i32 = 0;
#[cfg(target_arch = "aarch64")]
const SIG_UNBLOCK: i32 = 1;
#[cfg(target_arch = "aarch64")]
const SIG_SETMASK: i32 = 2;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_SIGINFO: u64 = 0x0000_0004;
#[cfg(target_arch = "aarch64")]
const SS_ONSTACK: i32 = 1;
#[cfg(target_arch = "aarch64")]
const SS_DISABLE: i32 = 2;
#[cfg(target_arch = "aarch64")]
const SI_QUEUE: i32 = -1;
#[cfg(target_arch = "aarch64")]
const SIGINFO_SIGNO_OFFSET: usize = 0;
#[cfg(target_arch = "aarch64")]
const SIGINFO_ERRNO_OFFSET: usize = 4;
#[cfg(target_arch = "aarch64")]
const SIGINFO_CODE_OFFSET: usize = 8;
#[cfg(target_arch = "aarch64")]
const SIGINFO_PID_OFFSET: usize = 16;
#[cfg(target_arch = "aarch64")]
const SIGINFO_UID_OFFSET: usize = 20;
#[cfg(target_arch = "aarch64")]
const SIGINFO_VALUE_OFFSET: usize = 24;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_SIGNO_OFFSET: usize = 0;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_ERRNO_OFFSET: usize = 4;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_CODE_OFFSET: usize = 8;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_PID_OFFSET: usize = 12;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_UID_OFFSET: usize = 16;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_STATUS_OFFSET: usize = 40;
#[cfg(target_arch = "aarch64")]
const SIGNALFD_VALUE_OFFSET: usize = 44;

// This is intentionally private and uniquely named so a program may link
// crabc-rs alongside crabc's C facade, whose public C restorer has another
// symbol. The architecture-specific `rt_sigreturn` trap lets the kernel
// return from a user handler without crossing either C ABI.
#[cfg(target_arch = "aarch64")]
global_asm!(
    ".global crabc_rs_signal_restorer",
    ".type crabc_rs_signal_restorer, %function",
    "crabc_rs_signal_restorer:",
    "mov x8, #139",
    "svc #0",
);

// Linux/x86-64 enters `rt_sigreturn` through syscall number 15 with no
// arguments. The kernel consumes the signal frame it placed at the current
// stack pointer; the restorer must therefore not adjust the stack first.
#[cfg(target_arch = "x86_64")]
global_asm!(
    ".global crabc_rs_signal_restorer",
    ".type crabc_rs_signal_restorer,@function",
    "crabc_rs_signal_restorer:",
    "mov rax, 15",
    "syscall",
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
#[cfg(target_arch = "aarch64")]
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct SignalSet(u64);

#[cfg(target_arch = "aarch64")]
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

    #[cfg(target_arch = "aarch64")]
    #[inline]
    pub(crate) const fn kernel_bits(&self) -> &u64 {
        &self.0
    }
}

/// A set of Linux signal numbers represented in the kernel's 64-bit signal
/// mask form.
///
/// Safe constructors exclude signals 32, 33, and 34, which musl reserves for
/// its internal runtime. The raw kernel bit pattern is intentionally not
/// exposed for construction, so ordinary Rust code cannot accidentally
/// perturb them.
#[cfg(target_arch = "x86_64")]
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct SignalSet(u64);

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "aarch64")]
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
#[cfg(target_arch = "aarch64")]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SignalFdInfo([u8; 128]);

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
impl fmt::Debug for SignalSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SignalSet").field(&self.0).finish()
    }
}

#[cfg(target_arch = "x86_64")]
impl fmt::Debug for SignalSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SignalSet").field(&self.0).finish()
    }
}

/// Selects how a signal set changes the calling thread's mask.
#[cfg(target_arch = "aarch64")]
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
    /// Signal-action flags accepted by Linux on the staged supported targets.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SigActionFlags: u64 {
        /// Do not report child stops through `SIGCHLD`.
        const NOCLDSTOP = 0x0000_0001;
        /// Do not leave terminated children as zombies.
        const NOCLDWAIT = 0x0000_0002;
        #[cfg(target_arch = "aarch64")]
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
    #[cfg(target_arch = "aarch64")]
    /// A three-argument `SA_SIGINFO` C-ABI signal handler.
    SigInfo(unsafe extern "C" fn(Signal, *mut SigInfo, *mut c_void)),
}

impl fmt::Debug for SigHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => formatter.write_str("SigHandler::Default"),
            Self::Ignore => formatter.write_str("SigHandler::Ignore"),
            Self::Simple(_) => formatter.write_str("SigHandler::Simple(..)"),
            #[cfg(target_arch = "aarch64")]
            Self::SigInfo(_) => formatter.write_str("SigHandler::SigInfo(..)"),
        }
    }
}

/// A complete kernel signal-action configuration.
///
/// On x86-64, an action returned by [`sigaction`] retains its original compact
/// kernel record privately. Reinstalling that returned object therefore
/// preserves every bit of the kernel mask, including musl-reserved signals,
/// and preserves the original `SA_RESTORER` flag and restorer address. Newly
/// constructed x86-64 actions instead select this crate's restorer.
#[derive(Clone, Copy)]
pub struct SigAction {
    #[cfg(target_arch = "aarch64")]
    handler: SigHandler,
    #[cfg(target_arch = "x86_64")]
    handler: Option<SigHandler>,
    #[cfg(target_arch = "aarch64")]
    mask: SignalSet,
    flags: SigActionFlags,
    #[cfg(target_arch = "x86_64")]
    queried_kernel: Option<crabc_core::signal::KernelSigAction>,
}

impl SigAction {
    /// Creates a signal action. A `SigInfo` handler automatically requests the
    /// matching `SA_SIGINFO` kernel ABI.
    #[inline]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
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
        Self {
            handler,
            mask,
            flags,
        }
    }

    /// Creates a one-argument x86-64 signal action with an empty handler mask.
    ///
    /// A newly constructed action always installs `crabc-rs`' x86-64
    /// `rt_sigreturn` restorer. Actions returned by [`sigaction`] retain the
    /// exact kernel record instead, so they can be restored without changing
    /// an inherited mask or restorer.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[must_use]
    pub fn new(handler: SigHandler, flags: SigActionFlags) -> Self {
        Self {
            handler: Some(handler),
            // A simple handler must never be entered through the three-
            // argument SA_SIGINFO ABI, even if a caller retained that raw
            // future-kernel bit from an observed action.
            flags: SigActionFlags::from_bits_retain(flags.bits() & !SA_SIGINFO),
            queried_kernel: None,
        }
    }

    /// Returns this action's configured handler.
    #[inline]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub const fn handler(self) -> SigHandler {
        self.handler
    }

    /// Returns the one-argument handler when its ABI is known to this staged
    /// x86-64 facade.
    ///
    /// `None` means the kernel action used an ABI this narrow facade does not
    /// expose. The action itself remains losslessly restorable through
    /// [`sigaction`].
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[must_use]
    pub const fn handler(self) -> Option<SigHandler> {
        self.handler
    }

    /// Returns the signals masked while this handler runs.
    #[inline]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub const fn mask(self) -> SignalSet {
        self.mask
    }

    /// Returns this action's kernel flags.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> SigActionFlags {
        self.flags
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn kernel(self) -> crabc_core::signal::KernelSigAction {
        let (handler, siginfo) = match self.handler {
            SigHandler::Default => (SIG_DFL, false),
            SigHandler::Ignore => (SIG_IGN, false),
            SigHandler::Simple(handler) => (handler as *const () as usize, false),
            SigHandler::SigInfo(handler) => (handler as *const () as usize, true),
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

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn kernel(self) -> crabc_core::signal::KernelSigAction {
        if let Some(action) = self.queried_kernel {
            return action;
        }

        let handler = match self.handler {
            Some(SigHandler::Default) => SIG_DFL,
            Some(SigHandler::Ignore) => SIG_IGN,
            Some(SigHandler::Simple(handler)) => handler as *const () as usize,
            None => unreachable!("new x86-64 SigAction always has a known handler"),
        };
        crabc_core::signal::KernelSigAction {
            handler,
            flags: self.flags.bits() | SA_RESTORER,
            restorer: crabc_rs_signal_restorer as *const () as usize,
            mask: 0,
        }
    }

    #[cfg(target_arch = "aarch64")]
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

    #[cfg(target_arch = "x86_64")]
    #[inline]
    unsafe fn from_kernel(action: crabc_core::signal::KernelSigAction) -> Self {
        let handler = match action.handler {
            SIG_DFL => Some(SigHandler::Default),
            SIG_IGN => Some(SigHandler::Ignore),
            // The staged facade deliberately does not expose the x86-64
            // SA_SIGINFO handler ABI. Keep its record opaque but restorable.
            _ if action.flags & SA_SIGINFO != 0 => None,
            address => {
                // SAFETY: Linux returned the address of a one-argument C-ABI
                // handler. This type stores but never invokes that address.
                Some(SigHandler::Simple(unsafe { core::mem::transmute(address) }))
            }
        };
        Self {
            handler,
            flags: SigActionFlags::from_bits_retain(action.flags & !SA_RESTORER),
            queried_kernel: Some(action),
        }
    }
}

impl fmt::Debug for SigAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SigAction");
        #[cfg(target_arch = "aarch64")]
        debug.field("handler", &self.handler).field("mask", &self.mask);
        #[cfg(target_arch = "x86_64")]
        debug.field("handler", &self.handler);
        debug.field("flags", &self.flags).finish()
    }
}

/// The kernel's 128-byte signal-information record.
#[cfg(target_arch = "aarch64")]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SigInfo(crabc_core::signal::SigInfo);

#[cfg(target_arch = "aarch64")]
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
        // the target Linux byte representation.
        unsafe { ptr::read_unaligned(self.0.bytes.as_ptr().add(offset).cast()) }
    }

    #[inline]
    fn queue(signal: Signal, value: i32) -> Self {
        let mut info = crabc_core::signal::SigInfo::zeroed();
        write_i32(&mut info.bytes, SIGINFO_SIGNO_OFFSET, signal.as_raw());
        write_i32(&mut info.bytes, SIGINFO_CODE_OFFSET, SI_QUEUE);
        write_i32(
            &mut info.bytes,
            SIGINFO_PID_OFFSET,
            calling_pid_raw(),
        );
        write_i32(
            &mut info.bytes,
            SIGINFO_UID_OFFSET,
            calling_uid_raw() as i32,
        );
        write_i32(&mut info.bytes, SIGINFO_VALUE_OFFSET, value);
        Self(info)
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    pub(crate) const fn from_core(info: crabc_core::signal::SigInfo) -> Self {
        Self(info)
    }
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
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
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    sp: *mut u8,
    size: usize,
    flags: StackFlags,
}

#[cfg(target_arch = "aarch64")]
impl Stack {
    /// Builds an enabled alternate stack over caller-owned memory.
    ///
    /// Installing this stack is unsafe because the memory must remain valid
    /// until a later replacement or disable operation succeeds.
    #[inline]
    #[must_use]
    pub const fn new(sp: *mut u8, size: usize) -> Self {
        Self {
            sp,
            size,
            flags: StackFlags::empty(),
        }
    }

    /// Builds the disabled-stack representation.
    #[inline]
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            sp: ptr::null_mut(),
            size: 0,
            flags: StackFlags::DISABLE,
        }
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
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn sigprocmask(how: SigmaskHow, set: Option<&SignalSet>) -> Result<SignalSet> {
    let mut old = MaybeUninit::<u64>::uninit();
    let set = set.map_or(ptr::null(), |set| &set.0);
    // SAFETY: `set` is null or points to one `SignalSet` word. `old` provides
    // writable output storage which Linux initializes on a successful call.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(how as i32, set, old.as_mut_ptr())?;
        Ok(SignalSet(
            old.assume_init() & !(1_u64 << 31) & !(1_u64 << 32) & !(1_u64 << 33),
        ))
    }
}

/// Returns the calling thread's signal mask.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn current_mask() -> Result<SignalSet> {
    sigprocmask(SigmaskHow::SetMask, None)
}

/// Blocks all signals in `set` and returns the previous mask.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn block(set: &SignalSet) -> Result<SignalSet> {
    sigprocmask(SigmaskHow::Block, Some(set))
}

/// Unblocks all signals in `set` and returns the previous mask.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn unblock(set: &SignalSet) -> Result<SignalSet> {
    sigprocmask(SigmaskHow::Unblock, Some(set))
}

/// Replaces the calling thread's mask and returns its previous mask.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn set_mask(set: &SignalSet) -> Result<SignalSet> {
    sigprocmask(SigmaskHow::SetMask, Some(set))
}

/// Returns signals pending for the calling thread.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn pending() -> Result<SignalSet> {
    let mut set = MaybeUninit::<u64>::uninit();
    // SAFETY: `set` is writable storage for the one kernel signal-set word.
    unsafe {
        crabc_core::signal::rt_sigpending_raw(set.as_mut_ptr())?;
        Ok(SignalSet(
            set.assume_init() & !(1_u64 << 31) & !(1_u64 << 32) & !(1_u64 << 33),
        ))
    }
}

/// Atomically installs `mask` while waiting for an unblocked signal.
///
/// Linux returns `EINTR` after a signal handler runs, so the normal result is
/// `Err(Errno::INTR)`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn suspend(mask: &SignalSet) -> Result<Infallible> {
    // SAFETY: `mask` provides one readable kernel signal-set word.
    match unsafe { crabc_core::signal::rt_sigsuspend_raw(&mask.0) } {
        Err(error) => Err(error),
        Ok(()) => panic!("Linux rt_sigsuspend unexpectedly returned success"),
    }
}

/// Waits indefinitely for one member of `set`, returning its signal metadata.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn wait_info(set: &SignalSet) -> Result<(Signal, SigInfo)> {
    timed_wait(set, None)
}

/// Waits for one member of `set` until the optional relative timeout expires.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn timed_wait(set: &SignalSet, timeout: Option<&Timespec>) -> Result<(Signal, SigInfo)> {
    let mut info = MaybeUninit::<crabc_core::signal::SigInfo>::uninit();
    let timeout = timeout.map_or(ptr::null(), |timeout| (timeout as *const Timespec).cast());
    // SAFETY: `set`, `info`, and optional `Timespec` each use the exact
    // target Linux kernel ABI layout expected by `rt_sigtimedwait`.
    let raw =
        unsafe { crabc_core::signal::rt_sigtimedwait_raw(&set.0, info.as_mut_ptr(), timeout)? };
    let signal = Signal::from_named_raw(raw).ok_or(Errno::INVAL)?;
    // SAFETY: Linux initialized `info` because the syscall returned a signal.
    Ok((signal, SigInfo(unsafe { info.assume_init() })))
}

/// Queues an integer-valued signal for `pid` using Linux `rt_sigqueueinfo`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn queue_process(pid: Pid, signal: Signal, value: i32) -> Result<()> {
    let info = SigInfo::queue(signal, value);
    // SAFETY: `SigInfo::queue` initialized the exact Linux queued-signal
    // layout, including the sender identity and `SI_QUEUE` discriminator.
    unsafe { crabc_core::signal::rt_sigqueueinfo_raw(pid.as_raw_pid(), signal.as_raw(), &info.0) }
}

/// Sends `signal` to a known thread in the current process.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn kill_thread(tid: Pid, signal: Signal) -> Result<()> {
    crabc_core::process::tgkill(
        calling_pid_raw(),
        tid.as_raw_pid(),
        signal.as_raw(),
    )
}

/// Sends `signal` to the current thread.
#[inline]
pub fn raise(signal: Signal) -> Result<()> {
    crabc_core::process::tgkill(
        calling_pid_raw(),
        crabc_core::thread::gettid(),
        signal.as_raw(),
    )
}

/// Creates a Linux signal descriptor for signals already blocked in every
/// thread which could otherwise receive them.
///
/// A signal file descriptor does not block the selected signals itself; use
/// [`block`] or [`set_mask`] before relying on descriptor delivery. The
/// returned descriptor is an owned native resource and never crosses the C
/// ABI.
#[cfg(target_arch = "aarch64")]
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
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn signalfd_update<Fd: AsFd>(fd: Fd, mask: &SignalSet) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: `fd` is borrowed for the call and `mask` owns its kernel word.
    unsafe { crabc_core::signal::signalfd4_raw(fd.as_raw_fd(), &mask.0, 0)? };
    Ok(())
}

/// Reads one complete Linux signal-descriptor record.
#[cfg(target_arch = "aarch64")]
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
#[cfg(target_arch = "aarch64")]
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

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[inline]
const fn signal_bit(signal: Signal) -> u64 {
    1_u64 << (signal.as_raw() - 1)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn write_i32(bytes: &mut [u8; 128], offset: usize, value: i32) {
    // SAFETY: Every caller uses a fixed field wholly within the 128-byte
    // Linux `siginfo_t` transport record. Unaligned storage is intentional.
    unsafe { ptr::write_unaligned(bytes.as_mut_ptr().add(offset).cast(), value) }
}
