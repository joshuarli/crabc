//! Darwin signal numbers, masks, actions and alternate stacks over libSystem.

use core::ffi::c_int;
use core::fmt;
use core::mem::MaybeUninit;
use core::num::NonZeroI32;
use core::ptr;

use super::errno::{self, Errno, Result};
use super::sys;
use crate::signal::{Pid, SigHandler};

/// A non-zero Darwin signal number.
///
/// Darwin numbers its 31 signals differently from Linux and has no realtime
/// signals. `EMT` and `INFO` are Darwin-only; Linux's `STKFLT`, `POWER`,
/// `RTMIN` and `RTMAX` have no Darwin counterpart.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Signal(NonZeroI32);

macro_rules! darwin_signals {
    ($($name:ident = $value:path, $doc:literal;)*) => {
        impl Signal {
            $(
                #[doc = $doc]
                pub const $name: Self = Self::from_known($value);
            )*
        }
    };
}

darwin_signals! {
    HUP = sys::SIGHUP, "`SIGHUP`.";
    INT = sys::SIGINT, "`SIGINT`.";
    QUIT = sys::SIGQUIT, "`SIGQUIT`.";
    ILL = sys::SIGILL, "`SIGILL`.";
    TRAP = sys::SIGTRAP, "`SIGTRAP`.";
    ABORT = sys::SIGABRT, "`SIGABRT` / `SIGIOT`.";
    EMT = sys::SIGEMT, "`SIGEMT`, Darwin's emulator trap.";
    FPE = sys::SIGFPE, "`SIGFPE`.";
    KILL = sys::SIGKILL, "`SIGKILL`.";
    BUS = sys::SIGBUS, "`SIGBUS`.";
    SEGV = sys::SIGSEGV, "`SIGSEGV`.";
    SYS = sys::SIGSYS, "`SIGSYS`.";
    PIPE = sys::SIGPIPE, "`SIGPIPE`.";
    ALARM = sys::SIGALRM, "`SIGALRM`.";
    TERM = sys::SIGTERM, "`SIGTERM`.";
    URG = sys::SIGURG, "`SIGURG`.";
    STOP = sys::SIGSTOP, "`SIGSTOP`.";
    TSTP = sys::SIGTSTP, "`SIGTSTP`.";
    CONT = sys::SIGCONT, "`SIGCONT`.";
    CHILD = sys::SIGCHLD, "`SIGCHLD`.";
    TTIN = sys::SIGTTIN, "`SIGTTIN`.";
    TTOU = sys::SIGTTOU, "`SIGTTOU`.";
    IO = sys::SIGIO, "`SIGIO` / `SIGPOLL`.";
    XCPU = sys::SIGXCPU, "`SIGXCPU`.";
    XFSZ = sys::SIGXFSZ, "`SIGXFSZ`.";
    VTALARM = sys::SIGVTALRM, "`SIGVTALRM`.";
    PROF = sys::SIGPROF, "`SIGPROF`.";
    WINCH = sys::SIGWINCH, "`SIGWINCH`.";
    INFO = sys::SIGINFO, "`SIGINFO`, Darwin's status request.";
    USR1 = sys::SIGUSR1, "`SIGUSR1`.";
    USR2 = sys::SIGUSR2, "`SIGUSR2`.";
}

impl Signal {
    const fn from_known(raw: c_int) -> Self {
        match NonZeroI32::new(raw) {
            Some(raw) => Self(raw),
            None => panic!("Darwin signal numbers are non-zero"),
        }
    }

    /// Converts a Darwin signal number in `1..=31` into a typed signal.
    #[inline]
    pub const fn from_named_raw(raw: i32) -> Option<Self> {
        if raw >= 1 && raw < sys::NSIG {
            // SAFETY: The range check proves that `raw` is non-zero.
            Some(Self(unsafe { NonZeroI32::new_unchecked(raw) }))
        } else {
            None
        }
    }

    /// Constructs an arbitrary non-zero signal number.
    ///
    /// # Safety
    ///
    /// `raw` must be non-zero and valid for the intended libSystem operation.
    #[inline]
    pub const unsafe fn from_raw_unchecked(raw: i32) -> Self {
        // SAFETY: The caller guarantees that `raw` is non-zero.
        Self(unsafe { NonZeroI32::new_unchecked(raw) })
    }

    /// Returns the raw Darwin signal number.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0.get()
    }

    /// Returns whether this is a realtime signal, which Darwin does not have.
    #[inline]
    #[must_use]
    pub const fn is_realtime(self) -> bool {
        false
    }
}

/// A set of Darwin signals in libSystem's 32-bit `sigset_t` form.
#[repr(transparent)]
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct SignalSet(sys::sigset_t);

impl SignalSet {
    /// The empty signal set.
    pub const EMPTY: Self = Self(0);

    /// Returns a set containing every Darwin signal.
    #[inline]
    #[must_use]
    pub const fn full() -> Self {
        Self(u32::MAX >> 1)
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

    #[cfg(feature = "alloc")]
    #[inline]
    pub(crate) const fn kernel_bits(&self) -> &sys::sigset_t {
        &self.0
    }
}

impl fmt::Debug for SignalSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SignalSet").field(&self.0).finish()
    }
}

/// `sigmask(signal)`; a signal outside `1..=32` has no bit, so it is never a
/// member and inserting it changes nothing.
#[inline]
const fn signal_bit(signal: Signal) -> sys::sigset_t {
    match signal.as_raw() {
        raw @ 1..=32 => 1 << (raw - 1),
        _ => 0,
    }
}

/// Selects how a signal set changes the calling thread's mask.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum SigmaskHow {
    /// Add the set's signals to the current mask.
    Block = sys::SIG_BLOCK,
    /// Remove the set's signals from the current mask.
    Unblock = sys::SIG_UNBLOCK,
    /// Replace the current mask with the supplied set.
    SetMask = sys::SIG_SETMASK,
}

bitflags::bitflags! {
    /// Signal-action flags accepted by Darwin `sigaction`, with Darwin values.
    ///
    /// libSystem stores the flags in a 32-bit `int`; [`sigaction`] rejects
    /// retained bits above it with [`Errno::INVAL`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SigActionFlags: u64 {
        /// Do not report child stops through `SIGCHLD`.
        const NOCLDSTOP = sys::SA_NOCLDSTOP as u64;
        /// Do not leave terminated children as zombies.
        const NOCLDWAIT = sys::SA_NOCLDWAIT as u64;
        /// Enter the three-argument signal-handler ABI.
        const SIGINFO = sys::SA_SIGINFO as u64;
        /// Run the handler on an enabled alternate signal stack.
        const ONSTACK = sys::SA_ONSTACK as u64;
        /// Restart interrupted calls where Darwin permits it.
        const RESTART = sys::SA_RESTART as u64;
        /// Do not automatically mask this signal while its handler runs.
        const NODEFER = sys::SA_NODEFER as u64;
        /// Restore the default disposition on entry to the handler.
        const RESETHAND = sys::SA_RESETHAND as u64;
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

/// A complete signal-action configuration.
///
/// An action returned by [`sigaction`] retains the libSystem record it was
/// decoded from, so reinstalling it restores the original handler, mask and
/// flags exactly.
#[derive(Clone, Copy)]
pub struct SigAction {
    handler: SigHandler,
    mask: SignalSet,
    flags: SigActionFlags,
    queried: Option<sys::Sigaction>,
}

impl SigAction {
    /// Creates a signal action. A `SigInfo` handler automatically requests the
    /// matching `SA_SIGINFO` ABI, and every other handler clears it.
    #[inline]
    #[must_use]
    pub fn new(handler: SigHandler, mask: SignalSet, flags: SigActionFlags) -> Self {
        let flags = match handler {
            SigHandler::SigInfo(_) => flags | SigActionFlags::SIGINFO,
            SigHandler::Default | SigHandler::Ignore | SigHandler::Simple(_) => {
                flags.difference(SigActionFlags::SIGINFO)
            }
        };
        Self {
            handler,
            mask,
            flags,
            queried: None,
        }
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

    /// Returns this action's flags.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> SigActionFlags {
        self.flags
    }

    #[inline]
    fn record(self) -> Result<sys::Sigaction> {
        if let Some(record) = self.queried {
            return Ok(record);
        }
        let sa_handler = match self.handler {
            SigHandler::Default => sys::SIG_DFL,
            SigHandler::Ignore => sys::SIG_IGN,
            SigHandler::Simple(handler) => handler as usize,
            SigHandler::SigInfo(handler) => handler as usize,
        };
        let sa_flags = u32::try_from(self.flags.bits()).map_err(|_| Errno::INVAL)?;
        Ok(sys::Sigaction {
            sa_handler,
            sa_mask: self.mask.0,
            sa_flags: sa_flags.cast_signed(),
        })
    }

    #[inline]
    fn from_record(record: sys::Sigaction) -> Self {
        let handler = match record.sa_handler {
            sys::SIG_DFL => SigHandler::Default,
            sys::SIG_IGN => SigHandler::Ignore,
            address if record.sa_flags & sys::SA_SIGINFO != 0 => {
                // SAFETY: libSystem returned the address of an installed
                // three-argument handler. It is stored but never invoked here;
                // invoking it stays behind `SigHandler`'s unsafe fn type.
                SigHandler::SigInfo(unsafe {
                    core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(Signal, *mut SigInfo, *mut core::ffi::c_void),
                    >(address)
                })
            }
            address => {
                // SAFETY: As above, for an installed one-argument handler.
                SigHandler::Simple(unsafe {
                    core::mem::transmute::<usize, unsafe extern "C" fn(Signal)>(address)
                })
            }
        };
        Self {
            handler,
            mask: SignalSet(record.sa_mask),
            flags: SigActionFlags::from_bits_retain(u64::from(record.sa_flags.cast_unsigned())),
            queried: Some(record),
        }
    }
}

impl fmt::Debug for SigAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigAction")
            .field("handler", &self.handler)
            .field("mask", &self.mask)
            .field("flags", &self.flags)
            .finish()
    }
}

/// Darwin's 104-byte `siginfo_t` signal-information record.
///
/// Interpret its fields according to `raw_code`. Darwin has no `sigqueue`,
/// so `queued_i32` only reads the `si_value` integer of records that carry
/// one.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SigInfo(sys::Siginfo);

impl SigInfo {
    /// Returns the raw `si_signo` value.
    #[inline]
    #[must_use]
    pub fn raw_signal(self) -> i32 {
        self.0.si_signo
    }

    /// Returns the signal number when it is a named Darwin signal.
    #[inline]
    #[must_use]
    pub fn signal(self) -> Option<Signal> {
        Signal::from_named_raw(self.raw_signal())
    }

    /// Returns the raw `si_errno` value.
    #[inline]
    #[must_use]
    pub fn raw_errno(self) -> i32 {
        self.0.si_errno
    }

    /// Returns the raw `si_code` value.
    #[inline]
    #[must_use]
    pub fn raw_code(self) -> i32 {
        self.0.si_code
    }

    /// Returns the sending process ID when the record carries a positive one.
    #[inline]
    #[must_use]
    pub fn sender_pid(self) -> Option<Pid> {
        Pid::from_raw(self.0.si_pid)
    }

    /// Returns the `int` member of the record's `si_value`.
    #[inline]
    #[must_use]
    pub fn queued_i32(self) -> i32 {
        self.0.si_value as u32 as i32
    }

    /// Returns the `si_status` field of a `SIGCHLD` information record.
    #[inline]
    #[must_use]
    pub fn status(self) -> i32 {
        self.0.si_status
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

bitflags::bitflags! {
    /// Flags reported by or supplied to `sigaltstack`, with Darwin values.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct StackFlags: i32 {
        /// The caller is currently executing on this alternate stack.
        const ONSTACK = sys::SS_ONSTACK;
        /// Disable alternate-stack delivery.
        const DISABLE = sys::SS_DISABLE;
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

/// An alternate signal-stack configuration.
///
/// Darwin requires at least 32 KiB (`MINSIGSTKSZ`) for an enabled stack.
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

    /// Returns the stack flags.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> StackFlags {
        self.flags
    }
}

/// Changes the calling thread's signal mask through `pthread_sigmask` and
/// returns the previous mask.
///
/// A missing `set` queries the mask without changing it for any `how` value.
/// Darwin ignores `SIGKILL` and `SIGSTOP` in an input set.
#[inline]
pub fn sigprocmask(how: SigmaskHow, set: Option<&SignalSet>) -> Result<SignalSet> {
    let set = set.map_or(ptr::null(), |set| &set.0);
    let mut old = MaybeUninit::<sys::sigset_t>::uninit();
    // SAFETY: `set` is null or points to one live `sigset_t`; `old` is
    // writable storage for the previous mask.
    let code = unsafe { sys::pthread_sigmask(how as c_int, set, old.as_mut_ptr()) };
    errno::check_code(code)?;
    // SAFETY: a successful `pthread_sigmask` stored the previous mask.
    Ok(SignalSet(unsafe { old.assume_init() }))
}

/// Returns the signals pending for the calling thread and its process.
///
/// Querying does not consume them or change the thread's mask.
#[inline]
pub fn pending() -> Result<SignalSet> {
    let mut set = MaybeUninit::<sys::sigset_t>::uninit();
    // SAFETY: `set` is writable storage for one `sigset_t`.
    let result = unsafe { sys::sigpending(set.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `sigpending` stored the pending set.
    Ok(SignalSet(unsafe { set.assume_init() }))
}

/// Atomically installs `mask` while waiting for an unblocked signal.
///
/// `sigsuspend` returns only after a signal handler runs, so the normal
/// result is `Err(Errno::INTR)`; libSystem restores the original mask first.
#[inline]
pub fn suspend(mask: &SignalSet) -> Result<!> {
    // SAFETY: `mask` points to one live `sigset_t` for the call.
    let result = unsafe { sys::sigsuspend(&mask.0) };
    match errno::check(result) {
        Err(error) => Err(error),
        Ok(_) => panic!("Darwin sigsuspend unexpectedly returned success"),
    }
}

/// Sends `signal` to the calling thread through `pthread_kill`.
#[inline]
pub fn raise(signal: Signal) -> Result<()> {
    // SAFETY: `pthread_self` names the calling thread, which is alive for the
    // whole call.
    let code = unsafe { sys::pthread_kill(sys::pthread_self(), signal.as_raw()) };
    errno::check_code(code)
}

/// Installs or queries a signal action through libSystem `sigaction`.
///
/// # Safety
///
/// Any installed handler must remain valid until a later successful action
/// replacement. It may run on any interrupted thread and must obey the
/// async-signal-safety, reentrancy, unwind, and foreign-call restrictions of
/// the target program. In particular, it must not allocate, lock ordinary
/// Rust synchronization primitives, or access data that another thread may
/// be mutating without signal-safe coordination.
/// A three-argument handler may use its `SigInfo` and context pointers only
/// during that invocation; their storage belongs to the signal frame.
/// An `ONSTACK` action requires sufficient live stack memory on each receiving
/// thread which has an enabled alternate stack.
#[inline]
pub unsafe fn sigaction(signal: Signal, action: Option<&SigAction>) -> Result<SigAction> {
    let record = match action {
        Some(action) => Some(action.record()?),
        None => None,
    };
    let new = record.as_ref().map_or(ptr::null(), |record| record);
    let mut old = MaybeUninit::<sys::Sigaction>::uninit();
    // SAFETY: `new` is null or points to a live record for the call, and
    // `old` is writable storage for the previous action. The caller upholds
    // the handler obligations documented above.
    let result = unsafe { sys::sigaction(signal.as_raw(), new, old.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `sigaction` stored the previous action.
    Ok(SigAction::from_record(unsafe { old.assume_init() }))
}

/// Installs or queries the calling thread's alternate signal stack.
///
/// POSIX ignores the size of a `DISABLE` request, but XNU rejects one below
/// `MINSIGSTKSZ` with `ENOMEM`, which would make [`Stack::disabled`] and a
/// queried disabled stack unusable. A `DISABLE` request is therefore passed
/// with at least `MINSIGSTKSZ` as its size. Disabling the stack a handler is
/// running on fails with [`Errno::INVAL`].
///
/// # Safety
///
/// An enabled `stack` must remain allocated, writable, correctly aligned for
/// signal frames, and otherwise unused for its entire installed lifetime. It
/// must not be freed while a handler can execute on it. The calling thread
/// owns this stack; its memory may be reused only after a replacement or
/// disable operation succeeds and every handler using it has returned.
#[inline]
pub unsafe fn sigaltstack(stack: Option<&Stack>) -> Result<Stack> {
    let record = stack.map(|stack| sys::StackT {
        ss_sp: stack.sp.cast(),
        ss_size: if stack.flags.contains(StackFlags::DISABLE) {
            stack.size.max(sys::MINSIGSTKSZ)
        } else {
            stack.size
        },
        ss_flags: stack.flags.bits(),
    });
    let new = record.as_ref().map_or(ptr::null(), |record| record);
    let mut old = MaybeUninit::<sys::StackT>::uninit();
    // SAFETY: `new` is null or points to a live record for the call, and
    // `old` is writable storage for the previous stack. The caller upholds
    // the stack lifetime obligations documented above.
    let result = unsafe { sys::sigaltstack(new, old.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `sigaltstack` stored the previous stack.
    let old = unsafe { old.assume_init() };
    Ok(Stack {
        sp: old.ss_sp.cast(),
        size: old.ss_size,
        flags: StackFlags::from_bits_retain(old.ss_flags),
    })
}
