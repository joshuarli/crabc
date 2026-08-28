//! Bounded Linux/x86-64 process operations and record-lock observations.
//!
//! This module intentionally admits only scalar identity queries, a
//! caller-buffer and alloc-gated physical/logical current-working-directory
//! observations, a query/replay-only raw program-break operation, explicitly
//! process-global `chdir`/`fchdir` mutation, and a separate process-global
//! `chroot` transition, the kernel's
//! three-word real/effective/saved credential observations, supplementary-group
//! query/fill protocol, a narrow alloc-gated prepared-exec child owner with
//! consuming wait, pidfd creation, typed calling-task filesystem
//! credential query/current-effective-ID requests, typed calling-process
//! resource-limit query/mutation, typed read-only resource usage copied from Linux's
//! initialized kernel prefix, typed read-only process accounting,
//! scheduling-priority observations, bounds, and bounded target mutation, and
//! the read-only typed
//! fcntl(F_GETLK) record-lock query, plus the process-global umask exchange.
//! Generic raw fork/exec/wait control and the larger process facade remain
//! AArch64-only until each of their target-sized records and state transitions
//! has an independent x86-64 contract.

use bitflags::bitflags;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::convert::Infallible;
use crate::buffer::Buffer;
use core::ffi::{c_void, CStr};
use core::fmt;
use core::ptr;
use crate::fs::PathArg;
pub use crate::fs::Mode;
#[cfg(feature = "alloc")]
use crate::{BorrowedFd, RawFd};
use crate::{AsFd, OwnedFd, Result};

/// A raw Linux/x86-64 `pid_t` representation.
pub type RawPid = i32;

/// A raw Linux/x86-64 `uid_t` representation.
pub type RawUid = u32;

/// A raw Linux/x86-64 `gid_t` representation.
pub type RawGid = u32;

/// A non-zero Linux process or thread identifier.
pub use crate::signal::Pid;

/// Queries or requests Linux's raw program break.
///
/// This is the Rustix-style kernel primitive, not a replacement for libc's
/// `brk`/`sbrk` bookkeeping. Linux returns the resulting current break even
/// when a requested change cannot be made, so callers which request a new
/// address must compare the returned pointer with that request themselves.
/// The operation changes process-global heap state and must be coordinated
/// with whichever allocator owns the process heap.
///
/// # Safety
///
/// `address` may be null to query the current break. Otherwise it is passed
/// directly to Linux and must satisfy the program-break address contract; no
/// allocator or concurrent heap operation may invalidate that coordination.
#[inline]
pub unsafe fn kernel_brk(address: *mut c_void) -> Result<*mut c_void> {
    // SAFETY: The caller owns Linux's process-global program-break contract;
    // this raw syscall has the nonstandard pointer-return failure behavior
    // documented above.
    Ok(unsafe { crabc_core::process::brk_raw(address.cast()) }.cast())
}

bitflags! {
    /// Options for waiting on one owned child process.
    ///
    /// These retain Linux's `wait4` encodings. [`Child::wait`] consumes its
    /// owner for every result, including a `NOHANG` observation which returns
    /// `None`; it is not a retry or supervision API.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct WaitOptions: u32 {
        /// Return immediately when this child has no reportable state change.
        const NOHANG = 0x0000_0001;
        /// Report a stopped child which is not being traced.
        const UNTRACED = 0x0000_0002;
        /// Report a child resumed with `SIGCONT`.
        const CONTINUED = 0x0000_0008;
        /// Preserve future Linux option bits for kernel validation.
        const _ = !0;
    }
}

/// A Linux wait-status word returned while consuming an owned child.
///
/// This typed value retains the kernel's status encoding without admitting a
/// general x86 `wait`, `waitpid`, or `waitid` selection API.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WaitStatus(i32);

impl WaitStatus {
    /// Returns the raw Linux wait-status word.
    #[inline]
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self.0
    }

    /// Returns whether the child exited normally.
    #[inline]
    #[must_use]
    pub const fn exited(self) -> bool {
        self.0 & 0x7f == 0
    }

    /// Returns the child's ordinary exit code when it exited normally.
    #[inline]
    #[must_use]
    pub const fn exit_status(self) -> Option<i32> {
        if self.exited() {
            Some((self.0 >> 8) & 0xff)
        } else {
            None
        }
    }

    /// Returns whether the child was terminated by a signal.
    #[inline]
    #[must_use]
    pub const fn signaled(self) -> bool {
        let signal = self.0 & 0x7f;
        signal != 0 && signal != 0x7f
    }

    /// Returns the terminating raw signal number when applicable.
    #[inline]
    #[must_use]
    pub const fn terminating_signal(self) -> Option<i32> {
        if self.signaled() {
            Some(self.0 & 0x7f)
        } else {
            None
        }
    }

    /// Returns whether the terminating signal produced a core dump.
    #[inline]
    #[must_use]
    pub const fn core_dumped(self) -> bool {
        self.signaled() && self.0 & 0x80 != 0
    }

    /// Returns whether the child is currently stopped.
    #[inline]
    #[must_use]
    pub const fn stopped(self) -> bool {
        self.0 & 0xff == 0x7f
    }

    /// Returns the raw stopping signal number when applicable.
    #[inline]
    #[must_use]
    pub const fn stopping_signal(self) -> Option<i32> {
        if self.stopped() {
            Some((self.0 >> 8) & 0xff)
        } else {
            None
        }
    }

    /// Returns whether the child has continued from a job-control stop.
    #[inline]
    #[must_use]
    pub const fn continued(self) -> bool {
        self.0 == 0xffff
    }
}

impl fmt::Debug for WaitStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut status = formatter.debug_struct("WaitStatus");
        status
            .field("exited", &self.exited())
            .field("signaled", &self.signaled())
            .field("stopped", &self.stopped())
            .field("continued", &self.continued());
        if let Some(code) = self.exit_status() {
            status.field("exit_status", &code);
        }
        if let Some(signal) = self.terminating_signal() {
            status.field("terminating_signal", &signal);
        }
        if let Some(signal) = self.stopping_signal() {
            status.field("stopping_signal", &signal);
        }
        status.finish()
    }
}

/// A descriptor action prepared in the parent for a child exec path.
///
/// The source borrow keeps the descriptor open while a [`PreparedExec`] is
/// used. Destination descriptor numbers intentionally remain raw because they
/// identify child namespace slots rather than a parent-owned resource.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub enum FdAction<'fd> {
    /// Close this descriptor in the child before exec.
    Close(BorrowedFd<'fd>),
    /// Duplicate `from` onto `to` in the child before exec.
    Dup2 { from: BorrowedFd<'fd>, to: RawFd },
}

#[cfg(feature = "alloc")]
impl<'fd> FdAction<'fd> {
    /// Prepares a child close action while retaining a borrow of `fd`.
    #[inline]
    pub fn close<Fd: AsFd + ?Sized>(fd: &'fd Fd) -> Self {
        Self::Close(fd.as_fd())
    }

    /// Prepares a child `dup2` action while retaining a borrow of `from`.
    #[inline]
    pub fn dup2<Fd: AsFd + ?Sized>(from: &'fd Fd, to: RawFd) -> Self {
        Self::Dup2 {
            from: from.as_fd(),
            to,
        }
    }
}

/// Process-state changes applied in the child before an exec.
///
/// The builder is intentionally narrow: every child operation is a direct
/// async-signal-safe syscall and preparation performs no hidden work after
/// the internal fork-equivalent clone. More complex POSIX spawn attributes
/// remain separate capability groups rather than silently introducing
/// child-side allocation or libc use.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SpawnOptions<'mask> {
    process_group: Option<Option<Pid>>,
    new_session: bool,
    signal_mask: Option<&'mask crate::signal::SignalSet>,
}

#[cfg(feature = "alloc")]
impl<'mask> SpawnOptions<'mask> {
    /// Creates options which inherit process group, session, and signal mask.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            process_group: None,
            new_session: false,
            signal_mask: None,
        }
    }

    /// Assigns the child to `pgid`; `None` creates a group led by the child.
    #[inline]
    #[must_use]
    pub const fn process_group(mut self, pgid: Option<Pid>) -> Self {
        self.process_group = Some(pgid);
        self
    }

    /// Makes the child a new session leader before exec.
    #[inline]
    #[must_use]
    pub const fn new_session(mut self, enabled: bool) -> Self {
        self.new_session = enabled;
        self
    }

    /// Replaces the child's signal mask before exec.
    #[inline]
    #[must_use]
    pub const fn signal_mask(mut self, mask: &'mask crate::signal::SignalSet) -> Self {
        self.signal_mask = Some(mask);
        self
    }
}

/// A validated, allocation-complete program image ready for safe prepared
/// fork/exec spawn.
///
/// Paths and argument/environment storage are copied and their
/// null-terminated pointer arrays are built in the parent. [`spawn`](Self::spawn)'s
/// child path therefore performs only direct descriptor/process syscalls,
/// `execve`, an error-pipe write, and `exit_group`. Direct current-process
/// exec remains a separate unsafe capability and is intentionally absent from
/// this staged x86 surface.
#[cfg(feature = "alloc")]
pub struct PreparedExec<'fd> {
    path: CString,
    // These owned strings keep the precomputed pointer arrays valid until an
    // exec replaces the child image or this prepared value is dropped.
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_pointers: Vec<*const u8>,
    envp_pointers: Vec<*const u8>,
    actions: Vec<FdAction<'fd>>,
    options: SpawnOptions<'fd>,
}

#[cfg(feature = "alloc")]
impl<'fd> PreparedExec<'fd> {
    /// Resolves and validates a program path plus its argument and environment
    /// strings in the parent process.
    ///
    /// `argv` must contain at least one entry. An empty `envp` deliberately
    /// means an empty environment; this facade never reads or mutates C's
    /// process-global environment behind the caller's back.
    #[inline]
    pub fn new<P: PathArg>(path: P, argv: &[&CStr], envp: &[&CStr]) -> Result<Self> {
        if argv.is_empty() {
            return Err(crate::Errno::INVAL);
        }
        path.into_with_c_str(|path| {
            let path = CString::new(path.to_bytes()).map_err(|_| crate::Errno::INVAL)?;
            let argv = copy_c_strings(argv)?;
            let envp = copy_c_strings(envp)?;
            Ok(Self {
                path,
                argv_pointers: c_string_pointers(&argv),
                envp_pointers: c_string_pointers(&envp),
                _argv: argv,
                _envp: envp,
                actions: Vec::new(),
                options: SpawnOptions::new(),
            })
        })
    }

    /// Replaces the prepared child descriptor actions. The vector copy occurs
    /// now, before any child path exists, rather than after the internal
    /// fork-equivalent clone.
    #[inline]
    #[must_use]
    pub fn with_actions(mut self, actions: &[FdAction<'fd>]) -> Self {
        self.actions.extend_from_slice(actions);
        self
    }

    /// Replaces the prepared child process-state options.
    #[inline]
    #[must_use]
    pub const fn with_options(mut self, options: SpawnOptions<'fd>) -> Self {
        self.options = options;
        self
    }

    /// Returns the fully encoded executable path.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &CStr {
        self.path.as_c_str()
    }

    /// Spawns this image with a `CLOEXEC` error pipe.
    ///
    /// The parent receives an `Errno` if child setup or `execve` fails and
    /// reaps that failed child before returning. A successful exec closes the
    /// pipe atomically via `CLOEXEC`, after which this returns a unique typed
    /// child owner. The internal clone never becomes a general public fork
    /// boundary.
    #[inline]
    pub fn spawn(&self) -> Result<Child> {
        let (reader, initial_writer) = crabc_core::pipe::pipe2(crabc_core::io::O_CLOEXEC)?;
        let writer = match reserve_child_error_fd(initial_writer, &self.actions) {
            Ok(writer) => writer,
            Err(error) => {
                let _ = crabc_core::io::close(reader);
                let _ = crabc_core::io::close(initial_writer);
                return Err(error);
            }
        };
        match crabc_core::process::fork_raw() {
            Err(error) => {
                let _ = crabc_core::io::close(reader);
                let _ = crabc_core::io::close(writer);
                Err(error)
            }
            Ok(0) => {
                let _ = crabc_core::io::close(reader);
                let error = match self.apply_child_setup().and_then(|()| self.exec_no_setup()) {
                    Err(error) => error,
                    Ok(never) => match never {},
                };
                write_child_exec_error_and_exit(writer, error)
            }
            Ok(raw_child) => {
                // A successful fork-equivalent clone returns only zero in the
                // child or a positive child PID in the parent.
                let child = unsafe { Pid::from_raw_unchecked(raw_child) };
                let _ = crabc_core::io::close(writer);
                let result = read_child_exec_result(reader);
                if let Err(error) = result {
                    let _ = wait_child(child, WaitOptions::empty());
                    Err(error)
                } else {
                    Ok(Child { pid: child })
                }
            }
        }
    }

    #[inline]
    fn apply_child_setup(&self) -> Result<()> {
        if self.options.new_session {
            crabc_core::process::setsid()?;
        }
        if let Some(process_group) = self.options.process_group {
            crabc_core::process::setpgid(0, process_group.map_or(0, Pid::as_raw_pid))?;
        }
        if let Some(mask) = self.options.signal_mask {
            // SAFETY: `mask` is a one-word kernel signal-set value retained by
            // this prepared object's borrow through the direct syscall.
            unsafe {
                crabc_core::signal::rt_sigprocmask_raw(
                    2,
                    mask.kernel_bits(),
                    core::ptr::null_mut(),
                )?;
            }
        }
        for action in &self.actions {
            match *action {
                FdAction::Close(fd) => crabc_core::io::close(fd.as_raw_fd())?,
                FdAction::Dup2 { from, to } => crabc_core::io::dup2(from.as_raw_fd(), to)?,
            }
        }
        Ok(())
    }

    #[inline]
    fn exec_no_setup(&self) -> Result<Infallible> {
        // SAFETY: `PreparedExec` owns every NUL-terminated string and both
        // terminal-null pointer arrays for the entire syscall. Linux execve
        // does not return after success.
        match unsafe {
            crabc_core::process::execve_raw(
                self.path.as_ptr().cast(),
                self.argv_pointers.as_ptr(),
                self.envp_pointers.as_ptr(),
            )
        } {
            Err(error) => Err(error),
            Ok(()) => panic!("Linux execve unexpectedly returned success"),
        }
    }
}

/// A successfully spawned native child process.
///
/// A `Child` is the unique owner of the wait state for its spawned process.
/// It is deliberately not `Clone` or `Copy`: duplicating the PID would create
/// multiple apparent owners that could each try to reap the same child.
///
/// ```compile_fail
/// # use crabc_rs::process::{Child, WaitOptions};
/// # fn duplicate_wait(child: Child) {
/// let _first = child.wait(WaitOptions::empty());
/// let _second = child.wait(WaitOptions::empty());
/// # }
/// ```
#[cfg(feature = "alloc")]
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Child {
    pid: Pid,
}

#[cfg(feature = "alloc")]
impl Child {
    /// Returns the child's process ID and consumes its unique wait owner.
    #[inline]
    #[must_use]
    pub const fn pid(self) -> Pid {
        self.pid
    }

    /// Waits for this child, consuming its unique owner. `NOHANG` may return
    /// `None`, while a state report returns its decoded wait status; either
    /// result consumes the `Child` and cannot be waited a second time.
    #[inline]
    pub fn wait(self, options: WaitOptions) -> Result<Option<WaitStatus>> {
        wait_child(self.pid, options)
    }
}

#[cfg(feature = "alloc")]
#[inline]
fn wait_child(pid: Pid, options: WaitOptions) -> Result<Option<WaitStatus>> {
    let mut status = 0_i32;
    // SAFETY: `status` is writable Linux `int` storage, `pid` is an exact
    // positive child selector, and the private caller owns this one-child
    // wait transition.
    let waited = unsafe {
        crabc_core::process::wait4_raw(pid.as_raw_pid(), &mut status, options.bits())?
    };
    if waited == 0 {
        Ok(None)
    } else {
        Ok(Some(WaitStatus(status)))
    }
}

#[cfg(feature = "alloc")]
#[inline]
fn copy_c_strings(values: &[&CStr]) -> Result<Vec<CString>> {
    let mut copied = Vec::with_capacity(values.len());
    for value in values {
        copied.push(CString::new(value.to_bytes()).map_err(|_| crate::Errno::INVAL)?);
    }
    Ok(copied)
}

#[cfg(feature = "alloc")]
#[inline]
fn c_string_pointers(values: &[CString]) -> Vec<*const u8> {
    let mut pointers = Vec::with_capacity(values.len() + 1);
    for value in values {
        pointers.push(value.as_ptr().cast());
    }
    pointers.push(core::ptr::null());
    pointers
}

/// Reserves a close-on-exec child error descriptor outside every `dup2` target.
///
/// A prepared action may legally replace any raw child descriptor. Relocating
/// the private error writer first preserves `spawn`'s promise to report child
/// setup and exec errors rather than mistaking a clobbered error pipe for a
/// successful exec.
#[cfg(feature = "alloc")]
fn reserve_child_error_fd(writer: RawFd, actions: &[FdAction<'_>]) -> Result<RawFd> {
    let mut minimum = 3;
    loop {
        let candidate = crabc_core::io::fcntl_dupfd_cloexec(writer, minimum)?;
        let collides = actions.iter().any(|action| match action {
            FdAction::Dup2 { to, .. } => *to == candidate,
            FdAction::Close(_) => false,
        });
        if !collides {
            let _ = crabc_core::io::close(writer);
            return Ok(candidate);
        }
        let _ = crabc_core::io::close(candidate);
        if candidate == i32::MAX {
            return Err(crate::Errno::MFILE);
        }
        minimum = candidate + 1;
    }
}

#[cfg(feature = "alloc")]
#[inline]
fn read_child_exec_result(reader: RawFd) -> Result<()> {
    let mut bytes = [0_u8; core::mem::size_of::<i32>()];
    let mut filled = 0;
    while filled != bytes.len() {
        match crabc_core::io::read(reader, &mut bytes[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(crate::Errno::INTR) => continue,
            Err(error) => {
                let _ = crabc_core::io::close(reader);
                return Err(error);
            }
        }
    }
    let _ = crabc_core::io::close(reader);
    if filled == 0 {
        return Ok(());
    }
    if filled != bytes.len() {
        return Err(crate::Errno::IO);
    }
    let raw = i32::from_ne_bytes(bytes);
    Err(crate::Errno::from_raw(raw).unwrap_or(crate::Errno::IO))
}

#[cfg(feature = "alloc")]
#[inline]
fn write_child_exec_error_and_exit(writer: RawFd, error: crate::Errno) -> ! {
    let bytes = error.raw().to_ne_bytes();
    let mut written = 0;
    while written != bytes.len() {
        match crabc_core::io::write(writer, &bytes[written..]) {
            Ok(0) => break,
            Ok(count) => written += count,
            Err(crate::Errno::INTR) => continue,
            Err(_) => break,
        }
    }
    let _ = crabc_core::io::close(writer);
    crabc_core::process::exit_immediately(127)
}

/// A Linux resource whose current and maximum limits can be queried.
///
/// This closed vocabulary matches the `RLIMIT_*` selectors in the pinned
/// Linux/musl x86-64 headers. There is no raw selector constructor, so an
/// unknown or future resource number cannot cross this facade boundary.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Resource {
    /// `RLIMIT_CPU`.
    Cpu = 0,
    /// `RLIMIT_FSIZE`.
    Fsize = 1,
    /// `RLIMIT_DATA`.
    Data = 2,
    /// `RLIMIT_STACK`.
    Stack = 3,
    /// `RLIMIT_CORE`.
    Core = 4,
    /// `RLIMIT_RSS`.
    Rss = 5,
    /// `RLIMIT_NPROC`.
    Nproc = 6,
    /// `RLIMIT_NOFILE`.
    Nofile = 7,
    /// `RLIMIT_MEMLOCK`.
    Memlock = 8,
    /// `RLIMIT_AS`.
    As = 9,
    /// `RLIMIT_LOCKS`.
    Locks = 10,
    /// `RLIMIT_SIGPENDING`.
    Sigpending = 11,
    /// `RLIMIT_MSGQUEUE`.
    Msgqueue = 12,
    /// `RLIMIT_NICE`.
    Nice = 13,
    /// `RLIMIT_RTPRIO`.
    Rtprio = 14,
    /// `RLIMIT_RTTIME`.
    Rttime = 15,
}

impl Resource {
    /// Returns the exact Linux resource selector used by `prlimit64`.
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

/// Current and maximum values for one Linux process resource.
///
/// Linux's `RLIM_INFINITY` is represented as `None`; every finite kernel
/// value is preserved exactly. The staged x86-64 facade uses this type for
/// queries and its bounded calling-process `setrlimit` operation only.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Rlimit {
    /// Soft/current limit. `None` means unlimited.
    pub current: Option<u64>,
    /// Hard/maximum limit. `None` means unlimited.
    pub maximum: Option<u64>,
}

impl Rlimit {
    #[inline]
    fn from_kernel(limit: crabc_core::process::KernelRlimit64) -> Self {
        Self {
            current: (limit.rlim_cur != u64::MAX).then_some(limit.rlim_cur),
            maximum: (limit.rlim_max != u64::MAX).then_some(limit.rlim_max),
        }
    }

    #[inline]
    fn into_kernel(self) -> Result<crabc_core::process::KernelRlimit64> {
        let current = self.current.unwrap_or(u64::MAX);
        let maximum = self.maximum.unwrap_or(u64::MAX);
        if current > maximum {
            return Err(crate::Errno::INVAL);
        }
        Ok(crabc_core::process::KernelRlimit64 {
            rlim_cur: current,
            rlim_max: maximum,
        })
    }
}

/// Which calling-task resource usage Linux should observe.
///
/// `SelfProcess` is the calling process, `Children` is terminated and waited
/// children of that process, and `Thread` is the calling thread. These are
/// the three selectors exposed by the pinned musl x86-64 `sys/resource.h`;
/// arbitrary future kernel selector values cannot cross this native boundary.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum ResourceUsageTarget {
    /// `RUSAGE_SELF`, the calling process.
    SelfProcess = 0,
    /// `RUSAGE_CHILDREN`, terminated and waited children.
    Children = -1,
    /// `RUSAGE_THREAD`, the calling thread.
    Thread = 1,
}

impl ResourceUsageTarget {
    /// Returns the Linux `RUSAGE_*` selector.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// One CPU-time value returned by Linux `getrusage`.
///
/// The x86-64 Linux ABI is LP64, so the kernel's timeval record contains two
/// signed 64-bit words. The fields retain that signed representation rather
/// than converting through a C `timeval` or a potentially lossy `Duration`.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResourceUsageTime {
    seconds: i64,
    microseconds: i64,
}

impl ResourceUsageTime {
    #[inline]
    fn from_kernel(value: crabc_core::process::KernelRusageTimeval) -> Self {
        Self {
            seconds: value.tv_sec,
            microseconds: value.tv_usec,
        }
    }

    /// Whole seconds of CPU time.
    #[inline]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Microseconds within the CPU-time second.
    #[inline]
    pub const fn microseconds(self) -> i64 {
        self.microseconds
    }
}

/// Read-only Linux resource-usage observations.
///
/// The fourteen counters are copied exactly from Linux's signed 64-bit
/// `long` fields. `maximum_resident_set_size` is measured in KiB on Linux;
/// the historical integral-memory, swap, IPC, and signal fields are retained
/// as kernel observations even though contemporary Linux normally reports
/// zero for them. No reserved words from musl's larger public C struct are
/// exposed: the kernel leaves that compatibility tail uninitialized.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResourceUsage {
    /// User CPU time consumed by the selected target.
    pub user_time: ResourceUsageTime,
    /// System CPU time consumed by the selected target.
    pub system_time: ResourceUsageTime,
    /// Maximum resident-set size, in KiB on Linux.
    pub maximum_resident_set_size: i64,
    /// Integral shared-memory size (historical Linux field).
    pub integral_shared_memory_size: i64,
    /// Integral unshared-data size (historical Linux field).
    pub integral_unshared_data_size: i64,
    /// Integral unshared-stack size (historical Linux field).
    pub integral_unshared_stack_size: i64,
    /// Number of minor page faults.
    pub minor_page_faults: i64,
    /// Number of major page faults.
    pub major_page_faults: i64,
    /// Number of swaps (historical Linux field).
    pub swaps: i64,
    /// Block input operations.
    pub block_input_operations: i64,
    /// Block output operations.
    pub block_output_operations: i64,
    /// IPC messages sent (historical Linux field).
    pub ipc_messages_sent: i64,
    /// IPC messages received (historical Linux field).
    pub ipc_messages_received: i64,
    /// Signals received (historical Linux field).
    pub signals_received: i64,
    /// Voluntary context switches.
    pub voluntary_context_switches: i64,
    /// Involuntary context switches.
    pub involuntary_context_switches: i64,
}

/// One raw Linux clock-tick count.
///
/// `times(2)` reports process CPU accounting and its independent elapsed
/// result in kernel clock ticks. This type intentionally carries no clock
/// frequency and therefore cannot be converted to seconds without a separate
/// process-configuration observation. Its raw signed representation preserves
/// Linux x86-64's `clock_t` convention; process-accounting fields are
/// validated non-negative by the kernel seam before construction.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockTicks(i64);

impl ClockTicks {
    /// Returns the exact Linux x86-64 `clock_t` word, still in clock ticks.
    #[must_use]
    #[inline]
    pub const fn as_raw(self) -> i64 {
        self.0
    }

    #[inline]
    fn from_process_ticks(value: i64) -> Self {
        debug_assert!(value >= 0);
        Self(value)
    }

    #[inline]
    fn from_elapsed_ticks(value: i64) -> Self {
        Self(value)
    }
}

/// Read-only process CPU-accounting observations from Linux `times(2)`.
///
/// The four process fields are the calling process and its waited-for
/// terminated children. `elapsed_ticks` is the syscall's independent count
/// since a kernel-defined arbitrary point; it is not a fifth CPU-time field.
/// All values remain in opaque clock ticks: this API does not assume or invent
/// a clock rate such as `CLK_TCK`.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProcessTimes {
    user_time: ClockTicks,
    system_time: ClockTicks,
    children_user_time: ClockTicks,
    children_system_time: ClockTicks,
    elapsed_ticks: ClockTicks,
}

impl ProcessTimes {
    /// User CPU time consumed by the calling process, in clock ticks.
    #[must_use]
    #[inline]
    pub const fn user_time(self) -> ClockTicks {
        self.user_time
    }

    /// System CPU time consumed on behalf of the calling process, in ticks.
    #[must_use]
    #[inline]
    pub const fn system_time(self) -> ClockTicks {
        self.system_time
    }

    /// User CPU time of waited-for terminated children, in clock ticks.
    #[must_use]
    #[inline]
    pub const fn children_user_time(self) -> ClockTicks {
        self.children_user_time
    }

    /// System CPU time of waited-for terminated children, in clock ticks.
    #[must_use]
    #[inline]
    pub const fn children_system_time(self) -> ClockTicks {
        self.children_system_time
    }

    /// Independent elapsed clock-tick return from Linux `times(2)`.
    ///
    /// Linux defines the origin arbitrarily and permits the `clock_t` result
    /// to overflow, so this value is useful for same-process observations and
    /// remains distinct from process CPU time. No seconds conversion is made.
    #[must_use]
    #[inline]
    pub const fn elapsed_ticks(self) -> ClockTicks {
        self.elapsed_ticks
    }
}

bitflags! {
    /// Flags accepted by Linux `pidfd_open`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PidfdFlags: u32 {
        /// Make operations on the returned pidfd nonblocking.
        const NONBLOCK = 0x0000_0800;
        /// Preserve future Linux-defined bits for kernel validation.
        const _ = !0;
    }
}

/// An opaque Linux user identifier.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Uid(RawUid);

impl Uid {
    /// The Linux root user identifier.
    pub const ROOT: Self = Self(0);

    /// Wraps an exact Linux x86-64 `uid_t` value.
    #[inline]
    pub const fn from_raw(raw: RawUid) -> Self {
        Self(raw)
    }

    /// Returns the exact Linux x86-64 `uid_t` value.
    #[inline]
    pub const fn as_raw(self) -> RawUid {
        self.0
    }

    /// Returns whether this identifier is the root user.
    #[inline]
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }
}

/// An opaque Linux group identifier.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Gid(RawGid);

impl Gid {
    /// The Linux root group identifier.
    pub const ROOT: Self = Self(0);

    /// Wraps an exact Linux x86-64 `gid_t` value.
    #[inline]
    pub const fn from_raw(raw: RawGid) -> Self {
        Self(raw)
    }

    /// Returns the exact Linux x86-64 `gid_t` value.
    #[inline]
    pub const fn as_raw(self) -> RawGid {
        self.0
    }

    /// Returns whether this identifier is the root group.
    #[inline]
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }
}

/// The calling process's real, effective, and saved user IDs.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UidTriple {
    /// The real user ID.
    pub real: Uid,
    /// The effective user ID.
    pub effective: Uid,
    /// The saved-set user ID.
    pub saved: Uid,
}

/// The calling process's real, effective, and saved group IDs.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GidTriple {
    /// The real group ID.
    pub real: Gid,
    /// The effective group ID.
    pub effective: Gid,
    /// The saved-set group ID.
    pub saved: Gid,
}

/// Copies the calling process's current working directory into caller-owned
/// storage through Linux's direct `getcwd` syscall.
///
/// The returned `Buffer::Output` contains exactly the initialized prefix. On
/// success Linux includes the terminating NUL in that prefix, so a
/// `MaybeUninit` result can be passed to
/// [`core::ffi::CStr::from_bytes_with_nul`] without reading the untouched
/// suffix. The borrow carried by the output keeps that initialized prefix
/// tied to the caller's storage. An undersized buffer is reported as
/// [`crate::Errno::RANGE`], including an empty buffer at this direct syscall
/// boundary. This operation only observes the current working directory; it
/// does not change it.
#[inline]
#[allow(private_interfaces)]
pub fn getcwd<Buf: Buffer<u8>>(mut buffer: Buf) -> Result<Buf::Output> {
    let (pointer, length) = buffer.parts_mut();
    // SAFETY: `Buffer` supplies writable storage for exactly `length` bytes.
    // Linux initializes exactly the returned successful prefix, including the
    // trailing NUL byte.
    let initialized = unsafe { crabc_core::process::getcwd_raw(pointer, length)? };
    // SAFETY: A successful getcwd initialized exactly the returned prefix.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Returns the current working directory as an owned NUL-terminated string.
///
/// The supplied vector is cleared and reused when possible. It is grown only
/// after Linux reports [`crate::Errno::RANGE`], retaining the same bounded
/// caller-buffered syscall contract as [`getcwd`].
#[cfg(feature = "alloc")]
#[inline]
pub fn getcwd_alloc<B: Into<Vec<u8>>>(reuse: B) -> Result<CString> {
    let mut buffer = reuse.into();
    buffer.clear();
    buffer.reserve(crate::fs::SMALL_PATH_BUFFER_SIZE);

    loop {
        let capacity = buffer.capacity();
        let spare = buffer.spare_capacity_mut();
        let length = match unsafe {
            crabc_core::process::getcwd_raw(spare.as_mut_ptr().cast(), spare.len())
        } {
            Ok(length) => length,
            Err(crate::Errno::RANGE) => {
                // Grow by at least one byte so a path exactly filling the
                // previous capacity can make progress on the next syscall.
                buffer.reserve(capacity.saturating_add(1));
                continue;
            }
            Err(error) => return Err(error),
        };

        // SAFETY: Linux's successful getcwd result is a pathname, which cannot
        // contain an interior NUL; it includes one terminating NUL byte and
        // reports its complete initialized length. The returned length is
        // bounded by the spare capacity supplied above.
        unsafe {
            buffer.set_len(length);
            return Ok(CString::from_vec_with_nul_unchecked(buffer));
        }
    }
}

/// Returns whether `pwd` is an absolute spelling of the calling process's
/// current directory.
//
// This is deliberately an explicit input rather than an environment lookup.
// A caller which owns an environment snapshot can pass its `PWD` value here;
// the value is trusted only after Linux confirms that it names the same
// `(st_dev, st_ino)` pair as `.`. This preserves logical symlink spellings
// without making environment state part of the native API.
#[inline]
fn logical_pwd_matches_current(pwd: &CStr) -> bool {
    let bytes = pwd.to_bytes();
    if bytes.is_empty() || bytes[0] != b'/' {
        return false;
    }

    let dot = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };
    let pwd_stat = match crate::fs::stat(pwd) {
        Ok(stat) => stat,
        Err(_) => return false,
    };
    let dot_stat = match crate::fs::stat(dot) {
        Ok(stat) => stat,
        Err(_) => return false,
    };
    pwd_stat.st_dev == dot_stat.st_dev && pwd_stat.st_ino == dot_stat.st_ino
}

/// Copies a validated logical pathname into caller-owned storage.
#[inline]
fn copy_cstr_into<Buf: Buffer<u8>>(source: &CStr, mut buffer: Buf) -> Result<Buf::Output> {
    let source = source.to_bytes_with_nul();
    let (destination, capacity) = buffer.parts_mut();
    if capacity < source.len() {
        return Err(crate::Errno::RANGE);
    }

    // SAFETY: The capacity check proves that the complete NUL-terminated
    // source fits in the writable buffer. `ptr::copy` permits a caller to
    // provide storage which overlaps the borrowed source spelling.
    unsafe {
        ptr::copy(source.as_ptr(), destination, source.len());
        Ok(buffer.assume_init(source.len()))
    }
}

/// Returns a logical current-directory spelling when the caller's `PWD`
/// snapshot is valid, otherwise the physical spelling from Linux `getcwd`.
///
/// `PWD` is never read from the process environment. When it is nonempty,
/// absolute, and names the same directory as `.`, its exact bytes—including
/// symlink components and non-UTF-8 bytes—are copied into `buffer`. A buffer
/// too small for that validated spelling returns [`crate::Errno::RANGE`]. All
/// fallback behavior has the same initialized-prefix and trailing-NUL
/// contract as [`getcwd`]. Validation is a point-in-time observation, so
/// callers which permit concurrent current-directory changes must coordinate
/// them themselves.
#[inline]
#[allow(private_interfaces)]
pub fn get_current_dir_name<Buf: Buffer<u8>>(
    pwd: Option<&CStr>,
    buffer: Buf,
) -> Result<Buf::Output> {
    if let Some(pwd) = pwd {
        if logical_pwd_matches_current(pwd) {
            return copy_cstr_into(pwd, buffer);
        }
    }
    getcwd(buffer)
}

/// Returns an owned logical current-directory spelling when the caller's
/// `PWD` snapshot is valid, otherwise the physical spelling from Linux
/// `getcwd`. The supplied vector is cleared and reused where possible.
///
/// This convenience API is allocation-enabled; the bounded
/// [`get_current_dir_name`] operation is the corresponding no-alloc surface.
#[cfg(feature = "alloc")]
#[inline]
pub fn get_current_dir_name_alloc<B: Into<Vec<u8>>>(
    pwd: Option<&CStr>,
    reuse: B,
) -> Result<CString> {
    if let Some(pwd) = pwd {
        if logical_pwd_matches_current(pwd) {
            let source = pwd.to_bytes_with_nul();
            let mut buffer = reuse.into();
            buffer.clear();
            buffer.reserve(source.len());
            // SAFETY: `reserve` guarantees capacity for the complete source;
            // the exact NUL-terminated bytes are copied before setting len.
            unsafe {
                ptr::copy_nonoverlapping(source.as_ptr(), buffer.as_mut_ptr(), source.len());
                buffer.set_len(source.len());
                return Ok(CString::from_vec_with_nul_unchecked(buffer));
            }
        }
    }
    getcwd_alloc(reuse)
}

/// Changes the calling process's current working directory.
///
/// The current working directory is process-global Linux state (and is
/// normally shared by all threads in a process). Callers must coordinate
/// concurrent pathname work while using this operation; it does not provide
/// per-thread isolation. The safe contract follows Rustix/std: `P` must
/// provide a valid path argument, and the kernel reports errors as [`Result`].
#[inline]
pub fn chdir<P: PathArg>(path: P) -> Result<()> {
    path.into_with_c_str(crabc_core::process::chdir)
}

/// Changes the calling process's current working directory to the directory
/// referenced by `fd`.
///
/// The current working directory is process-global Linux state (and is
/// normally shared by all threads in a process). Callers must coordinate
/// concurrent pathname work while using this operation; it does not provide
/// per-thread isolation. The safe descriptor contract follows Rustix/std:
/// `Fd` must keep an open descriptor alive for the duration of the call, and
/// the kernel reports errors as [`Result`].
#[inline]
pub fn fchdir<Fd: AsFd>(fd: Fd) -> Result<()> {
    let fd = fd.as_fd();
    crabc_core::process::fchdir(fd.as_raw_fd())
}

/// Changes the calling process's root directory.
///
/// This operation is process-wide and changes how future absolute pathnames
/// are resolved for every thread. It does not change the current working
/// directory, preserve a route back to the old root, or provide a containment
/// boundary: callers must coordinate affected threads and retain any directory
/// descriptors they need after the change. Privilege and pathname failures are
/// returned directly as [`crate::Errno`] values. The safe contract follows
/// Rustix/std: `P` must provide a valid path argument, and the kernel reports
/// whether the operation succeeded.
#[inline]
pub fn chroot<P: PathArg>(path: P) -> Result<()> {
    path.into_with_c_str(crabc_core::process::chroot)
}

/// A Linux nice value observed or supplied through the native priority facade.
///
/// Linux's scheduler accepts values from `-20` through `19`, inclusive. The
/// wrapper keeps that range closed so an arbitrary integer cannot cross this
/// API boundary. This is the normal nice-value representation; it is not the
/// kernel's non-negative `getpriority` wire encoding.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Priority(i32);

impl Priority {
    /// The most favorable Linux nice value.
    pub const MIN: Self = Self(-20);
    /// The least favorable Linux nice value.
    pub const MAX: Self = Self(19);
    /// Linux's default nice value.
    pub const DEFAULT: Self = Self(0);

    /// Converts a Linux nice value into the bounded priority type.
    #[inline]
    pub const fn from_raw(raw: i32) -> Option<Self> {
        if raw >= Self::MIN.0 && raw <= Self::MAX.0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Returns the Linux nice value.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.0
    }

    /// Converts Linux's non-negative `getpriority` syscall result.
    ///
    /// This is intentionally separate from [`from_raw`]: the syscall result
    /// is encoded as `20 - nice` to avoid a negative success return, whereas
    /// this facade exposes the ordinary nice value.
    #[inline]
    fn from_kernel_encoded(raw: i32) -> Option<Self> {
        if raw >= 1 && raw <= 40 {
            Self::from_raw(20 - raw)
        } else {
            None
        }
    }
}

/// Which Linux process set the native scheduling-priority operations target.
///
/// `Process(None)` and `ProcessGroup(None)` select the caller's process and
/// process group respectively. `User` transmits Linux's raw user selector:
/// its zero word selects the calling process's effective user, so it does not
/// let a non-root caller name UID zero explicitly. The closed enum prevents
/// unsupported `which` values from crossing the native API boundary.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum PriorityTarget {
    /// `PRIO_PROCESS`, with `None` meaning the calling process.
    Process(Option<Pid>),
    /// `PRIO_PGRP`, with `None` meaning the calling process group.
    ProcessGroup(Option<Pid>),
    /// `PRIO_USER`, selecting all processes for this user. A zero user word
    /// has Linux's current-effective-user shorthand semantics.
    User(Uid),
}

impl PriorityTarget {
    /// `PRIO_PROCESS`.
    pub const PRIO_PROCESS: i32 = 0;
    /// `PRIO_PGRP`.
    pub const PRIO_PGRP: i32 = 1;
    /// `PRIO_USER`.
    pub const PRIO_USER: i32 = 2;

    /// Constructs a process target, where `None` denotes the caller.
    #[inline]
    pub const fn process(pid: Option<Pid>) -> Self {
        Self::Process(pid)
    }

    /// Constructs a process-group target, where `None` denotes the caller's
    /// process group.
    #[inline]
    pub const fn process_group(pgid: Option<Pid>) -> Self {
        Self::ProcessGroup(pgid)
    }

    /// Constructs a raw Linux user target.
    ///
    /// `Uid::ROOT` transmits the zero selector, which Linux interprets as the
    /// calling process's effective user rather than as an explicit root-user
    /// request.
    #[inline]
    pub const fn user(uid: Uid) -> Self {
        Self::User(uid)
    }

    /// Returns the exact `(which, who)` words passed to Linux.
    #[inline]
    pub const fn as_raw(self) -> (i32, u32) {
        match self {
            Self::Process(pid) => (
                Self::PRIO_PROCESS,
                match pid {
                    Some(pid) => pid.as_raw_pid() as u32,
                    None => 0,
                },
            ),
            Self::ProcessGroup(pgid) => (
                Self::PRIO_PGRP,
                match pgid {
                    Some(pgid) => pgid.as_raw_pid() as u32,
                    None => 0,
                },
            ),
            Self::User(uid) => (Self::PRIO_USER, uid.as_raw()),
        }
    }
}

/// A Linux scheduler policy with a stable priority-range query.
///
/// This closed vocabulary deliberately covers only policies whose Linux
/// priority bounds are stable and directly observable here. Scheduler
/// selection and mutation are outside this read-only API.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum SchedulerPolicy {
    /// The normal time-sharing scheduler policy (`SCHED_OTHER`).
    Other = 0,
    /// The first-in, first-out real-time policy (`SCHED_FIFO`).
    Fifo = 1,
    /// The round-robin real-time policy (`SCHED_RR`).
    RoundRobin = 2,
}

impl SchedulerPolicy {
    /// Returns the Linux scheduler policy token.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// The minimum and maximum priority accepted by one Linux scheduler policy.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct SchedulerPriorityBounds {
    minimum: i32,
    maximum: i32,
}

impl SchedulerPriorityBounds {
    /// Returns the lowest priority accepted by the policy.
    #[inline]
    pub const fn minimum(self) -> i32 {
        self.minimum
    }

    /// Returns the highest priority accepted by the policy.
    #[inline]
    pub const fn maximum(self) -> i32 {
        self.maximum
    }
}

// Linux/x86-64 `struct flock` has the same field order and 32-byte record
// shape as the AArch64 ABI. Keep this wire record private to the facade and
// validate every field before returning it to a safe caller.
type KernelFlock = crabc_core::process::KernelFlock;

/// A process-associated record-lock query in Linux's `fcntl(F_GETLK)` ABI.
///
/// `start` and `length` are non-negative byte offsets. A zero `length` asks
/// Linux to consider the range through the current end of file. `pid` is
/// meaningful in a returned conflicting lock and is ignored for the input
/// query.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Flock {
    /// Starting byte offset.
    pub start: u64,
    /// Number of bytes in the lock range.
    pub length: u64,
    /// Process holding a returned conflicting lock, if reported by Linux.
    pub pid: Option<Pid>,
    /// Requested or observed lock kind.
    pub typ: FlockType,
    /// Requested or observed offset origin.
    pub offset_type: FlockOffsetType,
}

/// Lock kind used by [`fcntl_getlk`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i16)]
pub enum FlockType {
    /// A shared/read lock.
    ReadLock = 0,
    /// An exclusive/write lock.
    WriteLock = 1,
    /// No lock would block the query; valid only in a returned record.
    Unlocked = 2,
}

/// Byte-offset origin used by [`fcntl_getlk`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(i16)]
pub enum FlockOffsetType {
    /// Offset from the beginning of the file.
    Set = 0,
    /// Offset from the current file position.
    Current = 1,
    /// Offset from the end of the file.
    End = 2,
}

impl From<FlockType> for Flock {
    #[inline]
    fn from(typ: FlockType) -> Self {
        Self {
            start: 0,
            length: 0,
            pid: None,
            typ,
            offset_type: FlockOffsetType::Set,
        }
    }
}

impl Flock {
    #[inline]
    fn into_kernel(self) -> Result<KernelFlock> {
        if self.start > i64::MAX as u64 || self.length > i64::MAX as u64 {
            return Err(crate::Errno::RANGE);
        }
        let l_type = match self.typ {
            FlockType::ReadLock => FlockType::ReadLock as i16,
            FlockType::WriteLock => FlockType::WriteLock as i16,
            // Linux documents an unlocked input as undefined for F_GETLK;
            // reject it rather than sending an ambiguous wire record.
            FlockType::Unlocked => return Err(crate::Errno::INVAL),
        };
        Ok(KernelFlock {
            l_type,
            l_whence: self.offset_type as i16,
            l_start: self.start as i64,
            l_len: self.length as i64,
            l_pid: self.pid.map_or(0, Pid::as_raw_pid),
        })
    }

    #[inline]
    fn from_kernel(lock: KernelFlock) -> Result<Option<Self>> {
        let typ = match lock.l_type {
            2 => return Ok(None),
            0 => FlockType::ReadLock,
            1 => FlockType::WriteLock,
            _ => return Err(crate::Errno::RANGE),
        };
        let offset_type = match lock.l_whence {
            0 => FlockOffsetType::Set,
            1 => FlockOffsetType::Current,
            2 => FlockOffsetType::End,
            _ => return Err(crate::Errno::RANGE),
        };
        if lock.l_start < 0 || lock.l_len < 0 || lock.l_pid < 0 {
            return Err(crate::Errno::RANGE);
        }
        let pid = if lock.l_pid == 0 {
            None
        } else {
            // SAFETY: the range check above proves this raw PID is positive.
            Some(unsafe { Pid::from_raw_unchecked(lock.l_pid) })
        };
        Ok(Some(Self {
            start: lock.l_start as u64,
            length: lock.l_len as u64,
            pid,
            typ,
            offset_type,
        }))
    }
}

/// Returns the caller's process ID.
#[inline]
#[must_use]
pub fn getpid() -> Pid {
    // SAFETY: Linux returns a positive process ID for a running task.
    unsafe { Pid::from_raw_unchecked(crabc_core::process::getpid()) }
}

/// Reads the calling process's current and maximum resource limits through
/// Linux `prlimit64` without using libc, a public C ABI, or TLS `errno`.
///
/// This operation is strictly read-only: it selects PID zero, passes a null
/// new-limit pointer, and preserves the complete initialized `rlimit64`
/// result. Linux's `RLIM_INFINITY` is represented as `None` in the returned
/// [`Rlimit`].
#[inline]
pub fn getrlimit(resource: Resource) -> Result<Rlimit> {
    crabc_core::process::getrlimit_raw(resource.as_raw()).map(Rlimit::from_kernel)
}

/// Changes the calling process's file-creation mask and returns the previous
/// mask through Linux's direct umask syscall.
///
/// The mask is process-global state. Callers must coordinate concurrent file
/// creation while changing it; this operation does not use libc or TLS errno.
/// The returned value is the exact previous Linux mode mask. This does not
/// admit x86-64 pathname creation APIs.
#[inline]
pub fn umask(mask: Mode) -> Mode {
    Mode::from_bits_retain(crabc_core::process::umask_raw(mask.bits()))
}

/// Changes the calling process's current and maximum resource limits through
/// Linux `prlimit64`.
///
/// `None` represents Linux `RLIM64_INFINITY`. An unlimited current limit with
/// a finite maximum is rejected before the syscall because it cannot satisfy
/// Linux's `current <= maximum` invariant. The operation changes process-wide
/// state and therefore must be coordinated with other limit users. It neither
/// changes another process nor selects a public C resource-limit API.
#[inline]
pub fn setrlimit(resource: Resource, limit: Rlimit) -> Result<()> {
    let kernel_limit = limit.into_kernel()?;
    crabc_core::process::setrlimit_raw(resource.as_raw(), &kernel_limit)
}

/// Reads a target process's resource limits through Linux `prlimit64` without
/// using libc, a public C ABI, or TLS `errno`.
///
/// `None` selects the calling process; `Some(pid)` selects that Linux process.
/// This query preserves target-lifetime, permission, and invalid-target
/// errors as ordinary [`crate::Errno`] values and performs no mutation.
#[inline]
pub fn getrlimit_for(pid: Option<Pid>, resource: Resource) -> Result<Rlimit> {
    let pid = pid.map_or(0, Pid::as_raw_pid);
    crabc_core::process::getrlimit_for_raw(pid, resource.as_raw()).map(Rlimit::from_kernel)
}

/// Reads a calling-task resource-usage record through Linux's native
/// `getrusage` syscall.
///
/// This is a read-only direct-kernel query. It does not call the public C ABI,
/// inspect TLS `errno`, or expose musl's caller-provided `struct rusage`
/// storage. Linux's initialized 144-byte x86-64 record is copied into the
/// typed [`ResourceUsage`] value; musl's uninitialized reserved tail is
/// omitted.
#[inline]
pub fn getrusage(target: ResourceUsageTarget) -> Result<ResourceUsage> {
    crabc_core::process::getrusage_raw(target.as_raw()).map(ResourceUsage::from)
}

/// Reads the calling process's CPU-accounting observation through Linux's
/// native `times(2)` syscall.
///
/// The operation is read-only and returns typed Rust values. It does not call
/// the public C ABI, use an allocator, inspect TLS `errno`, or assume a clock
/// rate. The private 32-byte x86-64 kernel record is validated before any tick
/// value crosses this facade boundary.
#[inline]
pub fn times() -> Result<ProcessTimes> {
    crabc_core::process::times_raw().map(ProcessTimes::from)
}

/// Queries the number of supplementary groups currently attached to the
/// calling process.
///
/// This is the first half of Linux's `getgroups` query/fill protocol. The
/// credential snapshot may change before [`getgroups`] fills a caller buffer,
/// so a successful count is only a sizing observation and not a reservation.
/// The operation is read-only and does not mutate process credentials.
#[inline]
pub fn getgroups_count() -> Result<usize> {
    crabc_core::process::getgroups_count_raw()
}

/// Fills caller-owned storage with supplementary Linux group IDs.
///
/// The initialized-buffer form (`&mut [Gid]`, and its alloc-backed `Vec`
/// equivalent) returns the number of IDs written. The `MaybeUninit` form
/// returns the initialized prefix and untouched suffix through the shared
/// [`Buffer`] contract. Linux returns [`crate::Errno::INVAL`] when the buffer
/// is smaller than the current group list; callers performing a count query
/// first must retry the count/fill pair when that race occurs.
///
/// Linux's supplementary list is distinct from the effective group ID: this
/// function returns exactly the IDs reported by `getgroups`, without adding or
/// deduplicating [`getgid`].
#[inline]
#[allow(private_interfaces)]
pub fn getgroups<Buf: Buffer<Gid>>(mut buffer: Buf) -> Result<Buf::Output> {
    let (pointer, length) = buffer.parts_mut();
    let pointer = if length == 0 {
        core::ptr::null_mut()
    } else {
        pointer.cast::<u32>()
    };
    // SAFETY: `Buffer<Gid>` supplies writable storage for `length` values.
    // `Gid` is repr(transparent) over Linux x86-64's u32 gid_t representation.
    let initialized = unsafe { crabc_core::process::getgroups_raw(pointer, length)? };
    // SAFETY: Linux initialized exactly the successful return prefix.
    unsafe { Ok(buffer.assume_init(initialized)) }
}

/// Returns the caller's parent process ID, if one is visible in this PID
/// namespace.
#[inline]
#[must_use]
pub fn getppid() -> Option<Pid> {
    Pid::from_raw(crabc_core::process::getppid())
}

/// Opens a stable Linux process descriptor for `pid`.
///
/// The returned [`OwnedFd`] remains valid across PID reuse and closes through
/// the native descriptor owner. Linux's target-lifetime, permission, and
/// unsupported-flag errors are returned directly; this operation does not
/// call libc or inspect thread-local `errno`.
#[inline]
pub fn pidfd_open(pid: Pid, flags: PidfdFlags) -> Result<OwnedFd> {
    let fd = crabc_core::process::pidfd_open_raw(pid.as_raw_pid(), flags.bits())?;
    // SAFETY: successful Linux pidfd_open returns one fresh, non-negative
    // descriptor whose ownership transfers to this value.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reads the accepted priority bounds for one Linux scheduler policy.
///
/// This is a read-only direct-kernel observation. Linux errors remain
/// ordinary [`crate::Errno`] results. The facade also rejects an inverted
/// kernel record as [`crate::Errno::RANGE`] rather than exposing an impossible
/// range.
#[inline]
pub fn scheduler_priority_bounds(policy: SchedulerPolicy) -> Result<SchedulerPriorityBounds> {
    let (minimum, maximum) = crabc_core::process::scheduler_priority_bounds_raw(policy.as_raw())?;
    if minimum > maximum {
        return Err(crate::Errno::RANGE);
    }
    Ok(SchedulerPriorityBounds { minimum, maximum })
}

/// Reads the bounded Linux nice value for a process, process group, or user.
///
/// This is a read-only direct-kernel query. Linux's raw syscall returns the
/// inverted non-negative encoding `20 - nice` (the range `[1, 40]`) so that a
/// successful result cannot be confused with a negative errno. This facade
/// performs the kernel conversion and returns the ordinary nice value in
/// [`Priority`]. No C ABI, thread-local `errno`, or C `-1` sentinel is
/// involved.
#[inline]
pub fn getpriority(target: PriorityTarget) -> Result<Priority> {
    let (which, who) = target.as_raw();
    let encoded = crabc_core::process::getpriority_raw(which, who)?;
    // Linux documents successful getpriority results as [1, 40]. Treat a
    // violation as an impossible kernel contract rather than inventing an
    // errno or silently applying libc's sentinel convention.
    Priority::from_kernel_encoded(encoded).ok_or(crate::Errno::RANGE)
}

/// Reads `PRIO_PROCESS` for an optional process identifier.
#[inline]
pub fn getpriority_process(pid: Option<Pid>) -> Result<Priority> {
    getpriority(PriorityTarget::Process(pid))
}

/// Reads `PRIO_PGRP` for an optional process-group identifier.
#[inline]
pub fn getpriority_process_group(pgid: Option<Pid>) -> Result<Priority> {
    getpriority(PriorityTarget::ProcessGroup(pgid))
}

/// Reads `PRIO_USER` for a raw Linux user selector.
///
/// Passing [`Uid::ROOT`] transmits zero and therefore observes the calling
/// process's effective user under Linux's `PRIO_USER` shorthand semantics.
#[inline]
pub fn getpriority_user(uid: Uid) -> Result<Priority> {
    getpriority(PriorityTarget::User(uid))
}

/// Sets the priority of an optional process identifier.
///
/// `None` selects the calling process. This is a process-scheduling side
/// effect rather than a memory-safety boundary: callers should coordinate
/// with other code that intentionally changes the same task's priority.
/// Kernel permission and target failures remain ordinary [`crate::Errno`]
/// values; this operation does not use libc's TLS `errno` channel.
#[inline]
pub fn setpriority_process(pid: Option<Pid>, priority: Priority) -> Result<()> {
    setpriority(PriorityTarget::Process(pid), priority)
}

/// Sets the priority of an optional process-group identifier.
///
/// `None` selects the calling process group. The kernel may affect more than
/// one task when a process-group target is selected.
#[inline]
pub fn setpriority_process_group(pgid: Option<Pid>, priority: Priority) -> Result<()> {
    setpriority(PriorityTarget::ProcessGroup(pgid), priority)
}

/// Sets the priority of all processes matching a Linux user identifier.
///
/// This may affect multiple processes and requires the permissions enforced by
/// Linux's `setpriority` syscall. [`Uid::ROOT`] transmits Linux's zero
/// selector, which instead targets the calling process's effective user.
#[inline]
pub fn setpriority_user(uid: Uid, priority: Priority) -> Result<()> {
    setpriority(PriorityTarget::User(uid), priority)
}

#[inline]
fn setpriority(target: PriorityTarget, priority: Priority) -> Result<()> {
    let (which, who) = target.as_raw();
    crabc_core::process::setpriority_raw(which, who, priority.as_raw())
}

/// Returns the caller's real Linux user ID.
#[inline]
#[must_use]
pub fn getuid() -> Uid {
    Uid::from_raw(crabc_core::process::getuid())
}

/// Returns the caller's effective Linux user ID.
#[inline]
#[must_use]
pub fn geteuid() -> Uid {
    Uid::from_raw(crabc_core::process::geteuid())
}

/// Returns the caller's real Linux group ID.
#[inline]
#[must_use]
pub fn getgid() -> Gid {
    Gid::from_raw(crabc_core::process::getgid())
}

/// Returns the caller's effective Linux group ID.
#[inline]
#[must_use]
pub fn getegid() -> Gid {
    Gid::from_raw(crabc_core::process::getegid())
}

/// Sets or queries the calling task's Linux filesystem user ID.
///
/// `None` maps to Linux's all-ones query word and therefore leaves the
/// filesystem credential unchanged while returning its previous value.
/// `Some` requests a filesystem-UID change and returns the previous value.
/// Linux returns the previous value even when the requested change is denied,
/// so an unsuccessful request is not distinguishable through an errno; the
/// returned [`Result`] only represents a negative syscall return. This is a
/// Linux calling-task operation, not musl's synchronized process credential
/// API.
///
/// # Safety
///
/// Changing the filesystem UID changes permission checks for filesystem
/// operations performed by this task. The caller must ensure that this
/// authority transition is intentional, coordinate concurrent code which may
/// access filesystem objects, and not assume that other threads are changed.
#[inline]
pub unsafe fn set_fs_uid(uid: Option<Uid>) -> Result<Uid> {
    let uid = match uid {
        Some(uid) if uid.as_raw() == u32::MAX => return Err(crate::Errno::INVAL),
        Some(uid) => uid.as_raw(),
        None => u32::MAX,
    };
    // The caller owns the authority transition described above; the core seam
    // receives only an immediate, validated Linux uid_t word.
    crabc_core::process::setfsuid_raw(uid).map(Uid::from_raw)
}

/// Sets or queries the calling task's Linux filesystem group ID.
///
/// `None` maps to Linux's all-ones query word and therefore leaves the
/// filesystem credential unchanged while returning its previous value.
/// `Some` requests a filesystem-GID change and returns the previous value.
/// Linux returns the previous value even when the requested change is denied,
/// so an unsuccessful request is not distinguishable through an errno; the
/// returned [`Result`] only represents a negative syscall return. This is a
/// Linux calling-task operation, not musl's synchronized process credential
/// API.
///
/// # Safety
///
/// Changing the filesystem GID changes permission checks for filesystem
/// operations performed by this task. The caller must ensure that this
/// authority transition is intentional, coordinate concurrent code which may
/// access filesystem objects, and not assume that other threads are changed.
#[inline]
pub unsafe fn set_fs_gid(gid: Option<Gid>) -> Result<Gid> {
    let gid = match gid {
        Some(gid) if gid.as_raw() == u32::MAX => return Err(crate::Errno::INVAL),
        Some(gid) => gid.as_raw(),
        None => u32::MAX,
    };
    // The caller owns the authority transition described above; the core seam
    // receives only an immediate, validated Linux gid_t word.
    crabc_core::process::setfsgid_raw(gid).map(Gid::from_raw)
}

/// Reads the calling process's real, effective, and saved user IDs.
#[inline]
pub fn getresuid() -> crate::Result<UidTriple> {
    crabc_core::process::getresuid_raw().map(|ids| UidTriple {
        real: Uid::from_raw(ids.real),
        effective: Uid::from_raw(ids.effective),
        saved: Uid::from_raw(ids.saved),
    })
}

/// Reads the calling process's real, effective, and saved group IDs.
#[inline]
pub fn getresgid() -> crate::Result<GidTriple> {
    crabc_core::process::getresgid_raw().map(|ids| GidTriple {
        real: Gid::from_raw(ids.real),
        effective: Gid::from_raw(ids.effective),
        saved: Gid::from_raw(ids.saved),
    })
}

/// Returns a process group ID. `None` selects the calling process.
#[inline]
pub fn getpgid(pid: Option<Pid>) -> crate::Result<Pid> {
    crabc_core::process::getpgid(pid.map_or(0, Pid::as_raw_pid)).map(|raw| {
        // Linux returns a positive process ID for every successful process
        // group observation.
        unsafe { Pid::from_raw_unchecked(raw) }
    })
}

/// Returns the calling process's process group ID.
#[inline]
#[must_use]
pub fn getpgrp() -> Pid {
    match crabc_core::process::getpgid(0) {
        // Linux returns a positive process ID for a live calling process.
        Ok(raw) => unsafe { Pid::from_raw_unchecked(raw) },
        Err(_) => panic!("Linux getpgid(0) syscall failed"),
    }
}

/// Returns a session ID. `None` selects the calling process.
#[inline]
pub fn getsid(pid: Option<Pid>) -> crate::Result<Pid> {
    crabc_core::process::getsid(pid.map_or(0, Pid::as_raw_pid)).map(|raw| {
        // Linux returns a positive process ID for every successful session
        // observation.
        unsafe { Pid::from_raw_unchecked(raw) }
    })
}

/// Queries the first process-associated record lock that would block `lock`.
///
/// Linux returns `None` when no lock would block, or the first conflicting
/// lock as a typed [`Flock`]. The input must be a read or write lock; an
/// [`FlockType::Unlocked`] input is rejected because Linux leaves that input
/// form undefined. Integer offsets, enum values, and returned PIDs are
/// checked before crossing this safe facade. The query is read-only and uses
/// direct Linux `fcntl(F_GETLK)` without libc or TLS `errno`.
#[inline]
pub fn fcntl_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> Result<Option<Flock>> {
    let mut kernel_lock = (*lock).into_kernel()?;
    crabc_core::process::fcntl_getlk_raw(fd.as_fd().as_raw_fd(), &mut kernel_lock)?;
    Flock::from_kernel(kernel_lock)
}

const _: () = assert!(core::mem::size_of::<Uid>() == 4);
const _: () = assert!(core::mem::align_of::<Uid>() == 4);
const _: () = assert!(core::mem::size_of::<Gid>() == 4);
const _: () = assert!(core::mem::align_of::<Gid>() == 4);
const _: () = assert!(core::mem::size_of::<Pid>() == 4);
const _: () = assert!(core::mem::align_of::<Pid>() == 4);
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelRlimit64>() == 16);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelRlimit64>() == 8);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRlimit64, rlim_cur) == 0);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRlimit64, rlim_max) == 8);
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelRusageTimeval>() == 16);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelRusageTimeval>() == 8);
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelRusage>() == 144);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelRusage>() == 8);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_utime) == 0);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_stime) == 16);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_maxrss) == 32);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelRusage, ru_nivcsw) == 136);
const _: () = assert!(core::mem::size_of::<crabc_core::process::KernelProcessTimes>() == 32);
const _: () = assert!(core::mem::align_of::<crabc_core::process::KernelProcessTimes>() == 8);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelProcessTimes, user_ticks) == 0);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelProcessTimes, system_ticks) == 8);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelProcessTimes, children_user_ticks) == 16);
const _: () = assert!(core::mem::offset_of!(crabc_core::process::KernelProcessTimes, children_system_ticks) == 24);

impl From<crabc_core::process::KernelProcessTimesObservation> for ProcessTimes {
    #[inline]
    fn from(value: crabc_core::process::KernelProcessTimesObservation) -> Self {
        Self {
            user_time: ClockTicks::from_process_ticks(value.process.user_ticks),
            system_time: ClockTicks::from_process_ticks(value.process.system_ticks),
            children_user_time: ClockTicks::from_process_ticks(value.process.children_user_ticks),
            children_system_time: ClockTicks::from_process_ticks(
                value.process.children_system_ticks,
            ),
            elapsed_ticks: ClockTicks::from_elapsed_ticks(value.elapsed_ticks),
        }
    }
}

impl From<crabc_core::process::KernelRusage> for ResourceUsage {
    #[inline]
    fn from(value: crabc_core::process::KernelRusage) -> Self {
        Self {
            user_time: ResourceUsageTime::from_kernel(value.ru_utime),
            system_time: ResourceUsageTime::from_kernel(value.ru_stime),
            maximum_resident_set_size: value.ru_maxrss,
            integral_shared_memory_size: value.ru_ixrss,
            integral_unshared_data_size: value.ru_idrss,
            integral_unshared_stack_size: value.ru_isrss,
            minor_page_faults: value.ru_minflt,
            major_page_faults: value.ru_majflt,
            swaps: value.ru_nswap,
            block_input_operations: value.ru_inblock,
            block_output_operations: value.ru_oublock,
            ipc_messages_sent: value.ru_msgsnd,
            ipc_messages_received: value.ru_msgrcv,
            signals_received: value.ru_nsignals,
            voluntary_context_switches: value.ru_nvcsw,
            involuntary_context_switches: value.ru_nivcsw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClockTicks, Flock, FlockOffsetType, FlockType, KernelFlock, Pid, Priority,
        ProcessTimes, Resource, ResourceUsage, ResourceUsageTarget, Rlimit, WaitStatus,
    };

    #[test]
    fn x86_64_wait_status_decodes_each_linux_state_encoding() {
        let exited = WaitStatus(42 << 8);
        assert!(exited.exited());
        assert_eq!(exited.exit_status(), Some(42));
        assert!(!exited.signaled());
        assert!(!exited.stopped());
        assert!(!exited.continued());

        let dumped = WaitStatus(9 | 0x80);
        assert!(!dumped.exited());
        assert!(dumped.signaled());
        assert_eq!(dumped.terminating_signal(), Some(9));
        assert!(dumped.core_dumped());
        assert!(!dumped.stopped());

        let stopped = WaitStatus((19 << 8) | 0x7f);
        assert!(!stopped.signaled());
        assert!(stopped.stopped());
        assert_eq!(stopped.stopping_signal(), Some(19));
        assert!(!stopped.continued());

        let continued = WaitStatus(0xffff);
        assert!(!continued.exited());
        assert!(!continued.signaled());
        assert!(!continued.stopped());
        assert!(continued.continued());
    }

    #[test]
    fn x86_64_flock_conversion_preserves_a_conflicting_lock_record() {
        let raw = KernelFlock {
            l_type: FlockType::WriteLock as i16,
            l_whence: FlockOffsetType::End as i16,
            l_start: 12,
            l_len: 34,
            l_pid: 56,
        };
        let expected = Flock {
            start: 12,
            length: 34,
            // SAFETY: the synthetic raw kernel PID is positive.
            pid: Some(unsafe { Pid::from_raw_unchecked(56) }),
            typ: FlockType::WriteLock,
            offset_type: FlockOffsetType::End,
        };

        assert_eq!(Flock::from_kernel(raw), Ok(Some(expected)));
        assert_eq!(
            Flock::from_kernel(KernelFlock { l_type: FlockType::Unlocked as i16, ..raw }),
            Ok(None),
        );
    }

    #[test]
    fn x86_64_priority_decodes_only_the_kernel_success_range() {
        assert_eq!(Priority::from_kernel_encoded(1).map(Priority::as_raw), Some(19));
        assert_eq!(Priority::from_kernel_encoded(20).map(Priority::as_raw), Some(0));
        assert_eq!(Priority::from_kernel_encoded(40).map(Priority::as_raw), Some(-20));
        assert_eq!(Priority::from_kernel_encoded(0), None);
        assert_eq!(Priority::from_kernel_encoded(41), None);
    }

    #[test]
    fn x86_64_rlimit_maps_kernel_infinity_without_loss() {
        let finite = Rlimit::from_kernel(crabc_core::process::KernelRlimit64 {
            rlim_cur: 7,
            rlim_max: 11,
        });
        assert_eq!(finite.current, Some(7));
        assert_eq!(finite.maximum, Some(11));
        assert_eq!(
            finite.into_kernel(),
            Ok(crabc_core::process::KernelRlimit64 {
                rlim_cur: 7,
                rlim_max: 11,
            })
        );

        let unlimited = Rlimit::from_kernel(crabc_core::process::KernelRlimit64 {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        });
        assert_eq!(unlimited.current, None);
        assert_eq!(unlimited.maximum, None);
        assert_eq!(
            unlimited.into_kernel(),
            Ok(crabc_core::process::KernelRlimit64 {
                rlim_cur: u64::MAX,
                rlim_max: u64::MAX,
            })
        );
        assert_eq!(
            Rlimit {
                current: Some(1),
                maximum: Some(0),
            }
            .into_kernel(),
            Err(crate::Errno::INVAL),
        );
        assert_eq!(
            Rlimit {
                current: None,
                maximum: Some(7),
            }
            .into_kernel(),
            Err(crate::Errno::INVAL),
        );

        assert_eq!(Resource::Nofile.as_raw(), 7);
        assert_eq!(Resource::Rttime.as_raw(), 15);
    }

    #[test]
    fn x86_64_rusage_maps_the_initialized_kernel_record() {
        let value = crabc_core::process::KernelRusage {
            ru_utime: crabc_core::process::KernelRusageTimeval { tv_sec: 1, tv_usec: 2 },
            ru_stime: crabc_core::process::KernelRusageTimeval { tv_sec: 3, tv_usec: 4 },
            ru_maxrss: 5,
            ru_ixrss: 6,
            ru_idrss: 7,
            ru_isrss: 8,
            ru_minflt: 9,
            ru_majflt: 10,
            ru_nswap: 11,
            ru_inblock: 12,
            ru_oublock: 13,
            ru_msgsnd: 14,
            ru_msgrcv: 15,
            ru_nsignals: 16,
            ru_nvcsw: 17,
            ru_nivcsw: 18,
        };
        let usage = ResourceUsage::from(value);

        assert_eq!(usage.user_time.seconds(), 1);
        assert_eq!(usage.user_time.microseconds(), 2);
        assert_eq!(usage.system_time.seconds(), 3);
        assert_eq!(usage.system_time.microseconds(), 4);
        assert_eq!(usage.maximum_resident_set_size, 5);
        assert_eq!(usage.integral_shared_memory_size, 6);
        assert_eq!(usage.integral_unshared_data_size, 7);
        assert_eq!(usage.integral_unshared_stack_size, 8);
        assert_eq!(usage.minor_page_faults, 9);
        assert_eq!(usage.major_page_faults, 10);
        assert_eq!(usage.swaps, 11);
        assert_eq!(usage.block_input_operations, 12);
        assert_eq!(usage.block_output_operations, 13);
        assert_eq!(usage.ipc_messages_sent, 14);
        assert_eq!(usage.ipc_messages_received, 15);
        assert_eq!(usage.signals_received, 16);
        assert_eq!(usage.voluntary_context_switches, 17);
        assert_eq!(usage.involuntary_context_switches, 18);
        assert_eq!(ResourceUsageTarget::SelfProcess.as_raw(), 0);
        assert_eq!(ResourceUsageTarget::Children.as_raw(), -1);
        assert_eq!(ResourceUsageTarget::Thread.as_raw(), 1);
    }

    #[test]
    fn x86_64_times_maps_the_initialized_kernel_record() {
        let value = crabc_core::process::KernelProcessTimesObservation {
            process: crabc_core::process::KernelProcessTimes {
                user_ticks: 1,
                system_ticks: 2,
                children_user_ticks: 3,
                children_system_ticks: 4,
            },
            // Linux permits the independent elapsed clock_t return to wrap;
            // unlike the four process-accounting fields, it stays signed.
            elapsed_ticks: -1,
        };
        let times = ProcessTimes::from(value);

        assert_eq!(times.user_time(), ClockTicks::from_process_ticks(1));
        assert_eq!(times.system_time(), ClockTicks::from_process_ticks(2));
        assert_eq!(times.children_user_time(), ClockTicks::from_process_ticks(3));
        assert_eq!(
            times.children_system_time(),
            ClockTicks::from_process_ticks(4)
        );
        assert_eq!(times.elapsed_ticks(), ClockTicks::from_elapsed_ticks(-1));
    }
}
