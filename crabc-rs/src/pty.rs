//! Native Linux/x86-64 pseudoterminal ownership and explicit session handoff.
//!
//! This private native seam owns opening a `/dev/ptmx` master, validating and
//! unlocking its devpts slave, opening that slave with forced `O_NOCTTY`, and
//! deriving its `/dev/pts/<number>` name into caller-owned or alloc-backed
//! storage. Pair construction always forces `O_NOCTTY`; the only stateful
//! transition is the explicit unsafe session/controlling-terminal handoff on
//! the already-owned slave. It deliberately does not expose a
//! caller-controlled `TIOCGPTPEER` open or a generic ioctl boundary.

use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::slice;

use bitflags::bitflags;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::fs::{self, Mode};
use crate::{AsFd, BorrowedFd, Errno, OwnedFd, Result};

const TIOCGPTN: u32 = 0x8004_5430;
const TIOCSPTLCK: u32 = 0x4004_5431;
const TIOCGPTPEER: u32 = 0x5441;
const TIOCSCTTY: u32 = 0x540e;

const PTY_NAME_PREFIX: &[u8] = b"/dev/pts/";
#[cfg(feature = "alloc")]
const PTY_NAME_MAX: usize = PTY_NAME_PREFIX.len() + 10;

bitflags! {
    /// Linux `O_*` flags accepted by [`openpt`] and [`PtyPair::open`].
    ///
    /// The pair constructor requires [`Self::RDWR`]. `NOCTTY` and `CLOEXEC`
    /// are passed to the master as requested; its internal slave open always
    /// includes `NOCTTY` so constructing a pair cannot acquire a controlling
    /// terminal as a side effect.
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct OpenptFlags: u32 {
        /// `O_RDWR`.
        const RDWR = 0x2;
        /// `O_NOCTTY`.
        const NOCTTY = 0x100;
        /// `O_CLOEXEC`.
        const CLOEXEC = 0x80000;
        /// Preserve direct Linux flag words for kernel validation.
        const _ = !0;
    }
}

impl From<OpenptFlags> for fs::OFlags {
    #[inline]
    fn from(value: OpenptFlags) -> Self {
        Self::from_bits_retain(value.bits())
    }
}

/// An owned Linux pseudoterminal master/slave pair.
///
/// [`Self::open`] opens `/dev/ptmx`, validates and unlocks its devpts slave,
/// then opens that slave through an internal `TIOCGPTPEER` boundary. Both
/// descriptors are owned by this value and are closed on drop. The peer open
/// always includes `O_NOCTTY`, so construction cannot silently change the
/// calling process's terminal state. The only state-changing operation is the
/// explicit unsafe handoff below.
pub struct PtyPair {
    master: OwnedFd,
    slave: OwnedFd,
}

impl PtyPair {
    /// Opens a new owned PTY pair.
    ///
    /// `flags` must include [`OpenptFlags::RDWR`]. `NOCTTY` and `CLOEXEC`
    /// are passed to the master and peer opens as requested; the peer always
    /// receives `NOCTTY` to preserve the safe ownership-only boundary.
    #[inline]
    pub fn open(flags: OpenptFlags) -> Result<Self> {
        if !flags.contains(OpenptFlags::RDWR) {
            return Err(Errno::INVAL);
        }

        let master = openpt(flags)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let slave = open_peer_noctty(&master, flags | OpenptFlags::NOCTTY)?;
        Ok(Self { master, slave })
    }

    /// Borrows the PTY master descriptor.
    #[inline]
    #[must_use]
    pub fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }

    /// Borrows the PTY slave descriptor.
    #[inline]
    #[must_use]
    pub fn slave(&self) -> BorrowedFd<'_> {
        self.slave.as_fd()
    }

    /// Transfers both descriptors out of the pair in master/slave order.
    #[inline]
    #[must_use]
    pub fn into_parts(self) -> (OwnedFd, OwnedFd) {
        let Self { master, slave } = self;
        (master, slave)
    }

    /// Makes the already-open slave this process's controlling terminal.
    ///
    /// # Safety
    ///
    /// The caller must be a Linux session leader, keep this pair's slave open
    /// and exclusively owned for the ioctl, and serialize the transition with
    /// all other session, process-group, and terminal-state operations in the
    /// process. `steal` selects Linux's privileged reassignment behavior
    /// (`TIOCSCTTY` argument one), so the caller must also hold the authority
    /// the kernel requires. This process-global operation is not suitable for
    /// an arbitrary multithreaded caller.
    #[inline]
    pub unsafe fn set_controlling_terminal(&self, steal: bool) -> Result<()> {
        let argument = usize::from(steal) as *mut u8;
        // SAFETY: the method contract establishes the live descriptor,
        // session-leader, ownership, and process-state serialization rules.
        unsafe {
            crabc_core::io::ioctl_raw(self.slave.as_raw_fd(), TIOCSCTTY, argument)?;
        }
        Ok(())
    }

    /// Creates a new session and assigns this pair's slave as its controlling
    /// terminal.
    ///
    /// This is an explicit one-shot `setsid` + `TIOCSCTTY` handoff. It does
    /// not fork, supervise, duplicate, or exec a child process.
    ///
    /// # Safety
    ///
    /// The caller must be an isolated, single-threaded execution context in
    /// which changing the calling process's session and controlling terminal
    /// is intentional. No other code may concurrently inspect or mutate
    /// process groups, sessions, or terminal state. Linux `setsid` must be
    /// permitted for the caller (in particular, it must not already be a
    /// process-group leader), and `steal` has the authority requirements
    /// documented by [`Self::set_controlling_terminal`]. If the ioctl fails
    /// after `setsid` succeeds, the new session remains in effect.
    #[inline]
    pub unsafe fn establish_session_and_controlling_terminal(&self, steal: bool) -> Result<()> {
        crabc_core::process::setsid()?;
        // SAFETY: this method's documented caller obligations are exactly
        // those required by the constituent controlling-terminal operation.
        unsafe { self.set_controlling_terminal(steal) }
    }
}

/// Opens a new pseudoterminal master.
#[inline]
pub fn openpt(flags: OpenptFlags) -> Result<OwnedFd> {
    match fs::open("/dev/ptmx", flags.into(), Mode::empty()) {
        Err(Errno::NOSPC) => Err(Errno::AGAIN),
        other => other,
    }
}

/// Validates the Linux devpts grant associated with a PTY master.
#[inline]
pub fn grantpt<Fd: AsFd>(fd: Fd) -> Result<()> {
    let _ = pty_number(fd)?;
    Ok(())
}

/// Unlocks the slave side of a pseudoterminal.
#[inline]
pub fn unlockpt<Fd: AsFd>(fd: Fd) -> Result<()> {
    let mut unlocked = 0_i32;
    let fd = fd.as_fd();
    // SAFETY: TIOCSPTLCK reads one Linux int from stable storage.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_raw_fd(),
            TIOCSPTLCK,
            (&mut unlocked as *mut i32).cast(),
        )?;
    }
    Ok(())
}

/// Returns the slave device name into caller-provided uninitialized storage.
///
/// The returned [`CStr`] borrows `buffer`, includes its trailing NUL, and is
/// composed solely from the PTY number returned by Linux's `TIOCGPTN` ioctl.
/// A short buffer returns [`Errno::RANGE`] without partial-name success.
#[inline]
pub fn ptsname_into<'buffer, Fd: AsFd>(
    fd: Fd,
    buffer: &'buffer mut [MaybeUninit<u8>],
) -> Result<&'buffer CStr> {
    let number = pty_number(fd)?;
    ptsname_raw(number, buffer)
}

/// `ptsname_r(fd)` with an owned result.
///
/// The supplied vector is cleared and reused when possible. Unlike the C
/// static-buffer `ptsname` ABI, the returned [`CString`] owns its bytes and
/// can outlive the descriptor borrow. The allocation-gated API never uses
/// libc, C `errno`, or process-global storage.
#[cfg(feature = "alloc")]
#[inline]
pub fn ptsname<Fd: AsFd, B: Into<Vec<u8>>>(fd: Fd, reuse: B) -> Result<CString> {
    let number = pty_number(fd)?;
    let mut path = reuse.into();
    path.clear();
    path.reserve(PTY_NAME_MAX + 1);
    let length = {
        let name = ptsname_raw(number, path.spare_capacity_mut())?;
        name.to_bytes().len()
    };
    // SAFETY: `ptsname_raw` initialized exactly `length + 1` bytes, including
    // the trailing NUL, in the vector's spare capacity.
    unsafe {
        path.set_len(length + 1);
    }
    // SAFETY: The fixed ASCII PTY path has one trailing NUL and no interior
    // NUL bytes.
    Ok(unsafe { CString::from_vec_with_nul_unchecked(path) })
}

#[inline]
fn open_peer_noctty<Fd: AsFd>(fd: Fd, flags: OpenptFlags) -> Result<OwnedFd> {
    let fd = fd.as_fd();
    // SAFETY: TIOCGPTPEER encodes `O_*` flags in the ioctl argument word and
    // returns a newly-owned descriptor as its successful integer result. The
    // caller is private to this module and always includes O_NOCTTY.
    let raw = unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_raw_fd(),
            TIOCGPTPEER,
            flags.bits() as usize as *mut u8,
        )?
    };
    // SAFETY: a successful TIOCGPTPEER result is a newly allocated fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[inline]
fn ptsname_raw<'buffer>(
    number: i32,
    buffer: &'buffer mut [MaybeUninit<u8>],
) -> Result<&'buffer CStr> {
    if number < 0 {
        return Err(Errno::INVAL);
    }

    let mut digits = [0_u8; 10];
    let mut value = number as u32;
    let mut digit_count = 0;
    loop {
        digits[digit_count] = b'0' + (value % 10) as u8;
        digit_count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    let length = PTY_NAME_PREFIX.len() + digit_count;
    if buffer.len() < length + 1 {
        return Err(Errno::RANGE);
    }
    for (index, byte) in PTY_NAME_PREFIX.iter().copied().enumerate() {
        buffer[index].write(byte);
    }
    for index in 0..digit_count {
        buffer[PTY_NAME_PREFIX.len() + index].write(digits[digit_count - index - 1]);
    }
    buffer[length].write(0);

    // SAFETY: Every byte in the returned prefix, including its trailing NUL,
    // was initialized above. The path is generated from fixed ASCII bytes.
    let bytes = unsafe { slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), length + 1) };
    // SAFETY: `bytes` contains exactly one final NUL and no interior NUL.
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) })
}

#[inline]
fn pty_number<Fd: AsFd>(fd: Fd) -> Result<i32> {
    let mut number = 0_i32;
    let fd = fd.as_fd();
    // SAFETY: TIOCGPTN initializes one Linux int in stable writable storage.
    unsafe {
        crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCGPTN, (&mut number as *mut i32).cast())?;
    }
    Ok(number)
}
