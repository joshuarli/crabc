//! Linux pseudoterminal operations.

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
    /// Flags accepted by [`openpt`] and [`ioctl_tiocgptpeer`].
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct OpenptFlags: u32 {
        const RDWR = 0x2;
        const NOCTTY = 0x100;
        const CLOEXEC = 0x80000;
        const _ = !0;
    }
}

impl From<OpenptFlags> for fs::OFlags {
    fn from(value: OpenptFlags) -> Self {
        Self::from_bits_retain(value.bits())
    }
}

/// An owned Linux pseudoterminal master/slave pair.
///
/// `PtyPair::open` opens `/dev/ptmx`, validates and unlocks its devpts slave,
/// then obtains that slave through `TIOCGPTPEER`. Both descriptors are owned
/// by this value and are closed on drop. The peer open always includes
/// `O_NOCTTY`, so constructing a pair does not silently change the caller's
/// controlling terminal; use the explicit unsafe handoff methods below when
/// a session intentionally wants that transition.
pub struct PtyPair {
    master: OwnedFd,
    slave: OwnedFd,
}

impl PtyPair {
    /// Opens a new owned PTY pair.
    ///
    /// `flags` must include [`OpenptFlags::RDWR`]. `NOCTTY` and `CLOEXEC`
    /// are passed to the master and peer opens as requested; the peer always
    /// receives `NOCTTY` to keep session ownership explicit.
    #[inline]
    pub fn open(flags: OpenptFlags) -> Result<Self> {
        if !flags.contains(OpenptFlags::RDWR) {
            return Err(Errno::INVAL);
        }

        let master = openpt(flags)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let peer_flags = flags | OpenptFlags::NOCTTY;
        let slave = ioctl_tiocgptpeer(&master, peer_flags)?;
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
    /// The caller must be a Linux session leader, must keep this pair's slave
    /// open and exclusively owned for the ioctl, and must serialize this
    /// transition with all other session, process-group, and terminal-state
    /// operations in the process. `steal` requests Linux's privileged
    /// reassignment behavior (`TIOCSCTTY` argument one) and therefore also
    /// requires the authority demanded by the kernel. This operation changes
    /// process-global session state and is not suitable for an arbitrary
    /// multithreaded caller.
    #[inline]
    pub unsafe fn set_controlling_terminal(&self, steal: bool) -> Result<()> {
        let argument = usize::from(steal) as *mut u8;
        // SAFETY: The method contract requires a live PTY slave and a caller
        // that has serialized the process-global terminal transition.
        unsafe {
            crabc_core::io::ioctl_raw(self.slave.as_raw_fd(), TIOCSCTTY, argument)?;
        }
        Ok(())
    }

    /// Creates a new session and assigns this pair's slave as its controlling
    /// terminal.
    ///
    /// This combines Linux `setsid` with [`Self::set_controlling_terminal`]
    /// for a deliberately explicit one-shot handoff. It does not fork,
    /// supervise, duplicate, or exec a child process.
    ///
    /// # Safety
    ///
    /// The caller must be an isolated, single-threaded execution context in
    /// which changing the calling process's session and controlling terminal
    /// is intentional. No other code may concurrently inspect or mutate
    /// process groups, sessions, or terminal state. Linux `setsid` must be
    /// permitted for the caller (in particular, it must not already be a
    /// process-group leader), and `steal` carries the kernel's authority
    /// requirement. If the ioctl fails after `setsid` succeeds, the new
    /// session remains in effect and the error is returned.
    #[inline]
    pub unsafe fn establish_session_and_controlling_terminal(&self, steal: bool) -> Result<()> {
        crate::process::setsid()?;
        // SAFETY: The caller's obligations are identical to this method's
        // documented process-state and descriptor requirements.
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

/// Opens the slave side directly through `TIOCGPTPEER`.
#[inline]
pub fn ioctl_tiocgptpeer<Fd: AsFd>(fd: Fd, flags: OpenptFlags) -> Result<OwnedFd> {
    let fd = fd.as_fd();
    // SAFETY: TIOCGPTPEER encodes `O_*` flags in the ioctl argument word and
    // returns a newly-owned descriptor as its successful integer result.
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
