//! Linux pseudoterminal operations.

use bitflags::bitflags;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::fs::{self, Mode};
use crate::{AsFd, Errno, OwnedFd, Result};

const TIOCGPTN: u32 = 0x8004_5430;
const TIOCSPTLCK: u32 = 0x4004_5431;
const TIOCGPTPEER: u32 = 0x5441;

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
    fn from(value: OpenptFlags) -> Self { Self::from_bits_retain(value.bits()) }
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
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCSPTLCK, (&mut unlocked as *mut i32).cast())?; }
    Ok(())
}

/// Opens the slave side directly through `TIOCGPTPEER`.
#[inline]
pub fn ioctl_tiocgptpeer<Fd: AsFd>(fd: Fd, flags: OpenptFlags) -> Result<OwnedFd> {
    let fd = fd.as_fd();
    // SAFETY: TIOCGPTPEER encodes `O_*` flags in the ioctl argument word and
    // returns a newly-owned descriptor as its successful integer result.
    let raw = unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCGPTPEER, flags.bits() as usize as *mut u8)? };
    // SAFETY: a successful TIOCGPTPEER result is a newly allocated fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Returns the slave device name using caller-provided reusable storage.
#[cfg(feature = "alloc")]
#[inline]
pub fn ptsname<Fd: AsFd, B: Into<Vec<u8>>>(fd: Fd, _reuse: B) -> Result<CString> {
    let number = pty_number(fd)?;
    let mut digits = [0_u8; 10];
    let mut value = number as u32;
    let mut digit_count = 0;
    loop {
        digits[digit_count] = b'0' + (value % 10) as u8;
        digit_count += 1;
        value /= 10;
        if value == 0 { break; }
    }
    let mut path = Vec::with_capacity(9 + digit_count);
    path.extend_from_slice(b"/dev/pts/");
    for index in (0..digit_count).rev() { path.push(digits[index]); }
    CString::new(path).map_err(|_| Errno::INVAL)
}

#[inline]
fn pty_number<Fd: AsFd>(fd: Fd) -> Result<i32> {
    let mut number = 0_i32;
    let fd = fd.as_fd();
    // SAFETY: TIOCGPTN initializes one Linux int in stable writable storage.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCGPTN, (&mut number as *mut i32).cast())?; }
    Ok(number)
}
