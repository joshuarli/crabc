//! Darwin terminal control over libSystem.
//!
//! The facade module [`crate::termios`] re-exports these items next to the
//! vocabulary both targets share.

use core::ffi::{c_int, c_ulong, CStr};
use core::mem::{align_of, offset_of, size_of, MaybeUninit};

use super::errno::{self, Errno, Result};
use super::sys;
use crate::process::Pid;
use crate::termios::{OptionalActions, SpecialCode, Winsize};
use crate::{AsFd, BorrowedFd};

const _: () = {
    assert!(size_of::<Winsize>() == size_of::<sys::Winsize>());
    assert!(align_of::<Winsize>() == align_of::<sys::Winsize>());
    assert!(offset_of!(Winsize, ws_row) == offset_of!(sys::Winsize, ws_row));
    assert!(offset_of!(Winsize, ws_col) == offset_of!(sys::Winsize, ws_col));
    assert!(offset_of!(Winsize, ws_xpixel) == offset_of!(sys::Winsize, ws_xpixel));
    assert!(offset_of!(Winsize, ws_ypixel) == offset_of!(sys::Winsize, ws_ypixel));
    assert!(OptionalActions::Now as c_int == sys::TCSANOW);
    assert!(OptionalActions::Drain as c_int == sys::TCSADRAIN);
    assert!(OptionalActions::Flush as c_int == sys::TCSAFLUSH);
};

/// A Darwin terminal configuration.
///
/// Darwin's `struct termios` has 64-bit flag words, no line discipline,
/// twenty special codes and numeric speed words, so this value has its own
/// Darwin representation.
#[derive(Clone, Debug)]
pub struct Termios {
    input_modes: c_ulong,
    output_modes: c_ulong,
    control_modes: c_ulong,
    local_modes: c_ulong,
    /// How the terminal handles its special control bytes.
    ///
    /// This is Darwin's `NCCS == 20` array, indexed by Darwin's
    /// [`SpecialCodeIndex`] values.
    pub special_codes: SpecialCodes,
    input_speed: u32,
    output_speed: u32,
}

impl Termios {
    #[inline]
    fn from_sys(raw: &sys::Termios) -> Result<Self> {
        Ok(Self {
            input_modes: raw.c_iflag,
            output_modes: raw.c_oflag,
            control_modes: raw.c_cflag,
            local_modes: raw.c_lflag,
            special_codes: SpecialCodes(raw.c_cc),
            input_speed: u32::try_from(raw.c_ispeed).map_err(|_| Errno::RANGE)?,
            output_speed: u32::try_from(raw.c_ospeed).map_err(|_| Errno::RANGE)?,
        })
    }

    #[inline]
    fn to_sys(&self) -> sys::Termios {
        sys::Termios {
            c_iflag: self.input_modes,
            c_oflag: self.output_modes,
            c_cflag: self.control_modes,
            c_lflag: self.local_modes,
            c_cc: self.special_codes.0,
            c_ispeed: c_ulong::from(self.input_speed),
            c_ospeed: c_ulong::from(self.output_speed),
        }
    }

    /// Sets this configuration to the POSIX raw-mode transformation.
    ///
    /// This clears and sets the same named flags as the Linux transformation,
    /// with Darwin's bit values. It is not libSystem's `cfmakeraw`, which
    /// also sets `IGNBRK` and clears further flags.
    #[inline]
    pub fn make_raw(&mut self) {
        self.input_modes &= !(sys::IGNBRK
            | sys::BRKINT
            | sys::PARMRK
            | sys::ISTRIP
            | sys::INLCR
            | sys::IGNCR
            | sys::ICRNL
            | sys::IXON);
        self.output_modes &= !sys::OPOST;
        self.local_modes &= !(sys::ECHO | sys::ECHONL | sys::ICANON | sys::ISIG | sys::IEXTEN);
        self.control_modes = (self.control_modes & !(sys::CSIZE | sys::PARENB)) | sys::CS8;
        self.special_codes[SpecialCodeIndex::VMIN] = 1;
        self.special_codes[SpecialCodeIndex::VTIME] = 0;
    }

    /// Returns the numeric input baud rate.
    #[inline]
    pub const fn input_speed(&self) -> u32 {
        self.input_speed
    }

    /// Returns the numeric output baud rate.
    #[inline]
    pub const fn output_speed(&self) -> u32 {
        self.output_speed
    }

    /// Sets both numeric baud rates.
    ///
    /// Darwin's speed words hold the rate itself, so any rate is accepted
    /// here; the terminal's driver accepts or rejects it when
    /// [`tcsetattr`] applies the configuration.
    #[inline]
    pub fn set_speed(&mut self, speed: u32) -> Result<()> {
        self.input_speed = speed;
        self.output_speed = speed;
        Ok(())
    }

    /// Sets the numeric input baud rate.
    ///
    /// An input rate of zero asks the terminal to use the output rate, as
    /// POSIX specifies; [`tcgetattr`] then reports the output rate.
    #[inline]
    pub fn set_input_speed(&mut self, speed: u32) -> Result<()> {
        self.input_speed = speed;
        Ok(())
    }

    /// Sets the numeric output baud rate.
    #[inline]
    pub fn set_output_speed(&mut self, speed: u32) -> Result<()> {
        self.output_speed = speed;
        Ok(())
    }
}

/// An array indexed by [`SpecialCodeIndex`] containing the 20 Darwin terminal
/// control bytes.
///
/// The tuple field stays private so callers can only address the named
/// indices. A byte of `0xff` (`_POSIX_VDISABLE`) disables its function.
#[repr(transparent)]
#[derive(Clone)]
pub struct SpecialCodes(pub(crate) [u8; sys::NCCS]);

impl core::ops::Index<SpecialCodeIndex> for SpecialCodes {
    type Output = u8;

    #[inline]
    fn index(&self, index: SpecialCodeIndex) -> &Self::Output {
        &self.0[index.0]
    }
}

impl core::ops::IndexMut<SpecialCodeIndex> for SpecialCodes {
    #[inline]
    fn index_mut(&mut self, index: SpecialCodeIndex) -> &mut Self::Output {
        &mut self.0[index.0]
    }
}

impl core::fmt::Debug for SpecialCodes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SpecialCodes {")?;
        for (index, &byte) in self.0.iter().enumerate() {
            formatter.write_str(if index == 0 { " " } else { ", " })?;
            write!(formatter, "{:?}: ", SpecialCodeIndex(index))?;
            if byte == sys::POSIX_VDISABLE {
                formatter.write_str("<undef>")?;
            } else {
                write!(formatter, "{:?}", SpecialCode(byte))?;
            }
        }
        formatter.write_str(" }")
    }
}

/// Indices for use with [`Termios::special_codes`], with Darwin values.
///
/// Linux's `VSWTC` has no Darwin counterpart and is absent; Darwin's
/// `VDSUSP` and `VSTATUS` are added.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct SpecialCodeIndex(usize);

impl SpecialCodeIndex {
    /// `VEOF` — end-of-file character.
    pub const VEOF: Self = Self(sys::VEOF);
    /// `VEOL` — end-of-line character.
    pub const VEOL: Self = Self(sys::VEOL);
    /// `VEOL2` — secondary end-of-line character.
    pub const VEOL2: Self = Self(sys::VEOL2);
    /// `VERASE` — erase character.
    pub const VERASE: Self = Self(sys::VERASE);
    /// `VWERASE` — word-erase character.
    pub const VWERASE: Self = Self(sys::VWERASE);
    /// `VKILL` — line-kill character.
    pub const VKILL: Self = Self(sys::VKILL);
    /// `VREPRINT` — reprint character.
    pub const VREPRINT: Self = Self(sys::VREPRINT);
    /// `VINTR` — interrupt character.
    pub const VINTR: Self = Self(sys::VINTR);
    /// `VQUIT` — quit character.
    pub const VQUIT: Self = Self(sys::VQUIT);
    /// `VSUSP` — suspend character.
    pub const VSUSP: Self = Self(sys::VSUSP);
    /// `VDSUSP` — delayed-suspend character.
    pub const VDSUSP: Self = Self(sys::VDSUSP);
    /// `VSTART` — start character.
    pub const VSTART: Self = Self(sys::VSTART);
    /// `VSTOP` — stop character.
    pub const VSTOP: Self = Self(sys::VSTOP);
    /// `VLNEXT` — literal-next character.
    pub const VLNEXT: Self = Self(sys::VLNEXT);
    /// `VDISCARD` — discard character.
    pub const VDISCARD: Self = Self(sys::VDISCARD);
    /// `VMIN` — minimum read byte count.
    pub const VMIN: Self = Self(sys::VMIN);
    /// `VTIME` — read timeout.
    pub const VTIME: Self = Self(sys::VTIME);
    /// `VSTATUS` — status-request character.
    pub const VSTATUS: Self = Self(sys::VSTATUS);
}

impl core::fmt::Debug for SpecialCodeIndex {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match *self {
            Self::VEOF => "VEOF",
            Self::VEOL => "VEOL",
            Self::VEOL2 => "VEOL2",
            Self::VERASE => "VERASE",
            Self::VWERASE => "VWERASE",
            Self::VKILL => "VKILL",
            Self::VREPRINT => "VREPRINT",
            Self::VINTR => "VINTR",
            Self::VQUIT => "VQUIT",
            Self::VSUSP => "VSUSP",
            Self::VDSUSP => "VDSUSP",
            Self::VSTART => "VSTART",
            Self::VSTOP => "VSTOP",
            Self::VLNEXT => "VLNEXT",
            Self::VDISCARD => "VDISCARD",
            Self::VMIN => "VMIN",
            Self::VTIME => "VTIME",
            Self::VSTATUS => "VSTATUS",
            _ => "unknown",
        })
    }
}

/// Queue selection for [`tcflush`], with Darwin values.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum QueueSelector {
    /// `TCIFLUSH`: discard received input.
    IFlush = sys::TCIFLUSH as u32,
    /// `TCOFLUSH`: discard unsent output.
    OFlush = sys::TCOFLUSH as u32,
    /// `TCIOFLUSH`: discard both.
    IOFlush = sys::TCIOFLUSH as u32,
}

/// Flow-control action for [`tcflow`], with Darwin values.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum Action {
    /// `TCOOFF`: suspend output.
    OOff = sys::TCOOFF as u32,
    /// `TCOON`: resume output.
    OOn = sys::TCOON as u32,
    /// `TCIOFF`: send the stop character.
    IOff = sys::TCIOFF as u32,
    /// `TCION`: send the start character.
    IOn = sys::TCION as u32,
}

/// Obtains terminal attributes with libSystem `tcgetattr`.
///
/// A speed word above `u32::MAX` fails with [`Errno::RANGE`].
#[inline]
pub fn tcgetattr<Fd: AsFd>(fd: Fd) -> Result<Termios> {
    let mut raw = MaybeUninit::<sys::Termios>::uninit();
    // SAFETY: `raw` is writable storage for one `struct termios`, and the
    // borrow keeps the descriptor open for the call.
    let result = unsafe { sys::tcgetattr(fd.as_fd().as_raw_fd(), raw.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: a successful `tcgetattr` initialized the whole record.
    let raw = unsafe { raw.assume_init() };
    Termios::from_sys(&raw)
}

/// Updates terminal attributes with libSystem `tcsetattr`.
#[inline]
pub fn tcsetattr<Fd: AsFd>(fd: Fd, action: OptionalActions, termios: &Termios) -> Result<()> {
    let raw = termios.to_sys();
    // SAFETY: `raw` is a complete `struct termios` that `tcsetattr` only
    // reads, and the borrow keeps the descriptor open for the call.
    let result = unsafe { sys::tcsetattr(fd.as_fd().as_raw_fd(), action as c_int, &raw) };
    errno::check(result).map(|_| ())
}

/// Returns the terminal window size.
#[inline]
pub fn tcgetwinsize<Fd: AsFd>(fd: Fd) -> Result<Winsize> {
    let mut size = MaybeUninit::<Winsize>::uninit();
    // SAFETY: `TIOCGWINSZ` writes one `struct winsize`, whose layout the
    // assertions above prove `Winsize` shares, into this writable storage.
    let result = unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::TIOCGWINSZ, size.as_mut_ptr()) };
    errno::check(result)?;
    // SAFETY: the successful ioctl initialized all four fields.
    Ok(unsafe { size.assume_init() })
}

/// Updates the terminal window size.
#[inline]
pub fn tcsetwinsize<Fd: AsFd>(fd: Fd, size: Winsize) -> Result<()> {
    // SAFETY: `TIOCSWINSZ` reads one `struct winsize`, whose layout `Winsize`
    // shares, from this live value.
    let result = unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::TIOCSWINSZ, &raw const size) };
    errno::check(result).map(|_| ())
}

/// Enables exclusive mode on a terminal.
///
/// Exclusive mode asks the terminal to refuse further opens with
/// [`Errno::BUSY`]. XNU still admits an unprivileged open of a
/// pseudoterminal slave in exclusive mode. The setting belongs to the
/// terminal and remains active until [`ioctl_tiocnxcl`] or terminal teardown.
#[inline]
pub fn ioctl_tiocexcl<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `TIOCEXCL` takes no argument and touches no caller memory.
    let result = unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::TIOCEXCL) };
    errno::check(result).map(|_| ())
}

/// Disables exclusive mode on a terminal.
#[inline]
pub fn ioctl_tiocnxcl<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `TIOCNXCL` takes no argument and touches no caller memory.
    let result = unsafe { sys::ioctl(fd.as_fd().as_raw_fd(), sys::TIOCNXCL) };
    errno::check(result).map(|_| ())
}

/// Converts a libSystem process-group or session result. Zero, which XNU
/// reports for a terminal with no foreground process group, cannot be a
/// [`Pid`]; it fails with [`Errno::NOTSUP`] as on Linux.
#[inline]
fn checked_pid(raw: sys::pid_t) -> Result<Pid> {
    let raw = errno::check(raw)?;
    Pid::from_raw(raw).ok_or(Errno::NOTSUP)
}

/// Returns the terminal foreground process group.
#[inline]
pub fn tcgetpgrp<Fd: AsFd>(fd: Fd) -> Result<Pid> {
    // SAFETY: `tcgetpgrp` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    checked_pid(unsafe { sys::tcgetpgrp(fd.as_fd().as_raw_fd()) })
}

/// Sets the terminal foreground process group.
#[inline]
pub fn tcsetpgrp<Fd: AsFd>(fd: Fd, pgrp: Pid) -> Result<()> {
    // SAFETY: `tcsetpgrp` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    let result = unsafe { sys::tcsetpgrp(fd.as_fd().as_raw_fd(), pgrp.as_raw_pid()) };
    errno::check(result).map(|_| ())
}

/// Returns the session associated with the controlling terminal.
#[inline]
pub fn tcgetsid<Fd: AsFd>(fd: Fd) -> Result<Pid> {
    // SAFETY: `tcgetsid` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    checked_pid(unsafe { sys::tcgetsid(fd.as_fd().as_raw_fd()) })
}

/// Writes the name of the terminal open on `fd` into `buffer` with libSystem
/// `ttyname_r` and returns its length without the NUL.
///
/// `ttyname_r` validates that `fd` is a terminal and fails with
/// [`Errno::RANGE`] when the name and its NUL do not fit.
pub(crate) fn ttyname_raw(fd: BorrowedFd<'_>, buffer: &mut [MaybeUninit<u8>]) -> Result<usize> {
    // SAFETY: `buffer` is writable for its whole length, which is the bound
    // passed to `ttyname_r`.
    let code = unsafe { sys::ttyname_r(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    errno::check_code(code)?;
    // SAFETY: a successful `ttyname_r` stored a NUL-terminated name inside
    // `buffer`, so every byte up to that NUL is initialized.
    let name = unsafe { CStr::from_ptr(buffer.as_ptr().cast()) };
    Ok(name.count_bytes())
}

/// Waits for terminal output to drain.
#[inline]
pub fn tcdrain<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `tcdrain` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    errno::check(unsafe { sys::tcdrain(fd.as_fd().as_raw_fd()) }).map(|_| ())
}

/// Flushes selected terminal queues.
#[inline]
pub fn tcflush<Fd: AsFd>(fd: Fd, queue: QueueSelector) -> Result<()> {
    // SAFETY: `tcflush` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    errno::check(unsafe { sys::tcflush(fd.as_fd().as_raw_fd(), queue as c_int) }).map(|_| ())
}

/// Applies terminal flow control.
#[inline]
pub fn tcflow<Fd: AsFd>(fd: Fd, action: Action) -> Result<()> {
    // SAFETY: `tcflow` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    errno::check(unsafe { sys::tcflow(fd.as_fd().as_raw_fd(), action as c_int) }).map(|_| ())
}

/// Sends a terminal break using libSystem's implementation-defined duration.
#[inline]
pub fn tcsendbreak<Fd: AsFd>(fd: Fd) -> Result<()> {
    // SAFETY: `tcsendbreak` has no memory arguments; the borrow keeps the
    // descriptor open for the call.
    errno::check(unsafe { sys::tcsendbreak(fd.as_fd().as_raw_fd(), 0) }).map(|_| ())
}
