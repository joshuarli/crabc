//! Native terminal control for Linux/AArch64.
//!
//! `Termios` deliberately has a Rust-native representation. The C facade's
//! musl `struct termios` has a larger public control-code array, while Linux's
//! tty ioctls consume the older 19-byte kernel layout. The conversion remains
//! local to this module rather than leaking a C ABI cast into Rust callers.

use crate::process::Pid;
use crate::{AsFd, Errno, Result};

const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSBRK: u32 = 0x5409;
const TCXONC: u32 = 0x540a;
const TCFLSH: u32 = 0x540b;
const TIOCGPGRP: u32 = 0x540f;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCGSID: u32 = 0x5429;

const CBAUD: u32 = 0x100f;
const CIBAUD: u32 = 0x100f_0000;
const IBSHIFT: u32 = 16;

/// A Linux terminal configuration.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Termios {
    input_modes: u32,
    output_modes: u32,
    control_modes: u32,
    local_modes: u32,
    line_discipline: u8,
    special_codes: [u8; 19],
    input_speed: u32,
    output_speed: u32,
}

impl Termios {
    /// Sets this configuration to the POSIX raw-mode transformation.
    #[inline]
    pub fn make_raw(&mut self) {
        self.input_modes &= !(0x0000_0001 | 0x0000_0002 | 0x0000_0008 | 0x0000_0020 | 0x0000_0040 | 0x0000_0080 | 0x0000_0100 | 0x0000_0400);
        self.output_modes &= !0x0000_0001;
        self.local_modes &= !(0x0000_0001 | 0x0000_0002 | 0x0000_0008 | 0x0000_0040 | 0x0000_8000);
        self.control_modes = (self.control_modes & !(0x0000_0030 | 0x0000_0100)) | 0x0000_0030;
        self.special_codes[6] = 1; // VMIN
        self.special_codes[5] = 0; // VTIME
    }

    /// Returns the numeric input baud rate.
    #[inline]
    pub const fn input_speed(&self) -> u32 { self.input_speed }

    /// Returns the numeric output baud rate.
    #[inline]
    pub const fn output_speed(&self) -> u32 { self.output_speed }

    /// Sets both numeric baud rates.
    #[inline]
    pub fn set_speed(&mut self, speed: u32) -> Result<()> {
        let code = speed_code(speed).ok_or(Errno::INVAL)?;
        self.control_modes = (self.control_modes & !(CIBAUD | CBAUD)) | (code << IBSHIFT) | code;
        self.input_speed = speed;
        self.output_speed = speed;
        Ok(())
    }

    /// Sets the numeric input baud rate.
    #[inline]
    pub fn set_input_speed(&mut self, speed: u32) -> Result<()> {
        let code = speed_code(speed).ok_or(Errno::INVAL)?;
        self.control_modes = (self.control_modes & !CIBAUD) | (code << IBSHIFT);
        self.input_speed = speed;
        Ok(())
    }

    /// Sets the numeric output baud rate.
    #[inline]
    pub fn set_output_speed(&mut self, speed: u32) -> Result<()> {
        let code = speed_code(speed).ok_or(Errno::INVAL)?;
        self.control_modes = (self.control_modes & !CBAUD) | code;
        self.output_speed = speed;
        Ok(())
    }
}

/// Timing of a terminal-attribute update.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum OptionalActions { Now = 0, Drain = 1, Flush = 2 }

/// Queue selection for [`tcflush`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum QueueSelector { IFlush = 0, OFlush = 1, IOFlush = 2 }

/// Flow-control action for [`tcflow`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum Action { OOff = 0, OOn = 1, IOff = 2, IOn = 3 }

/// Linux `struct winsize`.
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// Obtains terminal attributes.
#[inline]
pub fn tcgetattr<Fd: AsFd>(fd: Fd) -> Result<Termios> {
    let mut termios = Termios {
        input_modes: 0, output_modes: 0, control_modes: 0, local_modes: 0,
        line_discipline: 0, special_codes: [0; 19], input_speed: 0, output_speed: 0,
    };
    let fd = fd.as_fd();
    // SAFETY: `termios` is the exact legacy Linux tty ABI initialized by
    // TCGETS, and the descriptor borrow remains live for the call.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TCGETS, (&mut termios as *mut Termios).cast())?; }
    termios.output_speed = decode_speed(termios.control_modes & CBAUD);
    let input = (termios.control_modes & CIBAUD) >> IBSHIFT;
    termios.input_speed = if input == 0 { termios.output_speed } else { decode_speed(input) };
    Ok(termios)
}

/// Updates terminal attributes.
#[inline]
pub fn tcsetattr<Fd: AsFd>(fd: Fd, action: OptionalActions, termios: &Termios) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: the legacy kernel reads the stable termios prefix for this ioctl.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TCSETS + action as u32, (termios as *const Termios).cast_mut().cast())?; }
    Ok(())
}

/// Returns the terminal window size.
#[inline]
pub fn tcgetwinsize<Fd: AsFd>(fd: Fd) -> Result<Winsize> {
    let mut size = Winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    let fd = fd.as_fd();
    // SAFETY: TIOCGWINSZ initializes this exact Linux layout.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCGWINSZ, (&mut size as *mut Winsize).cast())?; }
    Ok(size)
}

/// Updates the terminal window size.
#[inline]
pub fn tcsetwinsize<Fd: AsFd>(fd: Fd, size: Winsize) -> Result<()> {
    let mut size = size;
    let fd = fd.as_fd();
    // SAFETY: TIOCSWINSZ reads this exact Linux layout.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCSWINSZ, (&mut size as *mut Winsize).cast())?; }
    Ok(())
}

/// Returns the terminal foreground process group.
#[inline]
pub fn tcgetpgrp<Fd: AsFd>(fd: Fd) -> Result<Pid> {
    let mut pgrp = 0_i32;
    let fd = fd.as_fd();
    // SAFETY: TIOCGPGRP initializes one Linux int in stable writable storage.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCGPGRP, (&mut pgrp as *mut i32).cast())?; }
    Pid::from_raw(pgrp).ok_or(Errno::NOTSUP)
}

/// Sets the terminal foreground process group.
#[inline]
pub fn tcsetpgrp<Fd: AsFd>(fd: Fd, pgrp: Pid) -> Result<()> {
    let mut pgrp = pgrp.as_raw_pid();
    let fd = fd.as_fd();
    // SAFETY: TIOCSPGRP reads one Linux int from stable storage.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCSPGRP, (&mut pgrp as *mut i32).cast())?; }
    Ok(())
}

/// Returns the session associated with the controlling terminal.
#[inline]
pub fn tcgetsid<Fd: AsFd>(fd: Fd) -> Result<Pid> {
    let mut sid = 0_i32;
    let fd = fd.as_fd();
    // SAFETY: TIOCGSID initializes one Linux int in stable writable storage.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCGSID, (&mut sid as *mut i32).cast())?; }
    Pid::from_raw(sid).ok_or(Errno::NOTSUP)
}

/// Returns whether a descriptor is a terminal. This deliberately discards the
/// underlying ioctl error, matching Rustix's boolean API.
#[inline]
pub fn isatty<Fd: AsFd>(fd: Fd) -> bool { tcgetattr(fd).is_ok() }

/// Waits for terminal output to drain.
#[inline]
pub fn tcdrain<Fd: AsFd>(fd: Fd) -> Result<()> { ioctl_value(fd, TCSBRK, 1) }
/// Flushes selected terminal queues.
#[inline]
pub fn tcflush<Fd: AsFd>(fd: Fd, queue: QueueSelector) -> Result<()> { ioctl_value(fd, TCFLSH, queue as i32) }
/// Applies terminal flow control.
#[inline]
pub fn tcflow<Fd: AsFd>(fd: Fd, action: Action) -> Result<()> { ioctl_value(fd, TCXONC, action as i32) }
/// Sends a terminal break using Linux's implementation-defined duration.
#[inline]
pub fn tcsendbreak<Fd: AsFd>(fd: Fd) -> Result<()> { ioctl_value(fd, TCSBRK, 0) }

#[inline]
fn ioctl_value<Fd: AsFd>(fd: Fd, request: u32, value: i32) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: these tty requests encode their integer argument in the ioctl
    // pointer word and do not dereference it.
    unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), request, value as isize as *mut u8)?; }
    Ok(())
}

fn speed_code(speed: u32) -> Option<u32> {
    const SPEEDS: &[(u32, u32)] = &[(0, 0), (50, 1), (75, 2), (110, 3), (134, 4), (150, 5), (200, 6), (300, 7), (600, 8), (1200, 9), (1800, 10), (2400, 11), (4800, 12), (9600, 13), (19200, 14), (38400, 15)];
    SPEEDS.iter().find_map(|&(rate, code)| (rate == speed).then_some(code))
}

fn decode_speed(code: u32) -> u32 {
    const SPEEDS: [u32; 16] = [0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400];
    SPEEDS.get(code as usize).copied().unwrap_or(0)
}
