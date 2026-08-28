//! Native terminal control for Linux/x86-64.
//!
//! `Termios` deliberately has a Rust-native representation. The pinned musl
//! x86-64 `struct termios` has a larger public control-code array, while
//! Linux's `TCGETS`/`TCSETS*` ioctls consume the older 19-byte kernel
//! layout. The conversion remains local to this module rather than leaking a
//! C ABI cast into Rust callers.

use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::slice;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::fs::{self, FileType};
use crate::process::Pid;
use crate::{AsFd, Errno, Result};

const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSBRK: u32 = 0x5409;
const TCXONC: u32 = 0x540a;
const TCFLSH: u32 = 0x540b;
const TIOCEXCL: u32 = 0x540c;
const TIOCNXCL: u32 = 0x540d;
const TIOCGPGRP: u32 = 0x540f;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCGSID: u32 = 0x5429;

const PROC_SELF_FD_PREFIX: &[u8] = b"/proc/self/fd/";
const PROC_SELF_FD_BUFFER_LEN: usize = 25;

const CBAUD: u32 = 0x100f;
const CIBAUD: u32 = 0x100f_0000;
const IBSHIFT: u32 = 16;

/// A Linux terminal configuration.
#[derive(Clone, Debug)]
pub struct Termios {
    input_modes: u32,
    output_modes: u32,
    control_modes: u32,
    local_modes: u32,
    line_discipline: u8,
    /// How the terminal handles its special control bytes.
    ///
    /// This is the Linux/x86-64 kernel `NCCS == 19` region. The wrapper is
    /// intentionally Rust-native: the public C `struct termios` has a
    /// different control-code array and is never used as this ioctl buffer.
    pub special_codes: SpecialCodes,
    input_speed: u32,
    output_speed: u32,
}

/// The private Linux/x86-64 record consumed by `TCGETS`/`TCSETS*`.
///
/// Linux/x86-64 uses exactly four `u32` flags, one line-discipline byte, and
/// 19 special-code bytes: 36 bytes with four-byte alignment. The public musl
/// `struct termios` is a distinct C ABI with a larger control-code array, so
/// this Rust facade passes neither it nor the Rust-native [`Termios`] value
/// to the ioctl. The separately selected static C termios-control artifact
/// forwards a public C pointer directly, so Linux consumes only its shared
/// 36-byte prefix; that independent C boundary does not alter this facade.
#[repr(C)]
struct KernelTermios {
    input_modes: u32,
    output_modes: u32,
    control_modes: u32,
    local_modes: u32,
    line_discipline: u8,
    special_codes: [u8; 19],
}

const _: [(); 36] = [(); core::mem::size_of::<KernelTermios>()];
const _: [(); 4] = [(); core::mem::align_of::<KernelTermios>()];
const _: [(); 0] = [(); core::mem::offset_of!(KernelTermios, input_modes)];
const _: [(); 4] = [(); core::mem::offset_of!(KernelTermios, output_modes)];
const _: [(); 8] = [(); core::mem::offset_of!(KernelTermios, control_modes)];
const _: [(); 12] = [(); core::mem::offset_of!(KernelTermios, local_modes)];
const _: [(); 16] = [(); core::mem::offset_of!(KernelTermios, line_discipline)];
const _: [(); 17] = [(); core::mem::offset_of!(KernelTermios, special_codes)];
impl From<KernelTermios> for Termios {
    #[inline]
    fn from(kernel: KernelTermios) -> Self {
        Self {
            input_modes: kernel.input_modes,
            output_modes: kernel.output_modes,
            control_modes: kernel.control_modes,
            local_modes: kernel.local_modes,
            line_discipline: kernel.line_discipline,
            special_codes: SpecialCodes(kernel.special_codes),
            // Linux/x86-64 carries baud selectors in c_cflag rather than
            // speed words. `tcgetattr` decodes them after the ioctl succeeds.
            input_speed: 0,
            output_speed: 0,
        }
    }
}

impl Termios {
    #[inline]
    fn to_kernel(&self) -> KernelTermios {
        KernelTermios {
            input_modes: self.input_modes,
            output_modes: self.output_modes,
            control_modes: self.control_modes,
            local_modes: self.local_modes,
            line_discipline: self.line_discipline,
            special_codes: self.special_codes.0,
        }
    }
}

impl Termios {
    /// Sets this configuration to the POSIX raw-mode transformation.
    #[inline]
    pub fn make_raw(&mut self) {
        self.input_modes &= !(0x0000_0001
            | 0x0000_0002
            | 0x0000_0008
            | 0x0000_0020
            | 0x0000_0040
            | 0x0000_0080
            | 0x0000_0100
            | 0x0000_0400);
        self.output_modes &= !0x0000_0001;
        self.local_modes &= !(0x0000_0001 | 0x0000_0002 | 0x0000_0008 | 0x0000_0040 | 0x0000_8000);
        self.control_modes = (self.control_modes & !(0x0000_0030 | 0x0000_0100)) | 0x0000_0030;
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

/// An array indexed by [`SpecialCodeIndex`] containing the 19 Linux terminal
/// control bytes.
///
/// The tuple field stays private so callers can only address the bounded
/// kernel-defined indices. This preserves the native Linux/x86-64 layout
/// (`NCCS == 19`, one byte per code) without exposing a C `termios` value.
#[repr(transparent)]
#[derive(Clone)]
pub struct SpecialCodes(pub(crate) [u8; 19]);

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
        let mut first = true;
        for index in 0..self.0.len() {
            if first {
                formatter.write_str(" ")?;
                first = false;
            } else {
                formatter.write_str(", ")?;
            }
            let index = SpecialCodeIndex::from_raw(index);
            write!(formatter, "{:?}: {:?}", index, SpecialCode(self[index]))?;
        }
        if !first {
            formatter.write_str(" ")?;
        }
        formatter.write_str("}")
    }
}

/// A newtype used by [`SpecialCodes`] debug output for readable control bytes.
struct SpecialCode(u8);

impl core::fmt::Debug for SpecialCode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            0 => formatter.write_str("<undef>"),
            0x01..=0x1f => write!(formatter, "^{}", (self.0 + 0x40) as char),
            0x7f => formatter.write_str("^?"),
            0x80..=0xff => {
                formatter.write_str("M-")?;
                SpecialCode(self.0 - 0x80).fmt(formatter)
            }
            value => write!(formatter, "{}", value as char),
        }
    }
}

/// Indices for use with [`Termios::special_codes`].
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct SpecialCodeIndex(usize);

impl SpecialCodeIndex {
    #[inline]
    const fn from_raw(index: usize) -> Self {
        Self(index)
    }

    /// `VINTR` — interrupt character.
    pub const VINTR: Self = Self(0);
    /// `VQUIT` — quit character.
    pub const VQUIT: Self = Self(1);
    /// `VERASE` — erase character.
    pub const VERASE: Self = Self(2);
    /// `VKILL` — line-kill character.
    pub const VKILL: Self = Self(3);
    /// `VEOF` — end-of-file character.
    pub const VEOF: Self = Self(4);
    /// `VTIME` — read timeout.
    pub const VTIME: Self = Self(5);
    /// `VMIN` — minimum read byte count.
    pub const VMIN: Self = Self(6);
    /// `VSWTC` — switch character.
    pub const VSWTC: Self = Self(7);
    /// `VSTART` — start character.
    pub const VSTART: Self = Self(8);
    /// `VSTOP` — stop character.
    pub const VSTOP: Self = Self(9);
    /// `VSUSP` — suspend character.
    pub const VSUSP: Self = Self(10);
    /// `VEOL` — end-of-line character.
    pub const VEOL: Self = Self(11);
    /// `VREPRINT` — reprint character.
    pub const VREPRINT: Self = Self(12);
    /// `VDISCARD` — discard character.
    pub const VDISCARD: Self = Self(13);
    /// `VWERASE` — word-erase character.
    pub const VWERASE: Self = Self(14);
    /// `VLNEXT` — literal-next character.
    pub const VLNEXT: Self = Self(15);
    /// `VEOL2` — secondary end-of-line character.
    pub const VEOL2: Self = Self(16);
}

impl core::fmt::Debug for SpecialCodeIndex {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::VINTR => formatter.write_str("VINTR"),
            Self::VQUIT => formatter.write_str("VQUIT"),
            Self::VERASE => formatter.write_str("VERASE"),
            Self::VKILL => formatter.write_str("VKILL"),
            Self::VEOF => formatter.write_str("VEOF"),
            Self::VTIME => formatter.write_str("VTIME"),
            Self::VMIN => formatter.write_str("VMIN"),
            Self::VSWTC => formatter.write_str("VSWTC"),
            Self::VSTART => formatter.write_str("VSTART"),
            Self::VSTOP => formatter.write_str("VSTOP"),
            Self::VSUSP => formatter.write_str("VSUSP"),
            Self::VEOL => formatter.write_str("VEOL"),
            Self::VREPRINT => formatter.write_str("VREPRINT"),
            Self::VDISCARD => formatter.write_str("VDISCARD"),
            Self::VWERASE => formatter.write_str("VWERASE"),
            Self::VLNEXT => formatter.write_str("VLNEXT"),
            Self::VEOL2 => formatter.write_str("VEOL2"),
            _ => formatter.write_str("unknown"),
        }
    }
}

// The x86-64 ioctl representation is the legacy kernel record: four u32
// flags, one line byte, and exactly 19 control bytes.
const _: [(); 19] = [(); core::mem::size_of::<SpecialCodes>()];

/// Timing of a terminal-attribute update.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum OptionalActions {
    Now = 0,
    Drain = 1,
    Flush = 2,
}

/// Queue selection for [`tcflush`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum QueueSelector {
    IFlush = 0,
    OFlush = 1,
    IOFlush = 2,
}

/// Flow-control action for [`tcflow`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum Action {
    OOff = 0,
    OOn = 1,
    IOff = 2,
    IOn = 3,
}

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
    // On Linux/x86-64 this is the complete 36-byte record initialized by
    // TCGETS. Baud rates are decoded from the c_cflag selectors below.
    let mut kernel = KernelTermios {
        input_modes: 0,
        output_modes: 0,
        control_modes: 0,
        local_modes: 0,
        line_discipline: 0,
        special_codes: [0; 19],
    };
    let fd = fd.as_fd();
    // SAFETY: `kernel` is the exact complete Linux/x86-64 tty ioctl record
    // and the descriptor borrow remains live for the call.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_raw_fd(),
            TCGETS,
            (&mut kernel as *mut KernelTermios).cast(),
        )?;
    }
    let mut termios = Termios::from(kernel);
    termios.output_speed = decode_speed(termios.control_modes & CBAUD).ok_or(Errno::RANGE)?;
    // CIBAUD's zero selector is the distinct B0 input setting on Linux,
    // rather than a request to substitute the output rate. Keep that native
    // state observable through the Rust numeric-speed accessor as well.
    let input = (termios.control_modes & CIBAUD) >> IBSHIFT;
    termios.input_speed = decode_speed(input).ok_or(Errno::RANGE)?;
    Ok(termios)
}

/// Updates terminal attributes.
#[inline]
pub fn tcsetattr<Fd: AsFd>(fd: Fd, action: OptionalActions, termios: &Termios) -> Result<()> {
    let mut kernel = termios.to_kernel();
    let fd = fd.as_fd();
    // SAFETY: the legacy kernel reads this exact private record for the
    // selected action. It does not write through the argument pointer.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_raw_fd(),
            TCSETS + action as u32,
            (&mut kernel as *mut KernelTermios).cast(),
        )?;
    }
    Ok(())
}

/// Returns the terminal window size.
#[inline]
pub fn tcgetwinsize<Fd: AsFd>(fd: Fd) -> Result<Winsize> {
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let fd = fd.as_fd();
    // SAFETY: TIOCGWINSZ initializes this exact Linux layout.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_raw_fd(),
            TIOCGWINSZ,
            (&mut size as *mut Winsize).cast(),
        )?;
    }
    Ok(size)
}

/// Updates the terminal window size.
#[inline]
pub fn tcsetwinsize<Fd: AsFd>(fd: Fd, size: Winsize) -> Result<()> {
    let mut size = size;
    let fd = fd.as_fd();
    // SAFETY: TIOCSWINSZ reads this exact Linux layout.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_raw_fd(),
            TIOCSWINSZ,
            (&mut size as *mut Winsize).cast(),
        )?;
    }
    Ok(())
}

/// Enables exclusive mode on a terminal.
///
/// While exclusive mode is enabled, subsequent unprivileged opens of the
/// terminal device fail with [`Errno::BUSY`]. The setting belongs to the
/// terminal and remains active until [`ioctl_tiocnxcl`] or terminal teardown.
#[inline]
pub fn ioctl_tiocexcl<Fd: AsFd>(fd: Fd) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: TIOCEXCL is a no-argument terminal request. This narrow helper
    // intentionally does not expose a generic ioctl protocol to callers.
    unsafe {
        crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCEXCL, core::ptr::null_mut())?;
    }
    Ok(())
}

/// Disables exclusive mode on a terminal.
#[inline]
pub fn ioctl_tiocnxcl<Fd: AsFd>(fd: Fd) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: TIOCNXCL is a no-argument terminal request with no memory
    // payload. Its typed public surface remains this one operation.
    unsafe {
        crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCNXCL, core::ptr::null_mut())?;
    }
    Ok(())
}
/// Returns the terminal foreground process group.
#[inline]
pub fn tcgetpgrp<Fd: AsFd>(fd: Fd) -> Result<Pid> {
    let fd = fd.as_fd();
    ioctl_get_pid(fd, TIOCGPGRP)
}

/// Sets the terminal foreground process group.
#[inline]
pub fn tcsetpgrp<Fd: AsFd>(fd: Fd, pgrp: Pid) -> Result<()> {
    let mut pgrp = pgrp.as_raw_pid();
    let fd = fd.as_fd();
    // SAFETY: TIOCSPGRP reads one Linux int from stable storage.
    unsafe {
        crabc_core::io::ioctl_raw(fd.as_raw_fd(), TIOCSPGRP, (&mut pgrp as *mut i32).cast())?;
    }
    Ok(())
}

/// Returns the session associated with the controlling terminal.
#[inline]
pub fn tcgetsid<Fd: AsFd>(fd: Fd) -> Result<Pid> {
    let fd = fd.as_fd();
    ioctl_get_pid(fd, TIOCGSID)
}

/// Reads a terminal PID-like result without ever forming a Rust value from
/// the output buffer until Linux reports success. Linux uses zero to mean
/// “no foreground group” for some PTY states; that value cannot be represented
/// by the safe [`Pid`] type and follows Rustix as `OPNOTSUPP` (`NOTSUP`).
#[inline]
fn ioctl_get_pid(fd: crate::BorrowedFd<'_>, request: u32) -> Result<Pid> {
    let mut raw = MaybeUninit::<i32>::uninit();
    // SAFETY: TIOCGPGRP and TIOCGSID each initialize one Linux `pid_t` on
    // success, and `raw` remains writable for the duration of the syscall.
    unsafe {
        crabc_core::io::ioctl_raw(fd.as_raw_fd(), request, raw.as_mut_ptr().cast())?;
    }
    // SAFETY: the successful ioctl initialized the complete pid_t value.
    let raw = unsafe { raw.assume_init() };
    Pid::from_raw(raw).ok_or(Errno::NOTSUP)
}

/// Returns whether a descriptor is a terminal. This deliberately discards the
/// underlying ioctl error, matching Rustix's boolean API.
#[inline]
pub fn isatty<Fd: AsFd>(fd: Fd) -> bool {
    tcgetattr(fd).is_ok()
}

/// Returns the pathname of the tty open on `fd` into caller-owned storage.
///
/// The returned [`CStr`] borrows the supplied buffer and includes its trailing
/// NUL. This is the allocation-free form used by no-std callers; storage must
/// have room for the complete `/proc/self/fd/<fd>` target and its terminator.
/// Linux requires procfs for this operation. The procfs link is only an input
/// hint: the descriptor must first be a character device and pass
/// `TIOCGWINSZ`, and the resolved pathname must have the same device and inode
/// as the descriptor.
#[inline]
pub fn ttyname_into<'buffer, Fd: AsFd>(
    fd: Fd,
    buffer: &'buffer mut [MaybeUninit<u8>],
) -> Result<&'buffer CStr> {
    let length = ttyname_raw(fd.as_fd(), buffer)?;
    // SAFETY: `ttyname_raw` initialized exactly `length + 1` bytes and wrote
    // the final NUL after validating the pathname's device and inode.
    let bytes = unsafe { slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), length + 1) };
    // SAFETY: `ttyname_raw` wrote one trailing NUL, and Linux symlink targets
    // cannot contain an embedded NUL byte.
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) })
}

/// `ttyname_r(fd)`—Returns the name of the tty open on `fd`.
///
/// The supplied vector is cleared and reused when possible, matching Rustix
/// 1.1.4's allocation-gated API. The operation uses direct Linux syscalls and
/// never consults libc's `ttyname`, C `errno`, or thread-local state.
#[cfg(feature = "alloc")]
#[inline]
pub fn ttyname<Fd: AsFd, B: Into<Vec<u8>>>(fd: Fd, reuse: B) -> Result<CString> {
    let fd = fd.as_fd();
    let mut buffer = reuse.into();
    buffer.clear();
    buffer.reserve(fs::SMALL_PATH_BUFFER_SIZE);

    loop {
        match ttyname_raw(fd, buffer.spare_capacity_mut()) {
            Err(Errno::RANGE) => {
                // Match Rustix's growth rule while ensuring the next attempt
                // has at least one additional byte for the NUL terminator.
                buffer.reserve(buffer.capacity() + 1);
            }
            Ok(length) => {
                // SAFETY: `ttyname_raw` initialized `length` pathname bytes
                // and one trailing NUL in the vector's spare capacity.
                unsafe { buffer.set_len(length + 1) };
                // SAFETY: the validated Linux pathname has exactly one final
                // NUL and no interior NUL bytes.
                return Ok(unsafe { CString::from_vec_with_nul_unchecked(buffer) });
            }
            Err(error) => return Err(error),
        }
    }
}

/// Implements the shared ttyname validation and pathname read for both the
/// caller-buffered and allocating APIs. The returned length excludes NUL.
fn ttyname_raw(fd: crate::BorrowedFd<'_>, buffer: &mut [MaybeUninit<u8>]) -> Result<usize> {
    let fd_stat = fs::fstat(fd)?;

    // A character-device mode bit alone is not enough to establish that an
    // fd is a tty. Keep Rustix's inexpensive type check before the ioctl.
    if FileType::from_raw_mode(fd_stat.st_mode) != FileType::CharacterDevice {
        return Err(Errno::NOTTY);
    }

    // Validate terminal state before trusting the procfs link target.
    tcgetwinsize(fd)?;

    let mut proc_path_storage = [0_u8; PROC_SELF_FD_BUFFER_LEN];
    let proc_self_fd_path = proc_self_fd_path(fd.as_raw_fd(), &mut proc_path_storage)?;
    let (initialized, uninitialized) =
        fs::readlinkat_raw(fs::CWD, proc_self_fd_path, &mut *buffer)?;

    // A full readlink buffer may have truncated the target; reserve space for
    // the NUL we add below and retry through the public allocation loop.
    if uninitialized.is_empty() {
        return Err(Errno::RANGE);
    }
    let length = initialized.len();
    uninitialized[0].write(0);

    // SAFETY: readlinkat initialized the pathname prefix and the preceding
    // write supplied its trailing NUL. The target cannot contain NUL bytes.
    let path = unsafe { CStr::from_ptr(buffer.as_ptr().cast::<u8>().cast()) };
    let path_stat = fs::stat(path)?;
    if path_stat.st_dev != fd_stat.st_dev || path_stat.st_ino != fd_stat.st_ino {
        return Err(Errno::NODEV);
    }

    Ok(length)
}

fn proc_self_fd_path<'buffer>(
    fd: crate::RawFd,
    buffer: &'buffer mut [u8; PROC_SELF_FD_BUFFER_LEN],
) -> Result<&'buffer CStr> {
    if fd < 0 {
        return Err(Errno::BADF);
    }

    buffer[..PROC_SELF_FD_PREFIX.len()].copy_from_slice(PROC_SELF_FD_PREFIX);
    let mut value = fd as u32;
    let mut digits = [0_u8; 10];
    let mut digit_count = 0;
    loop {
        digits[digit_count] = b'0' + (value % 10) as u8;
        digit_count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut index = 0;
    while index < digit_count {
        buffer[PROC_SELF_FD_PREFIX.len() + index] = digits[digit_count - 1 - index];
        index += 1;
    }
    let length = PROC_SELF_FD_PREFIX.len() + digit_count;
    buffer[length] = 0;
    // SAFETY: the function wrote the complete pathname and its NUL into the
    // fixed buffer, with no interior NUL bytes.
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(&buffer[..length + 1]) })
}

/// Waits for terminal output to drain.
#[inline]
pub fn tcdrain<Fd: AsFd>(fd: Fd) -> Result<()> {
    ioctl_value(fd, TCSBRK, 1)
}
/// Flushes selected terminal queues.
#[inline]
pub fn tcflush<Fd: AsFd>(fd: Fd, queue: QueueSelector) -> Result<()> {
    ioctl_value(fd, TCFLSH, queue as i32)
}
/// Applies terminal flow control.
#[inline]
pub fn tcflow<Fd: AsFd>(fd: Fd, action: Action) -> Result<()> {
    ioctl_value(fd, TCXONC, action as i32)
}
/// Sends a terminal break using Linux's implementation-defined duration.
#[inline]
pub fn tcsendbreak<Fd: AsFd>(fd: Fd) -> Result<()> {
    ioctl_value(fd, TCSBRK, 0)
}

#[inline]
fn ioctl_value<Fd: AsFd>(fd: Fd, request: u32, value: i32) -> Result<()> {
    let fd = fd.as_fd();
    // SAFETY: these tty requests encode their integer argument in the ioctl
    // pointer word and do not dereference it.
    unsafe {
        crabc_core::io::ioctl_raw(fd.as_raw_fd(), request, value as isize as *mut u8)?;
    }
    Ok(())
}

fn speed_code(speed: u32) -> Option<u32> {
    const SPEEDS: &[(u32, u32)] = &[
        (0, 0),
        (50, 1),
        (75, 2),
        (110, 3),
        (134, 4),
        (150, 5),
        (200, 6),
        (300, 7),
        (600, 8),
        (1200, 9),
        (1800, 10),
        (2400, 11),
        (4800, 12),
        (9600, 13),
        (19200, 14),
        (38400, 15),
    ];
    SPEEDS
        .iter()
        .find_map(|&(rate, code)| (rate == speed).then_some(code))
}

fn decode_speed(code: u32) -> Option<u32> {
    const SPEEDS: [u32; 16] = [
        0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
    ];
    SPEEDS.get(code as usize).copied()
}
