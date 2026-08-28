//! Selected static Linux/x86-64 C termios-control boundary.
//!
//! This is a narrow, non-pthread adaptation of pinned musl 1.2.6 revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license. Its
//! source mapping is `src/termios/cfgetospeed.c`, `cfsetospeed.c`,
//! `cfsetspeed.c`, `cfmakeraw.c`, `tcgetattr.c`, `tcsetattr.c`, `tcflush.c`,
//! `tcflow.c`, `tcsendbreak.c`, `tcgetwinsize.c`, and `tcsetwinsize.c`.
//! `tcgetattr` and `tcsetattr` pass the public C `termios` pointer directly
//! to Linux syscall 16, as musl does. On x86 that matters: the 60-byte public
//! C `termios` record shares only its first 36 bytes with Linux's
//! `TCGETS`/`TCSETS*` record. Linux therefore writes or reads that prefix
//! only; the remaining public control-code tail, padding, and speed words
//! stay caller-resident. The other named calls pass their specified scalar or
//! `winsize` argument directly; none exposes generic `ioctl`.
//!
//! The selected artifact owns only fixed baud/raw transformations, named
//! attribute/queue/flow/break requests, and fixed `winsize` records. It
//! deliberately excludes generic `ioctl`, `tcdrain` (musl's cancellation-point
//! path), process/session/foreground-group terminal policy, TTY discovery and
//! naming, PTY helpers, arbitrary requests, pthread cancellation, dynamic
//! libc/CRT/TLS lifecycle, loader integration, sysroot integration, and public
//! x86 platform support. It also does not reuse the intentionally distinct
//! Rust-native terminal representation in `crabc-rs`.

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;

const CBAUD: c_uint = 0x0000_100f;
const CIBAUD: c_uint = 0x100f_0000;
const INPUT_SPEED_MULTIPLIER: c_uint = CIBAUD / CBAUD;

const IGNBRK: c_uint = 0o000001;
const BRKINT: c_uint = 0o000002;
const PARMRK: c_uint = 0o000010;
const ISTRIP: c_uint = 0o000040;
const INLCR: c_uint = 0o000100;
const IGNCR: c_uint = 0o000200;
const ICRNL: c_uint = 0o000400;
const IXON: c_uint = 0o002000;
const OPOST: c_uint = 0o000001;
const ECHO: c_uint = 0o000010;
const ECHONL: c_uint = 0o000100;
const ICANON: c_uint = 0o000002;
const ISIG: c_uint = 0o000001;
const IEXTEN: c_uint = 0o100000;
const CSIZE: c_uint = 0o000060;
const CS8: c_uint = 0o000060;
const PARENB: c_uint = 0o000400;
const VTIME: usize = 5;
const VMIN: usize = 6;

const TCSANOW: c_int = 0;
const TCSAFLUSH: c_int = 2;
const TCGETS: i64 = 0x5401;
const TCSETS: i64 = 0x5402;
const TCSBRK: i64 = 0x5409;
const TCXONC: i64 = 0x540a;
const TCFLSH: i64 = 0x540b;
const TIOCGWINSZ: i64 = 0x5413;
const TIOCSWINSZ: i64 = 0x5414;

/// The installed musl-shaped x86 public C record.
///
/// This only anchors compile-time ABI facts. All C entry points below use raw
/// byte pointers, so a direct syscall never creates a Rust reference to a
/// caller record or touches its caller-resident tail.
#[repr(C)]
struct PublicTermios {
    input_flags: c_uint,
    output_flags: c_uint,
    control_flags: c_uint,
    local_flags: c_uint,
    line_discipline: u8,
    control_codes: [u8; 32],
    input_speed: c_uint,
    output_speed: c_uint,
}

/// The Linux/x86-64 `TCGETS` and `TCSETS*` prefix.
#[repr(C)]
struct KernelTermios {
    input_flags: c_uint,
    output_flags: c_uint,
    control_flags: c_uint,
    local_flags: c_uint,
    line_discipline: u8,
    control_codes: [u8; 19],
}

/// The direct Linux `TIOCGWINSZ`/`TIOCSWINSZ` record.
#[repr(C)]
struct Winsize {
    rows: u16,
    columns: u16,
    x_pixels: u16,
    y_pixels: u16,
}

const _: [(); 60] = [(); size_of::<PublicTermios>()];
const _: [(); 4] = [(); align_of::<PublicTermios>()];
const _: [(); 0] = [(); offset_of!(PublicTermios, input_flags)];
const _: [(); 4] = [(); offset_of!(PublicTermios, output_flags)];
const _: [(); 8] = [(); offset_of!(PublicTermios, control_flags)];
const _: [(); 12] = [(); offset_of!(PublicTermios, local_flags)];
const _: [(); 16] = [(); offset_of!(PublicTermios, line_discipline)];
const _: [(); 17] = [(); offset_of!(PublicTermios, control_codes)];
const _: [(); 52] = [(); offset_of!(PublicTermios, input_speed)];
const _: [(); 56] = [(); offset_of!(PublicTermios, output_speed)];

const _: [(); 36] = [(); size_of::<KernelTermios>()];
const _: [(); 4] = [(); align_of::<KernelTermios>()];
const _: [(); 0] = [(); offset_of!(KernelTermios, input_flags)];
const _: [(); 4] = [(); offset_of!(KernelTermios, output_flags)];
const _: [(); 8] = [(); offset_of!(KernelTermios, control_flags)];
const _: [(); 12] = [(); offset_of!(KernelTermios, local_flags)];
const _: [(); 16] = [(); offset_of!(KernelTermios, line_discipline)];
const _: [(); 17] = [(); offset_of!(KernelTermios, control_codes)];

const _: [(); 8] = [(); size_of::<Winsize>()];
const _: [(); 2] = [(); align_of::<Winsize>()];
const _: [(); 0] = [(); offset_of!(Winsize, rows)];
const _: [(); 2] = [(); offset_of!(Winsize, columns)];
const _: [(); 4] = [(); offset_of!(Winsize, x_pixels)];
const _: [(); 6] = [(); offset_of!(Winsize, y_pixels)];

const PUBLIC_CONTROL_FLAGS_OFFSET: usize = offset_of!(PublicTermios, control_flags);
const PUBLIC_CONTROL_CODES_OFFSET: usize = offset_of!(PublicTermios, control_codes);

#[inline]
fn invalid_argument() -> c_int {
    // SAFETY: The selected static C ABI owns the calling thread's initial TLS
    // errno slot and this is the exact local EINVAL publication path.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

/// Read one caller-owned `u32` from a public termios byte offset.
///
/// # Safety
///
/// `termios` must designate at least four readable bytes at `offset`.
#[inline]
unsafe fn read_public_u32(termios: *const c_void, offset: usize) -> c_uint {
    // SAFETY: The caller supplies the exact readable public-record region.
    unsafe {
        core::ptr::read_unaligned(
            termios.cast::<u8>().wrapping_add(offset).cast::<c_uint>(),
        )
    }
}

/// Write one caller-owned `u32` at a public termios byte offset.
///
/// # Safety
///
/// `termios` must designate at least four writable bytes at `offset`.
#[inline]
unsafe fn write_public_u32(termios: *mut c_void, offset: usize, value: c_uint) {
    // SAFETY: The caller supplies the exact writable public-record region.
    unsafe {
        core::ptr::write_unaligned(
            termios.cast::<u8>().wrapping_add(offset).cast::<c_uint>(),
            value,
        )
    };
}

/// Write one caller-owned public termios control byte.
///
/// # Safety
///
/// `termios` must designate writable public-record storage at `index`.
#[inline]
unsafe fn write_control_code(termios: *mut c_void, index: usize, value: u8) {
    // SAFETY: The caller supplies a complete writable public `struct termios`.
    unsafe {
        core::ptr::write(
            termios
                .cast::<u8>()
                .wrapping_add(PUBLIC_CONTROL_CODES_OFFSET + index),
            value,
        )
    };
}

/// Return the public output baud selector from `c_cflag`.
///
/// # Safety
///
/// `termios` must point to readable storage for a complete public x86
/// `struct termios` record.
#[no_mangle]
pub unsafe extern "C" fn cfgetospeed(termios: *const c_void) -> c_uint {
    // SAFETY: The caller owns the readable C record contract.
    unsafe { read_public_u32(termios, PUBLIC_CONTROL_FLAGS_OFFSET) & CBAUD }
}

/// Return the public input baud selector from `c_cflag`.
///
/// # Safety
///
/// `termios` must point to readable storage for a complete public x86
/// `struct termios` record. A zero input selector remains Linux's distinct
/// `B0` value; this function does not infer the output selector.
#[no_mangle]
pub unsafe extern "C" fn cfgetispeed(termios: *const c_void) -> c_uint {
    // SAFETY: The caller owns the readable C record contract.
    unsafe {
        (read_public_u32(termios, PUBLIC_CONTROL_FLAGS_OFFSET) & CIBAUD)
            / INPUT_SPEED_MULTIPLIER
    }
}

/// Change only the output baud-selector bits of a public C termios record.
///
/// # Safety
///
/// For a valid selector, `termios` must point to writable storage for a
/// complete public x86 `struct termios`. As in musl, an invalid selector is
/// rejected with `EINVAL` before this function dereferences `termios`.
#[no_mangle]
pub unsafe extern "C" fn cfsetospeed(termios: *mut c_void, speed: c_uint) -> c_int {
    if speed & !CBAUD != 0 {
        return invalid_argument();
    }
    // SAFETY: The valid-speed branch reaches the caller's writable C record.
    unsafe {
        let flags = read_public_u32(termios.cast_const(), PUBLIC_CONTROL_FLAGS_OFFSET);
        write_public_u32(
            termios,
            PUBLIC_CONTROL_FLAGS_OFFSET,
            (flags & !CBAUD) | speed,
        );
    }
    0
}

/// Change only the input baud-selector bits of a public C termios record.
///
/// # Safety
///
/// For a valid selector, `termios` must point to writable storage for a
/// complete public x86 `struct termios`. As in musl, an invalid selector is
/// rejected with `EINVAL` before this function dereferences `termios`.
#[no_mangle]
pub unsafe extern "C" fn cfsetispeed(termios: *mut c_void, speed: c_uint) -> c_int {
    if speed & !CBAUD != 0 {
        return invalid_argument();
    }
    // SAFETY: The valid-speed branch reaches the caller's writable C record.
    unsafe {
        let flags = read_public_u32(termios.cast_const(), PUBLIC_CONTROL_FLAGS_OFFSET);
        write_public_u32(
            termios,
            PUBLIC_CONTROL_FLAGS_OFFSET,
            (flags & !CIBAUD) | speed * INPUT_SPEED_MULTIPLIER,
        );
    }
    0
}

/// Set an output selector and the distinct zero input selector.
///
/// # Safety
///
/// The pointer contract is the same as [`cfsetospeed`] and [`cfsetispeed`].
/// An invalid selector is rejected by the first operation before it touches
/// `termios`; a successful call keeps Linux's `B0` input selector rather than
/// copying the output selector.
#[no_mangle]
pub unsafe extern "C" fn cfsetspeed(termios: *mut c_void, speed: c_uint) -> c_int {
    // SAFETY: This forwards the C caller's record contract to the two
    // musl-shaped selected helpers.
    let result = unsafe { cfsetospeed(termios, speed) };
    if result != 0 {
        return result;
    }
    // SAFETY: zero is a valid selector and the first successful write proved
    // the caller's writable record contract for this direct follow-up write.
    unsafe { cfsetispeed(termios, 0) }
}

/// Apply musl's POSIX raw-mode bit transformation in place.
///
/// # Safety
///
/// `termios` must point to writable storage for one complete public x86
/// `struct termios`. Only the named flag fields and `VMIN`/`VTIME` bytes are
/// modified; every other control byte and the public record tail remain
/// caller-resident.
#[no_mangle]
pub unsafe extern "C" fn cfmakeraw(termios: *mut c_void) {
    // SAFETY: The C caller supplies the complete writable public record.
    unsafe {
        let input_flags = read_public_u32(termios.cast_const(), 0);
        write_public_u32(
            termios,
            0,
            input_flags & !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON),
        );
        let output_flags = read_public_u32(termios.cast_const(), 4);
        write_public_u32(termios, 4, output_flags & !OPOST);
        let local_flags = read_public_u32(termios.cast_const(), 12);
        write_public_u32(
            termios,
            12,
            local_flags & !(ECHO | ECHONL | ICANON | ISIG | IEXTEN),
        );
        let control_flags = read_public_u32(termios.cast_const(), PUBLIC_CONTROL_FLAGS_OFFSET);
        write_public_u32(
            termios,
            PUBLIC_CONTROL_FLAGS_OFFSET,
            (control_flags & !(CSIZE | PARENB)) | CS8,
        );
        write_control_code(termios, VMIN, 1);
        write_control_code(termios, VTIME, 0);
    }
}

/// Query one terminal's attributes through `TCGETS`.
///
/// # Safety
///
/// `termios` must be null or point to writable storage for a complete public
/// x86 `struct termios`; Linux itself reports `EFAULT` for an invalid non-null
/// pointer. On success Linux writes only the shared 36-byte kernel prefix,
/// leaving bytes 36 through 59 unchanged exactly as musl does.
#[no_mangle]
pub unsafe extern "C" fn tcgetattr(fd: c_int, termios: *mut c_void) -> c_int {
    // SAFETY: Linux receives the C caller's pointer directly and owns its
    // accessibility validation and exact 36-byte output boundary.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TCGETS,
            termios as usize as i64,
        )
    };
    c_status(result)
}

/// Apply one public termios prefix through `TCSETS`, `TCSETSW`, or `TCSETSF`.
///
/// # Safety
///
/// For actions `TCSANOW..=TCSAFLUSH`, `termios` must be null or point to a
/// readable public x86 `struct termios`; Linux consumes only its first 36
/// bytes and reports invalid pointers itself. As in musl, an invalid action is
/// rejected with `EINVAL` before this function accesses either `fd` or
/// `termios`.
#[no_mangle]
pub unsafe extern "C" fn tcsetattr(
    fd: c_int,
    action: c_int,
    termios: *const c_void,
) -> c_int {
    if !(TCSANOW..=TCSAFLUSH).contains(&action) {
        return invalid_argument();
    }
    // SAFETY: Linux receives the C caller's pointer directly and owns its
    // accessibility validation and exact 36-byte input boundary.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TCSETS + i64::from(action),
            termios as usize as i64,
        )
    };
    c_status(result)
}

/// Flush one named terminal queue through `TCFLSH`.
///
/// # Safety
///
/// `fd` must be suitable for the requested Linux terminal operation. Queue
/// validation and all error ordering remain with the kernel, matching musl.
#[no_mangle]
pub unsafe extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    // SAFETY: This is the fixed Linux ioctl argument boundary; kernel validates
    // the descriptor and queue selector.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TCFLSH,
            i64::from(queue),
        )
    };
    c_status(result)
}

/// Perform one named terminal flow operation through `TCXONC`.
///
/// # Safety
///
/// `fd` must be suitable for the requested Linux terminal operation. Action
/// validation and all error ordering remain with the kernel, matching musl.
#[no_mangle]
pub unsafe extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    // SAFETY: This is the fixed Linux ioctl argument boundary; kernel validates
    // the descriptor and flow selector.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TCXONC,
            i64::from(action),
        )
    };
    c_status(result)
}

/// Send Linux's fixed terminal break request.
///
/// # Safety
///
/// `fd` must be suitable for the Linux terminal operation. The duration is
/// intentionally ignored: musl always sends `TCSBRK` with a zero argument.
#[no_mangle]
pub unsafe extern "C" fn tcsendbreak(fd: c_int, _duration: c_int) -> c_int {
    // SAFETY: The named Linux request has a fixed zero argument. The kernel
    // validates the descriptor; no C generic ioctl API is exposed.
    let result = unsafe {
        raw_syscall::syscall3(raw_syscall::SYS_IOCTL, i64::from(fd), TCSBRK, 0)
    };
    c_status(result)
}

/// Read one fixed Linux `winsize` record through `TIOCGWINSZ`.
///
/// # Safety
///
/// `winsize` must be null or point to writable storage for an eight-byte x86
/// public `struct winsize`; Linux reports an invalid pointer with `EFAULT`.
#[no_mangle]
pub unsafe extern "C" fn tcgetwinsize(fd: c_int, winsize: *mut c_void) -> c_int {
    // SAFETY: Linux receives the caller's exact fixed-size output pointer.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TIOCGWINSZ,
            winsize as usize as i64,
        )
    };
    c_status(result)
}

/// Write one fixed Linux `winsize` record through `TIOCSWINSZ`.
///
/// # Safety
///
/// `winsize` must be null or point to readable storage for an eight-byte x86
/// public `struct winsize`; Linux reports an invalid pointer with `EFAULT`.
#[no_mangle]
pub unsafe extern "C" fn tcsetwinsize(fd: c_int, winsize: *const c_void) -> c_int {
    // SAFETY: Linux receives the caller's exact fixed-size input pointer.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TIOCSWINSZ,
            winsize as usize as i64,
        )
    };
    c_status(result)
}
