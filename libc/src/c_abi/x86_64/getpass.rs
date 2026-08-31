//! Selected static Linux/x86-64 C `getpass` terminal boundary.
//!
//! This is a narrow port of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Musl's `src/legacy/getpass.c` opens the calling process's `/dev/tty`, applies
//! a temporary canonical no-echo/no-signal termios image, writes an optional
//! prompt, reads one fixed 128-byte static buffer, restores the saved image,
//! writes a newline, and closes the temporary descriptor.  The selected x86
//! leaf retains that observable state sequence over the existing named
//! `tcgetattr`/`tcsetattr` boundary.  Linux's public x86 C `termios` record is
//! 60 bytes while `TCGETS`/`TCSETSF` consume its 36-byte kernel prefix; the
//! local record deliberately preserves that established C ABI distinction.
//! Source-function mapping: musl `getpass` -> `getpass.rs::getpass`.
//!
//! `getpass` is historical C ABI compatibility machinery only.  It does not
//! create a Rust secret type or password API; it does not read account data,
//! environment state, utmp, or NSS; and it does not expose a PTY allocator,
//! generic ioctl interface, process/session helper, cancellation protocol,
//! terminal policy framework, dynamic runtime, CRT, loader, sysroot, or a
//! public x86 support claim.  Its static buffer has the ordinary musl C
//! lifetime and race semantics.  The direct no-controlling-terminal error is
//! left to Linux's `/dev/tty` open (`ENXIO` in the native evidence).
//!
//! The Rust port deliberately makes three error-only safety choices explicit:
//! an initial `tcgetattr` failure returns null rather than continuing with
//! C's indeterminate termios image, a null prompt writes no bytes instead of
//! invoking `%s` on a null C pointer, and cleanup preserves a raw read error.
//! They do not create a portable password interface or broaden this historical
//! C ABI compatibility leaf.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{errno, raw_syscall, termios_control};

const O_RDWR: i64 = 0x2;
const O_NOCTTY: i64 = 0x100;
const O_CLOEXEC: i64 = 0x8_0000;

const ECHO: c_uint = 0o000010;
const ISIG: c_uint = 0o000001;
const ICANON: c_uint = 0o000002;
const INLCR: c_uint = 0o000100;
const IGNCR: c_uint = 0o000200;
const ICRNL: c_uint = 0o000400;
const TCSAFLUSH: c_int = 2;
const TCSBRK: i64 = 0x5409;

const PASSWORD_CAPACITY: usize = 128;

/// The installed musl-shaped public x86 C `termios` record.
///
/// The named termios sibling owns the kernel operation; this local value
/// exists only so `getpass` can save, modify, and restore the public C image
/// without exposing it as a Rust API.
#[repr(C)]
#[derive(Clone, Copy)]
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

static mut PASSWORD_BUFFER: [u8; PASSWORD_CAPACITY] = [0; PASSWORD_CAPACITY];

#[inline]
fn raw_error(result: i64) -> Option<c_int> {
    if (-4_095..=-1).contains(&result) {
        Some(result.wrapping_neg() as c_int)
    } else {
        None
    }
}

#[inline]
fn close_without_errno(file_descriptor: c_int) {
    // SAFETY: cleanup passes one scalar descriptor and intentionally ignores
    // its raw result so a preceding terminal/read failure keeps its errno.
    let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(file_descriptor)) };
}

#[inline]
fn drain_terminal_output(file_descriptor: c_int) {
    // Musl calls tcdrain here. Keep its one fixed TCSBRK-with-argument-one
    // request private to this historical helper so adding getpass does not
    // select the separately scoped public tcdrain/cancellation boundary.
    // SAFETY: the named request has only the scalar descriptor and fixed
    // drain-without-break argument; its result is intentionally ignored as in
    // musl's getpass sequence.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(file_descriptor),
            TCSBRK,
            1,
        )
    };
}

/// Return the byte length of one caller-owned NUL-terminated C string.
///
/// # Safety
///
/// `text` must point to a readable NUL-terminated C string for the whole
/// scan.  This is the normal `getpass` prompt precondition; no arbitrary
/// bounded-string or Rust text policy is introduced here.
#[inline]
unsafe fn c_string_length(text: *const c_char) -> usize {
    let mut length = 0_usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    length
}

/// Read one password line from the calling process's controlling terminal.
///
/// This C ABI returns process-global static storage containing at most 127
/// bytes plus a terminator, or null after the named terminal setup/read error.
/// A later call overwrites the same storage.
///
/// # Safety
///
/// When non-null, `prompt` must point to a readable NUL-terminated C string
/// for the call.  The caller must serialize use of this function and every
/// concurrent mutation or observation of the process controlling terminal:
/// this function temporarily applies `TCSAFLUSH`, which discards queued input
/// and changes echo/signal processing until restoration.  The returned static
/// storage must not be used after another `getpass` call and must not be used
/// concurrently without external synchronization.  Callers must treat its
/// secret bytes according to their own lifetime and disclosure requirements;
/// this historical C helper does not provide secret-memory ownership or
/// erasure guarantees.
#[no_mangle]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    // SAFETY: the fixed path remains valid for the direct open operation and
    // the selected flags do not encode a caller-owned pointer.
    let opened = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_OPEN,
            b"/dev/tty\0".as_ptr() as usize as i64,
            O_RDWR | O_NOCTTY | O_CLOEXEC,
            0,
        )
    };
    let Some(open_error) = raw_error(opened) else {
        let file_descriptor = opened as c_int;
        let mut saved = PublicTermios {
            input_flags: 0,
            output_flags: 0,
            control_flags: 0,
            local_flags: 0,
            line_discipline: 0,
            control_codes: [0; 32],
            input_speed: 0,
            output_speed: 0,
        };

        // SAFETY: `saved` is complete writable public C storage. The named
        // sibling owns Linux's exact 36-byte kernel-prefix interaction.
        if unsafe {
            termios_control::tcgetattr(
                file_descriptor,
                (&mut saved as *mut PublicTermios).cast::<c_void>(),
            )
        } < 0
        {
            close_without_errno(file_descriptor);
            return core::ptr::null_mut();
        }

        let mut modified = saved;
        modified.local_flags &= !(ECHO | ISIG);
        modified.local_flags |= ICANON;
        modified.input_flags &= !(INLCR | IGNCR);
        modified.input_flags |= ICRNL;

        // SAFETY: `modified` is complete readable public C storage and this
        // fixed action is the source-selected `TCSAFLUSH` transition.
        let _ = unsafe {
            termios_control::tcsetattr(
                file_descriptor,
                TCSAFLUSH,
                (&modified as *const PublicTermios).cast::<c_void>(),
            )
        };
        drain_terminal_output(file_descriptor);

        if !prompt.is_null() {
            // SAFETY: the public C caller upholds the non-null prompt's
            // NUL-terminated readable-string contract documented above.
            let prompt_bytes = unsafe { c_string_length(prompt) };
            // SAFETY: `prompt` remains readable for exactly its scanned C
            // string; musl deliberately ignores a short or failed prompt
            // write while it proceeds to the one terminal read.
            let _ = unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_WRITE,
                    i64::from(file_descriptor),
                    prompt as usize as i64,
                    prompt_bytes as i64,
                )
            };
        }

        let password = core::ptr::addr_of_mut!(PASSWORD_BUFFER).cast::<u8>();
        // SAFETY: the one fixed static buffer is writable for exactly 128
        // bytes. The public function documents the C static-storage race.
        let read_result = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_READ,
                i64::from(file_descriptor),
                password as usize as i64,
                PASSWORD_CAPACITY as i64,
            )
        };

        // SAFETY: the complete saved public record remains live. A restore
        // failure remains visible when the raw read succeeded.
        let _ = unsafe {
            termios_control::tcsetattr(
                file_descriptor,
                TCSAFLUSH,
                (&saved as *const PublicTermios).cast::<c_void>(),
            )
        };
        // SAFETY: the immutable newline storage is valid for this exact
        // one-byte write; the source deliberately ignores its result.
        let _ = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_WRITE,
                i64::from(file_descriptor),
                b"\n".as_ptr() as usize as i64,
                1,
            )
        };
        close_without_errno(file_descriptor);

        if let Some(read_error) = raw_error(read_result) {
            // SAFETY: this selected Rust-safety boundary deliberately
            // preserves the read's Linux error across cleanup.
            unsafe { errno::set_errno(read_error) };
            return core::ptr::null_mut();
        }

        let mut password_bytes = read_result as usize;
        // SAFETY: the bounded read wrote at most PASSWORD_CAPACITY bytes to
        // this exact static buffer, so the inspected final byte is initialized
        // when password_bytes is positive.
        if (password_bytes > 0 && unsafe { *password.add(password_bytes - 1) } == b'\n')
            || password_bytes == PASSWORD_CAPACITY
        {
            password_bytes -= 1;
        }
        // SAFETY: password_bytes is now in 0..PASSWORD_CAPACITY, reserving
        // one byte for the C terminator in the full-buffer path.
        unsafe { *password.add(password_bytes) = 0 };
        return password.cast::<c_char>();
    };

    // SAFETY: opening `/dev/tty` failed with one Linux errno and no terminal
    // state was changed, so this is the selected C errno publication path.
    unsafe { errno::set_errno(open_error) };
    core::ptr::null_mut()
}
