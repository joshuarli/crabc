//! Owned binary64/binary80 printf numerical boundary (not a wide formatter).
//!
//! `owned_printf_float_musl_x86_64.S` is a fixed translation of musl 1.2.6
//! `src/stdio/vfprintf.c::{fmt_fp,fmt_u,xdigits}`, release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417. Its complete MIT license is in
//! the assembly; the source tree and compiler pins are checked by
//! `compat/x86_64/generate_owned_printf_float.py`. The normal Rust product
//! build includes assembly and never compiles C or imports a foreign object.
//!
//! The base-1e9 limb algorithm, x87 evaluation order, rounding probe and
//! decimal/hexadecimal rendering are upstream. Only FILE out/pad become
//! synchronous sink callbacks; padding uses a repeated-byte operation so a
//! truncated/counting buffer need not iterate over discarded padding. Owned
//! frexpl/scalbn/classification and memcpy providers satisfy every direct call.
//! No allocation, locale database, parser or FILE lock lives in this leaf.
//!
//! Binary80 crosses the Rust boundary by ten meaningful bytes, never through
//! f64 or binary128. SysV va_arg advances the overflow stack slot, aligned to
//! 16, without consuming a GP/SSE register slot. Binary64 C arguments (also
//! promoted binary32) are widened exactly as musl pop_arg's union assignment.
//! The numeric body runs once per rendering pass, not during a second local
//! sizing pass; vasprintf's two rendering passes remain its upstream contract.

use super::*;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("owned_printf_float_musl_x86_64.S"), options(att_syntax));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("owned_printf_float_musl_aarch64.S"));

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub(super) struct Binary80 { bytes: [u8; 10] }

#[cfg(target_arch = "x86_64")]
pub(super) type LongDouble = Binary80;

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub(super) struct LongDouble { bytes: [u8; 16] }

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct SysvVaList {
    gp_offset: u32,
    fp_offset: u32,
    overflow_arg_area: *const u8,
    reg_save_area: *const u8,
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<VaList<'static>>() == core::mem::size_of::<SysvVaList>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::align_of::<VaList<'static>>() == core::mem::align_of::<SysvVaList>());

#[repr(C)]
struct Sink {
    state: *mut c_void,
    bytes: unsafe extern "C" fn(*mut c_void, *const u8, usize),
    repeat: unsafe extern "C" fn(*mut c_void, c_int, usize),
}

unsafe extern "C" {
    fn __crabc_owned_printf_promote(value: f64, destination: *mut LongDouble);
    fn __crabc_owned_printf_float(sink: *mut Sink, value: *const LongDouble,
        width: c_int, precision: c_int, flags: c_int, specifier: c_int,
        long_precision: c_int) -> c_int;
}

#[cfg(target_arch = "x86_64")]
pub(super) fn promote(value: f64) -> Binary80 {
    let mut result = Binary80 { bytes: [0; 10] };
    // The assembly stores exactly the initialized ten-byte payload.
    unsafe { __crabc_owned_printf_promote(value, &mut result); }
    result
}

// Caller has classified the next live C variadic argument as long double.
// VaList's repr(transparent) SysV layout is pinned with the compiler; only
// overflow_arg_area changes. Copying ten bytes avoids reading ABI padding.
#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn pop(args: &mut VaList<'_>) -> Binary80 {
    unsafe {
        let cursor = &mut *(args as *mut VaList<'_>).cast::<SysvVaList>();
        let pointer = cursor.overflow_arg_area.map_addr(|address| (address + 15) & !15);
        let mut result = Binary80 { bytes: [0; 10] };
        ptr::copy_nonoverlapping(pointer, result.bytes.as_mut_ptr(), 10);
        cursor.overflow_arg_area = pointer.add(16);
        result
    }
}

// AAPCS64 section 14.4: the compiler va_list tracks the saved vector area
// separately from the aligned overflow stack; musl uses IEEE binary128.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct AapcsVaList {
    stack: *const u8,
    gr_top: *const u8,
    vr_top: *const u8,
    gr_offs: i32,
    vr_offs: i32,
}

#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<VaList<'static>>() == core::mem::size_of::<AapcsVaList>());
#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::align_of::<VaList<'static>>() == core::mem::align_of::<AapcsVaList>());

#[cfg(target_arch = "aarch64")]
pub(super) fn promote(value: f64) -> LongDouble {
    let mut result = LongDouble { bytes: [0; 16] };
    // SAFETY: the translated musl helper writes one binary128 value to result.
    unsafe { __crabc_owned_printf_promote(value, &mut result); }
    result
}

#[cfg(target_arch = "aarch64")]
pub(super) unsafe fn pop(args: &mut VaList<'_>) -> LongDouble {
    // SAFETY: the caller guarantees a live long-double argument; the asserted
    // layout is the AAPCS64 va_list and each selected slot holds 16 bytes.
    unsafe {
        let cursor = &mut *(args as *mut VaList<'_>).cast::<AapcsVaList>();
        let pointer = if cursor.vr_offs < 0 {
            let offset = cursor.vr_offs;
            cursor.vr_offs += 16;
            cursor.vr_top.offset(offset as isize)
        } else {
            let pointer = cursor.stack.map_addr(|address| (address + 15) & !15);
            cursor.stack = pointer.add(16);
            pointer
        };
        let mut result = LongDouble { bytes: [0; 16] };
        ptr::copy_nonoverlapping(pointer, result.bytes.as_mut_ptr(), 16);
        result
    }
}

unsafe extern "C" fn bytes<S: FormatSink>(state: *mut c_void, data: *const u8, count: usize) {
    unsafe {
        let output = &mut *state.cast::<S>();
        if output.overflowed() { return; }
        if count > c_int::MAX as usize - output.count() { output.set_overflowed(); return; }
        output.bytes(data, count);
    }
}

unsafe extern "C" fn repeat<S: FormatSink>(state: *mut c_void, byte: c_int, count: usize) {
    unsafe {
        let output = &mut *state.cast::<S>();
        if output.overflowed() { return; }
        if count > c_int::MAX as usize - output.count() { output.set_overflowed(); return; }
        output.repeated(byte as u8, count);
    }
}

pub(super) fn render<S: FormatSink>(output: &mut S, value: LongDouble, extended: bool,
    width: usize, precision: Option<usize>, flags: u8, specifier: u8) -> Result<(), c_int> {
    // Explicit translation to upstream's ASCII-indexed flag bitset.
    let mut musl_flags = 0;
    for (flag, byte) in [(FLAG_MINUS, b'-'), (FLAG_PLUS, b'+'), (FLAG_SPACE, b' '),
        (FLAG_ZERO, b'0'), (FLAG_ALT, b'#')] {
        if flags & flag != 0 { musl_flags |= 1 << (byte - b' '); }
    }
    // printf_core clears ZERO_PAD when LEFT_ADJ is present before fmt_fp.
    if flags & FLAG_MINUS != 0 { musl_flags &= !(1 << (b'0' - b' ')); }
    let mut sink = Sink { state: (output as *mut S).cast(), bytes: bytes::<S>, repeat: repeat::<S> };
    // The borrowed sink and value stay live through all synchronous callbacks;
    // neither pointer escapes and no callback reacquires the FILE guard.
    let result = unsafe { __crabc_owned_printf_float(&mut sink, &value, width as c_int,
        precision.map_or(-1, |value| value as c_int), musl_flags, specifier as c_int, extended as c_int) };
    if result < 0 || output.overflowed() { Err(EOVERFLOW) } else { Ok(()) }
}
