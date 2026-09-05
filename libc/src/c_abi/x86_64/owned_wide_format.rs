//! Wide printf/scanf grammar from musl 1.2.6 (MIT), release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417. The digest-checked generator
//! `compat/x86_64/generate_owned_wide_format.py` maps stdio/vfwprintf.c and
//! vfwscanf.c into fixed owned assembly. Numeric directives retain their
//! source delegation to byte fprintf/fscanf, using the existing owned binary
//! 32/64/80 and integer engines, with the actual x86 long-double va_arg ABI.
//!
//! The synchronous proxy contains only context/callback pointers, never an
//! invented FILE layout. One real FILE guard covers the complete call,
//! including nested numeric formatting/scanning and allocation cleanup.
//! Error reset/restore and orientation act on the real FILE. Stack-only
//! vswprintf/vswscanf adapters retain the source 256-byte conversion buffer,
//! truncation and EOF semantics without registry insertion or allocation.

use super::*;
use core::ffi::c_void;
core::arch::global_asm!(include_str!("owned_wide_format_musl_x86_64.S"), options(att_syntax));

#[repr(C)]
struct Operations {
    get: unsafe extern "C" fn(*mut c_void) -> u32,
    put: unsafe extern "C" fn(*mut c_void, c_int) -> u32,
    unget: unsafe extern "C" fn(*mut c_void, u32) -> u32,
    error: unsafe extern "C" fn(*mut c_void) -> c_int,
    orient: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    begin: unsafe extern "C" fn(*mut c_void) -> c_int,
    end: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    print: unsafe extern "C" fn(*mut c_void, *const c_char, *mut VaList<'_>) -> c_int,
    scan: unsafe extern "C" fn(*mut c_void, *const c_char, *mut VaList<'_>) -> c_int,
}
unsafe extern "C" {
    fn __crabc_owned_wide_format(context: *mut c_void, operations: *const Operations,
        scan: c_int, format: *const c_int, arguments: *mut VaList<'_>) -> c_int;
}
unsafe extern "C" fn get(context: *mut c_void) -> u32 { unsafe { stdio_standard::wide_get_held(context.cast()) } }
unsafe extern "C" fn put(context: *mut c_void, character: c_int) -> u32 { unsafe { stdio_standard::wide_put_held(context.cast(), character) } }
unsafe extern "C" fn unget(context: *mut c_void, character: u32) -> u32 { unsafe { stdio_standard::wide_unget_held(context.cast(), character) } }
unsafe extern "C" fn error(context: *mut c_void) -> c_int { unsafe { stdio_standard::wide_error_held(context.cast()) } }
unsafe extern "C" fn orient(context: *mut c_void, mode: c_int) -> c_int { unsafe { stdio_standard::wide_orient_held(context.cast(), mode) } }
unsafe extern "C" fn begin(context: *mut c_void) -> c_int { unsafe { stdio_standard::wide_format_begin_held(context.cast()) } }
unsafe extern "C" fn end(context: *mut c_void, old: c_int) -> c_int { unsafe { stdio_standard::wide_format_end_held(context.cast(), old) } }
unsafe extern "C" fn print(context: *mut c_void, format: *const c_char, arguments: *mut VaList<'_>) -> c_int {
    unsafe { owned_printf::format_stream(context.cast(), format, &mut *arguments) }
}
unsafe extern "C" fn scan(context: *mut c_void, format: *const c_char, arguments: *mut VaList<'_>) -> c_int {
    unsafe { owned_scanf::stream(context.cast(), format, &mut *arguments) }
}
static OPERATIONS: Operations = Operations { get, put, unget, error, orient, begin, end, print, scan };

unsafe fn stream(stream: *mut StandardStream, format: *const c_int, args: &mut VaList<'_>, scan: bool) -> c_int {
    unsafe {
        let _guard = stdio_standard::StreamGuard::acquire(stream);
        let mut cursor = args.clone();
        __crabc_owned_wide_format(stream.cast(), &OPERATIONS, scan as c_int, format, &mut cursor)
    }
}

/// Format to a live wide/unoriented FILE, forwarding the supplied va_list.
/// # Safety
/// FILE is live and not concurrently destroyed. Format is a readable
/// NUL-terminated wchar_t string. Every promoted argument has the exact C
/// type/extent required by its conversion; %n destinations are writable.
#[no_mangle]
pub unsafe extern "C" fn vfwprintf(file: *mut StandardStream, format: *const c_int, mut args: VaList) -> c_int {
    unsafe { stream(file, format, &mut args, false) }
}
/// # Safety
/// The live FILE, wide format and promoted argument obligations are vfwprintf's.
#[no_mangle]
pub unsafe extern "C" fn fwprintf(file: *mut StandardStream, format: *const c_int, mut args: ...) -> c_int {
    unsafe { stream(file, format, &mut args, false) }
}
/// # Safety
/// stdout is live; format and argument obligations are vfwprintf's.
#[no_mangle]
pub unsafe extern "C" fn vwprintf(format: *const c_int, mut args: VaList) -> c_int {
    unsafe { stream(stdio_standard::stdout, format, &mut args, false) }
}
/// # Safety
/// stdout is live; format and promoted argument obligations are vfwprintf's.
#[no_mangle]
pub unsafe extern "C" fn wprintf(format: *const c_int, mut args: ...) -> c_int {
    unsafe { stream(stdio_standard::stdout, format, &mut args, false) }
}
/// Format to bounded caller wide storage; insufficient capacity returns -1.
/// # Safety
/// Destination has capacity writable wchar_t elements, disjoint from format
/// and readable argument sources. Format/arguments satisfy vfwprintf; zero
/// capacity does not access destination, and still requires a valid format.
#[no_mangle]
pub unsafe extern "C" fn vswprintf(destination: *mut c_int, capacity: usize, format: *const c_int, mut args: VaList) -> c_int {
    unsafe { stdio_standard::with_wide_output_buffer(destination, capacity, |file| stream(file, format, &mut args, false)) }
}
/// # Safety
/// Destination, format and promoted arguments satisfy vswprintf's contract.
#[no_mangle]
pub unsafe extern "C" fn swprintf(destination: *mut c_int, capacity: usize, format: *const c_int, mut args: ...) -> c_int {
    unsafe { stdio_standard::with_wide_output_buffer(destination, capacity, |file| stream(file, format, &mut args, false)) }
}

/// Scan a live wide/unoriented FILE through the pinned wide grammar.
/// # Safety
/// FILE is live and not concurrently destroyed; format is a readable
/// NUL-terminated wchar_t string. Each non-suppressed destination has the
/// exact type/extent required by its conversion; %m takes a writable pointer
/// object and transfers a malloc-family allocation on assignment success.
#[no_mangle]
pub unsafe extern "C" fn vfwscanf(file: *mut StandardStream, format: *const c_int, mut args: VaList) -> c_int {
    unsafe { stream(file, format, &mut args, true) }
}
/// # Safety
/// FILE, wide format and destination obligations are vfwscanf's.
#[no_mangle]
pub unsafe extern "C" fn fwscanf(file: *mut StandardStream, format: *const c_int, mut args: ...) -> c_int {
    unsafe { stream(file, format, &mut args, true) }
}
/// # Safety
/// stdin is live; format and destination obligations are vfwscanf's.
#[no_mangle]
pub unsafe extern "C" fn vwscanf(format: *const c_int, mut args: VaList) -> c_int {
    unsafe { stream(stdio_standard::stdin, format, &mut args, true) }
}
/// # Safety
/// stdin is live; format and destination obligations are vfwscanf's.
#[no_mangle]
pub unsafe extern "C" fn wscanf(format: *const c_int, mut args: ...) -> c_int {
    unsafe { stream(stdio_standard::stdin, format, &mut args, true) }
}
/// Scan a NUL-terminated wide string with the shared stream parser.
/// # Safety
/// Source and format are readable terminated wchar_t strings. Destinations
/// satisfy vfwscanf's typed storage/allocation obligations and do not overlap
/// either source string or the va_list object.
#[no_mangle]
pub unsafe extern "C" fn vswscanf(source: *const c_int, format: *const c_int, mut args: VaList) -> c_int {
    unsafe { stdio_standard::with_wide_input_string(source, |file| stream(file, format, &mut args, true)) }
}
/// # Safety
/// Source, format and typed destination obligations are vswscanf's.
#[no_mangle]
pub unsafe extern "C" fn swscanf(source: *const c_int, format: *const c_int, mut args: ...) -> c_int {
    unsafe { stdio_standard::with_wide_input_string(source, |file| stream(file, format, &mut args, true)) }
}

core::arch::global_asm!(r#"
    .weak __isoc99_fwscanf
    .set __isoc99_fwscanf, fwscanf
    .weak __isoc99_vfwscanf
    .set __isoc99_vfwscanf, vfwscanf
    .weak __isoc99_wscanf
    .set __isoc99_wscanf, wscanf
    .weak __isoc99_vwscanf
    .set __isoc99_vwscanf, vwscanf
    .weak __isoc99_swscanf
    .set __isoc99_swscanf, swscanf
    .weak __isoc99_vswscanf
    .set __isoc99_vswscanf, vswscanf
"#);
