//! Owned printf argument discovery and destinations.
//!
//! Pinned musl 1.2.6 `src/stdio/vfprintf.c` (MIT, release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417; `compat/upstreams.toml`) supplies
//! states/pop_arg, printf_core's two-pass NL_ARGMAX=9 argument discovery,
//! integer/string/count/pointer rendering and overflow discipline. Numeric
//! rendering uses the fixed x87 musl translation in owned_printf_float.
//! vdprintf.c supplies a borrowed descriptor with an 80-byte output buffer;
//! vasprintf.c supplies count-then-malloc ownership. No descriptor is closed.
//!
//! The supported owned grammar is byte c/s, signed/unsigned integer lengths,
//! n, p, m, binary64/binary80 a/e/f/g, flags and positional width/precision.
//! Wide conversion remains an EINVAL prerequisite. The C locale
//! has no thousands grouping, so the apostrophe flag has no output effect.
//! Unlike musl's underspecified invalid-format paths, mixed argument numbering
//! and conflicts between ABI extraction classes fail before output/va_arg.

use super::*;
use core::{ffi::c_void, ptr};
use super::super::{c_ssize_status, raw_syscall};

#[path = "owned_printf_float.rs"]
mod owned_printf_float;

const NL_ARGMAX: usize = 9;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind { Absent, None, Int, Uint, Long, Ulong, LongLong, UlongLong,
    Short, Ushort, Char, Uchar, Size, Difference, Pointer, Double, LongDouble }

impl Kind {
    fn extraction_class(self) -> u8 {
        match self {
            Self::Int | Self::Uint | Self::Short | Self::Ushort | Self::Char | Self::Uchar => 1,
            Self::Long | Self::Ulong | Self::LongLong | Self::UlongLong | Self::Size | Self::Difference => 2,
            Self::Pointer => 3,
            Self::Double => 4,
            Self::LongDouble => 5,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy)]
enum Argument { Integer(u64), Pointer(*mut c_void), Float(owned_printf_float::Binary80) }

// Concrete x86 C ABI va_arg types, including int promotion before h/hh
// narrowing. Cached positional slots retain musl's final classification of
// a reused argument; incompatible register/extraction classes are rejected.
unsafe fn pop(args: &mut VaList<'_>, kind: Kind) -> Argument {
    unsafe {
        Argument::Integer(match kind {
            Kind::Int => args.next_arg::<c_int>() as i64 as u64,
            Kind::Uint => args.next_arg::<c_uint>() as u64,
            Kind::Short => args.next_arg::<c_int>() as i16 as i64 as u64,
            Kind::Ushort => args.next_arg::<c_int>() as u16 as u64,
            Kind::Char => args.next_arg::<c_int>() as i8 as i64 as u64,
            Kind::Uchar => args.next_arg::<c_int>() as u8 as u64,
            Kind::Long => args.next_arg::<c_long>() as u64,
            Kind::Ulong => args.next_arg::<c_ulong>() as u64,
            Kind::LongLong => args.next_arg::<c_longlong>() as u64,
            Kind::UlongLong => args.next_arg::<c_ulonglong>() as u64,
            Kind::Size => args.next_arg::<usize>() as u64,
            Kind::Difference => args.next_arg::<isize>() as u64,
            Kind::Pointer => return Argument::Pointer(args.next_arg::<*mut c_void>()),
            Kind::Double => return Argument::Float(owned_printf_float::promote(args.next_arg::<f64>())),
            Kind::LongDouble => return Argument::Float(owned_printf_float::pop(args)),
            Kind::None | Kind::Absent => 0,
        })
    }
}

#[derive(Clone, Copy)]
enum Count { Literal(usize), Argument(usize) }

struct Conversion {
    position: usize,
    width: Count,
    precision: Option<Count>,
    flags: u8,
    length: Length,
    specifier: u8,
    kind: Kind,
}

fn kind(length: Length, specifier: u8) -> Result<Kind, c_int> {
    Ok(match specifier {
        b'd' | b'i' => match length {
            Length::None => Kind::Int, Length::H => Kind::Short, Length::Hh => Kind::Char,
            Length::L | Length::J => Kind::Long, Length::Ll => Kind::LongLong,
            Length::Z | Length::T => Kind::Difference,
        },
        b'u' | b'o' | b'x' | b'X' => match length {
            Length::None => Kind::Uint, Length::H => Kind::Ushort, Length::Hh => Kind::Uchar,
            Length::L | Length::J => Kind::Ulong, Length::Ll => Kind::UlongLong,
            Length::Z | Length::T => Kind::Size,
        },
        b'n' => Kind::Pointer,
        b'c' if length == Length::None => Kind::Int,
        b's' | b'p' if length == Length::None => Kind::Pointer,
        b'm' if length == Length::None => Kind::None,
        b'a' | b'A' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G'
            if matches!(length, Length::None | Length::L) => Kind::Double,
        _ => return Err(EINVAL),
    })
}

unsafe fn index(cursor: &mut *const u8) -> Result<usize, c_int> {
    unsafe {
        let byte = read_byte(*cursor);
        if byte.is_ascii_digit() && read_byte((*cursor).add(1)) == b'$' {
            let value = (byte - b'0') as usize;
            if value == 0 { return Err(EINVAL); }
            *cursor = (*cursor).add(2);
            Ok(value)
        } else { Ok(0) }
    }
}

unsafe fn decimal(cursor: &mut *const u8) -> Result<usize, c_int> {
    let value = unsafe { parse_decimal(cursor) };
    if value > c_int::MAX as usize { Err(EOVERFLOW) } else { Ok(value) }
}

// The caller has consumed %, and %% has already been handled as literal data.
unsafe fn conversion(cursor: &mut *const u8) -> Result<Conversion, c_int> {
    unsafe {
        let position = index(cursor)?;
        let mut flags = 0;
        loop {
            match read_byte(*cursor) {
                b'-' => flags |= FLAG_MINUS, b'+' => flags |= FLAG_PLUS,
                b' ' => flags |= FLAG_SPACE, b'0' => flags |= FLAG_ZERO,
                b'#' => flags |= FLAG_ALT, b'\'' => (),
                _ => break,
            }
            *cursor = (*cursor).add(1);
        }
        let width = if read_byte(*cursor) == b'*' {
            *cursor = (*cursor).add(1);
            Count::Argument(index(cursor)?)
        } else { Count::Literal(decimal(cursor)?) };
        let precision = if read_byte(*cursor) == b'.' {
            *cursor = (*cursor).add(1);
            Some(if read_byte(*cursor) == b'*' {
                *cursor = (*cursor).add(1);
                Count::Argument(index(cursor)?)
            } else { Count::Literal(decimal(cursor)?) })
        } else { None };
        let extended = read_byte(*cursor) == b'L';
        let length = if extended { *cursor = (*cursor).add(1); Length::None }
            else { parse_length(cursor) };
        let specifier = read_byte(*cursor);
        let mut kind = kind(length, specifier)?;
        if extended {
            if kind != Kind::Double { return Err(EINVAL); }
            kind = Kind::LongDouble;
        }
        *cursor = (*cursor).add(1);
        if kind == Kind::None && position != 0 { return Err(EINVAL); }
        Ok(Conversion { position, width, precision, flags, length, specifier, kind })
    }
}

enum Prepared { Sequential, Positional([Argument; NL_ARGMAX + 1]) }

fn register(kinds: &mut [Kind; NL_ARGMAX + 1], position: usize, kind: Kind,
    sequential: &mut bool, positional: &mut bool) -> Result<(), c_int> {
    if kind == Kind::None { return Ok(()); }
    if position == 0 { *sequential = true; return Ok(()); }
    *positional = true;
    let old = kinds[position];
    if old != Kind::Absent && old.extraction_class() != kind.extraction_class() { return Err(EINVAL); }
    kinds[position] = kind;
    Ok(())
}

unsafe fn prepare(format: *const c_char, args: &mut VaList<'_>) -> Result<Prepared, c_int> {
    unsafe {
        let mut kinds = [Kind::Absent; NL_ARGMAX + 1];
        let mut sequential = false;
        let mut positional = false;
        let mut cursor = format.cast::<u8>();
        while read_byte(cursor) != 0 {
            if read_byte(cursor) != b'%' { cursor = cursor.add(1); continue; }
            cursor = cursor.add(1);
            if read_byte(cursor) == b'%' { cursor = cursor.add(1); continue; }
            let item = conversion(&mut cursor)?;
            if let Count::Argument(position) = item.width {
                register(&mut kinds, position, Kind::Int, &mut sequential, &mut positional)?;
            }
            if let Some(Count::Argument(position)) = item.precision {
                register(&mut kinds, position, Kind::Int, &mut sequential, &mut positional)?;
            }
            register(&mut kinds, item.position, item.kind, &mut sequential, &mut positional)?;
        }
        if positional && sequential { return Err(EINVAL); }
        if !positional { return Ok(Prepared::Sequential); }
        let mut gap = false;
        for kind in &kinds[1..] {
            if *kind == Kind::Absent { gap = true; }
            else if gap { return Err(EINVAL); }
        }
        let mut values = [Argument::Integer(0); NL_ARGMAX + 1];
        for position in 1..=NL_ARGMAX {
            if kinds[position] == Kind::Absent { break; }
            values[position] = pop(args, kinds[position]);
        }
        Ok(Prepared::Positional(values))
    }
}

unsafe fn argument(prepared: &Prepared, args: &mut VaList<'_>, position: usize, kind: Kind) -> Argument {
    if kind == Kind::None { return Argument::Integer(0); }
    match prepared {
        Prepared::Sequential => unsafe { pop(args, kind) },
        Prepared::Positional(values) => values[position],
    }
}

unsafe fn count(value: Count, prepared: &Prepared, args: &mut VaList<'_>) -> i64 {
    match value {
        Count::Literal(value) => value as i64,
        Count::Argument(position) => {
            let Argument::Integer(value) = (unsafe { argument(prepared, args, position, Kind::Int) }) else { unreachable!() };
            value as i32 as i64
        }
    }
}

unsafe fn store_count(pointer: *mut c_void, length: Length, value: usize) {
    unsafe {
        match length {
            Length::None => pointer.cast::<c_int>().write(value as c_int),
            Length::Hh => pointer.cast::<i8>().write(value as i8),
            Length::H => pointer.cast::<i16>().write(value as i16),
            Length::L | Length::J => pointer.cast::<c_long>().write(value as c_long),
            Length::Ll => pointer.cast::<c_longlong>().write(value as c_longlong),
            Length::Z | Length::T => pointer.cast::<isize>().write(value as isize),
        }
    }
}

unsafe fn emit(output: &mut impl FormatSink, item: &Conversion, value: Argument,
    width: usize, precision: Option<usize>, flags: u8) {
    unsafe {
        match (item.specifier, value) {
            (b'd' | b'i', Argument::Integer(value)) => {
                let signed = value as i64;
                let sign = if signed < 0 { Some(b'-') } else if flags & FLAG_PLUS != 0 { Some(b'+') }
                    else if flags & FLAG_SPACE != 0 { Some(b' ') } else { None };
                write_number(output, signed.unsigned_abs(), 10, false, sign, false, width, precision, flags);
            }
            (b'u' | b'o' | b'x' | b'X', Argument::Integer(value)) => {
                let base = match item.specifier { b'u' => 10, b'o' => 8, _ => 16 };
                write_number(output, value, base, item.specifier == b'X', None,
                    flags & FLAG_ALT != 0, width, precision, flags);
            }
            (b'p', Argument::Pointer(pointer)) => {
                // musl's MAX(p, 2*sizeof(void*)) promotes p to size_t. Its -1
                // unspecified sentinel survives; only explicit precision gets
                // the 16-digit minimum. A null pointer has no 0x prefix.
                let precision = precision.map(|p| p.max(2 * core::mem::size_of::<*mut c_void>()));
                write_number(output, pointer as usize as u64, 16, false, None, true, width, precision, flags);
            }
            (b'c', Argument::Integer(value)) => write_character(output, value as u8, width, flags),
            (b's', Argument::Pointer(pointer)) => write_string(output, pointer.cast(), width, precision, flags),
            (b'm', _) => {
                let message = error_strings::error_message(errno::get_errno());
                write_string(output, message.as_ptr().cast(), width, precision, flags);
            }
            _ => unreachable!(),
        }
    }
}

unsafe fn render(output: &mut impl FormatSink, format: *const c_char,
    args: &mut VaList<'_>, prepared: &Prepared) -> Result<c_int, c_int> {
    unsafe {
        let mut cursor = format.cast::<u8>();
        while read_byte(cursor) != 0 {
            if read_byte(cursor) != b'%' || read_byte(cursor.add(1)) == b'%' {
                // printf_core batches raw literal bytes and adjacent %%
                // pairs. This preserves backend short-write boundaries.
                let start = cursor;
                while read_byte(cursor) != 0 && read_byte(cursor) != b'%' { cursor = cursor.add(1); }
                let mut end = cursor;
                while read_byte(cursor) == b'%' && read_byte(cursor.add(1)) == b'%' {
                    end = end.add(1); cursor = cursor.add(2);
                }
                let length = end.offset_from(start) as usize;
                if length > c_int::MAX as usize-output.count() { return Err(EOVERFLOW); }
                output.bytes(start, length);
                continue;
            }
            cursor = cursor.add(1);
            let item = conversion(&mut cursor)?;
            let raw_width = count(item.width, prepared, args);
            let mut flags = item.flags;
            if raw_width < 0 { flags |= FLAG_MINUS; }
            let width = raw_width.unsigned_abs() as usize;
            if width > c_int::MAX as usize { return Err(EOVERFLOW); }
            let precision = match item.precision {
                Some(value) => { let value = count(value, prepared, args); (value >= 0).then_some(value as usize) }
                None => None,
            };
            let value = argument(prepared, args, item.position, item.kind);
            // printf_core extracts the directive's argument before its F_ERR
            // gate, but does not execute a new conversion (including %n).
            if output.failed() { return Ok(-1); }
            if item.specifier == b'n' {
                let Argument::Pointer(pointer) = value else { unreachable!() };
                store_count(pointer, item.length, output.count());
                continue;
            }
            if let Argument::Float(value) = value {
                owned_printf_float::render(output, value, item.kind == Kind::LongDouble,
                    width, precision, flags, item.specifier)?;
                continue;
            }
            // Measure before emitting padding. This is printf_core's INT_MAX
            // gate, including prefixes and current count, without iterating
            // over impossible billion-byte stream results or modifying %n.
            let mut measured = Output::new(ptr::null_mut(), 0);
            measured.count = output.count();
            emit(&mut measured, &item, value, width, precision, flags);
            if measured.overflowed || measured.count > c_int::MAX as usize { return Err(EOVERFLOW); }
            emit(output, &item, value, width, precision, flags);
        }
        if output.failed() { Ok(-1) } else { Ok(output.count() as c_int) }
    }
}

fn result(value: Result<c_int, c_int>) -> c_int {
    match value {
        Ok(value) => value,
        Err(error) => { unsafe { errno::set_errno(error); } -1 }
    }
}

pub(super) unsafe fn format(output: &mut impl FormatSink, format: *const c_char, args: &mut VaList<'_>) -> c_int {
    unsafe {
        let mut cursor = args.clone();
        let prepared = match prepare(format, &mut cursor) { Ok(value) => value, Err(error) => return result(Err(error)) };
        result(render(output, format, &mut cursor, &prepared))
    }
}

pub(super) unsafe fn format_stream(stream: *mut StandardStream, format: *const c_char, args: &mut VaList<'_>) -> c_int {
    unsafe {
        let mut cursor = args.clone();
        let prepared = match prepare(format, &mut cursor) { Ok(value) => value, Err(error) => return result(Err(error)) };
        stdio_standard::with_formatted_stream(stream, || {
            let mut output = StreamOutput::new(stream);
            result(render(&mut output, format, &mut cursor, &prepared))
        })
    }
}

struct DescriptorOutput { fd: c_int, buffer: [u8; 80], pending: usize, count: usize, failed: bool, overflowed: bool }
impl DescriptorOutput {
    unsafe fn flush(&mut self, force_empty: bool) {
        // vfprintf flushes its temporary unbuffered adapter even when printf
        // emitted no bytes. __stdio_write then diagnoses an invalid descriptor.
        if force_empty && self.pending == 0 && !self.failed {
            if c_ssize_status(unsafe { raw_syscall::syscall3(raw_syscall::SYS_WRITE,
                self.fd as i64, self.buffer.as_ptr() as i64, 0) }) < 0 {
                self.failed = true;
            }
        }
        let mut written = 0;
        while written < self.pending && !self.failed {
            let count = c_ssize_status(unsafe { raw_syscall::syscall3(raw_syscall::SYS_WRITE,
                self.fd as i64, self.buffer.as_ptr().add(written) as i64, (self.pending - written) as i64) });
            if count <= 0 {
                if count == 0 { unsafe { errno::set_errno(5); } }
                self.failed = true;
            } else { written += count as usize; }
        }
        self.pending = 0;
    }
}
impl FormatSink for DescriptorOutput {
    unsafe fn byte(&mut self, byte: u8) {
        self.count += 1;
        if self.failed { return; }
        if self.pending == self.buffer.len() { unsafe { self.flush(false); } }
        if self.failed { return; }
        self.buffer[self.pending] = byte;
        self.pending += 1;
    }
    unsafe fn bytes(&mut self, source: *const u8, length: usize) {
        for index in 0..length {
            if self.failed { self.count += length-index; break; }
            unsafe { self.byte(*source.add(index)); }
        }
    }
    unsafe fn repeated(&mut self, byte: u8, length: usize) {
        for index in 0..length {
            if self.failed { self.count += length-index; break; }
            unsafe { self.byte(byte); }
        }
    }
    fn count(&self) -> usize { self.count }
    fn overflowed(&self) -> bool { self.overflowed }
    fn set_overflowed(&mut self) { self.overflowed = true; }
    fn failed(&self) -> bool { self.failed }
    fn allow_float(&self) -> bool { true }
    fn allow_errno_message(&self) -> bool { true }
}

/// # Safety
/// `format` is NUL terminated and each promoted argument has the type and
/// readable/writable extent required by its conversion. `fd` is borrowed.
#[no_mangle]
pub unsafe extern "C" fn vdprintf(fd: c_int, format_string: *const c_char, mut args: VaList) -> c_int {
    unsafe {
        let mut cursor = args.clone();
        let prepared = match prepare(format_string, &mut cursor) { Ok(value) => value, Err(error) => return result(Err(error)) };
        let mut output = DescriptorOutput { fd, buffer: [0; 80], pending: 0, count: 0, failed: false, overflowed: false };
        let value = result(render(&mut output, format_string, &mut cursor, &prepared));
        output.flush(true);
        if output.failed { -1 } else { value }
    }
}

/// # Safety
/// The format/argument obligations are those of vdprintf; this call does not
/// take ownership of or close `fd`.
#[no_mangle]
pub unsafe extern "C" fn dprintf(fd: c_int, format: *const c_char, mut args: ...) -> c_int {
    unsafe { vdprintf(fd, format, args) }
}

unsafe extern "C" { fn malloc(size: usize) -> *mut c_void; }

/// # Safety
/// `destination` is writable pointer storage; format and arguments satisfy
/// vsnprintf's type/extent contract. On allocation success the caller owns the
/// malloc-family allocation, including a possible second-pass failure.
#[no_mangle]
pub unsafe extern "C" fn vasprintf(destination: *mut *mut c_char, format: *const c_char, mut args: VaList) -> c_int {
    unsafe {
        let mut first = args.clone();
        let length = format_to_buffer(ptr::null_mut(), 0, format, &mut first);
        if length < 0 { return -1; }
        *destination = malloc(length as usize + 1).cast();
        if (*destination).is_null() { return -1; }
        format_to_buffer(*destination, length as usize + 1, format, &mut args)
    }
}

/// # Safety
/// The format, argument and output-ownership obligations are those of vasprintf.
#[no_mangle]
pub unsafe extern "C" fn asprintf(destination: *mut *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    unsafe { vasprintf(destination, format, args) }
}
