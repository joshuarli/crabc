//! Bounded static Linux/x86-64 POSIX regex compatibility artifact.
//!
//! This leaf owns the musl-shaped `regex_t`/`regmatch_t` C ABI and the four
//! public `regcomp`, `regexec`, `regerror`, and `regfree` entry points. Its
//! selected byte grammar is deliberately narrower than the complete POSIX
//! grammar: BRE/ERE concatenation, beginning/end anchors, dot, bracket byte
//! lists and ranges, `*`, and ERE `+`/`?`; `REG_ICASE`, `REG_NEWLINE`,
//! `REG_NOSUB`, `REG_NOTBOL`, and `REG_NOTEOL` are preserved. Matching is
//! leftmost-longest and reports the whole match; the selected grammar has no
//! subexpressions, so `re_nsub` is always zero and later match slots are -1.
//!
//! Groups, alternation, counted repetition, backreferences, named character
//! classes, collating/equivalence elements, and non-ASCII pattern bytes are
//! rejected at compile time rather than receiving approximate semantics. A
//! compiled expression has at most 128 atoms and a searched C string has at
//! most 4096 bytes; exceeding either fixed bound returns `REG_ESPACE`. This is
//! one private static C compatibility slice, not complete `pattern.regex`, a
//! Rust regex API, locale-aware/multibyte regex, C allocation, libc.so, CRT,
//! loader, sysroot, family completion, or public x86 support.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` is the behavior and ABI oracle:
//! `include/regex.h`, `src/regex/regcomp.c`, `src/regex/regexec.c`, and
//! `src/regex/regerror.c`. This fixed-capacity matcher is an independent
//! implementation, not a translation of musl's TRE engine. It therefore does
//! not copy TRE algorithms or source-specific licensed implementation text.

use core::ffi::{c_char, c_int, c_void};

use super::raw_syscall;

const REG_EXTENDED: c_int = 1;
const REG_ICASE: c_int = 2;
const REG_NEWLINE: c_int = 4;
const REG_NOSUB: c_int = 8;
const REG_NOTBOL: c_int = 1;
const REG_NOTEOL: c_int = 2;

const REG_OK: c_int = 0;
const REG_NOMATCH: c_int = 1;
const REG_BADPAT: c_int = 2;
const REG_EESCAPE: c_int = 5;
const REG_EBRACK: c_int = 7;
const REG_ERANGE: c_int = 11;
const REG_ESPACE: c_int = 12;
const REG_BADRPT: c_int = 13;

const KIND_BYTES: u8 = 1;
const KIND_ANY: u8 = 2;
const KIND_BOL: u8 = 3;
const KIND_EOL: u8 = 4;

const REPEAT_ONE: u8 = 0;
const REPEAT_ZERO_OR_ONE: u8 = 1;
const REPEAT_ZERO_OR_MORE: u8 = 2;
const REPEAT_ONE_OR_MORE: u8 = 3;

const MAX_TOKENS: usize = 128;
const MAX_PATTERN_BYTES: usize = 4_096;
const MAX_INPUT_BYTES: usize = 4_096;
const COMPILED_MAPPING_BYTES: usize = 8_192;
const COMPILED_MAGIC: u64 = 0x4352_4142_4352_4547;

const PROT_READ_WRITE: i64 = 3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x02 | 0x20;
const LINUX_ERRNO_MAX: i64 = 4_095;

type RegOff = i64;

#[repr(C)]
pub struct Regex {
    re_nsub: usize,
    opaque: *mut c_void,
    padding: [*mut c_void; 4],
    nsub2: usize,
    padding2: c_char,
}

#[repr(C)]
pub struct RegMatch {
    rm_so: RegOff,
    rm_eo: RegOff,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct Token {
    bitmap: [u64; 4],
    kind: u8,
    repetition: u8,
    negated: u8,
    reserved: [u8; 5],
}

impl Token {
    const fn new(kind: u8) -> Self {
        Self {
            bitmap: [0; 4],
            kind,
            repetition: REPEAT_ONE,
            negated: 0,
            reserved: [0; 5],
        }
    }

    fn set_byte(&mut self, byte: u8) {
        self.bitmap[(byte / 64) as usize] |= 1u64 << (byte % 64);
    }

    fn contains(&self, byte: u8) -> bool {
        self.bitmap[(byte / 64) as usize] & (1u64 << (byte % 64)) != 0
    }
}

#[repr(C)]
struct CompiledRegex {
    magic: u64,
    mapping_bytes: usize,
    flags: c_int,
    token_count: usize,
    tokens: [Token; MAX_TOKENS],
}

const _: () = assert!(core::mem::size_of::<CompiledRegex>() <= COMPILED_MAPPING_BYTES);
const _: () = assert!(core::mem::size_of::<Regex>() == 64);
const _: () = assert!(core::mem::align_of::<Regex>() == 8);
const _: () = assert!(core::mem::size_of::<RegMatch>() == 16);

#[inline]
fn ascii_other_case(byte: u8) -> u8 {
    if byte.is_ascii_lowercase() {
        byte - b'a' + b'A'
    } else if byte.is_ascii_uppercase() {
        byte - b'A' + b'a'
    } else {
        byte
    }
}

fn add_bitmap_byte(token: &mut Token, byte: u8, ignore_case: bool) {
    token.set_byte(byte);
    if ignore_case {
        token.set_byte(ascii_other_case(byte));
    }
}

fn add_bitmap_range(token: &mut Token, low: u8, high: u8, ignore_case: bool) {
    for byte in low..=high {
        add_bitmap_byte(token, byte, ignore_case);
    }
}

unsafe fn bounded_c_string_length(pointer: *const c_char, maximum: usize) -> Result<usize, c_int> {
    if pointer.is_null() {
        return Err(REG_BADPAT);
    }
    let mut length = 0usize;
    while length <= maximum {
        // SAFETY: C's string contract requires readable storage through its
        // terminating NUL. The fixed bound prevents an unbounded scan.
        if unsafe { *pointer.add(length) } == 0 {
            return Ok(length);
        }
        length += 1;
    }
    Err(REG_ESPACE)
}

unsafe fn map_compiled_regex() -> *mut CompiledRegex {
    // SAFETY: this private anonymous mapping has a fixed page-multiple length,
    // no file backing, and no caller-provided address.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            COMPILED_MAPPING_BYTES as i64,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            -1,
            0,
        )
    };
    if result < 0 && result >= -LINUX_ERRNO_MAX {
        core::ptr::null_mut()
    } else {
        result as usize as *mut CompiledRegex
    }
}

unsafe fn unmap_compiled_regex(compiled: *mut CompiledRegex) {
    // SAFETY: every non-null pointer passed here is the base of this leaf's
    // private fixed-length mapping and is consumed exactly once.
    let _ = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            compiled as usize as i64,
            COMPILED_MAPPING_BYTES as i64,
        )
    };
}

fn push_token(compiled: &mut CompiledRegex, token: Token) -> Result<(), c_int> {
    if compiled.token_count == MAX_TOKENS {
        return Err(REG_ESPACE);
    }
    compiled.tokens[compiled.token_count] = token;
    compiled.token_count += 1;
    Ok(())
}

fn literal_token(byte: u8, ignore_case: bool) -> Token {
    let mut token = Token::new(KIND_BYTES);
    add_bitmap_byte(&mut token, byte, ignore_case);
    token
}

unsafe fn parse_bracket(
    compiled: &mut CompiledRegex,
    pattern: *const u8,
    pattern_length: usize,
    opening: usize,
    ignore_case: bool,
) -> Result<usize, c_int> {
    let mut token = Token::new(KIND_BYTES);
    let mut index = opening + 1;
    let mut have_member = false;

    if index == pattern_length {
        return Err(REG_EBRACK);
    }
    // SAFETY: the caller established pattern_length readable pattern bytes.
    if unsafe { *pattern.add(index) } == b'^' {
        token.negated = 1;
        index += 1;
    }
    if index < pattern_length && unsafe { *pattern.add(index) } == b']' {
        add_bitmap_byte(&mut token, b']', ignore_case);
        have_member = true;
        index += 1;
    }

    while index < pattern_length {
        // SAFETY: index remains below the established pattern length.
        let low = unsafe { *pattern.add(index) };
        if low == b']' && have_member {
            push_token(compiled, token)?;
            return Ok(index + 1);
        }
        if low >= 0x80 {
            return Err(REG_BADPAT);
        }
        if low == b'[' && index + 1 < pattern_length {
            let marker = unsafe { *pattern.add(index + 1) };
            if marker == b':' || marker == b'.' || marker == b'=' {
                return Err(REG_BADPAT);
            }
        }

        if index + 2 < pattern_length
            && unsafe { *pattern.add(index + 1) } == b'-'
            && unsafe { *pattern.add(index + 2) } != b']'
        {
            let high = unsafe { *pattern.add(index + 2) };
            if high >= 0x80 {
                return Err(REG_BADPAT);
            }
            if high < low {
                return Err(REG_ERANGE);
            }
            add_bitmap_range(&mut token, low, high, ignore_case);
            have_member = true;
            index += 3;
        } else {
            add_bitmap_byte(&mut token, low, ignore_case);
            have_member = true;
            index += 1;
        }
    }
    Err(REG_EBRACK)
}

fn apply_repetition(compiled: &mut CompiledRegex, repetition: u8) -> Result<(), c_int> {
    if compiled.token_count == 0 {
        return Err(REG_BADRPT);
    }
    let token = &mut compiled.tokens[compiled.token_count - 1];
    if token.repetition != REPEAT_ONE || token.kind == KIND_BOL || token.kind == KIND_EOL {
        return Err(REG_BADRPT);
    }
    token.repetition = repetition;
    Ok(())
}

unsafe fn compile_pattern(
    compiled: &mut CompiledRegex,
    pattern: *const c_char,
    pattern_length: usize,
    flags: c_int,
) -> Result<(), c_int> {
    let bytes = pattern.cast::<u8>();
    let extended = flags & REG_EXTENDED != 0;
    let ignore_case = flags & REG_ICASE != 0;
    let mut index = 0usize;

    while index < pattern_length {
        // SAFETY: index remains below the established pattern length.
        let byte = unsafe { *bytes.add(index) };
        if byte >= 0x80 {
            return Err(REG_BADPAT);
        }

        if byte == b'[' {
            index = unsafe {
                parse_bracket(compiled, bytes, pattern_length, index, ignore_case)?
            };
            continue;
        }
        if byte == b'\\' {
            if index + 1 == pattern_length {
                return Err(REG_EESCAPE);
            }
            let escaped = unsafe { *bytes.add(index + 1) };
            if escaped >= 0x80 {
                return Err(REG_BADPAT);
            }
            if (!extended
                && (escaped == b'('
                    || escaped == b')'
                    || escaped == b'{'
                    || escaped == b'}'
                    || escaped == b'+'
                    || escaped == b'?'
                    || escaped == b'|'
                    || escaped.is_ascii_digit()))
                || (extended && escaped.is_ascii_digit())
            {
                return Err(REG_BADPAT);
            }
            push_token(compiled, literal_token(escaped, ignore_case))?;
            index += 2;
            continue;
        }
        if byte == b'^' && index == 0 {
            push_token(compiled, Token::new(KIND_BOL))?;
            index += 1;
            continue;
        }
        if byte == b'$' && index + 1 == pattern_length {
            push_token(compiled, Token::new(KIND_EOL))?;
            index += 1;
            continue;
        }
        if byte == b'.' {
            push_token(compiled, Token::new(KIND_ANY))?;
            index += 1;
            continue;
        }
        if byte == b'*' {
            if !extended && compiled.token_count == 0 {
                push_token(compiled, literal_token(byte, ignore_case))?;
            } else {
                apply_repetition(compiled, REPEAT_ZERO_OR_MORE)?;
            }
            index += 1;
            continue;
        }
        if extended && (byte == b'+' || byte == b'?') {
            apply_repetition(
                compiled,
                if byte == b'+' {
                    REPEAT_ONE_OR_MORE
                } else {
                    REPEAT_ZERO_OR_ONE
                },
            )?;
            index += 1;
            continue;
        }
        if extended
            && (byte == b'(' || byte == b')' || byte == b'|' || byte == b'{' || byte == b'}')
        {
            return Err(REG_BADPAT);
        }

        push_token(compiled, literal_token(byte, ignore_case))?;
        index += 1;
    }
    Ok(())
}

#[inline]
fn publish_earlier(slot: &mut u16, start_code: u16) {
    if *slot == 0 || start_code < *slot {
        *slot = start_code;
    }
}

unsafe fn byte_matches(
    token: &Token,
    input: *const u8,
    position: usize,
    input_length: usize,
    newline: bool,
) -> bool {
    if position == input_length {
        return false;
    }
    // SAFETY: position is strictly below the established input length.
    let byte = unsafe { *input.add(position) };
    if token.kind == KIND_ANY {
        return !newline || byte != b'\n';
    }
    let contained = token.contains(byte);
    if token.negated != 0 {
        (!newline || byte != b'\n') && !contained
    } else {
        contained
    }
}

unsafe fn execute(
    compiled: &CompiledRegex,
    input: *const c_char,
    input_length: usize,
    execution_flags: c_int,
) -> Option<(usize, usize)> {
    let bytes = input.cast::<u8>();
    let newline = compiled.flags & REG_NEWLINE != 0;
    let not_bol = execution_flags & REG_NOTBOL != 0;
    let not_eol = execution_flags & REG_NOTEOL != 0;
    let mut current = [0u16; MAX_INPUT_BYTES + 1];
    let mut next = [0u16; MAX_INPUT_BYTES + 1];

    for position in 0..=input_length {
        current[position] = (position + 1) as u16;
    }

    for token_index in 0..compiled.token_count {
        for slot in &mut next[..=input_length] {
            *slot = 0;
        }
        let token = &compiled.tokens[token_index];

        if token.kind == KIND_BOL || token.kind == KIND_EOL {
            for position in 0..=input_length {
                let start_code = current[position];
                if start_code == 0 {
                    continue;
                }
                let assertion_matches = if token.kind == KIND_BOL {
                    (position == 0 && !not_bol)
                        || (newline
                            && position > 0
                            && unsafe { *bytes.add(position - 1) } == b'\n')
                } else {
                    (position == input_length && !not_eol)
                        || (newline
                            && position < input_length
                            && unsafe { *bytes.add(position) } == b'\n')
                };
                if assertion_matches {
                    publish_earlier(&mut next[position], start_code);
                }
            }
        } else {
            match token.repetition {
                REPEAT_ONE => {
                    for position in 0..input_length {
                        let start_code = current[position];
                        if start_code != 0
                            && unsafe {
                                byte_matches(token, bytes, position, input_length, newline)
                            }
                        {
                            publish_earlier(&mut next[position + 1], start_code);
                        }
                    }
                }
                REPEAT_ZERO_OR_ONE => {
                    for position in 0..=input_length {
                        let start_code = current[position];
                        if start_code == 0 {
                            continue;
                        }
                        publish_earlier(&mut next[position], start_code);
                        if position < input_length
                            && unsafe {
                                byte_matches(token, bytes, position, input_length, newline)
                            }
                        {
                            publish_earlier(&mut next[position + 1], start_code);
                        }
                    }
                }
                REPEAT_ZERO_OR_MORE => {
                    next[..=input_length].copy_from_slice(&current[..=input_length]);
                    for position in 0..input_length {
                        let start_code = next[position];
                        if start_code != 0
                            && unsafe {
                                byte_matches(token, bytes, position, input_length, newline)
                            }
                        {
                            publish_earlier(&mut next[position + 1], start_code);
                        }
                    }
                }
                REPEAT_ONE_OR_MORE => {
                    for position in 0..input_length {
                        let start_code = current[position];
                        if start_code != 0
                            && unsafe {
                                byte_matches(token, bytes, position, input_length, newline)
                            }
                        {
                            publish_earlier(&mut next[position + 1], start_code);
                        }
                    }
                    for position in 0..input_length {
                        let start_code = next[position];
                        if start_code != 0
                            && unsafe {
                                byte_matches(token, bytes, position, input_length, newline)
                            }
                        {
                            publish_earlier(&mut next[position + 1], start_code);
                        }
                    }
                }
                _ => return None,
            }
        }
        core::mem::swap(&mut current, &mut next);
    }

    let mut earliest = u16::MAX;
    for start_code in &current[..=input_length] {
        if *start_code != 0 && *start_code < earliest {
            earliest = *start_code;
        }
    }
    if earliest == u16::MAX {
        return None;
    }
    let mut longest_end = 0usize;
    for (position, start_code) in current[..=input_length].iter().enumerate() {
        if *start_code == earliest {
            longest_end = position;
        }
    }
    Some((usize::from(earliest - 1), longest_end))
}

/// Compile one expression from the selected bounded byte grammar.
///
/// # Safety
///
/// `expression` must be a readable NUL-terminated C string. `compiled_regex`
/// must point to writable, aligned `regex_t` storage that is not concurrently
/// accessed until this function returns. A successful object must eventually
/// be passed once to [`regfree`] after its last concurrent execution.
#[no_mangle]
pub unsafe extern "C" fn regcomp(
    compiled_regex: *mut Regex,
    expression: *const c_char,
    flags: c_int,
) -> c_int {
    if compiled_regex.is_null() || expression.is_null() || flags & !0x0f != 0 {
        return REG_BADPAT;
    }
    // SAFETY: the caller supplies one writable regex_t record.
    unsafe {
        core::ptr::write_bytes(
            compiled_regex.cast::<u8>(),
            0,
            core::mem::size_of::<Regex>(),
        );
    }
    let pattern_length = match unsafe {
        bounded_c_string_length(expression, MAX_PATTERN_BYTES)
    } {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mapped = unsafe { map_compiled_regex() };
    if mapped.is_null() {
        return REG_ESPACE;
    }
    // SAFETY: anonymous mappings are zero-filled, aligned, and large enough
    // for CompiledRegex by the compile-time assertion above.
    let compiled = unsafe { &mut *mapped };
    compiled.mapping_bytes = COMPILED_MAPPING_BYTES;
    compiled.flags = flags;
    if let Err(error) = unsafe {
        compile_pattern(compiled, expression, pattern_length, flags)
    } {
        unsafe { unmap_compiled_regex(mapped) };
        return error;
    }
    compiled.magic = COMPILED_MAGIC;
    unsafe {
        (*compiled_regex).re_nsub = 0;
        (*compiled_regex).opaque = mapped.cast::<c_void>();
    }
    REG_OK
}

/// Execute a successfully compiled selected expression.
///
/// # Safety
///
/// `compiled_regex` must refer to a live object produced successfully by
/// [`regcomp`], `string` must be a readable NUL-terminated C string, and when
/// `match_count` is nonzero `matches` must designate that many writable,
/// aligned `regmatch_t` records unless `REG_NOSUB` was used. The caller must
/// exclude concurrent [`regfree`] of the compiled object.
#[no_mangle]
pub unsafe extern "C" fn regexec(
    compiled_regex: *const Regex,
    string: *const c_char,
    match_count: usize,
    matches: *mut RegMatch,
    execution_flags: c_int,
) -> c_int {
    if compiled_regex.is_null() || string.is_null() || execution_flags & !0x03 != 0 {
        return REG_BADPAT;
    }
    let mapped = unsafe { (*compiled_regex).opaque.cast::<CompiledRegex>() };
    if mapped.is_null() {
        return REG_BADPAT;
    }
    let compiled = unsafe { &*mapped };
    if compiled.magic != COMPILED_MAGIC || compiled.mapping_bytes != COMPILED_MAPPING_BYTES {
        return REG_BADPAT;
    }
    let input_length = match unsafe { bounded_c_string_length(string, MAX_INPUT_BYTES) } {
        Ok(length) => length,
        Err(error) => return error,
    };
    let Some((start, end)) = (unsafe {
        execute(compiled, string, input_length, execution_flags)
    }) else {
        return REG_NOMATCH;
    };

    if compiled.flags & REG_NOSUB == 0 && !matches.is_null() && match_count != 0 {
        unsafe {
            (*matches).rm_so = start as RegOff;
            (*matches).rm_eo = end as RegOff;
            for index in 1..match_count {
                (*matches.add(index)).rm_so = -1;
                (*matches.add(index)).rm_eo = -1;
            }
        }
    }
    REG_OK
}

const ERROR_MESSAGES: [&[u8]; 14] = [
    b"No error\0",
    b"No match\0",
    b"Invalid regexp\0",
    b"Unknown collating element\0",
    b"Unknown character class name\0",
    b"Trailing backslash\0",
    b"Invalid back reference\0",
    b"Missing ']'\0",
    b"Missing ')'\0",
    b"Missing '}'\0",
    b"Invalid contents of {}\0",
    b"Invalid character range\0",
    b"Out of memory\0",
    b"Repetition not preceded by valid expression\0",
];
const UNKNOWN_ERROR: &[u8] = b"Unknown error\0";

/// Render the pinned musl C-locale message for one regex result code.
///
/// # Safety
///
/// When `buffer_size` is nonzero, `buffer` must be null or designate that
/// many writable bytes. `compiled_regex` is ignored, matching musl's ABI.
#[no_mangle]
pub unsafe extern "C" fn regerror(
    error: c_int,
    _compiled_regex: *const Regex,
    buffer: *mut c_char,
    buffer_size: usize,
) -> usize {
    let message = if error >= 0 && (error as usize) < ERROR_MESSAGES.len() {
        ERROR_MESSAGES[error as usize]
    } else {
        UNKNOWN_ERROR
    };
    let required = message.len();
    if !buffer.is_null() && buffer_size != 0 {
        let copy = core::cmp::min(required - 1, buffer_size - 1);
        unsafe {
            core::ptr::copy_nonoverlapping(message.as_ptr(), buffer.cast::<u8>(), copy);
            *buffer.add(copy) = 0;
        }
    }
    required
}

/// Release one successfully compiled selected expression.
///
/// # Safety
///
/// `compiled_regex` must be null or point to writable, aligned `regex_t`
/// storage. Its live mapped object, if any, must have been returned by
/// [`regcomp`], must not already have been freed through an alias, and must
/// have no concurrent [`regexec`] users.
#[no_mangle]
pub unsafe extern "C" fn regfree(compiled_regex: *mut Regex) {
    if compiled_regex.is_null() {
        return;
    }
    let mapped = unsafe { (*compiled_regex).opaque.cast::<CompiledRegex>() };
    unsafe {
        (*compiled_regex).opaque = core::ptr::null_mut();
        (*compiled_regex).re_nsub = 0;
    }
    if !mapped.is_null() {
        let valid = unsafe {
            (*mapped).magic == COMPILED_MAGIC
                && (*mapped).mapping_bytes == COMPILED_MAPPING_BYTES
        };
        if valid {
            unsafe { unmap_compiled_regex(mapped) };
        }
    }
}
