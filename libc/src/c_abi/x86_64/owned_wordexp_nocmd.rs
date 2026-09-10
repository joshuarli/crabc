// Private Linux/x86-64 `WRDE_NOCMD` lexical preflight.
//
// This starts at musl 1.2.6 release commit
// `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
// `src/misc/wordexp.c::do_wordexp` lines 43-83 (MIT license; source SHA-256
// `018c97c999cb60966a0376b71f2c8c187179ef31cf5ddde47b959e8f440e08f8`).
// Musl's compact `sq`/`dq`/`np` preflight is the source mapping for the
// ordinary top-level `WRDE_BADCHAR` and `WRDE_CMDSUB` decisions. It cannot
// distinguish a real nested parameter expansion from a literal brace, and
// its one global parenthesis counter can be contaminated by parameter text.
//
// The target-local correction below keeps a small *lexical* stack instead of
// becoming a shell evaluator. A parameter WORD inherits outer double-quote
// context; a #/##/%/%% pattern owns its own local quote context; an arithmetic
// expansion owns its own delimiter count; and `$'...'` owns its escaped quote
// terminator. Thus a child cannot consume a delimiter from its parent. The
// stack has an inline fast path and spills through the selected C allocator,
// so valid nesting is not limited by a private fixed depth. It deliberately
// does not implement `WRDE_UNDEF`, shell expansion, or shell error typing.
//
// POSIX line continuation is removed before recognition outside single and
// dollar-single quoting. This is required before looking for `${`, `$(`,
// `$((`, and an arithmetic `))`; merely skipping a byte after `$` could let a
// physical `$\\\n(` reach the shell as an unchecked command substitution.
// Dollar-single contents stay opaque because continuation behavior there is
// not used as a portable scanner contract.
//
// Inclusion site: `owned_wordexp.rs`, which provides `c_char`, `c_int`,
// `cabi_realloc`, `cabi_free`, `size_of`, `ptr`, and the `WRDE_*` constants.

const NOCMD_INLINE_FRAMES: usize = 8;

const FRAME_SHELL: u8 = 1;
const FRAME_PARAMETER: u8 = 2;
const FRAME_ARITHMETIC: u8 = 3;

const QUOTE_NONE: u8 = 0;
const QUOTE_SINGLE: u8 = 1;
const QUOTE_DOUBLE: u8 = 2;
const QUOTE_DOLLAR_SINGLE: u8 = 3;

const PARAM_NAME: u8 = 0;
const PARAM_AFTER_COLON: u8 = 1;
const PARAM_WORD: u8 = 2;
const PARAM_PATTERN: u8 = 3;

const NAME_START: u8 = 0;
const NAME_IDENTIFIER: u8 = 1;
const NAME_SPECIAL: u8 = 2;
const NAME_LENGTH_PREFIX: u8 = 3;

#[derive(Clone, Copy)]
struct NocmdFrame {
    kind: u8,
    quote: u8,
    parameter_phase: u8,
    name_state: u8,
    inherited_double: bool,
    arithmetic_depth: usize,
}

const SHELL_FRAME: NocmdFrame = NocmdFrame {
    kind: FRAME_SHELL,
    quote: QUOTE_NONE,
    parameter_phase: PARAM_NAME,
    name_state: NAME_START,
    inherited_double: false,
    arithmetic_depth: 0,
};

const fn parameter_frame(inherited_double: bool) -> NocmdFrame {
    NocmdFrame {
        kind: FRAME_PARAMETER,
        quote: QUOTE_NONE,
        parameter_phase: PARAM_NAME,
        name_state: NAME_START,
        inherited_double,
        arithmetic_depth: 0,
    }
}

const fn arithmetic_frame() -> NocmdFrame {
    NocmdFrame {
        kind: FRAME_ARITHMETIC,
        quote: QUOTE_NONE,
        parameter_phase: PARAM_NAME,
        name_state: NAME_START,
        // Arithmetic expansion is scanned as-if its contents were double
        // quoted. In particular, an apostrophe cannot hide `$(` or a
        // backtick command substitution.
        inherited_double: true,
        arithmetic_depth: 0,
    }
}

struct NocmdFrames {
    inline: [NocmdFrame; NOCMD_INLINE_FRAMES],
    heap: *mut NocmdFrame,
    length: usize,
    capacity: usize,
}

impl NocmdFrames {
    const fn new() -> Self {
        Self {
            inline: [SHELL_FRAME; NOCMD_INLINE_FRAMES],
            heap: ptr::null_mut(),
            length: 1,
            capacity: NOCMD_INLINE_FRAMES,
        }
    }

    unsafe fn frame(&self, index: usize) -> NocmdFrame {
        // SAFETY: callers use an initialized index below `length`. A stack
        // either uses its initialized inline storage or its complete copied
        // heap storage after the first spill.
        unsafe {
            if self.heap.is_null() {
                ptr::read(self.inline.as_ptr().add(index))
            } else {
                ptr::read(self.heap.add(index))
            }
        }
    }

    unsafe fn top(&self) -> NocmdFrame {
        // SAFETY: construction leaves the shell frame present and pop never
        // removes it, so `length - 1` is a live frame.
        unsafe { self.frame(self.length - 1) }
    }

    unsafe fn replace_top(&mut self, frame: NocmdFrame) {
        let index = self.length - 1;
        // SAFETY: `index` is the initialized top frame. No raw reference is
        // retained across allocator calls; this writes only after any spill.
        unsafe {
            if self.heap.is_null() {
                ptr::write(self.inline.as_mut_ptr().add(index), frame);
            } else {
                ptr::write(self.heap.add(index), frame);
            }
        }
    }

    unsafe fn push(&mut self, frame: NocmdFrame) -> bool {
        if self.length == self.capacity {
            let doubled = match self.capacity.checked_mul(2) {
                Some(value) => value,
                None => return false,
            };
            let bytes = match doubled.checked_mul(size_of::<NocmdFrame>()) {
                Some(value) => value,
                None => return false,
            };
            // SAFETY: `heap` is either null for an allocator-owned first
            // allocation or the sole selected-C-allocator allocation. There
            // is intentionally no borrowed frame pointer across realloc.
            let grown = unsafe { cabi_realloc(self.heap.cast(), bytes) }.cast::<NocmdFrame>();
            if grown.is_null() { return false; }
            if self.heap.is_null() {
                // SAFETY: all frames through `length` are initialized inline,
                // and `grown` reserves the doubled capacity.
                unsafe {
                    ptr::copy_nonoverlapping(self.inline.as_ptr(), grown, self.length);
                }
            }
            self.heap = grown;
            self.capacity = doubled;
        }
        // SAFETY: growth above makes `length` a writable slot in the selected
        // backing allocation. The new frame contains no interior reference.
        unsafe {
            if self.heap.is_null() {
                ptr::write(self.inline.as_mut_ptr().add(self.length), frame);
            } else {
                ptr::write(self.heap.add(self.length), frame);
            }
        }
        self.length += 1;
        true
    }

    unsafe fn pop(&mut self) {
        // The shell frame is permanent; callers pop only a completed child.
        self.length -= 1;
    }

    unsafe fn release(&mut self) {
        if !self.heap.is_null() {
            // SAFETY: this is the one allocation made through `cabi_realloc`.
            unsafe { cabi_free(self.heap.cast()); }
            self.heap = ptr::null_mut();
        }
    }
}

#[inline]
unsafe fn input_byte(input: *const c_char, index: usize) -> u8 {
    // SAFETY: the public C contract supplies a readable NUL-terminated input;
    // every caller advances only from a non-NUL byte or reads its terminator.
    unsafe { *input.add(index) as u8 }
}

#[inline]
unsafe fn logical_next(input: *const c_char, mut index: usize) -> (u8, usize) {
    loop {
        // SAFETY: `input_byte` observes this C string's next logical byte.
        let byte = unsafe { input_byte(input, index) };
        if byte != b'\\' { return (byte, index); }
        // SAFETY: a successor of this non-NUL backslash exists in the C string.
        if unsafe { input_byte(input, index + 1) } != b'\n' {
            return (byte, index);
        }
        index += 2;
    }
}

#[inline]
unsafe fn skip_line_continuations(input: *const c_char, mut index: usize) -> usize {
    loop {
        // SAFETY: the byte and its successor are read only for a non-NUL
        // backslash in the caller-provided C string.
        if unsafe { input_byte(input, index) } != b'\\' ||
            unsafe { input_byte(input, index + 1) } != b'\n'
        {
            return index;
        }
        index += 2;
    }
}

#[inline]
const fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

#[inline]
const fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

#[inline]
const fn special_parameter(byte: u8) -> bool {
    matches!(byte, b'?' | b'*' | b'@' | b'$' | b'!' | b'-') || byte.is_ascii_digit()
}

#[inline]
const fn parameter_effective_double(frame: NocmdFrame) -> bool {
    frame.parameter_phase == PARAM_WORD &&
        (frame.inherited_double || frame.quote == QUOTE_DOUBLE)
}

#[inline]
const fn effective_double(frame: NocmdFrame) -> bool {
    match frame.kind {
        FRAME_SHELL => frame.quote == QUOTE_DOUBLE,
        FRAME_PARAMETER => parameter_effective_double(frame) ||
            (frame.parameter_phase == PARAM_PATTERN && frame.quote == QUOTE_DOUBLE),
        FRAME_ARITHMETIC => true,
        _ => false,
    }
}

#[inline]
const fn dollar_single_allowed(frame: NocmdFrame) -> bool {
    frame.quote == QUOTE_NONE && match frame.kind {
        FRAME_SHELL => true,
        FRAME_PARAMETER => (frame.parameter_phase == PARAM_WORD && !frame.inherited_double) ||
            frame.parameter_phase == PARAM_PATTERN,
        FRAME_ARITHMETIC => false,
        _ => false,
    }
}

#[inline]
const fn unquoted_control(byte: u8) -> bool {
    matches!(byte, b'\n' | b'|' | b'&' | b';' | b'<' | b'>' | b'{' | b'}' | b'(' | b')')
}

#[inline]
const fn double_escape(byte: u8) -> bool {
    matches!(byte, b'$' | b'`' | b'"' | b'\\' | b'\n')
}

unsafe fn parameter_name_step(input: *const c_char, index: usize, frame: &mut NocmdFrame)
    -> Result<usize, c_int>
{
    // SAFETY: the outer scanner has normalized an applicable continuation and
    // supplied the current readable byte.
    let byte = unsafe { input_byte(input, index) };

    match frame.parameter_phase {
        PARAM_NAME => match frame.name_state {
            NAME_START => {
                if byte == b'#' {
                    // `${#name}` is the length form, whereas `${#}` retains
                    // the shell's special parameter spelling. Looking past
                    // physical continuations matches shell tokenization.
                    let (next, _) = unsafe { logical_next(input, index + 1) };
                    frame.name_state = if next == b'}' { NAME_SPECIAL } else { NAME_LENGTH_PREFIX };
                    Ok(index + 1)
                } else if identifier_start(byte) {
                    frame.name_state = NAME_IDENTIFIER;
                    Ok(index + 1)
                } else if special_parameter(byte) {
                    frame.name_state = NAME_SPECIAL;
                    Ok(index + 1)
                } else {
                    Err(WRDE_SYNTAX)
                }
            }
            NAME_LENGTH_PREFIX => {
                if identifier_start(byte) {
                    frame.name_state = NAME_IDENTIFIER;
                    Ok(index + 1)
                } else {
                    Err(WRDE_SYNTAX)
                }
            }
            NAME_IDENTIFIER => {
                if identifier_continue(byte) {
                    Ok(index + 1)
                } else if byte == b'}' {
                    // The outer loop performs the actual pop so the same
                    // delimiter ownership rule is shared by all phases.
                    Ok(index)
                } else if byte == b':' {
                    frame.parameter_phase = PARAM_AFTER_COLON;
                    Ok(index + 1)
                } else if matches!(byte, b'-' | b'+' | b'=' | b'?') {
                    frame.parameter_phase = PARAM_WORD;
                    Ok(index + 1)
                } else if matches!(byte, b'#' | b'%') {
                    frame.parameter_phase = PARAM_PATTERN;
                    Ok(index + 1)
                } else {
                    Err(WRDE_SYNTAX)
                }
            }
            NAME_SPECIAL => {
                if byte == b'}' {
                    Ok(index)
                } else if byte == b':' {
                    frame.parameter_phase = PARAM_AFTER_COLON;
                    Ok(index + 1)
                } else if matches!(byte, b'-' | b'+' | b'=' | b'?') {
                    frame.parameter_phase = PARAM_WORD;
                    Ok(index + 1)
                } else if matches!(byte, b'#' | b'%') {
                    frame.parameter_phase = PARAM_PATTERN;
                    Ok(index + 1)
                } else {
                    Err(WRDE_SYNTAX)
                }
            }
            _ => Err(WRDE_SYNTAX),
        },
        PARAM_AFTER_COLON => {
            if matches!(byte, b'-' | b'+' | b'=' | b'?') {
                frame.parameter_phase = PARAM_WORD;
                Ok(index + 1)
            } else {
                Err(WRDE_SYNTAX)
            }
        }
        _ => Err(WRDE_SYNTAX),
    }
}

unsafe fn wordexp_nocmd_check(input: *const c_char) -> c_int {
    let mut frames = NocmdFrames::new();
    let mut index = 0usize;

    macro_rules! finish {
        ($result:expr) => {{
            // SAFETY: every exit retires the scanner's sole optional selected
            // C allocator allocation before returning to `do_wordexp`.
            unsafe { frames.release(); }
            return $result;
        }};
    }

    loop {
        // SAFETY: the stack permanently contains its shell frame.
        let mut frame = unsafe { frames.top() };
        // SAFETY: `index` stays within the supplied NUL-terminated input.
        let mut byte = unsafe { input_byte(input, index) };

        if byte == 0 {
            if frames.length != 1 || frame.quote != QUOTE_NONE {
                finish!(WRDE_SYNTAX);
            }
            finish!(0);
        }

        if frame.quote == QUOTE_DOLLAR_SINGLE {
            if byte == b'\\' {
                // SAFETY: current non-NUL backslash has a readable successor.
                if unsafe { input_byte(input, index + 1) } == 0 {
                    finish!(WRDE_SYNTAX);
                }
                // Dollar-single contents are opaque: a backslash plus one
                // physical byte cannot expose a lexical delimiter here.
                index += 2;
                continue;
            }
            if byte == b'\'' {
                frame.quote = QUOTE_NONE;
                // SAFETY: this is the live top frame and no allocator call is
                // made while its copied value is in use.
                unsafe { frames.replace_top(frame); }
            }
            index += 1;
            continue;
        }

        if frame.quote != QUOTE_SINGLE {
            // SAFETY: line joining applies outside the two quote forms handled
            // above, before every lexical decision on the current byte.
            index = unsafe { skip_line_continuations(input, index) };
            // SAFETY: continuation removal leaves another byte in this C string.
            byte = unsafe { input_byte(input, index) };
            if byte == 0 {
                if frames.length != 1 || frame.quote != QUOTE_NONE {
                    finish!(WRDE_SYNTAX);
                }
                finish!(0);
            }
        }

        if frame.kind == FRAME_PARAMETER &&
            matches!(frame.parameter_phase, PARAM_NAME | PARAM_AFTER_COLON)
        {
            match unsafe { parameter_name_step(input, index, &mut frame) } {
                Ok(next) if next != index => {
                    // SAFETY: this updates the same copied top frame after a
                    // pure parsing step with no external allocation.
                    unsafe { frames.replace_top(frame); }
                    index = next;
                    continue;
                }
                Ok(_) => {
                    // A completed parameter name leaves its `}` for the one
                    // closing rule below. Keep the current frame copy.
                }
                Err(result) => finish!(result),
            }
        }

        if frame.quote == QUOTE_SINGLE {
            if byte == b'\'' {
                frame.quote = QUOTE_NONE;
                // SAFETY: live top frame update.
                unsafe { frames.replace_top(frame); }
            }
            index += 1;
            continue;
        }

        let in_double = effective_double(frame);

        if byte == b'\\' {
            // SAFETY: current non-NUL backslash has a readable successor.
            let escaped = unsafe { input_byte(input, index + 1) };
            if escaped == 0 { finish!(WRDE_SYNTAX); }
            let parameter_inherited_closer = frame.kind == FRAME_PARAMETER &&
                frame.parameter_phase == PARAM_WORD && frame.inherited_double && escaped == b'}';
            if !in_double || double_escape(escaped) || parameter_inherited_closer {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if byte == b'\'' {
            if !in_double && frame.quote == QUOTE_NONE && frame.kind != FRAME_ARITHMETIC {
                frame.quote = QUOTE_SINGLE;
                // SAFETY: live top frame update.
                unsafe { frames.replace_top(frame); }
            }
            index += 1;
            continue;
        }

        if byte == b'"' {
            if frame.quote == QUOTE_DOUBLE {
                frame.quote = QUOTE_NONE;
                // SAFETY: live top frame update.
                unsafe { frames.replace_top(frame); }
            } else if !in_double && frame.kind != FRAME_ARITHMETIC {
                frame.quote = QUOTE_DOUBLE;
                // SAFETY: live top frame update.
                unsafe { frames.replace_top(frame); }
            }
            // An inner unescaped double quote in an inherited parameter WORD
            // stays ordinary. POSIX leaves that form unspecified; toggling it
            // would incorrectly activate a following apostrophe as a quote.
            index += 1;
            continue;
        }

        if byte == b'$' {
            // SAFETY: logical lookahead performs the same applicable line
            // joining as the outer cursor before token recognition.
            let (next, next_index) = unsafe { logical_next(input, index + 1) };
            if next == b'{' {
                let child = parameter_frame(match frame.kind {
                    FRAME_SHELL => frame.quote == QUOTE_DOUBLE,
                    FRAME_PARAMETER => effective_double(frame),
                    FRAME_ARITHMETIC => true,
                    _ => false,
                });
                // SAFETY: `child` has no interior pointers; `push` may spill
                // only after `frame` was copied out of stack storage.
                if !unsafe { frames.push(child) } { finish!(WRDE_NOSPACE); }
                index = next_index + 1;
                continue;
            }
            if next == b'(' {
                // SAFETY: second logical byte is read from the same C string.
                let (after, after_index) = unsafe { logical_next(input, next_index + 1) };
                if after == b'(' {
                    // SAFETY: child frame is movable and has no borrowed data.
                    if !unsafe { frames.push(arithmetic_frame()) } { finish!(WRDE_NOSPACE); }
                    index = after_index + 1;
                    continue;
                }
                finish!(WRDE_CMDSUB);
            }
            if next == b'\'' && dollar_single_allowed(frame) {
                frame.quote = QUOTE_DOLLAR_SINGLE;
                // SAFETY: live top frame update.
                unsafe { frames.replace_top(frame); }
                index = next_index + 1;
                continue;
            }
            index += 1;
            continue;
        }

        if byte == b'`' { finish!(WRDE_CMDSUB); }

        match frame.kind {
            FRAME_SHELL => {
                if !in_double && unquoted_control(byte) { finish!(WRDE_BADCHAR); }
                index += 1;
            }
            FRAME_PARAMETER => {
                if byte == b'}' && frame.quote == QUOTE_NONE {
                    // SAFETY: this completes only the top parameter frame;
                    // its parent lexical context resumes unchanged.
                    unsafe { frames.pop(); }
                    index += 1;
                    continue;
                }
                if !in_double && unquoted_control(byte) { finish!(WRDE_BADCHAR); }
                index += 1;
            }
            FRAME_ARITHMETIC => {
                if byte == b'(' {
                    let Some(next) = frame.arithmetic_depth.checked_add(1) else {
                        finish!(WRDE_SYNTAX);
                    };
                    frame.arithmetic_depth = next;
                    // SAFETY: live top frame update.
                    unsafe { frames.replace_top(frame); }
                    index += 1;
                    continue;
                }
                if byte == b')' {
                    if frame.arithmetic_depth != 0 {
                        frame.arithmetic_depth -= 1;
                        // SAFETY: live top frame update.
                        unsafe { frames.replace_top(frame); }
                        index += 1;
                        continue;
                    }
                    // SAFETY: this recognizes a logical `))` after line
                    // joining, rather than a physical-byte approximation.
                    let (next, next_index) = unsafe { logical_next(input, index + 1) };
                    if next != b')' { finish!(WRDE_BADCHAR); }
                    // SAFETY: only the arithmetic child is retired.
                    unsafe { frames.pop(); }
                    index = next_index + 1;
                    continue;
                }
                index += 1;
            }
            _ => finish!(WRDE_SYNTAX),
        }
    }
}
