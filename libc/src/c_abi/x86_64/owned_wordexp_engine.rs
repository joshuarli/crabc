//! Private deterministic core for a possible x86 wordexp replacement.
//!
//! The selected owned_wordexp provider still owns the C ABI and its musl shell
//! protocol. This module has no exported symbol and is intentionally not
//! called by that provider. Its contract is in
//! compat/x86_64/owned-wordexp-engine.md.
//!
//! The core recognizes shell-word expressions, keeps command substitutions as
//! opaque source spans, and delegates command/path behavior through private
//! adapters. All variable mutation is call-local. Every growable structure
//! crosses the selected C allocator boundary so valid nesting never depends on
//! a fixed Rust array or recursive Rust call stack.

use core::{ffi::c_void, mem::size_of, ptr, slice};

const NONE: usize = usize::MAX;

const NODE_LITERAL: u8 = 1;
const NODE_PARAMETER: u8 = 2;
const NODE_ARITHMETIC: u8 = 3;
const NODE_COMMAND: u8 = 4;
const NODE_TILDE: u8 = 5;

const NODE_QUOTED: u8 = 1;
const NODE_SINGLE: u8 = 2;
const NODE_DOUBLE: u8 = 4;
const NODE_DOLLAR_SINGLE: u8 = 8;
// Private syntax provenance for pieces of a `${parameter operator word}`.
// It preserves the parameter delimiter's special double-quote backslash rule
// without changing the outer parameter expansion's result quoting.
const NODE_PARAMETER_WORD: u8 = 16;

const PARAM_IDENTIFIER: u8 = 1;
const PARAM_POSITIONAL: u8 = 2;
const PARAM_SPECIAL: u8 = 3;

const PARAM_NONE: u8 = 0;
const PARAM_DEFAULT: u8 = 1;
const PARAM_ALTERNATE: u8 = 2;
const PARAM_ASSIGN: u8 = 3;
const PARAM_ERROR: u8 = 4;
const PARAM_REMOVE_PREFIX: u8 = 5;
const PARAM_REMOVE_LONGEST_PREFIX: u8 = 6;
const PARAM_REMOVE_SUFFIX: u8 = 7;
const PARAM_REMOVE_LONGEST_SUFFIX: u8 = 8;

const PARAM_COLON: u8 = 1;

const SCAN_PARAMETER: u8 = 1;
const SCAN_ARITHMETIC: u8 = 2;
const SCAN_COMMAND: u8 = 3;
const SCAN_BACKTICK: u8 = 4;

const QUOTE_NONE: u8 = 0;
const QUOTE_SINGLE: u8 = 1;
const QUOTE_DOUBLE: u8 = 2;
const QUOTE_DOLLAR_SINGLE: u8 = 3;

// The opaque command scanner needs only enough lexical structure to keep
// compound-command delimiters from closing an enclosing `$()`. These are
// movable lexer scopes, not a command execution AST: they retain no command,
// argument, redirection, or execution data.
const COMMAND_SCOPE_ROOT: u8 = 1;
const COMMAND_SCOPE_SUBSHELL: u8 = 2;
const COMMAND_SCOPE_BRACE: u8 = 3;
const COMMAND_SCOPE_CASE: u8 = 4;
const COMMAND_SCOPE_FOR: u8 = 5;
const COMMAND_SCOPE_FUNCTION: u8 = 6;
const COMMAND_SCOPE_IF: u8 = 7;
const COMMAND_SCOPE_WHILE: u8 = 8;
const COMMAND_SCOPE_UNTIL: u8 = 9;

const COMMAND_PHASE_BODY: u8 = 0;
const CASE_PHASE_WORD: u8 = 1;
const CASE_PHASE_IN: u8 = 2;
const CASE_PHASE_PATTERN: u8 = 3;
const CASE_PHASE_BODY: u8 = 4;
const FOR_PHASE_NAME: u8 = 5;
const FOR_PHASE_AFTER_NAME: u8 = 6;
const FOR_PHASE_WORDS: u8 = 7;
const FOR_PHASE_BODY: u8 = 8;
const FUNCTION_PHASE_CLOSE: u8 = 9;
const FUNCTION_PHASE_COMPOUND_BODY: u8 = 10;
const IF_PHASE_CONDITION: u8 = 11;
const IF_PHASE_BODY: u8 = 12;
const LOOP_PHASE_CONDITION: u8 = 13;
const LOOP_PHASE_BODY: u8 = 14;

/// Candidate-local semantic failures. The C ABI mapping remains a later
/// provider-integration decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WordexpError {
    NoSpace,
    Syntax,
    BadCharacter,
    CommandSubstitution,
    UndefinedVariable,
    ParameterError,
    Arithmetic,
    ArithmeticOverflow,
    OutputNul,
}

unsafe extern "C" {
    #[link_name = "realloc"]
    fn wordexp_engine_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn wordexp_engine_free(pointer: *mut c_void);
    #[link_name = "malloc"]
    fn wordexp_engine_malloc(size: usize) -> *mut c_void;
}

/// Move-only, C-allocator-backed storage for Copy records. It has no inline
/// capacity: a parser or evaluator grows until the selected allocator fails.
struct HeapVec<T: Copy> {
    pointer: *mut T,
    length: usize,
    capacity: usize,
}

impl<T: Copy> HeapVec<T> {
    const fn new() -> Self {
        Self { pointer: ptr::null_mut(), length: 0, capacity: 0 }
    }

    #[inline]
    fn len(&self) -> usize { self.length }

    #[inline]
    fn is_empty(&self) -> bool { self.length == 0 }

    unsafe fn get(&self, index: usize) -> T {
        debug_assert!(index < self.length);
        // SAFETY: callers prove the initialized index is below length.
        unsafe { ptr::read(self.pointer.add(index)) }
    }

    unsafe fn replace(&mut self, index: usize, value: T) {
        debug_assert!(index < self.length);
        // SAFETY: callers prove the initialized index is below length.
        unsafe { ptr::write(self.pointer.add(index), value); }
    }

    fn push(&mut self, value: T) -> Result<(), WordexpError> {
        if self.length == self.capacity {
            let capacity = if self.capacity == 0 { 8 } else {
                self.capacity.checked_mul(2).ok_or(WordexpError::NoSpace)?
            };
            let bytes = capacity.checked_mul(size_of::<T>()).ok_or(WordexpError::NoSpace)?;
            // SAFETY: realloc accepts the allocation owned by this vector, or
            // null for its first allocation.
            let grown = unsafe { wordexp_engine_realloc(self.pointer.cast(), bytes) }.cast::<T>();
            if grown.is_null() { return Err(WordexpError::NoSpace); }
            self.pointer = grown;
            self.capacity = capacity;
        }
        // SAFETY: growth reserves the slot at length.
        unsafe { ptr::write(self.pointer.add(self.length), value); }
        self.length += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        if self.length == 0 { return None; }
        self.length -= 1;
        // SAFETY: the old final slot was initialized and transfers out.
        Some(unsafe { ptr::read(self.pointer.add(self.length)) })
    }

    fn truncate(&mut self, length: usize) {
        debug_assert!(length <= self.length);
        self.length = length;
    }

    unsafe fn as_slice(&self) -> &[T] {
        if self.length == 0 {
            &[]
        } else {
            // SAFETY: a nonempty vector owns length initialized records.
            unsafe { slice::from_raw_parts(self.pointer, self.length) }
        }
    }
}

impl<T: Copy> Drop for HeapVec<T> {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: this object exclusively owns this C allocation.
            unsafe { wordexp_engine_free(self.pointer.cast()); }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    const fn empty(at: usize) -> Self { Self { start: at, end: at } }
    #[inline]
    const fn len(self) -> usize { self.end - self.start }
}

#[derive(Clone, Copy)]
struct SyntaxWord {
    first: usize,
    last: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct SyntaxNode {
    kind: u8,
    flags: u8,
    span: Span,
    payload: usize,
    next: usize,
}

#[derive(Clone, Copy)]
struct Parameter {
    name: Span,
    word: usize,
    kind: u8,
    length: bool,
    operator: u8,
    flags: u8,
}

#[derive(Clone, Copy)]
struct Arithmetic {
    word: usize,
}

#[derive(Clone, Copy)]
struct Command {
    body: Span,
    style: CommandStyle,
}

/// The spelling that introduced an opaque command substitution. The process
/// adapter receives the raw body plus the outer double-quote context needed
/// for POSIX backtick backslash handling; it must not reinterpret or preflight
/// the command body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandStyle {
    DollarParen,
    Backtick { double_quoted: bool },
}

/// The four POSIX parameter substring-pattern operations. Keeping this
/// boundary typed avoids making the sibling pathname adapter duplicate the
/// parser's private tag values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParameterPatternOperator {
    RemovePrefix,
    RemoveLongestPrefix,
    RemoveSuffix,
    RemoveLongestSuffix,
}

#[derive(Clone, Copy)]
struct PendingWord {
    parameter: usize,
    source: Span,
    inherited_flags: u8,
    mode: SyntaxMode,
}

#[derive(Clone, Copy)]
struct ParameterHeader {
    name: Span,
    kind: u8,
    length: bool,
    operator: u8,
    flags: u8,
    word_start: usize,
}

impl ParameterHeader {
    #[inline]
    const fn is_pattern_operand(self) -> bool {
        matches!(
            self.operator,
            PARAM_REMOVE_PREFIX | PARAM_REMOVE_LONGEST_PREFIX |
            PARAM_REMOVE_SUFFIX | PARAM_REMOVE_LONGEST_SUFFIX
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SyntaxMode {
    ShellWord,
    ArithmeticSource,
}

#[derive(Clone, Copy)]
struct PendingArithmetic {
    arithmetic: usize,
    source: Span,
}

/// Parsed input with source-owned spans. It is private so later C ABI
/// ownership and status mapping remain deliberate.
pub(super) struct WordexpSyntax {
    source: HeapVec<u8>,
    words: HeapVec<SyntaxWord>,
    roots: HeapVec<usize>,
    nodes: HeapVec<SyntaxNode>,
    parameters: HeapVec<Parameter>,
    arithmetic: HeapVec<Arithmetic>,
    commands: HeapVec<Command>,
    contains_command: bool,
}

impl WordexpSyntax {
    pub(super) fn parse(input: &[u8]) -> Result<Self, WordexpError> {
        if input.iter().any(|byte| *byte == 0) {
            return Err(WordexpError::OutputNul);
        }
        let mut syntax = Self {
            source: HeapVec::new(),
            words: HeapVec::new(),
            roots: HeapVec::new(),
            nodes: HeapVec::new(),
            parameters: HeapVec::new(),
            arithmetic: HeapVec::new(),
            commands: HeapVec::new(),
            contains_command: false,
        };
        for byte in input {
            syntax.source.push(*byte)?;
        }
        let mut parser = SyntaxParser {
            syntax: &mut syntax,
            pending_words: HeapVec::new(),
            pending_arithmetic: HeapVec::new(),
        };
        parser.parse_roots()?;
        loop {
            if let Some(pending) = parser.pending_words.pop() {
                let word = match pending.mode {
                    SyntaxMode::ShellWord => {
                        parser.parse_word(pending.source, false, pending.inherited_flags)?
                    }
                    SyntaxMode::ArithmeticSource => {
                        parser.parse_arithmetic_word(pending.source)?
                    }
                };
                // SAFETY: pending is created after its parameter was appended.
                let mut parameter = unsafe { parser.syntax.parameters.get(pending.parameter) };
                parameter.word = word;
                unsafe { parser.syntax.parameters.replace(pending.parameter, parameter); }
                continue;
            }
            let Some(pending) = parser.pending_arithmetic.pop() else { break; };
            let word = parser.parse_arithmetic_word(pending.source)?;
            // SAFETY: pending is created after its arithmetic record exists.
            let mut arithmetic = unsafe { parser.syntax.arithmetic.get(pending.arithmetic) };
            arithmetic.word = word;
            unsafe { parser.syntax.arithmetic.replace(pending.arithmetic, arithmetic); }
        }
        Ok(syntax)
    }

    #[inline]
    fn source_len(&self) -> usize { self.source.len() }

    unsafe fn byte(&self, index: usize) -> u8 {
        debug_assert!(index < self.source.len());
        // SAFETY: parser spans are checked against copied input.
        unsafe { self.source.get(index) }
    }

    unsafe fn bytes(&self, span: Span) -> &[u8] {
        debug_assert!(span.start <= span.end && span.end <= self.source.len());
        if span.len() == 0 { return &[]; }
        // SAFETY: span is within source and has nonzero length.
        unsafe { slice::from_raw_parts(self.source.pointer.add(span.start), span.len()) }
    }

    #[inline]
    fn has_commands(&self) -> bool { self.contains_command }

    unsafe fn word(&self, index: usize) -> SyntaxWord {
        // SAFETY: caller supplies a syntax-created word id.
        unsafe { self.words.get(index) }
    }

    unsafe fn node(&self, index: usize) -> SyntaxNode {
        // SAFETY: caller reaches this id from a syntax word.
        unsafe { self.nodes.get(index) }
    }

    unsafe fn parameter(&self, index: usize) -> Parameter {
        // SAFETY: a parameter node payload names this vector.
        unsafe { self.parameters.get(index) }
    }

    unsafe fn arithmetic(&self, index: usize) -> Arithmetic {
        // SAFETY: an arithmetic node payload names this vector.
        unsafe { self.arithmetic.get(index) }
    }

    unsafe fn command(&self, index: usize) -> Command {
        // SAFETY: a command node payload names this vector.
        unsafe { self.commands.get(index) }
    }
}

struct SyntaxParser<'a> {
    syntax: &'a mut WordexpSyntax,
    pending_words: HeapVec<PendingWord>,
    pending_arithmetic: HeapVec<PendingArithmetic>,
}

impl SyntaxParser<'_> {
    unsafe fn byte(&self, index: usize) -> u8 {
        // SAFETY: every parser cursor is checked against source length.
        unsafe { self.syntax.byte(index) }
    }

    /// Shell lexical line joining is local to word grammar. Opaque command
    /// bodies retain their original bytes for the command adapter.
    fn skip_line_continuations(&self, mut index: usize, end: usize) -> usize {
        while index + 1 < end &&
            unsafe { self.byte(index) } == b'\\' &&
            unsafe { self.byte(index + 1) } == b'\n'
        {
            index += 2;
        }
        index
    }

    fn new_word(&mut self) -> Result<usize, WordexpError> {
        let index = self.syntax.words.len();
        self.syntax.words.push(SyntaxWord { first: NONE, last: NONE, end: 0 })?;
        Ok(index)
    }

    fn append_node(&mut self, word: usize, node: SyntaxNode) -> Result<(), WordexpError> {
        let index = self.syntax.nodes.len();
        self.syntax.nodes.push(node)?;
        // SAFETY: word was created by new_word and only this parser changes
        // the linked node endpoints while it parses that word.
        let mut record = unsafe { self.syntax.words.get(word) };
        if record.first == NONE {
            record.first = index;
        } else {
            // SAFETY: a nonempty word always has one initialized final node.
            let mut last = unsafe { self.syntax.nodes.get(record.last) };
            last.next = index;
            unsafe { self.syntax.nodes.replace(record.last, last); }
        }
        record.last = index;
        unsafe { self.syntax.words.replace(word, record); }
        Ok(())
    }

    fn append_literal(
        &mut self,
        word: usize,
        span: Span,
        flags: u8,
        force_empty: bool,
    ) -> Result<(), WordexpError> {
        if span.len() != 0 || force_empty {
            self.append_node(word, SyntaxNode {
                kind: NODE_LITERAL, flags, span, payload: NONE, next: NONE,
            })?;
        }
        Ok(())
    }

    fn set_word_end(&mut self, word: usize, end: usize) {
        // SAFETY: word is still owned by this parser.
        let mut record = unsafe { self.syntax.words.get(word) };
        record.end = end;
        unsafe { self.syntax.words.replace(word, record); }
    }

    fn parse_roots(&mut self) -> Result<(), WordexpError> {
        let mut index = 0usize;
        while index < self.syntax.source_len() {
            // SAFETY: loop condition bounds this source read.
            let byte = unsafe { self.byte(index) };
            if matches!(byte, b' ' | b'\t') {
                index += 1;
                continue;
            }
            if byte == b'\n' || unquoted_control(byte) {
                return Err(WordexpError::BadCharacter);
            }
            let word = self.parse_word(
                Span { start: index, end: self.syntax.source_len() },
                true,
                0,
            )?;
            self.syntax.roots.push(word)?;
            // SAFETY: parse_word initializes its final cursor.
            index = unsafe { self.syntax.word(word) }.end;
        }
        Ok(())
    }

    /// Parse one shell-word source range. The outer form ends at unquoted
    /// space/tab; a parameter WORD consumes the entire supplied range.
    fn parse_word(
        &mut self,
        range: Span,
        outer: bool,
        inherited_flags: u8,
    ) -> Result<usize, WordexpError> {
        let word = self.new_word()?;
        let mut index = range.start;
        let mut at_start = true;
        while index < range.end {
            // SAFETY: range is created only from copied-source bounds.
            let byte = unsafe { self.byte(index) };
            if outer && matches!(byte, b' ' | b'\t') { break; }
            if outer && (byte == b'\n' || unquoted_control(byte)) {
                return Err(WordexpError::BadCharacter);
            }
            if byte == b'\'' && inherited_flags & NODE_DOUBLE == 0 {
                let after = scan_simple_quote(self.syntax, index + 1)?;
                if after > range.end { return Err(WordexpError::Syntax); }
                self.append_literal(
                    word,
                    Span { start: index + 1, end: after - 1 },
                    inherited_flags | NODE_QUOTED | NODE_SINGLE,
                    true,
                )?;
                index = after;
                at_start = false;
                continue;
            }
            if byte == b'"' {
                index = self.parse_double(word, index + 1, range.end, inherited_flags)?;
                at_start = false;
                continue;
            }
            if byte == b'$' {
                let after = self.parse_dollar(
                    word,
                    index,
                    range.end,
                    inherited_flags,
                    SyntaxMode::ShellWord,
                )?;
                if after != index {
                    index = after;
                    at_start = false;
                    continue;
                }
                // A dollar not followed by a recognized expansion is literal.
                // Consume it here rather than sending it to consume_literal,
                // whose expansion boundary intentionally stops before '$'.
                self.append_literal(
                    word,
                    Span { start: index, end: index + 1 },
                    inherited_flags,
                    false,
                )?;
                index += 1;
                at_start = false;
                continue;
            }
            if byte == b'\x60' {
                let (body, after, contains_command) =
                    scan_construct(self.syntax, SCAN_BACKTICK, index + 1, false)?;
                if after > range.end { return Err(WordexpError::Syntax); }
                self.syntax.contains_command |= contains_command;
                let command = self.syntax.commands.len();
                self.syntax.commands.push(Command {
                    body,
                    style: CommandStyle::Backtick {
                        double_quoted: inherited_flags & NODE_DOUBLE != 0,
                    },
                })?;
                self.append_node(word, SyntaxNode {
                    kind: NODE_COMMAND, flags: inherited_flags, span: body,
                    payload: command, next: NONE,
                })?;
                index = after;
                at_start = false;
                continue;
            }
            if byte == b'~' && at_start && inherited_flags == 0 {
                let mut end = index + 1;
                while end < range.end {
                    // SAFETY: range bound guards this read.
                    let next = unsafe { self.byte(end) };
                    if matches!(next, b'/' | b'\'' | b'"' | b'$' | b'\x60' | b'\\') ||
                        (outer && matches!(next, b' ' | b'\t'))
                    {
                        break;
                    }
                    end += 1;
                }
                self.append_node(word, SyntaxNode {
                    kind: NODE_TILDE, flags: 0, span: Span { start: index + 1, end },
                    payload: NONE, next: NONE,
                })?;
                index = end;
                at_start = false;
                continue;
            }
            let start = index;
            index = self.consume_literal(index, range.end, outer, inherited_flags)?;
            self.append_literal(word, Span { start, end: index }, inherited_flags, false)?;
            at_start = false;
        }
        self.set_word_end(word, index);
        Ok(word)
    }

    /// Parse an arithmetic-expansion body as an expansion source. POSIX
    /// treats this source as if it were double-quoted, except its inner quote
    /// characters remain arithmetic bytes. It therefore recognizes only the
    /// expansion forms needed to produce those bytes; it never treats tilde,
    /// field splitting, or pathname patterns as arithmetic-source syntax.
    fn parse_arithmetic_word(&mut self, range: Span) -> Result<usize, WordexpError> {
        let word = self.new_word()?;
        let flags = NODE_QUOTED | NODE_DOUBLE;
        let mut index = range.start;
        let mut literal_start = index;
        while index < range.end {
            // SAFETY: range comes from a checked source span.
            let byte = unsafe { self.byte(index) };
            if byte == b'\\' {
                if index + 1 >= range.end { return Err(WordexpError::Syntax); }
                // SAFETY: the preceding bound makes this source read valid.
                let next = unsafe { self.byte(index + 1) };
                if matches!(next, b'$' | b'\x60' | b'"' | b'\\' | b'\n') {
                    self.append_literal(
                        word,
                        Span { start: literal_start, end: index },
                        flags,
                        false,
                    )?;
                    if next != b'\n' {
                        self.append_literal(
                            word,
                            Span { start: index + 1, end: index + 2 },
                            flags,
                            false,
                        )?;
                    }
                    index += 2;
                    literal_start = index;
                    continue;
                }
                // A double-quote-context backslash before any other byte
                // remains literal. Its following byte cannot begin an
                // expansion that needs separate handling.
                index += 2;
                continue;
            }
            if byte == b'$' {
                self.append_literal(
                    word,
                    Span { start: literal_start, end: index },
                    flags,
                    false,
                )?;
                let after = self.parse_dollar(
                    word,
                    index,
                    range.end,
                    flags,
                    SyntaxMode::ArithmeticSource,
                )?;
                if after == index {
                    self.append_literal(
                        word,
                        Span { start: index, end: index + 1 },
                        flags,
                        false,
                    )?;
                    index += 1;
                } else {
                    index = after;
                }
                literal_start = index;
                continue;
            }
            if byte == b'\x60' {
                self.append_literal(
                    word,
                    Span { start: literal_start, end: index },
                    flags,
                    false,
                )?;
                let (body, after, contains_command) =
                    scan_construct(self.syntax, SCAN_BACKTICK, index + 1, false)?;
                if after > range.end { return Err(WordexpError::Syntax); }
                self.syntax.contains_command |= contains_command;
                let command = self.syntax.commands.len();
                self.syntax.commands.push(Command {
                    body,
                    // Arithmetic source is parsed as if double-quoted.
                    style: CommandStyle::Backtick { double_quoted: true },
                })?;
                self.append_node(word, SyntaxNode {
                    kind: NODE_COMMAND,
                    flags,
                    span: body,
                    payload: command,
                    next: NONE,
                })?;
                index = after;
                literal_start = index;
                continue;
            }
            index += 1;
        }
        self.append_literal(
            word,
            Span { start: literal_start, end: range.end },
            flags,
            false,
        )?;
        self.set_word_end(word, range.end);
        Ok(word)
    }

    fn consume_literal(
        &self,
        mut index: usize,
        end: usize,
        outer: bool,
        inherited_flags: u8,
    ) -> Result<usize, WordexpError> {
        while index < end {
            // SAFETY: loop condition bounds the source read.
            let byte = unsafe { self.byte(index) };
            if byte == b'\\' {
                if index + 1 >= end { return Err(WordexpError::Syntax); }
                index += 2;
                continue;
            }
            if (byte == b'\'' && inherited_flags & NODE_DOUBLE == 0) ||
                matches!(byte, b'"' | b'$' | b'\x60') ||
                (outer && matches!(byte, b' ' | b'\t'))
            {
                break;
            }
            if outer && (byte == b'\n' || unquoted_control(byte)) {
                return Err(WordexpError::BadCharacter);
            }
            index += 1;
        }
        Ok(index)
    }

    fn parse_double(
        &mut self,
        word: usize,
        mut index: usize,
        end: usize,
        inherited_flags: u8,
    ) -> Result<usize, WordexpError> {
        let flags = inherited_flags | NODE_QUOTED | NODE_DOUBLE;
        let mut literal_start = index;
        while index < end {
            // SAFETY: loop condition bounds the source read.
            let byte = unsafe { self.byte(index) };
            if byte == b'"' {
                self.append_literal(
                    word,
                    Span { start: literal_start, end: index },
                    flags,
                    true,
                )?;
                return Ok(index + 1);
            }
            if byte == b'\\' {
                if index + 1 >= end { return Err(WordexpError::Syntax); }
                index += 2;
                continue;
            }
            if byte == b'$' || byte == b'\x60' {
                self.append_literal(
                    word,
                    Span { start: literal_start, end: index },
                    flags,
                    false,
                )?;
                if byte == b'$' {
                    let after = self.parse_dollar(
                        word,
                        index,
                        end,
                        flags,
                        SyntaxMode::ShellWord,
                    )?;
                    if after != index {
                        index = after;
                        literal_start = index;
                        continue;
                    }
                } else {
                    let (body, after, contains_command) =
                        scan_construct(self.syntax, SCAN_BACKTICK, index + 1, false)?;
                    if after > end { return Err(WordexpError::Syntax); }
                    self.syntax.contains_command |= contains_command;
                    let command = self.syntax.commands.len();
                    self.syntax.commands.push(Command {
                        body,
                        style: CommandStyle::Backtick { double_quoted: true },
                    })?;
                    self.append_node(word, SyntaxNode {
                        kind: NODE_COMMAND, flags, span: body, payload: command, next: NONE,
                    })?;
                    index = after;
                    literal_start = index;
                    continue;
                }
            }
            index += 1;
        }
        Err(WordexpError::Syntax)
    }

    fn parse_dollar(
        &mut self,
        word: usize,
        index: usize,
        end: usize,
        flags: u8,
        mode: SyntaxMode,
    ) -> Result<usize, WordexpError> {
        let after_dollar = self.skip_line_continuations(index + 1, end);
        if after_dollar >= end { return Ok(index); }
        // SAFETY: the joined cursor is below the passed end bound.
        let next = unsafe { self.byte(after_dollar) };
        if next == b'{' {
            let parameter_outer_double = parameter_scan_outer_double(
                self.syntax,
                after_dollar + 1,
                flags & NODE_DOUBLE != 0,
            )?;
            let (inside, after, contains_command) =
                scan_construct(
                    self.syntax, SCAN_PARAMETER, after_dollar + 1, parameter_outer_double,
                )?;
            if after > end { return Err(WordexpError::Syntax); }
            self.syntax.contains_command |= contains_command;
            let parameter = self.parse_parameter(inside, flags, mode)?;
            self.append_node(word, SyntaxNode {
                kind: NODE_PARAMETER, flags, span: inside, payload: parameter, next: NONE,
            })?;
            return Ok(after);
        }
        if next == b'(' {
            if after_dollar + 1 < end && unsafe { self.byte(after_dollar + 1) } == b'(' {
                let (body, after, contains_command) =
                    scan_construct(self.syntax, SCAN_ARITHMETIC, after_dollar + 2, false)?;
                if after > end { return Err(WordexpError::Syntax); }
                self.syntax.contains_command |= contains_command;
                let arithmetic = self.syntax.arithmetic.len();
                self.syntax.arithmetic.push(Arithmetic { word: NONE })?;
                self.pending_arithmetic.push(PendingArithmetic {
                    arithmetic,
                    source: body,
                })?;
                self.append_node(word, SyntaxNode {
                    kind: NODE_ARITHMETIC, flags, span: body, payload: arithmetic, next: NONE,
                })?;
                return Ok(after);
            }
            let (body, after, contains_command) =
                scan_construct(self.syntax, SCAN_COMMAND, after_dollar + 1, false)?;
            if after > end { return Err(WordexpError::Syntax); }
            self.syntax.contains_command |= contains_command;
            let command = self.syntax.commands.len();
            self.syntax.commands.push(Command { body, style: CommandStyle::DollarParen })?;
            self.append_node(word, SyntaxNode {
                kind: NODE_COMMAND, flags, span: body, payload: command, next: NONE,
            })?;
            return Ok(after);
        }
        if next == b'\'' && flags & NODE_DOUBLE == 0 {
            let after = scan_dollar_single(self.syntax, after_dollar + 1)?;
            if after > end { return Err(WordexpError::Syntax); }
            self.append_literal(
                word,
                Span { start: after_dollar + 1, end: after - 1 },
                flags | NODE_QUOTED | NODE_DOLLAR_SINGLE,
                true,
            )?;
            return Ok(after);
        }
        let mut name_end = after_dollar;
        let kind;
        if identifier_start(next) {
            name_end += 1;
            while name_end < end && identifier_continue(unsafe { self.byte(name_end) }) {
                name_end += 1;
            }
            kind = PARAM_IDENTIFIER;
        } else if next.is_ascii_digit() {
            name_end += 1;
            while name_end < end && unsafe { self.byte(name_end) }.is_ascii_digit() {
                name_end += 1;
            }
            kind = PARAM_POSITIONAL;
        } else if special_parameter(next) {
            name_end += 1;
            kind = PARAM_SPECIAL;
        } else {
            return Ok(index);
        }
        let parameter = self.syntax.parameters.len();
        self.syntax.parameters.push(Parameter {
            name: Span { start: after_dollar, end: name_end },
            word: NONE,
            kind,
            length: false,
            operator: PARAM_NONE,
            flags: 0,
        })?;
        self.append_node(word, SyntaxNode {
            kind: NODE_PARAMETER,
            flags,
            span: Span { start: index, end: name_end },
            payload: parameter,
            next: NONE,
        })?;
        Ok(name_end)
    }

    fn parse_parameter(
        &mut self,
        inside: Span,
        inherited_flags: u8,
        mode: SyntaxMode,
    ) -> Result<usize, WordexpError> {
        let header = parse_parameter_header(self.syntax, inside.start, inside.end, true)?;
        let parameter = self.syntax.parameters.len();
        self.syntax.parameters.push(Parameter {
            name: header.name,
            word: NONE,
            kind: header.kind,
            length: header.length,
            operator: header.operator,
            flags: header.flags,
        })?;
        if header.operator != PARAM_NONE {
            // The outer parameter node keeps `inherited_flags` for result
            // quoting. A substring-pattern operand instead sees ordinary
            // shell-word syntax, so only quotes written inside its braces
            // suppress pattern metacharacters.
            let operand_flags = if header.is_pattern_operand() {
                (inherited_flags & !(NODE_QUOTED | NODE_DOUBLE)) | NODE_PARAMETER_WORD
            } else {
                inherited_flags | NODE_PARAMETER_WORD
            };
            self.pending_words.push(PendingWord {
                parameter,
                source: Span { start: header.word_start, end: inside.end },
                inherited_flags: operand_flags,
                mode: if header.is_pattern_operand() {
                    SyntaxMode::ShellWord
                } else {
                    mode
                },
            })?;
        }
        Ok(parameter)
    }
}

fn skip_parameter_line_continuations(
    syntax: &WordexpSyntax,
    mut index: usize,
    end: usize,
) -> usize {
    while index + 1 < end &&
        // SAFETY: the loop condition bounds both source reads.
        unsafe { syntax.byte(index) } == b'\\' &&
        unsafe { syntax.byte(index + 1) } == b'\n'
    {
        index += 2;
    }
    index
}

/// Parse only the fixed parameter header. The delimiter scanner uses the
/// non-strict form before it knows the matching `}` so it can choose the
/// correct outer-double-quote rule for the operand. The word parser then uses
/// the strict form on that exact bounded span, keeping header interpretation
/// in one place.
fn parse_parameter_header(
    syntax: &WordexpSyntax,
    start: usize,
    end: usize,
    strict: bool,
) -> Result<ParameterHeader, WordexpError> {
    if start >= end { return Err(WordexpError::Syntax); }
    let mut index = skip_parameter_line_continuations(syntax, start, end);
    if index >= end { return Err(WordexpError::Syntax); }
    // SAFETY: index is below the checked source bound.
    let first = unsafe { syntax.byte(index) };
    let (name, kind, length);
    if first == b'#' {
        index += 1;
        if index < end && identifier_start(unsafe { syntax.byte(index) }) {
            let name_start = index;
            index += 1;
            while index < end && identifier_continue(unsafe { syntax.byte(index) }) {
                index += 1;
            }
            name = Span { start: name_start, end: index };
            kind = PARAM_IDENTIFIER;
            length = true;
        } else if index < end && unsafe { syntax.byte(index) }.is_ascii_digit() {
            let name_start = index;
            index += 1;
            while index < end && unsafe { syntax.byte(index) }.is_ascii_digit() {
                index += 1;
            }
            name = Span { start: name_start, end: index };
            kind = PARAM_POSITIONAL;
            length = true;
        } else if index < end && special_parameter(unsafe { syntax.byte(index) }) {
            name = Span { start: index, end: index + 1 };
            kind = PARAM_SPECIAL;
            length = true;
            index += 1;
        } else {
            name = Span { start, end: start + 1 };
            kind = PARAM_SPECIAL;
            length = true;
            index = start + 1;
        }
    } else if identifier_start(first) {
        let name_start = index;
        index += 1;
        while index < end && identifier_continue(unsafe { syntax.byte(index) }) {
            index += 1;
        }
        name = Span { start: name_start, end: index };
        kind = PARAM_IDENTIFIER;
        length = false;
    } else if first.is_ascii_digit() {
        let name_start = index;
        index += 1;
        while index < end && unsafe { syntax.byte(index) }.is_ascii_digit() {
            index += 1;
        }
        name = Span { start: name_start, end: index };
        kind = PARAM_POSITIONAL;
        length = false;
    } else if special_parameter(first) {
        name = Span { start: index, end: index + 1 };
        index += 1;
        kind = PARAM_SPECIAL;
        length = false;
    } else {
        return Err(WordexpError::Syntax);
    }

    index = skip_parameter_line_continuations(syntax, index, end);
    let mut flags = 0u8;
    if index < end && unsafe { syntax.byte(index) } == b':' {
        flags |= PARAM_COLON;
        index += 1;
    }
    index = skip_parameter_line_continuations(syntax, index, end);
    let mut operator = PARAM_NONE;
    if index < end {
        // SAFETY: index is below the checked source bound.
        operator = match unsafe { syntax.byte(index) } {
            b'-' => PARAM_DEFAULT,
            b'+' => PARAM_ALTERNATE,
            b'=' => PARAM_ASSIGN,
            b'?' => PARAM_ERROR,
            b'#' => {
                index += 1;
                if index < end && unsafe { syntax.byte(index) } == b'#' {
                    index += 1;
                    PARAM_REMOVE_LONGEST_PREFIX
                } else {
                    PARAM_REMOVE_PREFIX
                }
            }
            b'%' => {
                index += 1;
                if index < end && unsafe { syntax.byte(index) } == b'%' {
                    index += 1;
                    PARAM_REMOVE_LONGEST_SUFFIX
                } else {
                    PARAM_REMOVE_SUFFIX
                }
            }
            _ if strict => return Err(WordexpError::Syntax),
            _ => PARAM_NONE,
        };
        if !matches!(
            operator,
            PARAM_NONE | PARAM_REMOVE_PREFIX | PARAM_REMOVE_LONGEST_PREFIX |
            PARAM_REMOVE_SUFFIX | PARAM_REMOVE_LONGEST_SUFFIX
        ) {
            index += 1;
        }
    } else if flags != 0 {
        return Err(WordexpError::Syntax);
    }
    let word_start = skip_parameter_line_continuations(syntax, index, end);
    Ok(ParameterHeader { name, kind, length, operator, flags, word_start })
}

fn parameter_scan_outer_double(
    syntax: &WordexpSyntax,
    body_start: usize,
    outer_double: bool,
) -> Result<bool, WordexpError> {
    if !outer_double { return Ok(false); }
    let header = parse_parameter_header(syntax, body_start, syntax.source_len(), false)?;
    Ok(!header.is_pattern_operand())
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
    matches!(byte, b'?' | b'*' | b'@' | b'$' | b'!' | b'-' | b'#')
}

#[inline]
const fn unquoted_control(byte: u8) -> bool {
    matches!(byte, b'|' | b'&' | b';' | b'<' | b'>' | b'{' | b'}' | b'(' | b')')
}

#[derive(Clone, Copy)]
struct ScanFrame {
    kind: u8,
    quote: u8,
    // An enclosing double quote remains active through an ordinary parameter
    // operand, but not through a `#`/`%` pattern operand.
    parameter_outer_double: bool,
    arithmetic_depth: usize,
    scope_start: usize,
    token_start: usize,
    word_start: bool,
    heredoc_start: usize,
    heredoc_next: usize,
}

impl ScanFrame {
    const fn new(
        kind: u8,
        heredoc_start: usize,
        scope_start: usize,
        parameter_outer_double: bool,
    ) -> Self {
        Self {
            kind,
            quote: QUOTE_NONE,
            parameter_outer_double,
            arithmetic_depth: 0,
            scope_start,
            token_start: NONE,
            word_start: true,
            heredoc_start,
            heredoc_next: heredoc_start,
        }
    }
}

#[derive(Clone, Copy)]
struct CommandScope {
    kind: u8,
    phase: u8,
    command_position: bool,
    for_list_boundary: bool,
    case_after_delimiter: bool,
    case_pattern_started: bool,
    // The offset is a sentinel-backed candidate, retained across blanks so
    // `name ()` is recognized as the same function definition as `name()`.
    function_name_candidate_end: usize,
}

impl CommandScope {
    const fn new(kind: u8, phase: u8, command_position: bool) -> Self {
        Self {
            kind,
            phase,
            command_position,
            for_list_boundary: false,
            case_after_delimiter: false,
            case_pattern_started: false,
            function_name_candidate_end: NONE,
        }
    }

    const fn root() -> Self {
        Self::new(COMMAND_SCOPE_ROOT, COMMAND_PHASE_BODY, true)
    }

    const fn subshell() -> Self {
        Self::new(COMMAND_SCOPE_SUBSHELL, COMMAND_PHASE_BODY, true)
    }

    const fn brace() -> Self {
        Self::new(COMMAND_SCOPE_BRACE, COMMAND_PHASE_BODY, true)
    }

    const fn case() -> Self {
        Self::new(COMMAND_SCOPE_CASE, CASE_PHASE_WORD, false)
    }

    const fn for_loop() -> Self {
        Self::new(COMMAND_SCOPE_FOR, FOR_PHASE_NAME, false)
    }

    const fn function() -> Self {
        Self::new(COMMAND_SCOPE_FUNCTION, FUNCTION_PHASE_CLOSE, false)
    }

    const fn if_command() -> Self {
        Self::new(COMMAND_SCOPE_IF, IF_PHASE_CONDITION, true)
    }

    const fn while_loop() -> Self {
        Self::new(COMMAND_SCOPE_WHILE, LOOP_PHASE_CONDITION, true)
    }

    const fn until_loop() -> Self {
        Self::new(COMMAND_SCOPE_UNTIL, LOOP_PHASE_CONDITION, true)
    }
}

#[derive(Clone, Copy)]
struct HereDoc {
    delimiter: Span,
    strip_tabs: bool,
}

fn scan_simple_quote(syntax: &WordexpSyntax, mut index: usize) -> Result<usize, WordexpError> {
    while index < syntax.source_len() {
        // SAFETY: loop condition bounds the read.
        if unsafe { syntax.byte(index) } == b'\'' { return Ok(index + 1); }
        index += 1;
    }
    Err(WordexpError::Syntax)
}

fn scan_dollar_single(
    syntax: &WordexpSyntax,
    mut index: usize,
) -> Result<usize, WordexpError> {
    while index < syntax.source_len() {
        // SAFETY: loop condition bounds the read.
        let byte = unsafe { syntax.byte(index) };
        if byte == b'\\' {
            if index + 1 >= syntax.source_len() { return Err(WordexpError::Syntax); }
            index += 2;
            continue;
        }
        if byte == b'\'' { return Ok(index + 1); }
        index += 1;
    }
    Err(WordexpError::Syntax)
}

#[inline]
const fn command_boundary(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')')
}

// `{` and `}` are reserved words only when the scanner sees a whole lexical
// token. In particular, `{missing` starts an ordinary command word instead of
// a brace group. `word_start` proves the preceding boundary; this lookahead
// proves the following boundary without retaining a command AST.
fn brace_control_word(
    syntax: &WordexpSyntax,
    frame: &ScanFrame,
    index: usize,
) -> bool {
    if !frame.word_start { return false; }
    let after = index + 1;
    if after >= syntax.source_len() { return true; }
    // SAFETY: the preceding length check bounds this one-byte lookahead.
    command_boundary(unsafe { syntax.byte(after) })
}

fn assignment_word(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !identifier_start(bytes[0]) { return false; }
    let mut index = 1usize;
    while index < bytes.len() && identifier_continue(bytes[index]) {
        index += 1;
    }
    index < bytes.len() && bytes[index] == b'='
}

fn command_control_word(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"if" | b"then" | b"elif" | b"else" | b"fi" | b"while" | b"until" |
        b"do" | b"done"
    )
}

fn identifier_word(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !identifier_start(bytes[0]) { return false; }
    let mut index = 1usize;
    while index < bytes.len() {
        if !identifier_continue(bytes[index]) { return false; }
        index += 1;
    }
    true
}

fn current_command_scope(
    scopes: &HeapVec<CommandScope>,
    frame: &ScanFrame,
) -> Result<(usize, CommandScope), WordexpError> {
    if frame.kind != SCAN_COMMAND || frame.scope_start == NONE ||
        scopes.len() <= frame.scope_start
    {
        return Err(WordexpError::Syntax);
    }
    let index = scopes.len() - 1;
    // SAFETY: the frame owns its root scope and every nested scope is above it.
    Ok((index, unsafe { scopes.get(index) }))
}

#[inline]
const fn scope_accepts_commands(scope: CommandScope) -> bool {
    matches!(
        scope.kind,
        COMMAND_SCOPE_ROOT |
        COMMAND_SCOPE_SUBSHELL |
        COMMAND_SCOPE_BRACE |
        COMMAND_SCOPE_IF |
        COMMAND_SCOPE_WHILE |
        COMMAND_SCOPE_UNTIL
    ) ||
    (scope.kind == COMMAND_SCOPE_CASE && scope.phase == CASE_PHASE_BODY) ||
    (scope.kind == COMMAND_SCOPE_FOR && scope.phase == FOR_PHASE_BODY)
}

// Begin a compound command only at a reserved-word position. A function
// definition is different: after `name ()`, its body is itself one compound
// command, so the pending function marker becomes that body's delimiter scope
// instead of becoming its parent. This remains lexical bookkeeping; no command
// or redirection tree is retained.
fn begin_compound_command(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
    child: CommandScope,
) -> Result<(), WordexpError> {
    let (scope_index, mut scope) = current_command_scope(scopes, frame)?;
    if scope.kind == COMMAND_SCOPE_FUNCTION {
        if scope.phase != FUNCTION_PHASE_COMPOUND_BODY { return Err(WordexpError::Syntax); }
        // SAFETY: scope_index identifies the pending function-body marker.
        unsafe { scopes.replace(scope_index, child); }
        return Ok(());
    }
    if !scope_accepts_commands(scope) || !scope.command_position {
        return Err(WordexpError::Syntax);
    }
    scope.command_position = false;
    scope.function_name_candidate_end = NONE;
    // SAFETY: scope_index identifies the command containing the child scope.
    unsafe { scopes.replace(scope_index, scope); }
    scopes.push(child)
}

fn complete_command_scope(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
) -> Result<(), WordexpError> {
    let completed = scopes.pop().ok_or(WordexpError::Syntax)?;
    if completed.kind == COMMAND_SCOPE_ROOT || scopes.len() <= frame.scope_start {
        return Err(WordexpError::Syntax);
    }
    let parent_index = scopes.len() - 1;
    // SAFETY: the completed lexical scope leaves its owning command scope live.
    let mut parent = unsafe { scopes.get(parent_index) };
    if !scope_accepts_commands(parent) { return Err(WordexpError::Syntax); }
    parent.command_position = false;
    parent.function_name_candidate_end = NONE;
    // SAFETY: parent_index is below the current live scope length.
    unsafe { scopes.replace(parent_index, parent); }
    Ok(())
}

fn command_separator(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
    byte: u8,
) -> Result<(), WordexpError> {
    let (scope_index, mut scope) = current_command_scope(scopes, frame)?;
    if scope.kind == COMMAND_SCOPE_FOR &&
        matches!(scope.phase, FOR_PHASE_AFTER_NAME | FOR_PHASE_WORDS)
    {
        if matches!(byte, b';' | b'\n') { scope.for_list_boundary = true; }
    } else if scope_accepts_commands(scope) {
        scope.command_position = true;
        scope.function_name_candidate_end = NONE;
    }
    // SAFETY: scope_index identifies the current top lexical scope.
    unsafe { scopes.replace(scope_index, scope); }
    Ok(())
}

fn begin_case_pattern(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
) -> Result<bool, WordexpError> {
    let (scope_index, mut scope) = current_command_scope(scopes, frame)?;
    if scope.kind != COMMAND_SCOPE_CASE || scope.phase != CASE_PHASE_BODY {
        return Ok(false);
    }
    scope.phase = CASE_PHASE_PATTERN;
    scope.command_position = true;
    scope.case_after_delimiter = true;
    scope.case_pattern_started = false;
    scope.function_name_candidate_end = NONE;
    // SAFETY: scope_index identifies the current top lexical scope.
    unsafe { scopes.replace(scope_index, scope); }
    Ok(true)
}

fn finish_command_token(
    syntax: &WordexpSyntax,
    frame: &mut ScanFrame,
    scopes: &mut HeapVec<CommandScope>,
    end: usize,
) -> Result<(), WordexpError> {
    if frame.token_start == NONE { return Ok(()); }
    let token = Span { start: frame.token_start, end };
    frame.token_start = NONE;
    // SAFETY: token starts and ends at the current bounded command source.
    let bytes = unsafe { syntax.bytes(token) };
    let (scope_index, mut scope) = current_command_scope(scopes, frame)?;

    if scope.kind == COMMAND_SCOPE_CASE {
        match scope.phase {
            CASE_PHASE_WORD => {
                scope.phase = CASE_PHASE_IN;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            CASE_PHASE_IN => {
                if bytes != b"in" { return Err(WordexpError::Syntax); }
                scope.phase = CASE_PHASE_PATTERN;
                scope.command_position = true;
                scope.case_after_delimiter = false;
                scope.case_pattern_started = false;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            CASE_PHASE_PATTERN => {
                // `esac` ends an empty case immediately after `in`, and it
                // ends the case after a final `;;`. Once a pattern has begun,
                // the same bytes remain pattern data; an optional leading `(`
                // records that distinction before its token is scanned.
                if bytes == b"esac" &&
                    (!scope.case_pattern_started || scope.case_after_delimiter)
                {
                    return complete_command_scope(scopes, frame);
                }
                scope.case_pattern_started = true;
                scope.case_after_delimiter = false;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            CASE_PHASE_BODY => {
                if scope.command_position && bytes == b"esac" {
                    return complete_command_scope(scopes, frame);
                }
            }
            _ => return Err(WordexpError::Syntax),
        }
    }

    if scope.kind == COMMAND_SCOPE_FOR {
        match scope.phase {
            FOR_PHASE_NAME => {
                scope.phase = FOR_PHASE_AFTER_NAME;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            FOR_PHASE_AFTER_NAME => {
                if bytes == b"in" {
                    scope.phase = FOR_PHASE_WORDS;
                    scope.for_list_boundary = false;
                } else if bytes == b"do" {
                    scope.phase = FOR_PHASE_BODY;
                    scope.command_position = true;
                } else {
                    return Err(WordexpError::Syntax);
                }
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            FOR_PHASE_WORDS => {
                if bytes == b"do" && scope.for_list_boundary {
                    scope.phase = FOR_PHASE_BODY;
                    scope.command_position = true;
                    scope.function_name_candidate_end = NONE;
                }
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            FOR_PHASE_BODY => {
                if scope.command_position && bytes == b"done" {
                    return complete_command_scope(scopes, frame);
                }
            }
            _ => return Err(WordexpError::Syntax),
        }
    }

    if scope.kind == COMMAND_SCOPE_IF && scope.command_position {
        match bytes {
            b"then" => {
                scope.phase = IF_PHASE_BODY;
                scope.function_name_candidate_end = NONE;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            b"elif" => {
                scope.phase = IF_PHASE_CONDITION;
                scope.function_name_candidate_end = NONE;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            b"else" => {
                scope.phase = IF_PHASE_BODY;
                scope.function_name_candidate_end = NONE;
                // SAFETY: scope_index identifies the current top lexical scope.
                unsafe { scopes.replace(scope_index, scope); }
                return Ok(());
            }
            b"fi" => return complete_command_scope(scopes, frame),
            _ => {}
        }
    }

    if matches!(scope.kind, COMMAND_SCOPE_WHILE | COMMAND_SCOPE_UNTIL) &&
        scope.command_position
    {
        if bytes == b"do" {
            scope.phase = LOOP_PHASE_BODY;
            scope.function_name_candidate_end = NONE;
            // SAFETY: scope_index identifies the current top lexical scope.
            unsafe { scopes.replace(scope_index, scope); }
            return Ok(());
        }
        if bytes == b"done" && scope.phase == LOOP_PHASE_BODY {
            return complete_command_scope(scopes, frame);
        }
    }

    if scope.kind == COMMAND_SCOPE_FUNCTION {
        let body = match bytes {
            b"case" => CommandScope::case(),
            b"for" => CommandScope::for_loop(),
            b"if" => CommandScope::if_command(),
            b"while" => CommandScope::while_loop(),
            b"until" => CommandScope::until_loop(),
            _ => return Err(WordexpError::Syntax),
        };
        return begin_compound_command(scopes, frame, body);
    }

    if !scope_accepts_commands(scope) { return Err(WordexpError::Syntax); }
    if !scope.command_position {
        scope.function_name_candidate_end = NONE;
        // SAFETY: scope_index identifies the current top lexical scope.
        unsafe { scopes.replace(scope_index, scope); }
        return Ok(());
    }
    if bytes == b"case" {
        begin_compound_command(scopes, frame, CommandScope::case())?;
    } else if bytes == b"for" {
        begin_compound_command(scopes, frame, CommandScope::for_loop())?;
    } else if bytes == b"if" {
        begin_compound_command(scopes, frame, CommandScope::if_command())?;
    } else if bytes == b"while" {
        begin_compound_command(scopes, frame, CommandScope::while_loop())?;
    } else if bytes == b"until" {
        begin_compound_command(scopes, frame, CommandScope::until_loop())?;
    } else if bytes == b"!" || command_control_word(bytes) || assignment_word(bytes) {
        scope.command_position = true;
        scope.function_name_candidate_end = NONE;
        // SAFETY: scope_index identifies the current top lexical scope.
        unsafe { scopes.replace(scope_index, scope); }
    } else {
        scope.command_position = false;
        scope.function_name_candidate_end = if identifier_word(bytes) { end } else { NONE };
        // SAFETY: scope_index identifies the current top lexical scope.
        unsafe { scopes.replace(scope_index, scope); }
    }
    Ok(())
}

fn open_command_parenthesis(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
) -> Result<(), WordexpError> {
    let (scope_index, mut scope) = current_command_scope(scopes, frame)?;
    if scope.kind == COMMAND_SCOPE_CASE && scope.phase == CASE_PHASE_PATTERN {
        // POSIX permits an optional opening parenthesis before each case
        // pattern. It is a pattern delimiter, not a subshell opener.
        scope.case_pattern_started = true;
        scope.case_after_delimiter = false;
        // SAFETY: scope_index identifies the current top lexical scope.
        unsafe { scopes.replace(scope_index, scope); }
        return Ok(());
    }
    if scope.function_name_candidate_end != NONE {
        scopes.push(CommandScope::function())?;
    } else if scope.kind == COMMAND_SCOPE_FUNCTION &&
        scope.phase == FUNCTION_PHASE_COMPOUND_BODY
    {
        // A function body may be a subshell compound command. Replace the
        // pending function marker so this matching `)` completes the body and
        // returns directly to the surrounding command scope.
        scope.kind = COMMAND_SCOPE_SUBSHELL;
        scope.phase = COMMAND_PHASE_BODY;
        scope.command_position = true;
        scope.function_name_candidate_end = NONE;
        // SAFETY: scope_index identifies the pending function-body marker.
        unsafe { scopes.replace(scope_index, scope); }
    } else if scope.kind != COMMAND_SCOPE_FUNCTION {
        // Retaining a parenthesized lexical scope is deliberately more
        // permissive than command validation. This scanner owns delimiters,
        // not a shell execution grammar.
        scopes.push(CommandScope::subshell())?;
    } else {
        return Err(WordexpError::Syntax);
    }
    Ok(())
}

fn open_command_brace(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
) -> Result<bool, WordexpError> {
    let (scope_index, mut scope) = current_command_scope(scopes, frame)?;
    if scope.kind == COMMAND_SCOPE_FUNCTION && scope.phase == FUNCTION_PHASE_COMPOUND_BODY {
        scope.kind = COMMAND_SCOPE_BRACE;
        scope.phase = COMMAND_PHASE_BODY;
        scope.command_position = true;
        scope.function_name_candidate_end = NONE;
        // SAFETY: scope_index identifies the current top lexical scope.
        unsafe { scopes.replace(scope_index, scope); }
        return Ok(true);
    }
    if !scope_accepts_commands(scope) || !scope.command_position {
        return Ok(false);
    }
    scope.command_position = false;
    scope.function_name_candidate_end = NONE;
    // SAFETY: scope_index identifies the current top lexical scope.
    unsafe { scopes.replace(scope_index, scope); }
    scopes.push(CommandScope::brace())?;
    Ok(true)
}

fn close_command_brace(
    scopes: &mut HeapVec<CommandScope>,
    frame: &ScanFrame,
) -> Result<bool, WordexpError> {
    let (_, scope) = current_command_scope(scopes, frame)?;
    if scope.kind != COMMAND_SCOPE_BRACE { return Ok(false); }
    complete_command_scope(scopes, frame)?;
    Ok(true)
}

fn parse_here_doc(
    syntax: &WordexpSyntax,
    mut index: usize,
) -> Result<(HereDoc, usize), WordexpError> {
    let mut strip_tabs = false;
    if index < syntax.source_len() && unsafe { syntax.byte(index) } == b'-' {
        strip_tabs = true;
        index += 1;
    }
    while index < syntax.source_len() && matches!(unsafe { syntax.byte(index) }, b' ' | b'\t') {
        index += 1;
    }
    let start = index;
    let mut quote = QUOTE_NONE;
    while index < syntax.source_len() {
        // SAFETY: loop condition bounds the read.
        let byte = unsafe { syntax.byte(index) };
        if quote == QUOTE_SINGLE {
            if byte == b'\'' { quote = QUOTE_NONE; }
            index += 1;
            continue;
        }
        if quote == QUOTE_DOUBLE {
            if byte == b'\\' {
                if index + 1 >= syntax.source_len() { return Err(WordexpError::Syntax); }
                index += 2;
                continue;
            }
            if byte == b'"' { quote = QUOTE_NONE; }
            index += 1;
            continue;
        }
        if byte == b'\\' {
            if index + 1 >= syntax.source_len() { return Err(WordexpError::Syntax); }
            index += 2;
            continue;
        }
        if byte == b'\'' {
            quote = QUOTE_SINGLE;
            index += 1;
            continue;
        }
        if byte == b'"' {
            quote = QUOTE_DOUBLE;
            index += 1;
            continue;
        }
        if command_boundary(byte) { break; }
        index += 1;
    }
    if quote != QUOTE_NONE || index == start {
        return Err(WordexpError::Syntax);
    }
    Ok((HereDoc { delimiter: Span { start, end: index }, strip_tabs }, index))
}

fn here_doc_matches(
    syntax: &WordexpSyntax,
    here: HereDoc,
    mut line_start: usize,
    line_end: usize,
) -> Result<bool, WordexpError> {
    if here.strip_tabs {
        while line_start < line_end && unsafe { syntax.byte(line_start) } == b'\t' {
            line_start += 1;
        }
    }
    let mut source = here.delimiter.start;
    let mut line = line_start;
    let mut quote = QUOTE_NONE;
    while source < here.delimiter.end {
        // SAFETY: delimiter span and line bounds are checked by caller.
        let byte = unsafe { syntax.byte(source) };
        let expected;
        if quote == QUOTE_SINGLE {
            if byte == b'\'' {
                quote = QUOTE_NONE;
                source += 1;
                continue;
            }
            expected = byte;
            source += 1;
        } else if quote == QUOTE_DOUBLE {
            if byte == b'"' {
                quote = QUOTE_NONE;
                source += 1;
                continue;
            }
            if byte == b'\\' {
                source += 1;
                if source == here.delimiter.end { return Err(WordexpError::Syntax); }
                expected = unsafe { syntax.byte(source) };
                source += 1;
            } else {
                expected = byte;
                source += 1;
            }
        } else if byte == b'\'' {
            quote = QUOTE_SINGLE;
            source += 1;
            continue;
        } else if byte == b'"' {
            quote = QUOTE_DOUBLE;
            source += 1;
            continue;
        } else if byte == b'\\' {
            source += 1;
            if source == here.delimiter.end { return Err(WordexpError::Syntax); }
            expected = unsafe { syntax.byte(source) };
            source += 1;
        } else {
            expected = byte;
            source += 1;
        }
        if line == line_end || unsafe { syntax.byte(line) } != expected {
            return Ok(false);
        }
        line += 1;
    }
    if quote != QUOTE_NONE { return Err(WordexpError::Syntax); }
    Ok(line == line_end)
}

fn consume_here_docs(
    syntax: &WordexpSyntax,
    here_docs: &HeapVec<HereDoc>,
    frame: &mut ScanFrame,
    mut index: usize,
) -> Result<usize, WordexpError> {
    while frame.heredoc_next < here_docs.len() {
        let line_start = index;
        while index < syntax.source_len() && unsafe { syntax.byte(index) } != b'\n' {
            index += 1;
        }
        if index == syntax.source_len() { return Err(WordexpError::Syntax); }
        // SAFETY: heredoc records are live from the frame's own queue.
        let here = unsafe { here_docs.get(frame.heredoc_next) };
        if here_doc_matches(syntax, here, line_start, index)? {
            frame.heredoc_next += 1;
        }
        index += 1;
    }
    Ok(index)
}

fn close_scan_frame(
    frames: &mut HeapVec<ScanFrame>,
    here_docs: &mut HeapVec<HereDoc>,
    scopes: &mut HeapVec<CommandScope>,
    closing: usize,
    after: usize,
    root_body: usize,
) -> Result<Option<(Span, usize)>, WordexpError> {
    // SAFETY: called only while one frame exists.
    let frame = frames.pop().ok_or(WordexpError::Syntax)?;
    if frame.heredoc_next != here_docs.len() {
        return Err(WordexpError::Syntax);
    }
    here_docs.truncate(frame.heredoc_start);
    if frame.kind == SCAN_COMMAND {
        if frame.scope_start == NONE || scopes.len() != frame.scope_start + 1 {
            return Err(WordexpError::Syntax);
        }
        scopes.truncate(frame.scope_start);
    }
    if frames.is_empty() {
        Ok(Some((Span { start: root_body, end: closing }, after)))
    } else {
        Ok(None)
    }
}

fn push_scan_frame(
    frames: &mut HeapVec<ScanFrame>,
    scopes: &mut HeapVec<CommandScope>,
    kind: u8,
    heredoc_start: usize,
    parameter_outer_double: bool,
) -> Result<(), WordexpError> {
    let scope_start = if kind == SCAN_COMMAND {
        let start = scopes.len();
        scopes.push(CommandScope::root())?;
        start
    } else {
        NONE
    };
    if let Err(error) = frames.push(ScanFrame::new(
        kind, heredoc_start, scope_start, parameter_outer_double,
    )) {
        if kind == SCAN_COMMAND { scopes.truncate(scope_start); }
        return Err(error);
    }
    Ok(())
}

fn nested_parameter_outer_double(
    syntax: &WordexpSyntax,
    parent: &ScanFrame,
    body_start: usize,
    directly_double_quoted: bool,
) -> Result<bool, WordexpError> {
    let outer_double = directly_double_quoted ||
        (parent.kind == SCAN_PARAMETER && parent.parameter_outer_double) ||
        parent.kind == SCAN_ARITHMETIC;
    parameter_scan_outer_double(syntax, body_start, outer_double)
}

/// Find the complete body of a parameter, arithmetic, command, or backquote
/// construct. Nested constructs use this movable explicit stack rather than
/// calling this routine recursively.
fn scan_construct(
    syntax: &WordexpSyntax,
    initial_kind: u8,
    body_start: usize,
    parameter_outer_double: bool,
) -> Result<(Span, usize, bool), WordexpError> {
    let mut frames = HeapVec::<ScanFrame>::new();
    let mut here_docs = HeapVec::<HereDoc>::new();
    let mut scopes = HeapVec::<CommandScope>::new();
    let mut contains_command = matches!(initial_kind, SCAN_COMMAND | SCAN_BACKTICK);
    push_scan_frame(
        &mut frames, &mut scopes, initial_kind, 0, parameter_outer_double,
    )?;
    let mut index = body_start;
    loop {
        if index >= syntax.source_len() { return Err(WordexpError::Syntax); }
        let top = frames.len() - 1;
        // SAFETY: at least the initial frame is live until a successful close.
        let mut frame = unsafe { frames.get(top) };
        // SAFETY: cursor is bounded by the check at loop start.
        let byte = unsafe { syntax.byte(index) };

        if frame.quote == QUOTE_SINGLE {
            if byte == b'\'' { frame.quote = QUOTE_NONE; }
            unsafe { frames.replace(top, frame); }
            index += 1;
            continue;
        }
        if frame.quote == QUOTE_DOLLAR_SINGLE {
            if byte == b'\\' {
                if index + 1 >= syntax.source_len() { return Err(WordexpError::Syntax); }
                index += 2;
                continue;
            }
            if byte == b'\'' { frame.quote = QUOTE_NONE; }
            unsafe { frames.replace(top, frame); }
            index += 1;
            continue;
        }
        if frame.quote == QUOTE_DOUBLE {
            if byte == b'\\' {
                if index + 1 >= syntax.source_len() { return Err(WordexpError::Syntax); }
                index += 2;
                continue;
            }
            if byte == b'"' {
                frame.quote = QUOTE_NONE;
                unsafe { frames.replace(top, frame); }
                index += 1;
                continue;
            }
            if byte == b'$' && index + 1 < syntax.source_len() {
                // SAFETY: lookahead is below source length.
                let next = unsafe { syntax.byte(index + 1) };
                let child = if next == b'{' {
                    Some((SCAN_PARAMETER, index + 2))
                } else if next == b'(' {
                    if index + 2 < syntax.source_len() &&
                        unsafe { syntax.byte(index + 2) } == b'('
                    {
                        Some((SCAN_ARITHMETIC, index + 3))
                    } else {
                        Some((SCAN_COMMAND, index + 2))
                    }
                } else {
                    None
                };
                if let Some((kind, after_open)) = child {
                    if matches!(kind, SCAN_COMMAND | SCAN_BACKTICK) {
                        contains_command = true;
                    }
                    let parameter_outer_double = if kind == SCAN_PARAMETER {
                        nested_parameter_outer_double(
                            syntax, &frame, after_open, true,
                        )?
                    } else {
                        false
                    };
                    unsafe { frames.replace(top, frame); }
                    push_scan_frame(
                        &mut frames, &mut scopes, kind, here_docs.len(), parameter_outer_double,
                    )?;
                    index = after_open;
                    continue;
                }
            }
            if byte == b'\x60' && frame.kind != SCAN_BACKTICK {
                contains_command = true;
                unsafe { frames.replace(top, frame); }
                push_scan_frame(
                    &mut frames, &mut scopes, SCAN_BACKTICK, here_docs.len(), false,
                )?;
                index += 1;
                continue;
            }
            // A quoted command-body byte cannot start a separator, comment,
            // heredoc, or close the enclosing command substitution.
            unsafe { frames.replace(top, frame); }
            index += 1;
            continue;
        } else {
            if frame.kind == SCAN_COMMAND && frame.word_start && byte == b'#' {
                while index < syntax.source_len() && unsafe { syntax.byte(index) } != b'\n' {
                    index += 1;
                }
                frame.token_start = NONE;
                frame.word_start = true;
                unsafe { frames.replace(top, frame); }
                continue;
            }
            if byte == b'\\' {
                if index + 1 >= syntax.source_len() { return Err(WordexpError::Syntax); }
                if frame.kind == SCAN_COMMAND {
                    frame.word_start = false;
                    if frame.token_start == NONE { frame.token_start = index; }
                    unsafe { frames.replace(top, frame); }
                }
                index += 2;
                continue;
            }
            if byte == b'\'' &&
                !(frame.kind == SCAN_PARAMETER && frame.parameter_outer_double)
            {
                frame.quote = QUOTE_SINGLE;
                frame.word_start = false;
                if frame.kind == SCAN_COMMAND && frame.token_start == NONE {
                    frame.token_start = index;
                }
                unsafe { frames.replace(top, frame); }
                index += 1;
                continue;
            }
            if byte == b'"' {
                frame.quote = QUOTE_DOUBLE;
                frame.word_start = false;
                if frame.kind == SCAN_COMMAND && frame.token_start == NONE {
                    frame.token_start = index;
                }
                unsafe { frames.replace(top, frame); }
                index += 1;
                continue;
            }
            if byte == b'$' && index + 1 < syntax.source_len() {
                // SAFETY: lookahead is below source length.
                let next = unsafe { syntax.byte(index + 1) };
                let child = if next == b'{' {
                    Some((SCAN_PARAMETER, index + 2))
                } else if next == b'(' {
                    if index + 2 < syntax.source_len() &&
                        unsafe { syntax.byte(index + 2) } == b'('
                    {
                        Some((SCAN_ARITHMETIC, index + 3))
                    } else {
                        Some((SCAN_COMMAND, index + 2))
                    }
                } else {
                    None
                };
                if let Some((kind, after_open)) = child {
                    if matches!(kind, SCAN_COMMAND | SCAN_BACKTICK) {
                        contains_command = true;
                    }
                    let parameter_outer_double = if kind == SCAN_PARAMETER {
                        nested_parameter_outer_double(
                            syntax, &frame, after_open, false,
                        )?
                    } else {
                        false
                    };
                    frame.word_start = false;
                    if frame.kind == SCAN_COMMAND && frame.token_start == NONE {
                        frame.token_start = index;
                    }
                    unsafe { frames.replace(top, frame); }
                    push_scan_frame(
                        &mut frames, &mut scopes, kind, here_docs.len(), parameter_outer_double,
                    )?;
                    index = after_open;
                    continue;
                }
                if next == b'\'' && frame.quote != QUOTE_DOUBLE {
                    frame.quote = QUOTE_DOLLAR_SINGLE;
                    frame.word_start = false;
                    if frame.kind == SCAN_COMMAND && frame.token_start == NONE {
                        frame.token_start = index;
                    }
                    unsafe { frames.replace(top, frame); }
                    index += 2;
                    continue;
                }
            }
            if byte == b'\x60' && frame.kind != SCAN_BACKTICK {
                contains_command = true;
                frame.word_start = false;
                if frame.kind == SCAN_COMMAND && frame.token_start == NONE {
                    frame.token_start = index;
                }
                unsafe { frames.replace(top, frame); }
                push_scan_frame(
                    &mut frames, &mut scopes, SCAN_BACKTICK, here_docs.len(), false,
                )?;
                index += 1;
                continue;
            }
        }

        if frame.kind == SCAN_COMMAND {
            if byte == b'<' && index + 1 < syntax.source_len() &&
                unsafe { syntax.byte(index + 1) } == b'<'
            {
                finish_command_token(syntax, &mut frame, &mut scopes, index)?;
                let (here, after) = parse_here_doc(syntax, index + 2)?;
                here_docs.push(here)?;
                frame.word_start = false;
                unsafe { frames.replace(top, frame); }
                index = after;
                continue;
            }
            if byte == b'\n' {
                finish_command_token(syntax, &mut frame, &mut scopes, index)?;
                frame.word_start = true;
                command_separator(&mut scopes, &frame, byte)?;
                let after = consume_here_docs(syntax, &here_docs, &mut frame, index + 1)?;
                unsafe { frames.replace(top, frame); }
                index = after;
                continue;
            }
            let brace_control = matches!(byte, b'{' | b'}') &&
                brace_control_word(syntax, &frame, index);
            if command_boundary(byte) || brace_control {
                let at_word_start = frame.word_start;
                finish_command_token(syntax, &mut frame, &mut scopes, index)?;
                frame.word_start = true;
                if matches!(byte, b';' | b'|' | b'&') {
                    command_separator(&mut scopes, &frame, byte)?;
                }
                if byte == b';' && index + 1 < syntax.source_len() &&
                    unsafe { syntax.byte(index + 1) } == b';' &&
                    begin_case_pattern(&mut scopes, &frame)?
                {
                    unsafe { frames.replace(top, frame); }
                    index += 2;
                    continue;
                }
                if byte == b'{' && at_word_start &&
                    open_command_brace(&mut scopes, &frame)?
                {
                    unsafe { frames.replace(top, frame); }
                    index += 1;
                    continue;
                }
                if byte == b'}' && at_word_start &&
                    close_command_brace(&mut scopes, &frame)?
                {
                    unsafe { frames.replace(top, frame); }
                    index += 1;
                    continue;
                }
            } else {
                if frame.token_start == NONE { frame.token_start = index; }
                frame.word_start = false;
            }
        }

        match frame.kind {
            SCAN_PARAMETER if byte == b'}' => {
                if let Some(done) = close_scan_frame(
                    &mut frames, &mut here_docs, &mut scopes, index, index + 1, body_start,
                )? {
                    return Ok((done.0, done.1, contains_command));
                }
                index += 1;
            }
            SCAN_ARITHMETIC if byte == b'(' => {
                frame.arithmetic_depth = frame.arithmetic_depth
                    .checked_add(1).ok_or(WordexpError::Syntax)?;
                unsafe { frames.replace(top, frame); }
                index += 1;
            }
            SCAN_ARITHMETIC if byte == b')' => {
                if frame.arithmetic_depth != 0 {
                    frame.arithmetic_depth -= 1;
                    unsafe { frames.replace(top, frame); }
                    index += 1;
                } else if index + 1 < syntax.source_len() &&
                    unsafe { syntax.byte(index + 1) } == b')'
                {
                    if let Some(done) = close_scan_frame(
                        &mut frames, &mut here_docs, &mut scopes, index, index + 2, body_start,
                    )? {
                        return Ok((done.0, done.1, contains_command));
                    }
                    index += 2;
                } else {
                    return Err(WordexpError::Syntax);
                }
            }
            SCAN_COMMAND if byte == b'(' => {
                open_command_parenthesis(&mut scopes, &frame)?;
                unsafe { frames.replace(top, frame); }
                index += 1;
            }
            SCAN_COMMAND if byte == b')' => {
                let (_, mut scope) = current_command_scope(&scopes, &frame)?;
                if scope.kind == COMMAND_SCOPE_SUBSHELL {
                    complete_command_scope(&mut scopes, &frame)?;
                    unsafe { frames.replace(top, frame); }
                    index += 1;
                } else if scope.kind == COMMAND_SCOPE_CASE && scope.phase == CASE_PHASE_PATTERN {
                    scope.phase = CASE_PHASE_BODY;
                    scope.command_position = true;
                    scope.function_name_candidate_end = NONE;
                    let scope_index = scopes.len() - 1;
                    // SAFETY: scope_index identifies the current top lexical scope.
                    unsafe { scopes.replace(scope_index, scope); }
                    unsafe { frames.replace(top, frame); }
                    index += 1;
                } else if scope.kind == COMMAND_SCOPE_FUNCTION &&
                    scope.phase == FUNCTION_PHASE_CLOSE
                {
                    scope.phase = FUNCTION_PHASE_COMPOUND_BODY;
                    let scope_index = scopes.len() - 1;
                    // SAFETY: scope_index identifies the current top lexical scope.
                    unsafe { scopes.replace(scope_index, scope); }
                    unsafe { frames.replace(top, frame); }
                    index += 1;
                } else if scope.kind != COMMAND_SCOPE_ROOT {
                    return Err(WordexpError::Syntax);
                } else {
                    if let Some(done) = close_scan_frame(
                        &mut frames, &mut here_docs, &mut scopes, index, index + 1, body_start,
                    )? {
                        return Ok((done.0, done.1, contains_command));
                    }
                    index += 1;
                }
            }
            SCAN_BACKTICK if byte == b'\x60' => {
                if let Some(done) = close_scan_frame(
                    &mut frames, &mut here_docs, &mut scopes, index, index + 1, body_start,
                )? {
                    return Ok((done.0, done.1, contains_command));
                }
                index += 1;
            }
            _ => {
                unsafe { frames.replace(top, frame); }
                index += 1;
            }
        }
    }
}

const VARIABLE_UNSET: u8 = 0;
const VARIABLE_SET: u8 = 1;
const VARIABLE_INITIAL: u8 = 1;
const VARIABLE_ASSIGNMENT: u8 = 2;

/// The call-local character interpretation used by the private expression
/// core. `C` also represents POSIX's byte-oriented locale behavior; it is the
/// explicit default until a later C ABI adapter supplies its locale snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WordexpLocaleMode {
    C,
    CUtf8,
}

const ATOM_SPLIT: u8 = 1;
const ATOM_PATTERN: u8 = 2;
const ATOM_EMPTY: u8 = 4;
const ATOM_QUOTED: u8 = 8;
const ATOM_ESCAPED: u8 = 16;

#[derive(Clone, Copy)]
struct StoredValue {
    state: u8,
    bytes: Span,
}

impl StoredValue {
    const fn unset() -> Self {
        Self { state: VARIABLE_UNSET, bytes: Span::empty(0) }
    }

    #[inline]
    const fn is_set(self) -> bool { self.state == VARIABLE_SET }
}

#[derive(Clone, Copy)]
struct Variable {
    name: Span,
    value: StoredValue,
    exported: bool,
    origin: u8,
}

/// Call-local variable/environment state. This object deliberately has no
/// link to the public process environment and can model an unset value
/// separately from an explicitly set empty value.
pub(super) struct WordexpContext {
    bytes: HeapVec<u8>,
    variables: HeapVec<Variable>,
    specials: HeapVec<Variable>,
    locale_mode: WordexpLocaleMode,
    undefined_is_error: bool,
    no_command_substitution: bool,
}

impl WordexpContext {
    pub(super) const fn new() -> Self {
        Self {
            bytes: HeapVec::new(),
            variables: HeapVec::new(),
            specials: HeapVec::new(),
            locale_mode: WordexpLocaleMode::C,
            undefined_is_error: false,
            no_command_substitution: false,
        }
    }

    pub(super) fn set_undefined_is_error(&mut self, value: bool) {
        self.undefined_is_error = value;
    }

    pub(super) fn set_no_command_substitution(&mut self, value: bool) {
        self.no_command_substitution = value;
    }

    /// Select the call-local C/POSIX byte mode or C.UTF-8 character mode.
    /// This candidate deliberately does not read process-global locale state.
    pub(super) fn set_locale_mode(&mut self, value: WordexpLocaleMode) {
        self.locale_mode = value;
    }

    pub(super) const fn locale_mode(&self) -> WordexpLocaleMode {
        self.locale_mode
    }

    fn store(&mut self, bytes: &[u8]) -> Result<Span, WordexpError> {
        let start = self.bytes.len();
        for byte in bytes {
            if *byte == 0 { return Err(WordexpError::OutputNul); }
            self.bytes.push(*byte)?;
        }
        Ok(Span { start, end: self.bytes.len() })
    }

    fn stored(&self, span: Span) -> &[u8] {
        debug_assert!(span.start <= span.end && span.end <= self.bytes.len());
        if span.len() == 0 { return &[]; }
        // SAFETY: store creates every context span inside this allocation.
        let bytes = unsafe { self.bytes.as_slice() };
        &bytes[span.start..span.end]
    }

    fn same(&self, left: Span, right: &[u8]) -> bool {
        if left.len() != right.len() { return false; }
        for index in 0..left.len() {
            // SAFETY: left is a stored context span.
            if unsafe { self.bytes.get(left.start + index) } != right[index] { return false; }
        }
        true
    }

    fn find(&self, variables: &HeapVec<Variable>, name: &[u8]) -> Option<usize> {
        let mut index = 0usize;
        while index < variables.len() {
            // SAFETY: index is below vector length.
            let variable = unsafe { variables.get(index) };
            if self.same(variable.name, name) { return Some(index); }
            index += 1;
        }
        None
    }

    /// Install one adapter-snapshotted variable. An empty Some is set-empty;
    /// None is explicitly unset and retains its requested export attribute.
    pub(super) fn set_initial(
        &mut self,
        name: &[u8],
        value: Option<&[u8]>,
        exported: bool,
    ) -> Result<(), WordexpError> {
        if !valid_identifier(name) { return Err(WordexpError::Syntax); }
        let existing = self.find(&self.variables, name);
        let stored = match value {
            Some(value) => StoredValue { state: VARIABLE_SET, bytes: self.store(value)? },
            None => StoredValue::unset(),
        };
        if let Some(index) = existing {
            // SAFETY: this exact initialized slot belongs to this context.
            let mut old = unsafe { self.variables.get(index) };
            old.value = stored;
            old.exported = exported;
            old.origin = VARIABLE_INITIAL;
            unsafe { self.variables.replace(index, old); }
        } else {
            let name_span = self.store(name)?;
            self.variables.push(Variable {
                name: name_span, value: stored, exported, origin: VARIABLE_INITIAL,
            })?;
        }
        Ok(())
    }

    /// Supply one finite special-parameter value. The public wordexp contract
    /// leaves special parameter results unspecified, so integration must make
    /// this state explicit instead of borrowing host shell state.
    pub(super) fn set_special(
        &mut self,
        name: &[u8],
        value: Option<&[u8]>,
    ) -> Result<(), WordexpError> {
        if name.is_empty() ||
            !(name.iter().all(|byte| byte.is_ascii_digit()) ||
              (name.len() == 1 && special_parameter(name[0])))
        {
            return Err(WordexpError::Syntax);
        }
        let existing = self.find(&self.specials, name);
        let stored = match value {
            Some(value) => StoredValue { state: VARIABLE_SET, bytes: self.store(value)? },
            None => StoredValue::unset(),
        };
        if let Some(index) = existing {
            // SAFETY: this exact initialized slot belongs to this context.
            let mut old = unsafe { self.specials.get(index) };
            old.value = stored;
            unsafe { self.specials.replace(index, old); }
        } else {
            let name_span = self.store(name)?;
            self.specials.push(Variable {
                name: name_span, value: stored, exported: false, origin: VARIABLE_INITIAL,
            })?;
        }
        Ok(())
    }

    /// None is an unset IFS and therefore its POSIX default. Some(empty)
    /// records a set-empty IFS and disables field splitting. This updates the
    /// same identifier record that parameter and arithmetic assignments use.
    pub(super) fn set_ifs(&mut self, value: Option<&[u8]>) -> Result<(), WordexpError> {
        let existing = self.find(&self.variables, b"IFS");
        let stored = match value {
            Some(value) => StoredValue { state: VARIABLE_SET, bytes: self.store(value)? },
            None => StoredValue::unset(),
        };
        if let Some(index) = existing {
            // SAFETY: the found record belongs to this context.
            let mut variable = unsafe { self.variables.get(index) };
            variable.value = stored;
            variable.origin = VARIABLE_INITIAL;
            unsafe { self.variables.replace(index, variable); }
        } else {
            let name = self.store(b"IFS")?;
            self.variables.push(Variable {
                name,
                value: stored,
                exported: false,
                origin: VARIABLE_INITIAL,
            })?;
        }
        Ok(())
    }

    fn lookup_identifier(&self, name: &[u8]) -> StoredValue {
        let Some(index) = self.find(&self.variables, name) else {
            return StoredValue::unset();
        };
        // SAFETY: find returned a live initialized index.
        unsafe { self.variables.get(index) }.value
    }

    fn lookup_special(&self, name: &[u8]) -> StoredValue {
        let Some(index) = self.find(&self.specials, name) else {
            return StoredValue::unset();
        };
        // SAFETY: find returned a live initialized index.
        unsafe { self.specials.get(index) }.value
    }

    fn lookup(&self, name: &[u8], kind: u8) -> StoredValue {
        if kind == PARAM_IDENTIFIER { self.lookup_identifier(name) }
        else { self.lookup_special(name) }
    }

    fn assign_local(&mut self, name: &[u8], value: &[u8]) -> Result<(), WordexpError> {
        if !valid_identifier(name) { return Err(WordexpError::Syntax); }
        let value = StoredValue { state: VARIABLE_SET, bytes: self.store(value)? };
        if let Some(index) = self.find(&self.variables, name) {
            // SAFETY: find returned one initialized context slot.
            let mut variable = unsafe { self.variables.get(index) };
            variable.value = value;
            if !variable.exported { variable.origin = VARIABLE_ASSIGNMENT; }
            unsafe { self.variables.replace(index, variable); }
        } else {
            let name = self.store(name)?;
            self.variables.push(Variable {
                name, value, exported: false, origin: VARIABLE_ASSIGNMENT,
            })?;
        }
        Ok(())
    }

    fn value_bytes(&self, value: StoredValue) -> &[u8] {
        if !value.is_set() { &[] } else { self.stored(value.bytes) }
    }

    fn ifs_bytes(&self) -> &[u8] {
        let ifs = self.lookup_identifier(b"IFS");
        if !ifs.is_set() {
            b" \t\n"
        } else {
            self.stored(ifs.bytes)
        }
    }

    /// Append unexported assignment-created state as literal shell
    /// assignments. Each value is single-quoted and embedded apostrophes use
    /// the conventional close/escape/reopen spelling. Existing exported
    /// variables never appear here because the future adapter places them in
    /// envp instead.
    fn child_assignment_prefix(
        &self,
        output: &mut HeapVec<u8>,
    ) -> Result<(), WordexpError> {
        let mut index = 0usize;
        while index < self.variables.len() {
            // SAFETY: loop bound names one initialized variable.
            let variable = unsafe { self.variables.get(index) };
            if variable.origin == VARIABLE_ASSIGNMENT && !variable.exported && variable.value.is_set() {
                let name = self.stored(variable.name);
                let value = self.value_bytes(variable.value);
                for byte in name { output.push(*byte)?; }
                output.push(b'=')?;
                output.push(b'\'')?;
                for byte in value {
                    if *byte == b'\'' {
                        for escaped in b"'\\''" { output.push(*escaped)?; }
                    } else {
                        output.push(*byte)?;
                    }
                }
                output.push(b'\'')?;
                // A newline makes this a shell assignment command before the
                // byte-exact command body, rather than a temporary command
                // environment prefix for that body's first simple command.
                output.push(b'\n')?;
            }
            index += 1;
        }
        Ok(())
    }

    /// Produce exported NAME=value entries in adapter insertion order. The
    /// future process adapter owns C-string vector allocation.
    fn append_exported_entries(
        &self,
        output: &mut HeapVec<u8>,
    ) -> Result<(), WordexpError> {
        let mut index = 0usize;
        while index < self.variables.len() {
            // SAFETY: loop bound names one initialized variable.
            let variable = unsafe { self.variables.get(index) };
            if variable.exported && variable.value.is_set() {
                for byte in self.stored(variable.name) {
                    output.push(*byte)?;
                }
                output.push(b'=')?;
                for byte in self.value_bytes(variable.value) {
                    output.push(*byte)?;
                }
                output.push(0)?;
            }
            index += 1;
        }
        Ok(())
    }
}

#[inline]
fn valid_identifier(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !identifier_start(bytes[0]) { return false; }
    bytes[1..].iter().all(|byte| identifier_continue(*byte))
}

#[derive(Clone, Copy)]
struct ExpandedAtom {
    byte: u8,
    flags: u8,
    // One semantic expansion run. C.UTF-8 IFS matching stays inside one run
    // so bytes from adjacent expansions cannot synthesize an IFS character.
    origin: usize,
}

/// One not-yet-split expanded word. Empty quoted expansions occupy ordered
/// zero-width atoms instead of a word-global bit, so field splitting can
/// preserve their position around delimiters.
struct ExpandedWord {
    atoms: HeapVec<ExpandedAtom>,
    next_origin: usize,
}

impl ExpandedWord {
    const fn new() -> Self {
        Self { atoms: HeapVec::new(), next_origin: 0 }
    }

    fn reserve_origin(&mut self) -> Result<usize, WordexpError> {
        let origin = self.next_origin;
        self.next_origin = self.next_origin.checked_add(1).ok_or(WordexpError::NoSpace)?;
        Ok(origin)
    }

    fn append_in_origin(
        &mut self,
        bytes: &[u8],
        flags: u8,
        explicit_empty: bool,
        origin: usize,
    ) -> Result<(), WordexpError> {
        if bytes.is_empty() && explicit_empty {
            self.atoms.push(ExpandedAtom {
                byte: 0,
                flags: flags | ATOM_EMPTY,
                origin,
            })?;
        }
        for byte in bytes {
            if *byte == 0 { return Err(WordexpError::OutputNul); }
            self.atoms.push(ExpandedAtom { byte: *byte, flags, origin })?;
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8], flags: u8, explicit_empty: bool) -> Result<(), WordexpError> {
        let origin = self.reserve_origin()?;
        self.append_in_origin(bytes, flags, explicit_empty, origin)
    }

    /// Insert an evaluated parameter WORD into its outer parameter expansion.
    /// Inner quotes and backslash escapes remain protected; otherwise the
    /// outer quote state determines whether the selected WORD participates in
    /// field splitting and pathname generation.
    fn append_parameter_result(
        &mut self,
        other: &ExpandedWord,
        outer_node_flags: u8,
    ) -> Result<(), WordexpError> {
        let outer_quoted = outer_node_flags & NODE_QUOTED != 0;
        let mut prior = NONE;
        let mut target_origin = NONE;
        // SAFETY: other owns all initialized atom records for this call.
        for source in unsafe { other.atoms.as_slice() } {
            if source.origin != prior {
                target_origin = self.reserve_origin()?;
                prior = source.origin;
            }
            let protected = source.flags & (ATOM_QUOTED | ATOM_ESCAPED) != 0;
            let mut flags = source.flags;
            if outer_quoted {
                flags &= !(ATOM_SPLIT | ATOM_PATTERN);
                flags |= ATOM_QUOTED;
            } else if protected {
                flags &= !(ATOM_SPLIT | ATOM_PATTERN);
            } else {
                flags |= ATOM_SPLIT | ATOM_PATTERN;
            }
            self.atoms.push(ExpandedAtom {
                byte: source.byte,
                flags,
                origin: target_origin,
            })?;
        }
        Ok(())
    }

    fn append_atom(&mut self, atom: ExpandedAtom) -> Result<(), WordexpError> {
        self.atoms.push(atom)
    }

    fn plain_bytes(&self, output: &mut HeapVec<u8>) -> Result<(), WordexpError> {
        // SAFETY: this word owns all initialized atoms for this call.
        for atom in unsafe { self.atoms.as_slice() } {
            if atom.flags & ATOM_EMPTY == 0 {
                output.push(atom.byte)?;
            }
        }
        Ok(())
    }

    fn has_pattern(&self) -> bool {
        // SAFETY: this word owns all initialized atoms.
        unsafe { self.atoms.as_slice() }.iter().any(|atom| {
            atom.flags & (ATOM_PATTERN | ATOM_ESCAPED | ATOM_EMPTY) == ATOM_PATTERN &&
                matches!(atom.byte, b'*' | b'?' | b'[')
        })
    }
}

pub(super) struct ExpandedWords {
    words: HeapVec<*mut ExpandedWord>,
}

impl ExpandedWords {
    const fn new() -> Self { Self { words: HeapVec::new() } }

    fn allocate_word(&mut self) -> Result<*mut ExpandedWord, WordexpError> {
        // SAFETY: selected C malloc allocates one private word record.
        let word = unsafe { wordexp_engine_malloc(size_of::<ExpandedWord>()) }.cast::<ExpandedWord>();
        if word.is_null() { return Err(WordexpError::NoSpace); }
        // SAFETY: word points to enough uninitialized storage for this object.
        unsafe { ptr::write(word, ExpandedWord::new()); }
        Ok(word)
    }

    fn push(&mut self, word: *mut ExpandedWord) -> Result<(), WordexpError> {
        self.words.push(word)
    }

    pub(super) fn len(&self) -> usize { self.words.len() }

    pub(super) fn result_word(&self, index: usize) -> Option<ExpandedResultWord<'_>> {
        if index >= self.words.len() { return None; }
        // SAFETY: each non-null list entry owns a live result word.
        let word = unsafe { self.words.get(index) };
        if word.is_null() { return None; }
        // SAFETY: the result list retains this word through the returned view.
        Some(ExpandedResultWord { word: unsafe { &*word } })
    }
}

/// Read-only result bytes for later C-record construction. Empty quote
/// markers remain private evaluator metadata and are omitted here.
pub(super) struct ExpandedResultWord<'a> {
    word: &'a ExpandedWord,
}

impl ExpandedResultWord<'_> {
    pub(super) fn byte_len(&self) -> usize {
        let mut length = 0usize;
        // SAFETY: this view borrows a live result word.
        for atom in unsafe { self.word.atoms.as_slice() } {
            if atom.flags & ATOM_EMPTY == 0 { length += 1; }
        }
        length
    }

    pub(super) fn byte_at(&self, wanted: usize) -> Option<u8> {
        let mut index = 0usize;
        // SAFETY: this view borrows a live result word.
        for atom in unsafe { self.word.atoms.as_slice() } {
            if atom.flags & ATOM_EMPTY != 0 { continue; }
            if index == wanted { return Some(atom.byte); }
            index += 1;
        }
        None
    }
}

/// One opaque pattern byte with only the eligibility information the pathname
/// owner needs. Quote and origin representation stay inside this module.
#[derive(Clone, Copy)]
pub(super) struct PatternAtom {
    byte: u8,
    pattern_eligible: bool,
    empty_marker: bool,
}

impl PatternAtom {
    pub(super) const fn byte(self) -> u8 { self.byte }
    pub(super) const fn is_pattern_eligible(self) -> bool { self.pattern_eligible }
    pub(super) const fn is_empty_marker(self) -> bool { self.empty_marker }
}

pub(super) struct PatternInput<'a> {
    atoms: &'a [ExpandedAtom],
}

impl PatternInput<'_> {
    pub(super) fn len(&self) -> usize { self.atoms.len() }

    pub(super) fn atom(&self, index: usize) -> Option<PatternAtom> {
        let atom = *self.atoms.get(index)?;
        Some(PatternAtom {
            byte: atom.byte,
            pattern_eligible: atom.flags & (ATOM_PATTERN | ATOM_ESCAPED | ATOM_EMPTY)
                == ATOM_PATTERN,
            empty_marker: atom.flags & ATOM_EMPTY != 0,
        })
    }
}

/// Restricted sink for a tilde result. Its atom classification stays owned by
/// the expansion core.
pub(super) struct TildeOutput<'a> {
    word: &'a mut ExpandedWord,
}

impl TildeOutput<'_> {
    pub(super) fn append_home(&mut self, bytes: &[u8]) -> Result<(), WordexpError> {
        // POSIX treats a tilde replacement as quoted. In particular, bytes in
        // HOME must neither form fields nor become pathname metacharacters. An
        // empty HOME still replaces bare `~` with one explicit empty field.
        self.word.append(bytes, ATOM_QUOTED, bytes.is_empty())
    }
}

/// Restricted sink for pathname matches. It transfers a copied byte path only
/// after every allocation and append step succeeds.
pub(super) struct PathnameMatches<'a> {
    output: &'a mut ExpandedWords,
}

impl PathnameMatches<'_> {
    pub(super) fn append_path(&mut self, bytes: &[u8]) -> Result<(), WordexpError> {
        let word = self.output.allocate_word()?;
        let appended = unsafe { (*word).append(bytes, 0, bytes.is_empty()) };
        if let Err(error) = appended {
            // SAFETY: allocation did not transfer to the result owner.
            unsafe { free_expanded_word(word); }
            return Err(error);
        }
        if let Err(error) = self.output.push(word) {
            // SAFETY: push failed before ownership transferred.
            unsafe { free_expanded_word(word); }
            return Err(error);
        }
        Ok(())
    }
}

/// Restricted sink for one parameter-pattern removal result.
pub(super) struct ParameterPatternOutput<'a> {
    word: &'a mut ExpandedWord,
}

impl ParameterPatternOutput<'_> {
    pub(super) fn append_bytes(&mut self, bytes: &[u8]) -> Result<(), WordexpError> {
        // The evaluator decides whether an empty removal result survives from
        // the outer parameter quote state after the adapter has finished.
        self.word.append(bytes, 0, false)
    }
}

impl Drop for ExpandedWords {
    fn drop(&mut self) {
        while let Some(word) = self.words.pop() {
            if !word.is_null() {
                // SAFETY: this list owns each word pointer exactly once.
                unsafe {
                    ptr::drop_in_place(word);
                    wordexp_engine_free(word.cast());
                }
            }
        }
    }
}

fn allocate_expanded_word() -> Result<*mut ExpandedWord, WordexpError> {
    // SAFETY: selected C malloc allocates one private word record.
    let word = unsafe { wordexp_engine_malloc(size_of::<ExpandedWord>()) }.cast::<ExpandedWord>();
    if word.is_null() { return Err(WordexpError::NoSpace); }
    // SAFETY: word points to enough uninitialized storage for this object.
    unsafe { ptr::write(word, ExpandedWord::new()); }
    Ok(word)
}

unsafe fn free_expanded_word(word: *mut ExpandedWord) {
    if word.is_null() { return; }
    // SAFETY: the caller transfers one private word allocation to this helper.
    unsafe {
        ptr::drop_in_place(word);
        wordexp_engine_free(word.cast());
    }
}

/// Owns evaluator temporaries until they either become result words or are
/// retired. It makes every error path reclaim both nested parameter WORD
/// buffers and root-word buffers without recursive cleanup.
struct ScratchWords {
    words: HeapVec<*mut ExpandedWord>,
}

impl ScratchWords {
    const fn new() -> Self { Self { words: HeapVec::new() } }

    fn allocate(&mut self) -> Result<*mut ExpandedWord, WordexpError> {
        let word = allocate_expanded_word()?;
        if let Err(error) = self.words.push(word) {
            // SAFETY: allocation has not escaped the scratch owner.
            unsafe { free_expanded_word(word); }
            return Err(error);
        }
        Ok(word)
    }

    fn release(&mut self, word: *mut ExpandedWord) {
        let mut index = 0usize;
        while index < self.words.len() {
            // SAFETY: index is below the initialized pointer list.
            if unsafe { self.words.get(index) } == word {
                unsafe { self.words.replace(index, ptr::null_mut()); }
                return;
            }
            index += 1;
        }
        debug_assert!(false, "scratch allocation must be released exactly once");
    }

    unsafe fn free(&mut self, word: *mut ExpandedWord) {
        self.release(word);
        // SAFETY: caller transfers one scratch-owned allocation.
        unsafe { free_expanded_word(word); }
    }
}

impl Drop for ScratchWords {
    fn drop(&mut self) {
        while let Some(word) = self.words.pop() {
            // SAFETY: non-null entries have not transferred to output.
            unsafe { free_expanded_word(word); }
        }
    }
}

/// Narrow writable boundary for one delegated command substitution. The
/// adapter can append output bytes but cannot retain or reallocate evaluator
/// storage.
pub(super) struct CommandOutput<'a> {
    bytes: &'a mut HeapVec<u8>,
}

impl CommandOutput<'_> {
    pub(super) fn append(&mut self, bytes: &[u8]) -> Result<(), WordexpError> {
        for byte in bytes {
            if *byte == 0 { return Err(WordexpError::OutputNul); }
            self.bytes.push(*byte)?;
        }
        Ok(())
    }
}

/// The eventual process adapter receives an opaque command body, its spelling
/// context, the already-quoted assignment prefix, and the current
/// NUL-separated exported entries. For a backtick body it applies only the
/// POSIX backslash rule selected by `CommandStyle::Backtick`, then executes
/// that body exactly once. This core never asks it to parse, preflight, or
/// classify stderr/status.
pub(super) trait WordexpCommandAdapter {
    fn execute(
        &mut self,
        body: &[u8],
        style: CommandStyle,
        assignment_prefix: &[u8],
        exported_entries: &[u8],
        output: &mut CommandOutput<'_>,
    ) -> Result<(), WordexpError>;
}

/// The future concrete adapter binds these three operations to the selected
/// passwd and pattern owners. The core keeps their byte and ownership
/// boundaries explicit for deterministic tests.
pub(super) trait WordexpPathAdapter {
    /// Return true after appending a resolved home path to output. Return false
    /// to preserve an unresolved tilde spelling as literal source text.
    fn expand_tilde(
        &mut self,
        user: &[u8],
        home: Option<&[u8]>,
        output: &mut TildeOutput<'_>,
    ) -> Result<bool, WordexpError>;

    /// Append replacement words and return true when pathname expansion
    /// matched. The input exposes only quote-derived pattern eligibility.
    fn expand_pattern(
        &mut self,
        pattern: &PatternInput<'_>,
        output: &mut PathnameMatches<'_>,
    ) -> Result<bool, WordexpError>;

    /// Apply a parameter substring-pattern operator. The pattern is an
    /// already-evaluated operand, never a new source string to parse.
    fn remove_parameter_pattern(
        &mut self,
        value: &[u8],
        pattern: &PatternInput<'_>,
        operator: ParameterPatternOperator,
        output: &mut ParameterPatternOutput<'_>,
    ) -> Result<(), WordexpError>;
}

#[derive(Clone, Copy)]
enum EvaluationContext {
    ParameterWord,
    AssignmentValue,
    PatternOperand,
    ArithmeticToken,
}

const TASK_WORD: u8 = 1;
const TASK_FINISH_PARAMETER: u8 = 2;
const TASK_FINISH_ROOT: u8 = 3;
const TASK_FINISH_ARITHMETIC: u8 = 4;

#[derive(Clone, Copy)]
struct EvaluationTask {
    kind: u8,
    word: usize,
    node: usize,
    target: *mut ExpandedWord,
    parameter: usize,
    temporary: *mut ExpandedWord,
    node_flags: u8,
    context: EvaluationContext,
}

impl EvaluationTask {
    const fn word(
        word: usize,
        node: usize,
        target: *mut ExpandedWord,
        context: EvaluationContext,
    ) -> Self {
        Self {
            kind: TASK_WORD, word, node, target, parameter: NONE,
            temporary: ptr::null_mut(), node_flags: 0, context,
        }
    }

    const fn finish_parameter(
        target: *mut ExpandedWord,
        parameter: usize,
        temporary: *mut ExpandedWord,
        node_flags: u8,
        context: EvaluationContext,
    ) -> Self {
        Self {
            kind: TASK_FINISH_PARAMETER, word: NONE, node: NONE, target,
            parameter, temporary, node_flags, context,
        }
    }

    const fn finish_root(temporary: *mut ExpandedWord) -> Self {
        Self {
            kind: TASK_FINISH_ROOT, word: NONE, node: NONE,
            target: ptr::null_mut(), parameter: NONE, temporary,
            node_flags: 0, context: EvaluationContext::ParameterWord,
        }
    }

    const fn finish_arithmetic(
        target: *mut ExpandedWord,
        temporary: *mut ExpandedWord,
        node_flags: u8,
    ) -> Self {
        Self {
            kind: TASK_FINISH_ARITHMETIC,
            word: NONE,
            node: NONE,
            target,
            parameter: NONE,
            temporary,
            node_flags,
            context: EvaluationContext::ArithmeticToken,
        }
    }
}

#[inline]
const fn expansion_atom_flags(node_flags: u8) -> u8 {
    if node_flags & NODE_QUOTED != 0 {
        ATOM_QUOTED
    } else {
        ATOM_SPLIT | ATOM_PATTERN
    }
}

#[inline]
const fn literal_atom_flags(node_flags: u8) -> u8 {
    if node_flags & NODE_QUOTED != 0 { ATOM_QUOTED } else { ATOM_PATTERN }
}

fn append_literal_node(
    syntax: &WordexpSyntax,
    node: SyntaxNode,
    output: &mut ExpandedWord,
) -> Result<(), WordexpError> {
    // SAFETY: literal node spans are created by this syntax object.
    let input = unsafe { syntax.bytes(node.span) };
    let flags = literal_atom_flags(node.flags);
    let origin = output.reserve_origin()?;
    if node.flags & NODE_DOLLAR_SINGLE != 0 {
        return append_dollar_single(input, flags, origin, output);
    }
    let mut index = 0usize;
    if node.flags & NODE_SINGLE != 0 {
        return output.append_in_origin(input, flags, true, origin);
    }
    while index < input.len() {
        let byte = input[index];
        if byte != b'\\' {
            output.append_in_origin(&input[index..index + 1], flags, false, origin)?;
            index += 1;
            continue;
        }
        if index + 1 == input.len() { return Err(WordexpError::Syntax); }
        let next = input[index + 1];
        if next == b'\n' {
            index += 2;
            continue;
        }
        if node.flags & NODE_DOUBLE != 0 {
            if matches!(next, b'$' | b'\x60' | b'"' | b'\\') ||
                (node.flags & NODE_PARAMETER_WORD != 0 && next == b'}')
            {
                output.append_in_origin(&input[index + 1..index + 2], flags, false, origin)?;
                index += 2;
            } else {
                output.append_in_origin(&input[index..index + 2], flags, false, origin)?;
                index += 2;
            }
        } else {
            output.append_in_origin(
                &input[index + 1..index + 2],
                (flags & !ATOM_PATTERN) | ATOM_ESCAPED,
                false,
                origin,
            )?;
            index += 2;
        }
    }
    if input.is_empty() && node.flags & NODE_QUOTED != 0 {
        output.append_in_origin(&[], flags, true, origin)?;
    }
    Ok(())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn append_dollar_single(
    input: &[u8],
    flags: u8,
    origin: usize,
    output: &mut ExpandedWord,
) -> Result<(), WordexpError> {
    if input.is_empty() { return output.append_in_origin(&[], flags, true, origin); }
    let mut index = 0usize;
    while index < input.len() {
        if input[index] != b'\\' {
            output.append_in_origin(&input[index..index + 1], flags, false, origin)?;
            index += 1;
            continue;
        }
        if index + 1 == input.len() { return Err(WordexpError::Syntax); }
        let escape = input[index + 1];
        let mut consumed = 2usize;
        let value = match escape {
            b'"' => b'"',
            b'\'' => b'\'',
            b'\\' => b'\\',
            b'a' => 7,
            b'b' => 8,
            b'e' => 27,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 11,
            b'x' => {
                if index + 2 >= input.len() { return Err(WordexpError::Syntax); }
                let high = hex_value(input[index + 2]).ok_or(WordexpError::Syntax)?;
                let low = if index + 3 < input.len() {
                    hex_value(input[index + 3])
                } else {
                    None
                };
                consumed = if low.is_some() { 4 } else { 3 };
                match low {
                    Some(low) => high * 16 + low,
                    None => high,
                }
            }
            b'0'..=b'7' => {
                let mut value = escape - b'0';
                while consumed < 4 && index + consumed < input.len() {
                    let digit = input[index + consumed];
                    if !(b'0'..=b'7').contains(&digit) { break; }
                    value = value.checked_mul(8)
                        .and_then(|prior| prior.checked_add(digit - b'0'))
                        .ok_or(WordexpError::OutputNul)?;
                    consumed += 1;
                }
                value
            }
            b'c' => {
                if index + 2 >= input.len() { return Err(WordexpError::Syntax); }
                consumed = 3;
                input[index + 2] & 0x1f
            }
            _ => {
                output.append_in_origin(b"\\", flags, false, origin)?;
                escape
            }
        };
        if value == 0 { return Err(WordexpError::OutputNul); }
        output.append_in_origin(&[value], flags, false, origin)?;
        index += consumed;
    }
    Ok(())
}

fn append_stored_value(
    context: &WordexpContext,
    value: StoredValue,
    flags: u8,
    output: &mut ExpandedWord,
) -> Result<(), WordexpError> {
    let bytes = context.value_bytes(value);
    output.append(bytes, flags, flags & ATOM_QUOTED != 0 && bytes.is_empty())
}

fn append_decimal(
    mut value: usize,
    flags: u8,
    output: &mut ExpandedWord,
) -> Result<(), WordexpError> {
    let mut digits = [0u8; 3 * size_of::<usize>()];
    let mut count = 0usize;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 { break; }
    }
    let mut rendered = [0u8; 3 * size_of::<usize>()];
    let mut length = 0usize;
    while count != 0 {
        count -= 1;
        rendered[length] = digits[count];
        length += 1;
    }
    output.append(&rendered[..length], flags, false)
}

fn word_has_content(word: &ExpandedWord) -> bool {
    !word.atoms.is_empty()
}

/// Return the next valid UTF-8 scalar byte length, or one for an invalid or
/// incomplete lead byte. This is the same forward-progress choice as musl's
/// C.UTF-8 `fnmatch` scanner: malformed input remains ordinary byte data and
/// cannot make a word-expansion scan reject or stall.
fn utf8_unit_len(bytes: &[u8], index: usize) -> usize {
    debug_assert!(index < bytes.len());
    let first = bytes[index];
    let tail = &bytes[index + 1..];
    let continuation = |offset: usize| match tail.get(offset) {
        Some(byte) => *byte & 0xc0 == 0x80,
        None => false,
    };
    match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf if continuation(0) => 2,
        0xe0 if matches!(tail.first().copied(), Some(0xa0..=0xbf)) && continuation(1) => 3,
        0xe1..=0xec | 0xee..=0xef if continuation(0) && continuation(1) => 3,
        0xed if matches!(tail.first().copied(), Some(0x80..=0x9f)) && continuation(1) => 3,
        0xf0 if matches!(tail.first().copied(), Some(0x90..=0xbf)) &&
            continuation(1) && continuation(2) => 4,
        0xf1..=0xf3 if continuation(0) && continuation(1) && continuation(2) => 4,
        0xf4 if matches!(tail.first().copied(), Some(0x80..=0x8f)) &&
            continuation(1) && continuation(2) => 4,
        _ => 1,
    }
}

fn character_count(bytes: &[u8], locale_mode: WordexpLocaleMode) -> usize {
    if locale_mode == WordexpLocaleMode::C { return bytes.len(); }
    let mut count = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        index += utf8_unit_len(bytes, index);
        count += 1;
    }
    count
}

fn ifs_contains_byte(ifs: &[u8], byte: u8) -> bool {
    ifs.iter().any(|candidate| *candidate == byte)
}

const IFS_WHITE: u8 = 1;
const IFS_NONWHITE: u8 = 2;

#[derive(Clone, Copy)]
struct IfsDelimiter {
    after: usize,
    kind: u8,
}

fn atom_is_splittable(atom: ExpandedAtom) -> bool {
    atom.flags & (ATOM_SPLIT | ATOM_EMPTY | ATOM_QUOTED) == ATOM_SPLIT
}

fn ifs_delimiter_kind(bytes: &[u8]) -> u8 {
    if bytes.len() == 1 && matches!(bytes[0], b' ' | b'\t' | b'\n') {
        IFS_WHITE
    } else {
        // POSIX permits implementations to classify additional locale white
        // space. This private core deliberately treats only portable ASCII
        // space, tab, and newline as IFS white space.
        IFS_NONWHITE
    }
}

/// Match one leading IFS delimiter in an expansion result. In C.UTF-8 mode an
/// IFS character is matched as its complete byte sequence and every byte must
/// belong to the same unquoted expansion origin. This implements the POSIX
/// 2.6.5 rule that a candidate character sequence cannot combine bytes from
/// separate expansion results or non-expansion source.
fn ifs_delimiter_at(
    atoms: &[ExpandedAtom],
    index: usize,
    ifs: &[u8],
    locale_mode: WordexpLocaleMode,
) -> Option<IfsDelimiter> {
    let first = *atoms.get(index)?;
    if !atom_is_splittable(first) { return None; }
    if locale_mode == WordexpLocaleMode::C {
        if !ifs_contains_byte(ifs, first.byte) { return None; }
        return Some(IfsDelimiter {
            after: index + 1,
            kind: ifs_delimiter_kind(&[first.byte]),
        });
    }

    let origin = first.origin;
    let mut ifs_index = 0usize;
    while ifs_index < ifs.len() {
        let length = utf8_unit_len(ifs, ifs_index);
        let Some(after) = index.checked_add(length) else { return None; };
        if after <= atoms.len() {
            let mut offset = 0usize;
            while offset < length {
                let atom = atoms[index + offset];
                if !atom_is_splittable(atom) || atom.origin != origin ||
                    atom.byte != ifs[ifs_index + offset]
                {
                    break;
                }
                offset += 1;
            }
            if offset == length {
                return Some(IfsDelimiter {
                    after,
                    kind: ifs_delimiter_kind(&ifs[ifs_index..ifs_index + length]),
                });
            }
        }
        ifs_index += length;
    }
    None
}

/// Consume one POSIX field-delimiter unit. An IFS white-space run is absorbed
/// with an adjacent non-white IFS delimiter, while adjacent non-white
/// delimiters remain distinct and therefore retain their empty field between
/// them.
fn consume_ifs_delimiter(
    atoms: &[ExpandedAtom],
    mut index: usize,
    ifs: &[u8],
    locale_mode: WordexpLocaleMode,
) -> (usize, bool) {
    let Some(delimiter) = ifs_delimiter_at(atoms, index, ifs, locale_mode) else {
        return (index, false);
    };
    if delimiter.kind == IFS_NONWHITE {
        index = delimiter.after;
        while let Some(white) = ifs_delimiter_at(atoms, index, ifs, locale_mode) {
            if white.kind != IFS_WHITE { break; }
            index = white.after;
        }
        return (index, true);
    }
    while let Some(white) = ifs_delimiter_at(atoms, index, ifs, locale_mode) {
        if white.kind != IFS_WHITE { break; }
        index = white.after;
    }
    if let Some(nonwhite) = ifs_delimiter_at(atoms, index, ifs, locale_mode) {
        if nonwhite.kind == IFS_NONWHITE {
            index = nonwhite.after;
            while let Some(white) = ifs_delimiter_at(atoms, index, ifs, locale_mode) {
                if white.kind != IFS_WHITE { break; }
                index = white.after;
            }
            return (index, true);
        }
    }
    (index, false)
}

fn split_root_word(
    scratch: &mut ScratchWords,
    root: *mut ExpandedWord,
    ifs: &[u8],
    locale_mode: WordexpLocaleMode,
    output: &mut ExpandedWords,
) -> Result<(), WordexpError> {
    if ifs.is_empty() {
        if word_has_content(unsafe { &*root }) {
            output.push(root)?;
            scratch.release(root);
        } else {
            // SAFETY: an empty unquoted expansion has no result field.
            unsafe { scratch.free(root); }
        }
        return Ok(());
    }
    let mut current = scratch.allocate()?;
    let mut index = 0usize;
    // SAFETY: root is scratch-owned through the entire split operation.
    let atoms = unsafe { (*root).atoms.as_slice() };
    while index < atoms.len() {
        let atom = atoms[index];
        if ifs_delimiter_at(atoms, index, ifs, locale_mode).is_none() {
            // SAFETY: current is a scratch-owned live word.
            unsafe { (*current).append_atom(atom)?; }
            index += 1;
            continue;
        }
        let (after, nonwhite) = consume_ifs_delimiter(atoms, index, ifs, locale_mode);
        if word_has_content(unsafe { &*current }) || nonwhite {
            output.push(current)?;
            scratch.release(current);
            current = scratch.allocate()?;
        }
        index = after;
    }
    // SAFETY: root and current are scratch-owned live words.
    if word_has_content(unsafe { &*current }) {
        output.push(current)?;
        scratch.release(current);
    } else {
        unsafe { scratch.free(current); }
    }
    unsafe { scratch.free(root); }
    Ok(())
}

fn apply_pathname_expansion(
    paths: &mut dyn WordexpPathAdapter,
    output: &mut ExpandedWords,
) -> Result<(), WordexpError> {
    // Keep the input owner separate while adapters append replacement words.
    // Besides making allocation failure reclaim every source word, this
    // preserves left-to-right word order when a pattern produces many paths.
    let mut source = ExpandedWords {
        words: core::mem::replace(&mut output.words, HeapVec::new()),
    };
    let source_count = source.words.len();
    let mut index = 0usize;
    while index < source_count {
        // SAFETY: each index is initialized before this pass starts.
        let word = unsafe { source.words.get(index) };
        // SAFETY: each output pointer is owned and live through this pass.
        if unsafe { (*word).has_pattern() } {
            let before = output.words.len();
            // SAFETY: atoms stay live while the adapter observes them.
            let pattern = PatternInput {
                // SAFETY: source word remains live through this adapter call.
                atoms: unsafe { (*word).atoms.as_slice() },
            };
            let mut matches = PathnameMatches { output };
            let matched = paths.expand_pattern(&pattern, &mut matches)?;
            if matched {
                if output.words.len() == before { return Err(WordexpError::Syntax); }
                // SAFETY: this old word has been replaced by adapter output.
                unsafe { free_expanded_word(word); }
                unsafe { source.words.replace(index, ptr::null_mut()); }
            } else {
                output.push(word)?;
                unsafe { source.words.replace(index, ptr::null_mut()); }
            }
        } else {
            output.push(word)?;
            unsafe { source.words.replace(index, ptr::null_mut()); }
        }
        index += 1;
    }
    Ok(())
}

/// Evaluate a parsed wordexp expression with private deterministic adapters.
/// This does not select a C ABI provider or launch a child by itself.
pub(super) fn evaluate_wordexp(
    syntax: &WordexpSyntax,
    context: &mut WordexpContext,
    commands: &mut dyn WordexpCommandAdapter,
    paths: &mut dyn WordexpPathAdapter,
) -> Result<ExpandedWords, WordexpError> {
    if context.no_command_substitution && syntax.has_commands() {
        return Err(WordexpError::CommandSubstitution);
    }
    let mut results = ExpandedWords::new();
    let mut scratch = ScratchWords::new();
    let mut tasks = HeapVec::<EvaluationTask>::new();
    let mut root_index = 0usize;
    while root_index < syntax.roots.len() {
        // SAFETY: root_index is bounded by the initialized root vector.
        let root = unsafe { syntax.roots.get(root_index) };
        let target = scratch.allocate()?;
        // SAFETY: root ids come from the syntax parser.
        let first = unsafe { syntax.word(root) }.first;
        tasks.push(EvaluationTask::finish_root(target))?;
        tasks.push(EvaluationTask::word(
            root,
            first,
            target,
            EvaluationContext::ParameterWord,
        ))?;
        run_evaluation_tasks(
            syntax,
            context,
            commands,
            paths,
            &mut scratch,
            &mut results,
            &mut tasks,
        )?;
        root_index += 1;
    }
    apply_pathname_expansion(paths, &mut results)?;
    Ok(results)
}

fn run_evaluation_tasks(
    syntax: &WordexpSyntax,
    context: &mut WordexpContext,
    commands: &mut dyn WordexpCommandAdapter,
    paths: &mut dyn WordexpPathAdapter,
    scratch: &mut ScratchWords,
    results: &mut ExpandedWords,
    tasks: &mut HeapVec<EvaluationTask>,
) -> Result<(), WordexpError> {
    while let Some(task) = tasks.pop() {
        match task.kind {
            TASK_WORD => {
                if task.node == NONE { continue; }
                // SAFETY: every task node begins at a parsed word node or a
                // next link established by the same parser.
                let node = unsafe { syntax.node(task.node) };
                match node.kind {
                    NODE_LITERAL => {
                        // SAFETY: task target is scratch-owned until root split.
                        append_literal_node(syntax, node, unsafe { &mut *task.target })?;
                        tasks.push(EvaluationTask::word(
                            task.word, node.next, task.target, task.context,
                        ))?;
                    }
                    NODE_PARAMETER => {
                        start_parameter(
                            syntax, context, paths, scratch, tasks, task,
                            node, node.next,
                        )?;
                    }
                    NODE_ARITHMETIC => {
                        // SAFETY: node payload was created from arithmetic.
                        let arithmetic = unsafe { syntax.arithmetic(node.payload) };
                        push_arithmetic_source(
                            syntax,
                            scratch,
                            tasks,
                            task,
                            node.next,
                            arithmetic,
                            node.flags,
                        )?;
                    }
                    NODE_COMMAND => {
                        // SAFETY: command node payload is syntax-owned.
                        let command = unsafe { syntax.command(node.payload) };
                        let mut prefix = HeapVec::new();
                        context.child_assignment_prefix(&mut prefix)?;
                        let mut exports = HeapVec::new();
                        context.append_exported_entries(&mut exports)?;
                        let mut command_output = HeapVec::new();
                        // SAFETY: command body is a source span retained by
                        // syntax through this adapter call.
                        {
                            let mut output = CommandOutput { bytes: &mut command_output };
                            commands.execute(
                                unsafe { syntax.bytes(command.body) },
                                command.style,
                                unsafe { prefix.as_slice() },
                                unsafe { exports.as_slice() },
                                &mut output,
                            )?;
                        }
                        while !command_output.is_empty() {
                            // SAFETY: nonempty vector has a live final byte.
                            let last = unsafe { command_output.get(command_output.len() - 1) };
                            if last != b'\n' { break; }
                            command_output.truncate(command_output.len() - 1);
                        }
                        // SAFETY: output ownership stays with this local vector
                        // until append has copied every atom.
                        unsafe { &mut *task.target }.append(
                            unsafe { command_output.as_slice() },
                            expansion_atom_flags(node.flags),
                            node.flags & NODE_QUOTED != 0 && command_output.is_empty(),
                        )?;
                        tasks.push(EvaluationTask::word(
                            task.word, node.next, task.target, task.context,
                        ))?;
                    }
                    NODE_TILDE => {
                        // SAFETY: tilde span is a retained syntax source slice.
                        let user = unsafe { syntax.bytes(node.span) };
                        let home = if user.is_empty() {
                            let value = context.lookup_identifier(b"HOME");
                            if value.is_set() {
                                Some(context.value_bytes(value))
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        // SAFETY: target remains scratch-owned for this task.
                        let target = unsafe { &mut *task.target };
                        let mut output = TildeOutput { word: target };
                        if !paths.expand_tilde(user, home, &mut output)? {
                            // The unresolved spelling is one literal run.
                            let origin = target.reserve_origin()?;
                            target.append_in_origin(b"~", ATOM_PATTERN, false, origin)?;
                            target.append_in_origin(user, ATOM_PATTERN, false, origin)?;
                        }
                        tasks.push(EvaluationTask::word(
                            task.word, node.next, task.target, task.context,
                        ))?;
                    }
                    _ => return Err(WordexpError::Syntax),
                }
            }
            TASK_FINISH_PARAMETER => {
                finish_parameter(syntax, context, paths, scratch, task)?;
            }
            TASK_FINISH_ROOT => {
                split_root_word(
                    scratch,
                    task.temporary,
                    context.ifs_bytes(),
                    context.locale_mode(),
                    results,
                )?;
            }
            TASK_FINISH_ARITHMETIC => {
                finish_arithmetic(context, scratch, task)?;
            }
            _ => return Err(WordexpError::Syntax),
        }
    }
    Ok(())
}

fn push_arithmetic_source(
    syntax: &WordexpSyntax,
    scratch: &mut ScratchWords,
    tasks: &mut HeapVec<EvaluationTask>,
    parent: EvaluationTask,
    next: usize,
    arithmetic: Arithmetic,
    node_flags: u8,
) -> Result<(), WordexpError> {
    if arithmetic.word == NONE { return Err(WordexpError::Syntax); }
    let temporary = scratch.allocate()?;
    // The source must complete every parameter, command, and nested
    // arithmetic expansion before the arithmetic grammar sees its bytes.
    tasks.push(EvaluationTask::word(parent.word, next, parent.target, parent.context))?;
    tasks.push(EvaluationTask::finish_arithmetic(
        parent.target,
        temporary,
        node_flags,
    ))?;
    // SAFETY: arithmetic.word comes from the syntax parser's pending queue.
    let child = unsafe { syntax.word(arithmetic.word) };
    tasks.push(EvaluationTask::word(
        arithmetic.word,
        child.first,
        temporary,
        EvaluationContext::ArithmeticToken,
    ))?;
    Ok(())
}

fn finish_arithmetic(
    context: &mut WordexpContext,
    scratch: &mut ScratchWords,
    task: EvaluationTask,
) -> Result<(), WordexpError> {
    let mut source = HeapVec::new();
    // SAFETY: temporary remains scratch-owned until this function succeeds.
    unsafe { (*task.temporary).plain_bytes(&mut source)?; }
    let result = evaluate_arithmetic(unsafe { source.as_slice() }, context);
    if let Ok(value) = result {
        // SAFETY: target is owned by the running evaluator task.
        append_i64(
            value,
            expansion_atom_flags(task.node_flags),
            unsafe { &mut *task.target },
        )?;
        // SAFETY: successful finishing consumes the temporary source word.
        unsafe { scratch.free(task.temporary); }
    }
    result.map(|_| ())
}

fn append_i64(
    value: i64,
    flags: u8,
    output: &mut ExpandedWord,
) -> Result<(), WordexpError> {
    if value == 0 { return output.append(b"0", flags, false); }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    while magnitude != 0 {
        digits[count] = b'0' + (magnitude % 10) as u8;
        count += 1;
        magnitude /= 10;
    }
    let mut rendered = [0u8; 20];
    let mut length = 0usize;
    if negative {
        rendered[length] = b'-';
        length += 1;
    }
    while count != 0 {
        count -= 1;
        rendered[length] = digits[count];
        length += 1;
    }
    output.append(&rendered[..length], flags, false)
}

const ARITH_NUMBER: u8 = 1;
const ARITH_IDENTIFIER: u8 = 2;
const ARITH_UNARY: u8 = 3;
const ARITH_BINARY: u8 = 4;
const ARITH_CONDITIONAL: u8 = 5;

const ARITH_POSITIVE: u8 = 1;
const ARITH_NEGATIVE: u8 = 2;
const ARITH_NOT: u8 = 3;
const ARITH_COMPLEMENT: u8 = 4;
const ARITH_MULTIPLY: u8 = 5;
const ARITH_DIVIDE: u8 = 6;
const ARITH_REMAINDER: u8 = 7;
const ARITH_ADD: u8 = 8;
const ARITH_SUBTRACT: u8 = 9;
const ARITH_SHIFT_LEFT: u8 = 10;
const ARITH_SHIFT_RIGHT: u8 = 11;
const ARITH_LESS: u8 = 12;
const ARITH_LESS_EQUAL: u8 = 13;
const ARITH_GREATER: u8 = 14;
const ARITH_GREATER_EQUAL: u8 = 15;
const ARITH_EQUAL: u8 = 16;
const ARITH_NOT_EQUAL: u8 = 17;
const ARITH_BIT_AND: u8 = 18;
const ARITH_BIT_XOR: u8 = 19;
const ARITH_BIT_OR: u8 = 20;
const ARITH_LOGICAL_AND: u8 = 21;
const ARITH_LOGICAL_OR: u8 = 22;
const ARITH_ASSIGN: u8 = 23;
const ARITH_OPEN: u8 = 24;
const ARITH_QUESTION: u8 = 25;
const ARITH_SELECT: u8 = 26;
const ARITH_MULTIPLY_ASSIGN: u8 = 27;
const ARITH_DIVIDE_ASSIGN: u8 = 28;
const ARITH_REMAINDER_ASSIGN: u8 = 29;
const ARITH_ADD_ASSIGN: u8 = 30;
const ARITH_SUBTRACT_ASSIGN: u8 = 31;
const ARITH_SHIFT_LEFT_ASSIGN: u8 = 32;
const ARITH_SHIFT_RIGHT_ASSIGN: u8 = 33;
const ARITH_BIT_AND_ASSIGN: u8 = 34;
const ARITH_BIT_XOR_ASSIGN: u8 = 35;
const ARITH_BIT_OR_ASSIGN: u8 = 36;

#[derive(Clone, Copy)]
struct ArithmeticNode {
    kind: u8,
    operator: u8,
    name: Span,
    value: i64,
    first: usize,
    second: usize,
    third: usize,
}

#[derive(Clone, Copy)]
struct ArithmeticOperator {
    operator: u8,
}

struct ArithmeticParser<'a> {
    source: &'a [u8],
    nodes: HeapVec<ArithmeticNode>,
    values: HeapVec<usize>,
    operators: HeapVec<ArithmeticOperator>,
}

impl<'a> ArithmeticParser<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            nodes: HeapVec::new(),
            values: HeapVec::new(),
            operators: HeapVec::new(),
        }
    }

    fn append_node(&mut self, node: ArithmeticNode) -> Result<usize, WordexpError> {
        let index = self.nodes.len();
        self.nodes.push(node)?;
        Ok(index)
    }

    fn reduce_top(&mut self) -> Result<(), WordexpError> {
        let operator = self.operators.pop().ok_or(WordexpError::Arithmetic)?.operator;
        let node = if matches!(
            operator,
            ARITH_POSITIVE | ARITH_NEGATIVE | ARITH_NOT | ARITH_COMPLEMENT
        ) {
            let first = self.values.pop().ok_or(WordexpError::Arithmetic)?;
            ArithmeticNode {
                kind: ARITH_UNARY, operator, name: Span::empty(0), value: 0,
                first, second: NONE, third: NONE,
            }
        } else if operator == ARITH_SELECT {
            let third = self.values.pop().ok_or(WordexpError::Arithmetic)?;
            let second = self.values.pop().ok_or(WordexpError::Arithmetic)?;
            let first = self.values.pop().ok_or(WordexpError::Arithmetic)?;
            ArithmeticNode {
                kind: ARITH_CONDITIONAL, operator, name: Span::empty(0), value: 0,
                first, second, third,
            }
        } else if operator == ARITH_OPEN || operator == ARITH_QUESTION {
            return Err(WordexpError::Arithmetic);
        } else {
            let second = self.values.pop().ok_or(WordexpError::Arithmetic)?;
            let first = self.values.pop().ok_or(WordexpError::Arithmetic)?;
            ArithmeticNode {
                kind: ARITH_BINARY, operator, name: Span::empty(0), value: 0,
                first, second, third: NONE,
            }
        };
        let index = self.append_node(node)?;
        self.values.push(index)
    }

    fn push_operator(&mut self, operator: u8) -> Result<(), WordexpError> {
        let precedence = arithmetic_precedence(operator);
        loop {
            let Some(top) = self.operators.pop() else { break; };
            if matches!(top.operator, ARITH_OPEN | ARITH_QUESTION) {
                self.operators.push(top)?;
                break;
            }
            let top_precedence = arithmetic_precedence(top.operator);
            let reduce = top_precedence > precedence ||
                (top_precedence == precedence && !arithmetic_right_associative(operator));
            if !reduce {
                self.operators.push(top)?;
                break;
            }
            self.operators.push(top)?;
            self.reduce_top()?;
        }
        self.operators.push(ArithmeticOperator { operator })
    }

    /// A conditional marker sits below its middle arm. Reduce tighter
    /// operators first, but retain an equal-precedence enclosing conditional
    /// so nested conditionals remain right-associative.
    fn push_question(&mut self) -> Result<(), WordexpError> {
        let precedence = arithmetic_precedence(ARITH_SELECT);
        loop {
            let Some(top) = self.operators.pop() else { break; };
            if matches!(top.operator, ARITH_OPEN | ARITH_QUESTION) {
                self.operators.push(top)?;
                break;
            }
            if arithmetic_precedence(top.operator) <= precedence {
                self.operators.push(top)?;
                break;
            }
            self.operators.push(top)?;
            self.reduce_top()?;
        }
        self.operators.push(ArithmeticOperator { operator: ARITH_QUESTION })
    }

    fn close_parenthesis(&mut self) -> Result<(), WordexpError> {
        loop {
            let top = self.operators.pop().ok_or(WordexpError::Arithmetic)?;
            if top.operator == ARITH_OPEN { return Ok(()); }
            if top.operator == ARITH_QUESTION { return Err(WordexpError::Arithmetic); }
            self.operators.push(top)?;
            self.reduce_top()?;
        }
    }

    fn select_colon(&mut self) -> Result<(), WordexpError> {
        loop {
            let top = self.operators.pop().ok_or(WordexpError::Arithmetic)?;
            if top.operator == ARITH_QUESTION { break; }
            if top.operator == ARITH_OPEN { return Err(WordexpError::Arithmetic); }
            self.operators.push(top)?;
            self.reduce_top()?;
        }
        // Do not route this through generic precedence reduction: the
        // marker must keep the just-finished middle arm paired with its
        // matching question mark before any enclosing operator can consume it.
        self.operators.push(ArithmeticOperator { operator: ARITH_SELECT })
    }

    fn parse(mut self) -> Result<(HeapVec<ArithmeticNode>, usize), WordexpError> {
        let mut index = 0usize;
        let mut want_value = true;
        let mut saw_value = false;
        while index < self.source.len() {
            while index < self.source.len() && arithmetic_space(self.source[index]) {
                index += 1;
            }
            if index == self.source.len() { break; }
            let byte = self.source[index];
            if want_value {
                if byte == b'(' {
                    self.operators.push(ArithmeticOperator { operator: ARITH_OPEN })?;
                    index += 1;
                    continue;
                }
                if byte == b'-' && index + 1 < self.source.len() &&
                    self.source[index + 1].is_ascii_digit()
                {
                    // Parse signed literals as one token so the one
                    // representable magnitude beyond i64::MAX maps to MIN.
                    let (value, after) = scan_arithmetic_integer(self.source, index, true)?;
                    index = after;
                    let value = self.append_node(ArithmeticNode {
                        kind: ARITH_NUMBER,
                        operator: 0,
                        name: Span::empty(0),
                        value,
                        first: NONE,
                        second: NONE,
                        third: NONE,
                    })?;
                    self.values.push(value)?;
                    saw_value = true;
                    want_value = false;
                    continue;
                }
                let unary = match byte {
                    b'+' => Some(ARITH_POSITIVE),
                    b'-' => Some(ARITH_NEGATIVE),
                    b'!' => Some(ARITH_NOT),
                    b'~' => Some(ARITH_COMPLEMENT),
                    _ => None,
                };
                if let Some(unary) = unary {
                    self.push_operator(unary)?;
                    index += 1;
                    continue;
                }
                let value = if byte.is_ascii_digit() {
                    let (value, after) = scan_arithmetic_integer(self.source, index, false)?;
                    index = after;
                    self.append_node(ArithmeticNode {
                        kind: ARITH_NUMBER,
                        operator: 0,
                        name: Span::empty(0),
                        value,
                        first: NONE,
                        second: NONE,
                        third: NONE,
                    })?
                } else if identifier_start(byte) {
                    let start = index;
                    index += 1;
                    while index < self.source.len() && identifier_continue(self.source[index]) {
                        index += 1;
                    }
                    self.append_node(ArithmeticNode {
                        kind: ARITH_IDENTIFIER,
                        operator: 0,
                        name: Span {
                            start,
                            end: index,
                        },
                        value: 0,
                        first: NONE,
                        second: NONE,
                        third: NONE,
                    })?
                } else {
                    return Err(WordexpError::Arithmetic);
                };
                self.values.push(value)?;
                saw_value = true;
                want_value = false;
                continue;
            }

            if byte == b')' {
                self.close_parenthesis()?;
                index += 1;
                continue;
            }
            if byte == b'?' {
                self.push_question()?;
                index += 1;
                want_value = true;
                continue;
            }
            if byte == b':' {
                self.select_colon()?;
                index += 1;
                want_value = true;
                continue;
            }
            let (operator, after) = arithmetic_binary_operator(self.source, index)?;
            self.push_operator(operator)?;
            index = after;
            want_value = true;
        }
        if want_value || !saw_value { return Err(WordexpError::Arithmetic); }
        while let Some(operator) = self.operators.pop() {
            if matches!(operator.operator, ARITH_OPEN | ARITH_QUESTION) {
                return Err(WordexpError::Arithmetic);
            }
            self.operators.push(operator)?;
            self.reduce_top()?;
        }
        if self.values.len() != 1 { return Err(WordexpError::Arithmetic); }
        let root = self.values.pop().ok_or(WordexpError::Arithmetic)?;
        Ok((self.nodes, root))
    }
}

#[inline]
const fn arithmetic_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

#[inline]
const fn arithmetic_precedence(operator: u8) -> u8 {
    match operator {
        ARITH_ASSIGN | ARITH_MULTIPLY_ASSIGN | ARITH_DIVIDE_ASSIGN |
        ARITH_REMAINDER_ASSIGN | ARITH_ADD_ASSIGN | ARITH_SUBTRACT_ASSIGN |
        ARITH_SHIFT_LEFT_ASSIGN | ARITH_SHIFT_RIGHT_ASSIGN |
        ARITH_BIT_AND_ASSIGN | ARITH_BIT_XOR_ASSIGN | ARITH_BIT_OR_ASSIGN => 1,
        ARITH_SELECT => 2,
        ARITH_LOGICAL_OR => 3,
        ARITH_LOGICAL_AND => 4,
        ARITH_BIT_OR => 5,
        ARITH_BIT_XOR => 6,
        ARITH_BIT_AND => 7,
        ARITH_EQUAL | ARITH_NOT_EQUAL => 8,
        ARITH_LESS | ARITH_LESS_EQUAL | ARITH_GREATER | ARITH_GREATER_EQUAL => 9,
        ARITH_SHIFT_LEFT | ARITH_SHIFT_RIGHT => 10,
        ARITH_ADD | ARITH_SUBTRACT => 11,
        ARITH_MULTIPLY | ARITH_DIVIDE | ARITH_REMAINDER => 12,
        ARITH_POSITIVE | ARITH_NEGATIVE | ARITH_NOT | ARITH_COMPLEMENT => 13,
        _ => 0,
    }
}

#[inline]
const fn arithmetic_right_associative(operator: u8) -> bool {
    matches!(
        operator,
        ARITH_ASSIGN | ARITH_MULTIPLY_ASSIGN | ARITH_DIVIDE_ASSIGN |
        ARITH_REMAINDER_ASSIGN | ARITH_ADD_ASSIGN | ARITH_SUBTRACT_ASSIGN |
        ARITH_SHIFT_LEFT_ASSIGN | ARITH_SHIFT_RIGHT_ASSIGN |
        ARITH_BIT_AND_ASSIGN | ARITH_BIT_XOR_ASSIGN | ARITH_BIT_OR_ASSIGN |
        ARITH_SELECT |
        ARITH_POSITIVE | ARITH_NEGATIVE | ARITH_NOT | ARITH_COMPLEMENT
    )
}

fn arithmetic_binary_operator(
    source: &[u8],
    index: usize,
) -> Result<(u8, usize), WordexpError> {
    let byte = source[index];
    let next = if index + 1 < source.len() { Some(source[index + 1]) } else { None };
    let pair = |operator| Ok((operator, index + 2));
    match byte {
        b'*' => if next == Some(b'=') { pair(ARITH_MULTIPLY_ASSIGN) }
            else { Ok((ARITH_MULTIPLY, index + 1)) },
        b'/' => if next == Some(b'=') { pair(ARITH_DIVIDE_ASSIGN) }
            else { Ok((ARITH_DIVIDE, index + 1)) },
        b'%' => if next == Some(b'=') { pair(ARITH_REMAINDER_ASSIGN) }
            else { Ok((ARITH_REMAINDER, index + 1)) },
        b'+' => if next == Some(b'+') { Err(WordexpError::Arithmetic) }
            else if next == Some(b'=') { pair(ARITH_ADD_ASSIGN) }
            else { Ok((ARITH_ADD, index + 1)) },
        b'-' => if next == Some(b'-') { Err(WordexpError::Arithmetic) }
            else if next == Some(b'=') { pair(ARITH_SUBTRACT_ASSIGN) }
            else { Ok((ARITH_SUBTRACT, index + 1)) },
        b'<' => if next == Some(b'<') {
                if index + 2 < source.len() && source[index + 2] == b'=' {
                    Ok((ARITH_SHIFT_LEFT_ASSIGN, index + 3))
                } else {
                    pair(ARITH_SHIFT_LEFT)
                }
            }
            else if next == Some(b'=') { pair(ARITH_LESS_EQUAL) }
            else { Ok((ARITH_LESS, index + 1)) },
        b'>' => if next == Some(b'>') {
                if index + 2 < source.len() && source[index + 2] == b'=' {
                    Ok((ARITH_SHIFT_RIGHT_ASSIGN, index + 3))
                } else {
                    pair(ARITH_SHIFT_RIGHT)
                }
            }
            else if next == Some(b'=') { pair(ARITH_GREATER_EQUAL) }
            else { Ok((ARITH_GREATER, index + 1)) },
        b'=' => if next == Some(b'=') { pair(ARITH_EQUAL) }
            else { Ok((ARITH_ASSIGN, index + 1)) },
        b'!' => if next == Some(b'=') { pair(ARITH_NOT_EQUAL) }
            else { Err(WordexpError::Arithmetic) },
        b'&' => if next == Some(b'&') { pair(ARITH_LOGICAL_AND) }
            else if next == Some(b'=') { pair(ARITH_BIT_AND_ASSIGN) }
            else { Ok((ARITH_BIT_AND, index + 1)) },
        b'|' => if next == Some(b'|') { pair(ARITH_LOGICAL_OR) }
            else if next == Some(b'=') { pair(ARITH_BIT_OR_ASSIGN) }
            else { Ok((ARITH_BIT_OR, index + 1)) },
        b'^' => if next == Some(b'=') { pair(ARITH_BIT_XOR_ASSIGN) }
            else { Ok((ARITH_BIT_XOR, index + 1)) },
        _ => Err(WordexpError::Arithmetic),
    }
}

fn scan_arithmetic_integer(
    source: &[u8],
    mut index: usize,
    allow_sign: bool,
) -> Result<(i64, usize), WordexpError> {
    let mut negative = false;
    if allow_sign && index < source.len() && matches!(source[index], b'+' | b'-') {
        negative = source[index] == b'-';
        index += 1;
    }
    if index >= source.len() || !source[index].is_ascii_digit() {
        return Err(WordexpError::Arithmetic);
    }
    let mut base = 10u64;
    if source[index] == b'0' && index + 1 < source.len() &&
        matches!(source[index + 1], b'x' | b'X')
    {
        base = 16;
        index += 2;
    } else if source[index] == b'0' && index + 1 < source.len() &&
        source[index + 1].is_ascii_digit()
    {
        // POSIX arithmetic constants retain the shell's leading-zero octal
        // spelling. An 8 or 9 is rejected by the digit/base check below.
        base = 8;
    }
    let start = index;
    let mut magnitude = 0u64;
    while index < source.len() {
        let digit = match source[index] {
            b'0'..=b'9' => (source[index] - b'0') as u64,
            b'a'..=b'f' if base == 16 => (source[index] - b'a' + 10) as u64,
            b'A'..=b'F' if base == 16 => (source[index] - b'A' + 10) as u64,
            _ => break,
        };
        if digit >= base { return Err(WordexpError::Arithmetic); }
        magnitude = magnitude.checked_mul(base)
            .and_then(|prior| prior.checked_add(digit))
            .ok_or(WordexpError::ArithmeticOverflow)?;
        index += 1;
    }
    if index == start { return Err(WordexpError::Arithmetic); }
    let value = if negative {
        if magnitude == (1u64 << 63) {
            i64::MIN
        } else if magnitude <= i64::MAX as u64 {
            -(magnitude as i64)
        } else {
            return Err(WordexpError::ArithmeticOverflow);
        }
    } else if magnitude <= i64::MAX as u64 {
        magnitude as i64
    } else {
        return Err(WordexpError::ArithmeticOverflow);
    };
    Ok((value, index))
}

fn parse_arithmetic_variable_value(value: &[u8]) -> Result<i64, WordexpError> {
    let mut start = 0usize;
    let mut end = value.len();
    while start < end && arithmetic_space(value[start]) { start += 1; }
    while end > start && arithmetic_space(value[end - 1]) { end -= 1; }
    if start == end { return Ok(0); }
    let (number, after) = scan_arithmetic_integer(&value[start..end], 0, true)?;
    if after != end - start { return Err(WordexpError::Arithmetic); }
    Ok(number)
}

#[derive(Clone, Copy)]
struct ArithmeticEvalFrame {
    node: usize,
    state: u8,
    left: i64,
}

fn arithmetic_assignment(
    context: &mut WordexpContext,
    name: &[u8],
    value: i64,
) -> Result<(), WordexpError> {
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut bytes = [0u8; 20];
    let mut count = 0usize;
    loop {
        bytes[count] = b'0' + (magnitude % 10) as u8;
        count += 1;
        magnitude /= 10;
        if magnitude == 0 { break; }
    }
    let mut rendered = [0u8; 20];
    let mut length = 0usize;
    if negative {
        rendered[length] = b'-';
        length += 1;
    }
    while count != 0 {
        count -= 1;
        rendered[length] = bytes[count];
        length += 1;
    }
    context.assign_local(name, &rendered[..length])
}

fn arithmetic_binary(
    operator: u8,
    left: i64,
    right: i64,
) -> Result<i64, WordexpError> {
    let boolean = |value: bool| if value { 1 } else { 0 };
    match operator {
        ARITH_MULTIPLY => left.checked_mul(right).ok_or(WordexpError::ArithmeticOverflow),
        ARITH_DIVIDE => if right == 0 { Err(WordexpError::Arithmetic) }
            else { left.checked_div(right).ok_or(WordexpError::ArithmeticOverflow) },
        ARITH_REMAINDER => if right == 0 { Err(WordexpError::Arithmetic) }
            else { left.checked_rem(right).ok_or(WordexpError::ArithmeticOverflow) },
        ARITH_ADD => left.checked_add(right).ok_or(WordexpError::ArithmeticOverflow),
        ARITH_SUBTRACT => left.checked_sub(right).ok_or(WordexpError::ArithmeticOverflow),
        ARITH_SHIFT_LEFT => {
            if !(0..64).contains(&right) { return Err(WordexpError::Arithmetic); }
            let shifted = left.wrapping_shl(right as u32);
            // Checked signed scaling accepts negative input when its exact
            // signed result fits, and rejects every lost high bit.
            if shifted >> right as u32 != left {
                Err(WordexpError::ArithmeticOverflow)
            } else {
                Ok(shifted)
            }
        }
        ARITH_SHIFT_RIGHT => {
            if !(0..64).contains(&right) { return Err(WordexpError::Arithmetic); }
            Ok(left >> right as u32)
        }
        ARITH_LESS => Ok(boolean(left < right)),
        ARITH_LESS_EQUAL => Ok(boolean(left <= right)),
        ARITH_GREATER => Ok(boolean(left > right)),
        ARITH_GREATER_EQUAL => Ok(boolean(left >= right)),
        ARITH_EQUAL => Ok(boolean(left == right)),
        ARITH_NOT_EQUAL => Ok(boolean(left != right)),
        ARITH_BIT_AND => Ok(left & right),
        ARITH_BIT_XOR => Ok(left ^ right),
        ARITH_BIT_OR => Ok(left | right),
        _ => Err(WordexpError::Arithmetic),
    }
}

#[inline]
const fn arithmetic_is_assignment(operator: u8) -> bool {
    matches!(
        operator,
        ARITH_ASSIGN | ARITH_MULTIPLY_ASSIGN | ARITH_DIVIDE_ASSIGN |
        ARITH_REMAINDER_ASSIGN | ARITH_ADD_ASSIGN | ARITH_SUBTRACT_ASSIGN |
        ARITH_SHIFT_LEFT_ASSIGN | ARITH_SHIFT_RIGHT_ASSIGN |
        ARITH_BIT_AND_ASSIGN | ARITH_BIT_XOR_ASSIGN | ARITH_BIT_OR_ASSIGN
    )
}

#[inline]
const fn arithmetic_compound_base(operator: u8) -> Option<u8> {
    match operator {
        ARITH_MULTIPLY_ASSIGN => Some(ARITH_MULTIPLY),
        ARITH_DIVIDE_ASSIGN => Some(ARITH_DIVIDE),
        ARITH_REMAINDER_ASSIGN => Some(ARITH_REMAINDER),
        ARITH_ADD_ASSIGN => Some(ARITH_ADD),
        ARITH_SUBTRACT_ASSIGN => Some(ARITH_SUBTRACT),
        ARITH_SHIFT_LEFT_ASSIGN => Some(ARITH_SHIFT_LEFT),
        ARITH_SHIFT_RIGHT_ASSIGN => Some(ARITH_SHIFT_RIGHT),
        ARITH_BIT_AND_ASSIGN => Some(ARITH_BIT_AND),
        ARITH_BIT_XOR_ASSIGN => Some(ARITH_BIT_XOR),
        ARITH_BIT_OR_ASSIGN => Some(ARITH_BIT_OR),
        _ => None,
    }
}

fn evaluate_arithmetic(
    source: &[u8],
    context: &mut WordexpContext,
) -> Result<i64, WordexpError> {
    let parser = ArithmeticParser::new(source);
    let (nodes, root) = parser.parse()?;
    let mut frames = HeapVec::<ArithmeticEvalFrame>::new();
    let mut values = HeapVec::<i64>::new();
    frames.push(ArithmeticEvalFrame { node: root, state: 0, left: 0 })?;
    while let Some(frame) = frames.pop() {
        // SAFETY: every frame node is created by this parser.
        let node = unsafe { nodes.get(frame.node) };
        match node.kind {
            ARITH_NUMBER => values.push(node.value)?,
            ARITH_IDENTIFIER => {
                let name = &source[node.name.start..node.name.end];
                let value = context.lookup_identifier(name);
                if !value.is_set() {
                    values.push(0)?;
                } else {
                    values.push(parse_arithmetic_variable_value(context.value_bytes(value))?)?;
                }
            }
            ARITH_UNARY => {
                if frame.state == 0 {
                    frames.push(ArithmeticEvalFrame {
                        node: frame.node, state: 1, left: 0,
                    })?;
                    frames.push(ArithmeticEvalFrame {
                        node: node.first, state: 0, left: 0,
                    })?;
                    continue;
                }
                let value = values.pop().ok_or(WordexpError::Arithmetic)?;
                let result = match node.operator {
                    ARITH_POSITIVE => value,
                    ARITH_NEGATIVE => value.checked_neg().ok_or(WordexpError::ArithmeticOverflow)?,
                    ARITH_NOT => if value == 0 { 1 } else { 0 },
                    ARITH_COMPLEMENT => !value,
                    _ => return Err(WordexpError::Arithmetic),
                };
                values.push(result)?;
            }
            ARITH_BINARY if arithmetic_is_assignment(node.operator) => {
                if frame.state == 0 {
                    // SAFETY: first is a parser-created node id.
                    let left = unsafe { nodes.get(node.first) };
                    if left.kind != ARITH_IDENTIFIER {
                        return Err(WordexpError::Arithmetic);
                    }
                    frames.push(ArithmeticEvalFrame {
                        node: frame.node, state: 1, left: 0,
                    })?;
                    frames.push(ArithmeticEvalFrame {
                        node: node.second, state: 0, left: 0,
                    })?;
                    continue;
                }
                let value = values.pop().ok_or(WordexpError::Arithmetic)?;
                // SAFETY: first is a parser-created identifier node.
                let left = unsafe { nodes.get(node.first) };
                let name = &source[left.name.start..left.name.end];
                let assigned = if let Some(base) = arithmetic_compound_base(node.operator) {
                    let prior = context.lookup_identifier(name);
                    let left_value = if prior.is_set() {
                        parse_arithmetic_variable_value(context.value_bytes(prior))?
                    } else {
                        0
                    };
                    arithmetic_binary(base, left_value, value)?
                } else {
                    value
                };
                arithmetic_assignment(context, name, assigned)?;
                values.push(assigned)?;
            }
            ARITH_BINARY => {
                if frame.state == 0 {
                    frames.push(ArithmeticEvalFrame {
                        node: frame.node, state: 1, left: 0,
                    })?;
                    frames.push(ArithmeticEvalFrame {
                        node: node.first, state: 0, left: 0,
                    })?;
                    continue;
                }
                if frame.state == 1 {
                    let left = values.pop().ok_or(WordexpError::Arithmetic)?;
                    if node.operator == ARITH_LOGICAL_AND && left == 0 {
                        values.push(0)?;
                        continue;
                    }
                    if node.operator == ARITH_LOGICAL_OR && left != 0 {
                        values.push(1)?;
                        continue;
                    }
                    frames.push(ArithmeticEvalFrame {
                        node: frame.node, state: 2, left,
                    })?;
                    frames.push(ArithmeticEvalFrame {
                        node: node.second, state: 0, left: 0,
                    })?;
                    continue;
                }
                let right = values.pop().ok_or(WordexpError::Arithmetic)?;
                let result = if node.operator == ARITH_LOGICAL_AND {
                    if right == 0 { 0 } else { 1 }
                } else if node.operator == ARITH_LOGICAL_OR {
                    if right == 0 { 0 } else { 1 }
                } else {
                    arithmetic_binary(node.operator, frame.left, right)?
                };
                values.push(result)?;
            }
            ARITH_CONDITIONAL => {
                if frame.state == 0 {
                    frames.push(ArithmeticEvalFrame {
                        node: frame.node, state: 1, left: 0,
                    })?;
                    frames.push(ArithmeticEvalFrame {
                        node: node.first, state: 0, left: 0,
                    })?;
                    continue;
                }
                if frame.state == 1 {
                    let condition = values.pop().ok_or(WordexpError::Arithmetic)?;
                    frames.push(ArithmeticEvalFrame {
                        node: frame.node, state: 2, left: 0,
                    })?;
                    frames.push(ArithmeticEvalFrame {
                        node: if condition != 0 { node.second } else { node.third },
                        state: 0,
                        left: 0,
                    })?;
                    continue;
                }
            }
            _ => return Err(WordexpError::Arithmetic),
        }
    }
    if values.len() != 1 { return Err(WordexpError::Arithmetic); }
    values.pop().ok_or(WordexpError::Arithmetic)
}

fn parameter_condition(value: StoredValue, colon: bool) -> bool {
    value.is_set() && (!colon || value.bytes.len() != 0)
}

fn start_parameter(
    syntax: &WordexpSyntax,
    context: &mut WordexpContext,
    paths: &mut dyn WordexpPathAdapter,
    scratch: &mut ScratchWords,
    tasks: &mut HeapVec<EvaluationTask>,
    task: EvaluationTask,
    node: SyntaxNode,
    next: usize,
) -> Result<(), WordexpError> {
    // SAFETY: node payload refers to syntax-owned parameter metadata.
    let parameter = unsafe { syntax.parameter(node.payload) };
    // SAFETY: parameter name is a syntax-owned byte span.
    let name = unsafe { syntax.bytes(parameter.name) };
    let value = context.lookup(name, parameter.kind);
    let colon = parameter.flags & PARAM_COLON != 0;
    let selected = parameter_condition(value, colon);
    let output_flags = expansion_atom_flags(node.flags);
    if parameter.length {
        if !value.is_set() && context.undefined_is_error {
            return Err(WordexpError::UndefinedVariable);
        }
        let length = if value.is_set() {
            character_count(context.value_bytes(value), context.locale_mode())
        } else {
            0
        };
        append_decimal(length, output_flags, unsafe { &mut *task.target })?;
        tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        return Ok(());
    }
    match parameter.operator {
        PARAM_NONE => {
            if !value.is_set() && context.undefined_is_error {
                return Err(WordexpError::UndefinedVariable);
            }
            append_stored_value(context, value, output_flags, unsafe { &mut *task.target })?;
            tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        }
        PARAM_DEFAULT if !selected => {
            push_parameter_word(
                syntax, scratch, tasks, task, next, node.payload, node.flags,
                EvaluationContext::ParameterWord,
            )?;
        }
        PARAM_DEFAULT => {
            append_stored_value(context, value, output_flags, unsafe { &mut *task.target })?;
            tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        }
        PARAM_ALTERNATE if selected => {
            push_parameter_word(
                syntax, scratch, tasks, task, next, node.payload, node.flags,
                EvaluationContext::ParameterWord,
            )?;
        }
        PARAM_ALTERNATE => {
            unsafe { &mut *task.target }.append(
                &[],
                output_flags,
                node.flags & NODE_QUOTED != 0,
            )?;
            tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        }
        PARAM_ASSIGN if !selected => {
            if parameter.kind != PARAM_IDENTIFIER { return Err(WordexpError::Syntax); }
            push_parameter_word(
                syntax, scratch, tasks, task, next, node.payload, node.flags,
                EvaluationContext::AssignmentValue,
            )?;
        }
        PARAM_ASSIGN => {
            append_stored_value(context, value, output_flags, unsafe { &mut *task.target })?;
            tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        }
        PARAM_ERROR if !selected => return Err(WordexpError::ParameterError),
        PARAM_ERROR => {
            append_stored_value(context, value, output_flags, unsafe { &mut *task.target })?;
            tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        }
        PARAM_REMOVE_PREFIX | PARAM_REMOVE_LONGEST_PREFIX |
        PARAM_REMOVE_SUFFIX | PARAM_REMOVE_LONGEST_SUFFIX if value.is_set() => {
            push_parameter_word(
                syntax, scratch, tasks, task, next, node.payload, node.flags,
                EvaluationContext::PatternOperand,
            )?;
        }
        PARAM_REMOVE_PREFIX | PARAM_REMOVE_LONGEST_PREFIX |
        PARAM_REMOVE_SUFFIX | PARAM_REMOVE_LONGEST_SUFFIX => {
            if context.undefined_is_error { return Err(WordexpError::UndefinedVariable); }
            unsafe { &mut *task.target }.append(
                &[],
                output_flags,
                node.flags & NODE_QUOTED != 0,
            )?;
            tasks.push(EvaluationTask::word(task.word, next, task.target, task.context))?;
        }
        _ => return Err(WordexpError::Syntax),
    }
    let _ = paths;
    Ok(())
}

fn push_parameter_word(
    syntax: &WordexpSyntax,
    scratch: &mut ScratchWords,
    tasks: &mut HeapVec<EvaluationTask>,
    parent: EvaluationTask,
    next: usize,
    parameter: usize,
    node_flags: u8,
    context: EvaluationContext,
) -> Result<(), WordexpError> {
    // SAFETY: parameter comes from one syntax node payload.
    let parameter_record = unsafe { syntax.parameter(parameter) };
    if parameter_record.word == NONE { return Err(WordexpError::Syntax); }
    let temporary = scratch.allocate()?;
    // Continuation is pushed first so the LIFO stack evaluates the selected
    // source branch, performs its operator action, then resumes the caller.
    tasks.push(EvaluationTask::word(parent.word, next, parent.target, parent.context))?;
    tasks.push(EvaluationTask::finish_parameter(
        parent.target, parameter, temporary, node_flags, context,
    ))?;
    // SAFETY: child word id is parser-created.
    let child = unsafe { syntax.word(parameter_record.word) };
    tasks.push(EvaluationTask::word(parameter_record.word, child.first, temporary, context))?;
    Ok(())
}

fn finish_parameter(
    syntax: &WordexpSyntax,
    context: &mut WordexpContext,
    paths: &mut dyn WordexpPathAdapter,
    scratch: &mut ScratchWords,
    task: EvaluationTask,
) -> Result<(), WordexpError> {
    // SAFETY: temporary is scratch-owned and parameter is syntax-owned.
    let parameter = unsafe { syntax.parameter(task.parameter) };
    let result = match parameter.operator {
        PARAM_ASSIGN => {
            let mut value = HeapVec::new();
            unsafe { (*task.temporary).plain_bytes(&mut value)?; }
            // SAFETY: parameter name lives in syntax and value is copied before
            // any context growth can move context-owned bytes.
            context.assign_local(
                unsafe { syntax.bytes(parameter.name) },
                unsafe { value.as_slice() },
            )?;
            // The assignment operand's quotes build the stored value, but
            // they do not quote the result of the outer := expansion. Emit
            // that result from the assigned value under the outer node state.
            let assigned = context.lookup(
                unsafe { syntax.bytes(parameter.name) },
                parameter.kind,
            );
            append_stored_value(
                context,
                assigned,
                expansion_atom_flags(task.node_flags),
                unsafe { &mut *task.target },
            )
        }
        PARAM_REMOVE_PREFIX | PARAM_REMOVE_LONGEST_PREFIX |
        PARAM_REMOVE_SUFFIX | PARAM_REMOVE_LONGEST_SUFFIX => {
            // SAFETY: both source name and context value stay live during this
            // adapter call; the temporary owns its pattern atoms.
            let value = context.lookup(
                unsafe { syntax.bytes(parameter.name) },
                parameter.kind,
            );
            let bytes = context.value_bytes(value);
            let mut removed = ExpandedWord::new();
            let pattern = PatternInput {
                // SAFETY: the scratch operand remains live through this call.
                atoms: unsafe { (*task.temporary).atoms.as_slice() },
            };
            let mut output = ParameterPatternOutput { word: &mut removed };
            paths.remove_parameter_pattern(
                bytes,
                &pattern,
                parameter_pattern_operator(parameter.operator)?,
                &mut output,
            )?;
            if removed.atoms.is_empty() {
                if task.node_flags & NODE_QUOTED != 0 {
                    // An unquoted empty removal result vanishes; a quoted one
                    // is an explicit empty field, like other parameter output.
                    unsafe {
                        (*task.target).append(
                            &[], expansion_atom_flags(task.node_flags), true,
                        )
                    }
                } else {
                    Ok(())
                }
            } else {
                unsafe { (*task.target).append_parameter_result(&removed, task.node_flags) }
            }
        }
        PARAM_DEFAULT | PARAM_ALTERNATE => unsafe {
            (*task.target).append_parameter_result(&*task.temporary, task.node_flags)
        },
        _ => Err(WordexpError::Syntax),
    };
    if result.is_ok() {
        // SAFETY: success consumes the one private temporary allocation.
        unsafe { scratch.free(task.temporary); }
    }
    let _ = task.context;
    result
}

fn parameter_pattern_operator(operator: u8) -> Result<ParameterPatternOperator, WordexpError> {
    match operator {
        PARAM_REMOVE_PREFIX => Ok(ParameterPatternOperator::RemovePrefix),
        PARAM_REMOVE_LONGEST_PREFIX => Ok(ParameterPatternOperator::RemoveLongestPrefix),
        PARAM_REMOVE_SUFFIX => Ok(ParameterPatternOperator::RemoveSuffix),
        PARAM_REMOVE_LONGEST_SUFFIX => Ok(ParameterPatternOperator::RemoveLongestSuffix),
        _ => Err(WordexpError::Syntax),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCommands {
        calls: usize,
        expected_body: Option<&'static [u8]>,
        expected_style: Option<CommandStyle>,
        expected_prefix: Option<&'static [u8]>,
        expected_exports: Option<&'static [u8]>,
        result: &'static [u8],
    }

    impl TestCommands {
        const fn new(result: &'static [u8]) -> Self {
            Self {
                calls: 0,
                expected_body: None,
                expected_style: None,
                expected_prefix: None,
                expected_exports: None,
                result,
            }
        }
    }

    impl WordexpCommandAdapter for TestCommands {
        fn execute(
            &mut self,
            body: &[u8],
            style: CommandStyle,
            assignment_prefix: &[u8],
            exported_entries: &[u8],
            output: &mut CommandOutput<'_>,
        ) -> Result<(), WordexpError> {
            self.calls += 1;
            if let Some(expected) = self.expected_body {
                assert_eq!(body, expected);
            }
            if let Some(expected) = self.expected_style {
                assert_eq!(style, expected);
            }
            if let Some(expected) = self.expected_prefix {
                assert_eq!(assignment_prefix, expected);
            }
            if let Some(expected) = self.expected_exports {
                assert_eq!(exported_entries, expected);
            }
            output.append(self.result)
        }
    }

    struct TestPaths {
        pattern_calls: usize,
        match_patterns: bool,
        empty_parameter_pattern_result: bool,
    }

    impl TestPaths {
        const fn plain() -> Self {
            Self {
                pattern_calls: 0,
                match_patterns: false,
                empty_parameter_pattern_result: false,
            }
        }

        const fn matching() -> Self {
            Self {
                pattern_calls: 0,
                match_patterns: true,
                empty_parameter_pattern_result: false,
            }
        }

        const fn empty_parameter_pattern_result() -> Self {
            Self {
                pattern_calls: 0,
                match_patterns: false,
                empty_parameter_pattern_result: true,
            }
        }
    }

    impl WordexpPathAdapter for TestPaths {
        fn expand_tilde(
            &mut self,
            user: &[u8],
            home: Option<&[u8]>,
            output: &mut TildeOutput<'_>,
        ) -> Result<bool, WordexpError> {
            if user == b"tester" {
                output.append_home(b"/home/tester")?;
                Ok(true)
            } else if user.is_empty() {
                if let Some(home) = home {
                    output.append_home(home)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            } else {
                Ok(false)
            }
        }

        fn expand_pattern(
            &mut self,
            pattern: &PatternInput<'_>,
            output: &mut PathnameMatches<'_>,
        ) -> Result<bool, WordexpError> {
            self.pattern_calls += 1;
            if !self.match_patterns { return Ok(false); }
            let mut bytes = HeapVec::new();
            let mut index = 0usize;
            while index < pattern.len() {
                let atom = pattern.atom(index).ok_or(WordexpError::Syntax)?;
                if !atom.is_empty_marker() {
                    if matches!(atom.byte(), b'*' | b'?' | b'[') &&
                        !atom.is_pattern_eligible()
                    {
                        return Ok(false);
                    }
                    bytes.push(atom.byte())?;
                }
                index += 1;
            }
            if unsafe { bytes.as_slice() } != b"*.rs" { return Ok(false); }
            output.append_path(b"first.rs")?;
            output.append_path(b"second.rs")?;
            Ok(true)
        }

        fn remove_parameter_pattern(
            &mut self,
            value: &[u8],
            _pattern: &PatternInput<'_>,
            _operator: ParameterPatternOperator,
            output: &mut ParameterPatternOutput<'_>,
        ) -> Result<(), WordexpError> {
            if self.empty_parameter_pattern_result {
                output.append_bytes(b"")
            } else {
                output.append_bytes(value)
            }
        }
    }

    struct PatternOperandPaths {
        expected: &'static [(u8, bool)],
        operator: ParameterPatternOperator,
        calls: usize,
    }

    impl WordexpPathAdapter for PatternOperandPaths {
        fn expand_tilde(
            &mut self,
            _user: &[u8],
            _home: Option<&[u8]>,
            _output: &mut TildeOutput<'_>,
        ) -> Result<bool, WordexpError> {
            Ok(false)
        }

        fn expand_pattern(
            &mut self,
            _pattern: &PatternInput<'_>,
            _output: &mut PathnameMatches<'_>,
        ) -> Result<bool, WordexpError> {
            Ok(false)
        }

        fn remove_parameter_pattern(
            &mut self,
            value: &[u8],
            pattern: &PatternInput<'_>,
            operator: ParameterPatternOperator,
            output: &mut ParameterPatternOutput<'_>,
        ) -> Result<(), WordexpError> {
            assert_eq!(operator, self.operator);
            let mut expected = 0usize;
            let mut index = 0usize;
            while index < pattern.len() {
                let atom = pattern.atom(index).ok_or(WordexpError::Syntax)?;
                if !atom.is_empty_marker() {
                    assert!(expected < self.expected.len());
                    assert_eq!(
                        (atom.byte(), atom.is_pattern_eligible()),
                        self.expected[expected],
                    );
                    expected += 1;
                }
                index += 1;
            }
            assert_eq!(expected, self.expected.len());
            self.calls += 1;
            output.append_bytes(value)
        }
    }

    fn assert_words(words: &ExpandedWords, expected: &[&[u8]]) {
        assert_eq!(words.len(), expected.len());
        let mut index = 0usize;
        while index < expected.len() {
            let word = words.result_word(index).unwrap();
            assert_eq!(word.byte_len(), expected[index].len());
            let mut byte = 0usize;
            while byte < expected[index].len() {
                assert_eq!(word.byte_at(byte), Some(expected[index][byte]));
                byte += 1;
            }
            index += 1;
        }
    }

    fn evaluate(
        input: &[u8],
        context: &mut WordexpContext,
        commands: &mut TestCommands,
        paths: &mut TestPaths,
    ) -> Result<ExpandedWords, WordexpError> {
        let syntax = WordexpSyntax::parse(input)?;
        evaluate_wordexp(&syntax, context, commands, paths)
    }

    #[test]
    fn undefined_variable_covers_bare_quoted_and_braced_forms() {
        for input in [b"$MISSING".as_slice(), b"\"$MISSING\"".as_slice(), b"$\x7bMISSING}".as_slice()] {
            let mut context = WordexpContext::new();
            context.set_undefined_is_error(true);
            let mut commands = TestCommands::new(b"");
            let mut paths = TestPaths::plain();
            assert!(matches!(
                evaluate(input, &mut context, &mut commands, &mut paths),
                Err(WordexpError::UndefinedVariable),
            ));
            assert_eq!(commands.calls, 0);
        }
    }

    #[test]
    fn set_empty_is_distinct_from_unset_and_selected_parameter_words() {
        let mut context = WordexpContext::new();
        context.set_undefined_is_error(true);
        context.set_initial(b"EMPTY", Some(b""), false).unwrap();
        context.set_initial(b"SET", Some(b"present"), false).unwrap();
        let mut commands = TestCommands::new(b"unexpected");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"\"$EMPTY\" $\x7bMISSING-default} $\x7bSET:-$(unexpected)}",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"", b"default", b"present"]);
        assert_eq!(commands.calls, 0);

        let syntax = WordexpSyntax::parse(b"$\x7bMISSING:-$OTHER}").unwrap();
        assert!(matches!(
            evaluate_wordexp(&syntax, &mut context, &mut commands, &mut paths),
            Err(WordexpError::UndefinedVariable),
        ));
    }

    #[test]
    fn parameter_assignment_is_local_and_supplies_a_child_prefix() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"done\n");
        commands.expected_body = Some(b"selected");
        commands.expected_prefix = Some(b"VALUE='two words'\n");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7bVALUE:=two words} \"$(selected)\" \"$VALUE\"",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"two", b"words", b"done", b"two words"]);
        assert_eq!(commands.calls, 1);
    }

    #[test]
    fn exported_assignment_updates_each_selected_command_environment() {
        let mut context = WordexpContext::new();
        context.set_initial(b"EXPORTED", Some(b""), true).unwrap();
        let mut commands = TestCommands::new(b"ok\n");
        commands.expected_body = Some(b"selected");
        commands.expected_prefix = Some(b"");
        commands.expected_exports = Some(b"EXPORTED=new\0");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7bEXPORTED:=new} $(selected)",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"new", b"ok"]);
        assert_eq!(commands.calls, 1);
    }

    #[test]
    fn tilde_adapter_receives_current_call_local_home() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7bHOME:=/changed} ~",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"/changed", b"/changed"]);
    }

    #[test]
    fn tilde_home_bytes_are_quoted_before_pathname_expansion() {
        let mut context = WordexpContext::new();
        context.set_initial(b"HOME", Some(b"star*"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::matching();
        let words = evaluate(b"~", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"star*"]);
        assert_eq!(paths.pattern_calls, 0);
    }

    #[test]
    fn empty_home_keeps_bare_tilde_as_one_explicit_empty_field() {
        let mut context = WordexpContext::new();
        context.set_initial(b"HOME", Some(b""), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::matching();
        let words = evaluate(b"~", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b""]);
        assert_eq!(paths.pattern_calls, 0);
    }

    #[test]
    fn empty_parameter_pattern_results_follow_the_outer_quote_state() {
        let mut context = WordexpContext::new();
        context.set_initial(b"A", Some(b"a"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::empty_parameter_pattern_result();
        for input in [
            b"${A#a}".as_slice(),
            b"${A##a}".as_slice(),
            b"${A%a}".as_slice(),
            b"${A%%a}".as_slice(),
        ] {
            let result = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&result, &[]);
        }
        for input in [
            b"\"${A#a}\"".as_slice(),
            b"\"${A##a}\"".as_slice(),
            b"\"${A%a}\"".as_slice(),
            b"\"${A%%a}\"".as_slice(),
        ] {
            let result = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&result, &[b""]);
        }

        context.set_initial(b"A", Some(b"one two"), false).unwrap();
        let mut nonempty_paths = TestPaths::plain();
        let result = evaluate(b"${A#a}", &mut context, &mut commands, &mut nonempty_paths).unwrap();
        assert_words(&result, &[b"one", b"two"]);
        let result = evaluate(b"\"${A#a}\"", &mut context, &mut commands, &mut nonempty_paths).unwrap();
        assert_words(&result, &[b"one two"]);
    }

    #[test]
    fn parameter_pattern_operands_ignore_only_the_enclosing_double_quote() {
        const ACTIVE_STAR: &[(u8, bool)] = &[(b'*', true)];
        const QUOTED_STAR: &[(u8, bool)] = &[(b'*', false)];
        const QUOTED_RANGE_BYTE: &[(u8, bool)] = &[
            (b'[', true), (b'a', true), (b'-', false), (b'z', true), (b']', true),
        ];
        for (input, expected, operator) in [
            (
                b"\"${A#*}\"".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"\"${A#'*'}\"".as_slice(),
                QUOTED_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"${A#\"*\"}".as_slice(),
                QUOTED_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"\"${A#[a\"-\"z]}\"".as_slice(),
                QUOTED_RANGE_BYTE,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"\"${A#$PATTERN}\"".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"\"${A#\"$PATTERN\"}\"".as_slice(),
                QUOTED_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"${A#${PATTERN}}".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"\"${A#${PATTERN}}\"".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemovePrefix,
            ),
            (
                b"\"${A##*}\"".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemoveLongestPrefix,
            ),
            (
                b"\"${A%*}\"".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemoveSuffix,
            ),
            (
                b"\"${A%%*}\"".as_slice(),
                ACTIVE_STAR,
                ParameterPatternOperator::RemoveLongestSuffix,
            ),
        ] {
            let syntax = WordexpSyntax::parse(input).unwrap();
            let mut context = WordexpContext::new();
            context.set_initial(b"A", Some(b"abcabc"), false).unwrap();
            context.set_initial(b"PATTERN", Some(b"*"), false).unwrap();
            let mut commands = TestCommands::new(b"");
            let mut paths = PatternOperandPaths { expected, operator, calls: 0 };
            let words = evaluate_wordexp(&syntax, &mut context, &mut commands, &mut paths)
                .unwrap();
            assert_words(&words, &[b"abcabc"]);
            assert_eq!(paths.calls, 1);
        }

        let syntax = WordexpSyntax::parse(b"$(( ${A#'*'} ))").unwrap();
        let mut context = WordexpContext::new();
        context.set_initial(b"A", Some(b"1"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = PatternOperandPaths {
            expected: QUOTED_STAR,
            operator: ParameterPatternOperator::RemovePrefix,
            calls: 0,
        };
        let words = evaluate_wordexp(&syntax, &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"1"]);
        assert_eq!(paths.calls, 1);
    }

    #[test]
    fn parameter_word_delimiters_follow_the_outer_double_quote_rules() {
        for (input, expected) in [
            (b"\"${U:-\\}}\"".as_slice(), b"}".as_slice()),
            (b"\"${U:-\\{}\"".as_slice(), b"\\{".as_slice()),
            (b"\"${U:-\\a}\"".as_slice(), b"\\a".as_slice()),
            (b"\"${U:-'}'}\"".as_slice(), b"''}".as_slice()),
            (b"\"${U:-a'}'b}\"".as_slice(), b"a''b}".as_slice()),
            (b"\"${U:-\\$A}\"".as_slice(), b"$A".as_slice()),
            (b"\"${U:-\\`}\"".as_slice(), b"`".as_slice()),
            (b"${U:-\\}}".as_slice(), b"}".as_slice()),
            (b"${U:-'}'}".as_slice(), b"}".as_slice()),
            (b"\"${U:-\\\\}\"".as_slice(), b"\\".as_slice()),
        ] {
            let mut context = WordexpContext::new();
            let mut commands = TestCommands::new(b"");
            let mut paths = TestPaths::plain();
            let words = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&words, &[expected]);
        }
    }

    #[test]
    fn arithmetic_assignment_short_circuit_and_conditionals_are_lazy() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$((COUNT=2+3)) $((COUNT)) $((0 && (FAIL=1/0))) $((1 || (FAIL=1/0))) $((1 ? 7 : (FAIL=1/0)))",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"5", b"5", b"0", b"1", b"7"]);
        assert!(!context.lookup_identifier(b"FAIL").is_set());
        assert_eq!(commands.calls, 0);
    }

    #[test]
    fn skipped_arithmetic_assignments_leave_following_quoted_parameters_empty() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$((0 && (LEFT=9))) \"$LEFT\" $((1 || (RIGHT=9))) \"$RIGHT\"",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"0", b"", b"1", b""]);
        assert!(!context.lookup_identifier(b"LEFT").is_set());
        assert!(!context.lookup_identifier(b"RIGHT").is_set());
    }

    #[test]
    fn arithmetic_reports_an_independent_failure_and_direct_parameter_undef() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        assert!(matches!(
            evaluate(b"$((1/0))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::Arithmetic),
        ));
        context.set_undefined_is_error(true);
        assert!(matches!(
            evaluate(b"$(( $MISSING + 1 ))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::UndefinedVariable),
        ));
    }

    #[test]
    fn arithmetic_command_is_rejected_before_evaluation_or_delegated_once() {
        let syntax = WordexpSyntax::parse(b"$(( $(number) + 1 ))").unwrap();
        let mut blocked = WordexpContext::new();
        blocked.set_no_command_substitution(true);
        let mut commands = TestCommands::new(b"4\n");
        commands.expected_body = Some(b"number");
        let mut paths = TestPaths::plain();
        assert!(matches!(
            evaluate_wordexp(&syntax, &mut blocked, &mut commands, &mut paths),
            Err(WordexpError::CommandSubstitution),
        ));
        assert_eq!(commands.calls, 0);

        let mut allowed = WordexpContext::new();
        let words = evaluate_wordexp(&syntax, &mut allowed, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"5"]);
        assert_eq!(commands.calls, 1);
    }

    #[test]
    fn arithmetic_expands_all_selected_envelope_tokens_before_lazy_ast_evaluation() {
        for (input, expected) in [
            (b"$((0 && $(number)))".as_slice(), b"0".as_slice()),
            (b"$((1 || $(number)))".as_slice(), b"1".as_slice()),
            (b"$((1 ? 2 : $(number)))".as_slice(), b"2".as_slice()),
        ] {
            let mut context = WordexpContext::new();
            let mut commands = TestCommands::new(b"1\n");
            commands.expected_body = Some(b"number");
            let mut paths = TestPaths::plain();
            let words = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&words, &[expected]);
            assert_eq!(commands.calls, 1);
        }

        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$((V+$\x7bV:=3})) $((0 && $((N=3))))",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"6", b"0"]);
        assert_eq!(context.value_bytes(context.lookup_identifier(b"V")), b"3");
        assert_eq!(context.value_bytes(context.lookup_identifier(b"N")), b"3");
    }

    #[test]
    fn arithmetic_expansion_outputs_are_arithmetic_tokens_never_shell_source() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"1+2\n");
        commands.expected_body = Some(b"number");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$(( $(number) * 3))",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"7"]);
        assert_eq!(commands.calls, 1);

        let mut commands = TestCommands::new(b"$(second)\n");
        commands.expected_body = Some(b"number");
        assert!(matches!(
            evaluate(b"$(( $(number) ))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::Arithmetic),
        ));
        assert_eq!(commands.calls, 1);
    }

    #[test]
    fn arithmetic_undef_numbers_ternaries_compound_assignments_and_checked_shifts() {
        let mut context = WordexpContext::new();
        context.set_undefined_is_error(true);
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        assert!(matches!(
            evaluate(b"$((0 && $MISSING))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::UndefinedVariable),
        ));
        let words = evaluate(
            b"$((0 && MISSING)) $\x7bMISSING:-2}",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"0", b"2"]);

        context.set_undefined_is_error(false);
        let words = evaluate(
            b"$((010+0x10+10)) $((1+2?3:4)) $((A=8)) $((A*=2)) $((A/=2)) $((A%=3)) $((A+=4)) $((A-=1)) $((A<<=1)) $((A>>=1)) $((A&=3)) $((A^=6)) $((A|=8))",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(
            &words,
            &[
                b"34", b"3", b"8", b"16", b"8", b"2", b"6", b"5",
                b"10", b"5", b"1", b"7", b"15",
            ],
        );
        assert!(matches!(
            evaluate(b"$((08))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::Arithmetic),
        ));
        assert!(matches!(
            evaluate(b"$((1<<63))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::ArithmeticOverflow),
        ));
        let words = evaluate(
            b"$((0<<63)) $((-1<<63))",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"0", b"-9223372036854775808"]);
        assert!(matches!(
            evaluate(b"$((1<<64))", &mut context, &mut commands, &mut paths),
            Err(WordexpError::Arithmetic),
        ));

        context.set_initial(b"MIN", Some(b"-9223372036854775808"), false).unwrap();
        let words = evaluate(
            b"$((MIN)) $(( $MIN ))",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"-9223372036854775808", b"-9223372036854775808"]);
    }

    #[test]
    fn no_command_rejection_precedes_arithmetic_or_parameter_mutation() {
        let syntax = WordexpSyntax::parse(
            b"$\x7bV:=3} $((0 && $(blocked))) $\x7bSET:-$(not-selected)}",
        ).unwrap();
        let mut context = WordexpContext::new();
        context.set_initial(b"SET", Some(b"yes"), false).unwrap();
        context.set_no_command_substitution(true);
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        assert!(matches!(
            evaluate_wordexp(&syntax, &mut context, &mut commands, &mut paths),
            Err(WordexpError::CommandSubstitution),
        ));
        assert!(!context.lookup_identifier(b"V").is_set());
        assert_eq!(commands.calls, 0);
    }

    #[test]
    fn splitting_pattern_quoting_and_explicit_empty_are_preserved() {
        let mut context = WordexpContext::new();
        context.set_initial(b"VALUE", Some(b"one two"), false).unwrap();
        context.set_initial(b"EMPTY", Some(b""), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::matching();
        let words = evaluate(
            b"a$VALUE \"x$VALUE\" \"$EMPTY\" $EMPTY *.rs '*.rs'",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(
            &words,
            &[b"aone", b"two", b"xone two", b"", b"first.rs", b"second.rs", b"*.rs"],
        );
        assert_eq!(paths.pattern_calls, 1);
    }

    #[test]
    fn parameter_word_results_reflag_for_outer_splitting_and_keep_inner_quotes() {
        let mut context = WordexpContext::new();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7bVALUE:-two words}",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"two", b"words"]);

        let words = evaluate(
            b"$\x7bVALUE:=\"two words\"} \"$VALUE\"",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"two", b"words", b"two words"]);
        assert_eq!(context.value_bytes(context.lookup_identifier(b"VALUE")), b"two words");
    }

    #[test]
    fn parameter_length_preserves_named_special_and_positional_identity() {
        let mut context = WordexpContext::new();
        context.set_initial(b"VALUE", Some(b"hello"), false).unwrap();
        context.set_special(b"?", Some(b"42")).unwrap();
        context.set_special(b"12", Some(b"abc")).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7b#VALUE} $\x7b#?} $\x7b#12}",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"5", b"2", b"3"]);
    }

    #[test]
    fn field_delimiters_and_ordered_empty_quote_markers_follow_ifs_rules() {
        let mut context = WordexpContext::new();
        context.set_initial(b"SPACE", Some(b" a "), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"\"\"$SPACE $SPACE\"\"",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"", b"a", b"a", b""]);

        context.set_ifs(Some(b":")).unwrap();
        context.set_initial(b"COLON", Some(b"a:"), false).unwrap();
        let words = evaluate(
            b"\"\"$COLON $COLON\"\"",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"a", b"a", b""]);

        context.set_initial(b"FIELDS", Some(b"a:"), false).unwrap();
        context.set_initial(b"ONLY", Some(b":"), false).unwrap();
        context.set_initial(b"DOUBLE", Some(b"::"), false).unwrap();
        context.set_ifs(Some(b": ")).unwrap();
        context.set_initial(b"MIXED", Some(b"a : b"), false).unwrap();
        context.set_initial(b"TRAIL", Some(b"a: "), false).unwrap();
        let words = evaluate(
            b"$FIELDS $ONLY $DOUBLE $MIXED $TRAIL",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"a", b"", b"", b"", b"a", b"b", b"a"]);
    }

    #[test]
    fn ifs_assignment_uses_the_same_call_local_variable_state() {
        let mut context = WordexpContext::new();
        context.set_initial(b"VALUE", Some(b"a:b"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7bIFS:=:} $VALUE",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"", b"a", b"b"]);
        assert_eq!(context.value_bytes(context.lookup_identifier(b"IFS")), b":");
    }

    #[test]
    fn literals_progress_and_quote_aware_line_joining_do_not_reparse_shell_source() {
        let mut context = WordexpContext::new();
        context.set_initial(b"A", Some(b"joined"), false).unwrap();
        let mut commands = TestCommands::new(b"k\n");
        commands.expected_body = Some(b"printf k");
        let mut paths = TestPaths::matching();
        let words = evaluate(
            b"$ $= before~after \"$\" \"$=\" $\\\nA $\x7bA\\\n} $\\\n\x7bA} \\*.rs \x60printf k\x60",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(
            &words,
            &[
                b"$", b"$=", b"before~after", b"$", b"$=",
                b"joined", b"joined", b"joined", b"*.rs", b"k",
            ],
        );
        assert_eq!(paths.pattern_calls, 0);
        assert_eq!(commands.calls, 1);
    }

    #[test]
    fn double_quoted_parameter_words_and_tilde_prefix_boundaries_are_lexical() {
        let mut context = WordexpContext::new();
        context.set_initial(b"A", Some(b"set"), false).unwrap();
        context.set_initial(b"HOMEWORD", Some(b"one two"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"\"$\x7bUNSET:-a' b'}\" \"$\x7bA+'quoted'}\" ~\"$HOMEWORD\"",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"a' b'", b"'quoted'", b"~one two"]);
    }

    #[test]
    fn command_adapter_runs_once_only_when_the_selected_branch_evaluates() {
        let mut context = WordexpContext::new();
        context.set_initial(b"SET", Some(b"yes"), false).unwrap();
        let mut commands = TestCommands::new(b"line\n\n");
        commands.expected_body = Some(b"selected");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$\x7bSET:+$(selected)} $\x7bSET:-$(not-selected)}",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"line", b"yes"]);
        assert_eq!(commands.calls, 1);

        let syntax = WordexpSyntax::parse(b"$(blocked)").unwrap();
        context.set_no_command_substitution(true);
        assert!(matches!(
            evaluate_wordexp(&syntax, &mut context, &mut commands, &mut paths),
            Err(WordexpError::CommandSubstitution),
        ));
        assert_eq!(commands.calls, 1);

        let deferred = WordexpSyntax::parse(
            b"$\x7bASSIGNED:=before} $\x7bSET:-$(still-blocked)}",
        ).unwrap();
        assert!(matches!(
            evaluate_wordexp(&deferred, &mut context, &mut commands, &mut paths),
            Err(WordexpError::CommandSubstitution),
        ));
        assert!(!context.lookup_identifier(b"ASSIGNED").is_set());
        assert_eq!(commands.calls, 1);
    }

    #[test]
    fn opaque_command_scanner_closes_after_nested_quotes_comments_case_and_heredoc() {
        let input = b"$(case \"$(echo inner)\" in x) cat <<'EOF'\n$(not a substitution)\nEOF\n;; esac # )\n)";
        let syntax = WordexpSyntax::parse(input).unwrap();
        assert_eq!(syntax.commands.len(), 1);
        // SAFETY: the one command record belongs to this syntax object.
        let command = unsafe { syntax.command(0) };
        // SAFETY: the record span is inside the copied input.
        assert_eq!(
            unsafe { syntax.bytes(command.body) },
            b"case \"$(echo inner)\" in x) cat <<'EOF'\n$(not a substitution)\nEOF\n;; esac # )\n",
        );
    }

    #[test]
    fn opaque_command_scanner_reserves_case_keywords_only_at_lexical_positions() {
        for (input, body) in [
            (b"$(printf '%s' case in)".as_slice(), b"printf '%s' case in".as_slice()),
            (b"$(printf '%s' case x in)".as_slice(), b"printf '%s' case x in".as_slice()),
            (b"$(printf '%s' 'a << b')".as_slice(), b"printf '%s' 'a << b'".as_slice()),
            (b"$(printf \"%s\" \"a << b\")".as_slice(), b"printf \"%s\" \"a << b\"".as_slice()),
            (b"$(printf '%s' case; printf '%s' in)".as_slice(), b"printf '%s' case; printf '%s' in".as_slice()),
            (
                b"$(case x in x) printf '%s' esac;; y) printf y;; esac)".as_slice(),
                b"case x in x) printf '%s' esac;; y) printf y;; esac".as_slice(),
            ),
            (
                b"$(case x in x) printf '%s' in;; y) printf y;; esac)".as_slice(),
                b"case x in x) printf '%s' in;; y) printf y;; esac".as_slice(),
            ),
            (
                b"$(case esac in (esac) printf yes;; esac)".as_slice(),
                b"case esac in (esac) printf yes;; esac".as_slice(),
            ),
            (b"$(printf '%s' 'case in')".as_slice(), b"printf '%s' 'case in'".as_slice()),
            (b"$(case x in x) printf yes;; esac)".as_slice(), b"case x in x) printf yes;; esac".as_slice()),
            (
                b"$(if true; then printf '%s' case in; fi)".as_slice(),
                b"if true; then printf '%s' case in; fi".as_slice(),
            ),
            (
                b"$(for value in case in; do printf '%s' \"$value\"; done)".as_slice(),
                b"for value in case in; do printf '%s' \"$value\"; done".as_slice(),
            ),
            (b"$(printf '%s' 'a ) b')".as_slice(), b"printf '%s' 'a ) b'".as_slice()),
            (
                b"$(case outer in outer) case inner in inner) printf nested;; esac;; esac)".as_slice(),
                b"case outer in outer) case inner in inner) printf nested;; esac;; esac".as_slice(),
            ),
            (
                b"$(case x in (x) printf '%s' esac;; y) printf y;; esac)".as_slice(),
                b"case x in (x) printf '%s' esac;; y) printf y;; esac".as_slice(),
            ),
            (
                b"$(case x in (x) (printf yes);; esac)".as_slice(),
                b"case x in (x) (printf yes);; esac".as_slice(),
            ),
            (
                b"$(if true; then case x in x) printf yes;; esac; fi)".as_slice(),
                b"if true; then case x in x) printf yes;; esac; fi".as_slice(),
            ),
            (
                b"$(for value in x; do case $value in x) printf yes;; esac; done)".as_slice(),
                b"for value in x; do case $value in x) printf yes;; esac; done".as_slice(),
            ),
        ] {
            let syntax = WordexpSyntax::parse(input).unwrap();
            assert_eq!(syntax.commands.len(), 1);
            // SAFETY: the single command record belongs to this syntax object.
            let command = unsafe { syntax.command(0) };
            // SAFETY: the recorded body span is inside the copied source.
            assert_eq!(unsafe { syntax.bytes(command.body) }, body);

            let mut context = WordexpContext::new();
            let mut commands = TestCommands::new(b"ok");
            commands.expected_body = Some(body);
            let mut paths = TestPaths::plain();
            let words = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&words, &[b"ok"]);
            assert_eq!(commands.calls, 1);
        }
    }

    #[test]
    fn opaque_command_scanner_retains_compound_body_scopes() {
        for (input, body) in [
            (
                b"$(for v in do case x in; do printf \"%s\" \"$v\"; done)".as_slice(),
                b"for v in do case x in; do printf \"%s\" \"$v\"; done".as_slice(),
            ),
            (
                b"$(for v in do case x in\ndo printf \"%s\" \"$v\"; done)".as_slice(),
                b"for v in do case x in\ndo printf \"%s\" \"$v\"; done".as_slice(),
            ),
            (
                b"$(for v in do case x in; do case \"$v\" in case) printf C;; *) printf X;; esac; done)".as_slice(),
                b"for v in do case x in; do case \"$v\" in case) printf C;; *) printf X;; esac; done".as_slice(),
            ),
            (
                b"$( { case x in x) printf yes;; esac; } )".as_slice(),
                b" { case x in x) printf yes;; esac; } ".as_slice(),
            ),
            (
                b"$(f() { case x in x) printf yes;; esac; }; f)".as_slice(),
                b"f() { case x in x) printf yes;; esac; }; f".as_slice(),
            ),
            (
                b"$( ! case x in x) printf yes;; esac )".as_slice(),
                b" ! case x in x) printf yes;; esac ".as_slice(),
            ),
            (
                b"$(case x in (x) case y in y) printf yes;; esac;; z) printf z;; esac)".as_slice(),
                b"case x in (x) case y in y) printf yes;; esac;; z) printf z;; esac".as_slice(),
            ),
            (
                b"$(case x in (x) case y in (y) printf yes;; esac;; (z) printf z;; esac)".as_slice(),
                b"case x in (x) case y in (y) printf yes;; esac;; (z) printf z;; esac".as_slice(),
            ),
            (
                b"$(case x in (x) printf yes;; (z) printf z;; esac)".as_slice(),
                b"case x in (x) printf yes;; (z) printf z;; esac".as_slice(),
            ),
            (
                b"$(case x in x) { case y in y) printf yes;; esac; };; esac)".as_slice(),
                b"case x in x) { case y in y) printf yes;; esac; };; esac".as_slice(),
            ),
            (
                b"$(for v in x; do (case \"$v\" in x) printf yes;; esac); done)".as_slice(),
                b"for v in x; do (case \"$v\" in x) printf yes;; esac); done".as_slice(),
            ),
            (
                b"$(case x in x) (case y in y) printf yes;; esac);; esac)".as_slice(),
                b"case x in x) (case y in y) printf yes;; esac);; esac".as_slice(),
            ),
            (
                b"$(case x in x) printf yes; esac)".as_slice(),
                b"case x in x) printf yes; esac".as_slice(),
            ),
            (
                b"$(for v in x do case; do printf \"%s\" \"$v\"; done)".as_slice(),
                b"for v in x do case; do printf \"%s\" \"$v\"; done".as_slice(),
            ),
        ] {
            let syntax = WordexpSyntax::parse(input).unwrap();
            assert_eq!(syntax.commands.len(), 1);
            // SAFETY: the single command record belongs to this syntax object.
            let command = unsafe { syntax.command(0) };
            // SAFETY: the recorded body span is inside the copied source.
            assert_eq!(unsafe { syntax.bytes(command.body) }, body);

            let mut context = WordexpContext::new();
            let mut commands = TestCommands::new(b"ok");
            commands.expected_body = Some(body);
            let mut paths = TestPaths::plain();
            let words = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&words, &[b"ok"]);
            assert_eq!(commands.calls, 1);
        }
    }

    #[test]
    fn opaque_command_scanner_tracks_function_compound_bodies_and_whole_brace_words() {
        // These are lexer-boundary regressions. The deterministic command
        // adapter observes the body verbatim; it does not execute shell code.
        for (input, body) in [
            (
                b"$(f () { case x in x) printf yes;; esac; }; f)".as_slice(),
                b"f () { case x in x) printf yes;; esac; }; f".as_slice(),
            ),
            (
                b"$(f() (case x in x) printf yes;; esac); f)".as_slice(),
                b"f() (case x in x) printf yes;; esac); f".as_slice(),
            ),
            (
                b"$(f() if true; then case x in x) printf yes;; esac; fi; f)".as_slice(),
                b"f() if true; then case x in x) printf yes;; esac; fi; f".as_slice(),
            ),
            (
                b"$(f() for v in x; do case \"$v\" in x) printf yes;; esac; done; f)".as_slice(),
                b"f() for v in x; do case \"$v\" in x) printf yes;; esac; done; f".as_slice(),
            ),
            (
                b"$(f() while false; do case x in x) printf yes;; esac; done; f)".as_slice(),
                b"f() while false; do case x in x) printf yes;; esac; done; f".as_slice(),
            ),
            (
                b"$(f() until true; do case x in x) printf yes;; esac; done; f)".as_slice(),
                b"f() until true; do case x in x) printf yes;; esac; done; f".as_slice(),
            ),
            (b"$(case x in esac)".as_slice(), b"case x in esac".as_slice()),
            (
                b"$(case esac in (esac) printf yes;; esac)".as_slice(),
                b"case esac in (esac) printf yes;; esac".as_slice(),
            ),
            (
                b"$( {missing argument; printf yes)".as_slice(),
                b" {missing argument; printf yes".as_slice(),
            ),
        ] {
            let syntax = WordexpSyntax::parse(input).unwrap();
            assert_eq!(syntax.commands.len(), 1);
            // SAFETY: the single command record belongs to this syntax object.
            let command = unsafe { syntax.command(0) };
            // SAFETY: the recorded body span is inside the copied source.
            assert_eq!(unsafe { syntax.bytes(command.body) }, body);

            let mut context = WordexpContext::new();
            let mut commands = TestCommands::new(b"ok");
            commands.expected_body = Some(body);
            let mut paths = TestPaths::plain();
            let words = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&words, &[b"ok"]);
            assert_eq!(commands.calls, 1);
        }
    }

    #[test]
    fn locale_mode_controls_parameter_character_length() {
        let mut context = WordexpContext::new();
        context.set_initial(
            b"TEXT",
            Some(b"\xc3\xa9\xce\xbb\xe2\x82\xac\xf0\x9f\x98\x80"),
            false,
        ).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();

        assert_eq!(context.locale_mode(), WordexpLocaleMode::C);
        let words = evaluate(b"${#TEXT}", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"11"]);

        context.set_locale_mode(WordexpLocaleMode::CUtf8);
        let words = evaluate(b"${#TEXT}", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"4"]);
    }

    #[test]
    fn c_utf8_ifs_matches_complete_characters_within_one_expansion_origin() {
        let mut context = WordexpContext::new();
        context.set_locale_mode(WordexpLocaleMode::CUtf8);
        context.set_ifs(Some(b"\xc3\xa9")).unwrap();
        context.set_initial(b"SAME", Some(b"a\xc3\xa9b"), false).unwrap();
        context.set_initial(b"FIRST", Some(b"\xc3"), false).unwrap();
        context.set_initial(b"SECOND", Some(b"\xa9"), false).unwrap();
        context.set_initial(b"NY", Some(b"a\xc3\xb1b"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$SAME $FIRST$SECOND $FIRST\"\"$SECOND $FIRST\xa9 $NY",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(
            &words,
            &[b"a", b"b", b"\xc3\xa9", b"\xc3\xa9", b"\xc3\xa9", b"a\xc3\xb1b"],
        );
    }

    #[test]
    fn c_mode_retains_byte_ifs_matching() {
        let mut context = WordexpContext::new();
        context.set_ifs(Some(b"\xc3\xa9")).unwrap();
        context.set_initial(b"VALUE", Some(b"a\xc3\xa9b"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(b"$VALUE", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"a", b"", b"b"]);
    }

    #[test]
    fn c_utf8_ifs_handles_three_four_byte_and_mixed_delimiters() {
        let mut context = WordexpContext::new();
        context.set_locale_mode(WordexpLocaleMode::CUtf8);
        context.set_ifs(Some(b" \xe2\x82\xac\xf0\x9f\x98\x80")).unwrap();
        context.set_initial(b"THREE", Some(b"a\xe2\x82\xacb"), false).unwrap();
        context.set_initial(b"FOUR", Some(b"a\xf0\x9f\x98\x80b"), false).unwrap();
        context.set_initial(b"MIXED", Some(b"a \xe2\x82\xac b"), false).unwrap();
        context.set_initial(b"ADJACENT", Some(b"\xe2\x82\xac\xf0\x9f\x98\x80"), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();
        let words = evaluate(
            b"$THREE $FOUR $MIXED $ADJACENT",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"a", b"b", b"a", b"b", b"a", b"b", b"", b""]);
    }

    #[test]
    fn c_utf8_empty_unset_and_invalid_ifs_bytes_have_defined_progress() {
        let mut context = WordexpContext::new();
        context.set_locale_mode(WordexpLocaleMode::CUtf8);
        context.set_initial(b"TEXT", Some(b"a b"), false).unwrap();
        context.set_initial(b"EMPTY", Some(b""), false).unwrap();
        let mut commands = TestCommands::new(b"");
        let mut paths = TestPaths::plain();

        context.set_ifs(None).unwrap();
        let words = evaluate(b"$TEXT", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"a", b"b"]);

        context.set_ifs(Some(b"")).unwrap();
        let words = evaluate(b"$TEXT $EMPTY \"$EMPTY\"", &mut context, &mut commands, &mut paths).unwrap();
        assert_words(&words, &[b"a b", b""]);

        context.set_initial(b"BAD", Some(b"\xff\xc3"), false).unwrap();
        context.set_initial(b"INVALID_IFS", Some(b"a\xc3b"), false).unwrap();
        context.set_ifs(Some(b"\xc3")).unwrap();
        let words = evaluate(
            b"${#BAD} $INVALID_IFS",
            &mut context,
            &mut commands,
            &mut paths,
        ).unwrap();
        assert_words(&words, &[b"2", b"a", b"b"]);
    }

    #[test]
    fn backtick_style_preserves_its_outer_double_quote_context_for_the_adapter() {
        const BODY: &[u8] = b"printf '%s' \\\"hi\\\"";
        for (input, reply, expected, double_quoted) in [
            (b"`printf '%s' \\\"hi\\\"`".as_slice(), b"word\n".as_slice(), b"word".as_slice(), false),
            (b"\"`printf '%s' \\\"hi\\\"`\"".as_slice(), b"word\n".as_slice(), b"word".as_slice(), true),
            (b"${U:-`printf '%s' \\\"hi\\\"`}".as_slice(), b"word\n".as_slice(), b"word".as_slice(), false),
            (b"\"${U:-`printf '%s' \\\"hi\\\"`}\"".as_slice(), b"word\n".as_slice(), b"word".as_slice(), true),
            (b"$((`printf '%s' \\\"hi\\\"`))".as_slice(), b"1\n".as_slice(), b"1".as_slice(), true),
        ] {
            let mut context = WordexpContext::new();
            let mut commands = TestCommands::new(reply);
            commands.expected_body = Some(BODY);
            commands.expected_style = Some(CommandStyle::Backtick { double_quoted });
            let mut paths = TestPaths::plain();
            let words = evaluate(input, &mut context, &mut commands, &mut paths).unwrap();
            assert_words(&words, &[expected]);
            assert_eq!(commands.calls, 1);
        }
    }

    #[test]
    fn deep_nesting_uses_heap_parser_and_evaluator_stacks() {
        const PARAMETER_DEPTH: usize = 4_000;
        const ARITHMETIC_DEPTH: usize = 4_000;
        const PARENTHESIS_DEPTH: usize = 8_000;
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut parameter = std::vec::Vec::new();
                for _ in 0..PARAMETER_DEPTH { parameter.extend_from_slice(b"${U:-"); }
                parameter.push(b'x');
                for _ in 0..PARAMETER_DEPTH { parameter.push(b'}'); }
                let mut context = WordexpContext::new();
                let mut commands = TestCommands::new(b"");
                let mut paths = TestPaths::plain();
                let words = evaluate(&parameter, &mut context, &mut commands, &mut paths).unwrap();
                assert_words(&words, &[b"x"]);

                let mut arithmetic = std::vec::Vec::new();
                for _ in 0..ARITHMETIC_DEPTH { arithmetic.extend_from_slice(b"$(("); }
                arithmetic.push(b'1');
                for _ in 0..ARITHMETIC_DEPTH { arithmetic.extend_from_slice(b"))"); }
                let words = evaluate(&arithmetic, &mut context, &mut commands, &mut paths).unwrap();
                assert_words(&words, &[b"1"]);

                let mut parentheses = std::vec::Vec::new();
                parentheses.extend_from_slice(b"$((");
                for _ in 0..PARENTHESIS_DEPTH { parentheses.push(b'('); }
                parentheses.push(b'1');
                for _ in 0..PARENTHESIS_DEPTH { parentheses.push(b')'); }
                parentheses.extend_from_slice(b"))");
                let words = evaluate(&parentheses, &mut context, &mut commands, &mut paths).unwrap();
                assert_words(&words, &[b"1"]);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
