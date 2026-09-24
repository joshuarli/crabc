//! TRE compiler port from musl 1.2.6 `src/regex/regcomp.c`.
//!
//! This module preserves the source pipeline from pinned
//! `regcomp.c:70-2953`
//! (`56b0a765e084a5cd3ed7113a893b50d259265ba76b6bea98889c45d7aec302a0`): parsed BRE/ERE input becomes
//! the source AST, tags and iteration expansion operate on that AST, and the
//! final stage materializes `TreTnfa` transitions for `regexec.c`'s parallel
//! and backtracking algorithms. It is not an AST evaluator or an alternative
//! matching engine. `regcomp.c` carries the TRE two-clause BSD provenance in
//! [`super::LICENSE-TRE-2-CLAUSE-BSD.txt`].

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::ptr;

use super::{cabi_calloc, cabi_free, cabi_malloc, cabi_realloc};
use super::memory::{tre_mem_alloc, tre_mem_calloc, tre_mem_destroy, tre_mem_new};
use super::types::{
    regex_t, tre_ctype_t, TreAssertionParameter, TreTagDirection, TreTnfa,
    TreTnfaTransition, TreMem, TreSubmatchData, ASSERT_AT_BOL, ASSERT_AT_BOW,
    ASSERT_AT_EOL, ASSERT_AT_EOW, ASSERT_AT_WB, ASSERT_AT_WB_NEG,
    ASSERT_BACKREF, ASSERT_CHAR_CLASS, ASSERT_CHAR_CLASS_NEG, REG_BADBR, REG_BADPAT,
    REG_EBRACE, REG_ECOLLATE, REG_ECTYPE, REG_EESCAPE, REG_EPAREN, REG_ERANGE,
    REG_BADRPT, REG_ESPACE, REG_ESUBREG, REG_EXTENDED, REG_ICASE, REG_NEWLINE, REG_NOSUB, REG_OK,
    TRE_MEM_BLOCK_SIZE, TRE_TAG_MAXIMIZE, TRE_TAG_MINIMIZE,
};

// `tre.h`'s parser-private AST definitions (regcomp.c:70-138).
const LITERAL: c_int = 0;
const CATENATION: c_int = 1;
const ITERATION: c_int = 2;
const UNION: c_int = 3;

const EMPTY: c_long = -1;
const ASSERTION: c_long = -2;
const TAG: c_long = -3;
const BACKREF: c_long = -4;
const TRE_CHAR_MAX: c_int = 0x10ffff;
const RE_DUP_MAX: c_int = 255;
const CHARCLASS_NAME_MAX: usize = 14;
const MAX_NEG_CLASSES: usize = 64;

#[repr(C)]
struct TrePosAndTags {
    position: c_int,
    code_min: c_int,
    code_max: c_int,
    tags: *mut c_int,
    assertions: c_int,
    class: tre_ctype_t,
    neg_classes: *mut tre_ctype_t,
    backref: c_int,
}

#[repr(C)]
struct TreAstNode {
    node_type: c_int,
    object: *mut c_void,
    nullable: c_int,
    submatch_id: c_int,
    num_submatches: c_int,
    num_tags: c_int,
    firstpos: *mut TrePosAndTags,
    lastpos: *mut TrePosAndTags,
}

#[repr(C)]
struct TreLiteral {
    code_min: c_long,
    code_max: c_long,
    position: c_int,
    class: tre_ctype_t,
    neg_classes: *mut tre_ctype_t,
}

#[repr(C)]
struct TreCatenation {
    left: *mut TreAstNode,
    right: *mut TreAstNode,
}

#[repr(C)]
struct TreIteration {
    argument: *mut TreAstNode,
    minimum: c_int,
    maximum: c_int,
    minimal: c_uint,
}

#[repr(C)]
struct TreUnion {
    left: *mut TreAstNode,
    right: *mut TreAstNode,
}

#[inline]
unsafe fn literal_is_special(literal: *const TreLiteral) -> bool {
    unsafe { (*literal).code_min < 0 }
}

#[inline]
unsafe fn literal_is_empty(literal: *const TreLiteral) -> bool {
    unsafe { (*literal).code_min == EMPTY }
}

#[inline]
unsafe fn literal_is_assertion(literal: *const TreLiteral) -> bool {
    unsafe { (*literal).code_min == ASSERTION }
}

#[inline]
unsafe fn literal_is_tag(literal: *const TreLiteral) -> bool {
    unsafe { (*literal).code_min == TAG }
}

#[inline]
unsafe fn literal_is_backref(literal: *const TreLiteral) -> bool {
    unsafe { (*literal).code_min == BACKREF }
}

/// `tre_ast_new_node` from regcomp.c:141-151.
unsafe fn tre_ast_new_node(
    memory: *mut TreMem,
    node_type: c_int,
    object: *mut c_void,
) -> *mut TreAstNode {
    let node = unsafe { tre_mem_calloc(memory, size_of::<TreAstNode>()) }.cast::<TreAstNode>();
    if node.is_null() || object.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*node).object = object;
        (*node).node_type = node_type;
        (*node).nullable = -1;
        (*node).submatch_id = -1;
    }
    node
}

/// `tre_ast_new_literal` from regcomp.c:154-167.
unsafe fn tre_ast_new_literal(
    memory: *mut TreMem,
    code_min: c_long,
    code_max: c_long,
    position: c_int,
) -> *mut TreAstNode {
    let literal = unsafe { tre_mem_calloc(memory, size_of::<TreLiteral>()) }.cast::<TreLiteral>();
    let node = unsafe { tre_ast_new_node(memory, LITERAL, literal.cast()) };
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*literal).code_min = code_min;
        (*literal).code_max = code_max;
        (*literal).position = position;
    }
    node
}

/// `tre_ast_new_iter` from regcomp.c:170-185.
unsafe fn tre_ast_new_iter(
    memory: *mut TreMem,
    argument: *mut TreAstNode,
    minimum: c_int,
    maximum: c_int,
    minimal: c_int,
) -> *mut TreAstNode {
    let iteration = unsafe { tre_mem_calloc(memory, size_of::<TreIteration>()) }.cast::<TreIteration>();
    let node = unsafe { tre_ast_new_node(memory, ITERATION, iteration.cast()) };
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*iteration).argument = argument;
        (*iteration).minimum = minimum;
        (*iteration).maximum = maximum;
        (*iteration).minimal = minimal as c_uint;
        (*node).num_submatches = (*argument).num_submatches;
    }
    node
}

/// `tre_ast_new_union` from regcomp.c:188-203.
unsafe fn tre_ast_new_union(
    memory: *mut TreMem,
    left: *mut TreAstNode,
    right: *mut TreAstNode,
) -> *mut TreAstNode {
    if left.is_null() {
        return right;
    }
    let union = unsafe { tre_mem_calloc(memory, size_of::<TreUnion>()) }.cast::<TreUnion>();
    let node = unsafe { tre_ast_new_node(memory, UNION, union.cast()) };
    if node.is_null() || right.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*union).left = left;
        (*union).right = right;
        (*node).num_submatches = (*left).num_submatches + (*right).num_submatches;
    }
    node
}

/// `tre_ast_new_catenation` from regcomp.c:206-221.
unsafe fn tre_ast_new_catenation(
    memory: *mut TreMem,
    left: *mut TreAstNode,
    right: *mut TreAstNode,
) -> *mut TreAstNode {
    if left.is_null() {
        return right;
    }
    let catenation = unsafe { tre_mem_calloc(memory, size_of::<TreCatenation>()) }
        .cast::<TreCatenation>();
    let node = unsafe { tre_ast_new_node(memory, CATENATION, catenation.cast()) };
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*catenation).left = left;
        (*catenation).right = right;
        (*node).num_submatches = (*left).num_submatches + (*right).num_submatches;
    }
    node
}

// regcomp.c:234-386, the dynamic stack used by parser, tag, expansion, and
// first/last-position phases. The source's 1,024,000-object bound belongs to
// `regcomp`'s call site, rather than a replacement fixed parser capacity.
#[repr(C)]
union TreStackItem {
    voidptr_value: *mut c_void,
    int_value: c_int,
}

#[repr(C)]
struct TreStack {
    size: c_int,
    max_size: c_int,
    increment: c_int,
    pointer: c_int,
    stack: *mut TreStackItem,
}

unsafe fn tre_stack_new(size: c_int, max_size: c_int, increment: c_int) -> *mut TreStack {
    if size <= 0 || max_size < size || increment <= 0 {
        return ptr::null_mut();
    }
    let stack = unsafe { cabi_malloc(size_of::<TreStack>()) }.cast::<TreStack>();
    if stack.is_null() {
        return ptr::null_mut();
    }
    let Some(bytes) = (size as usize).checked_mul(size_of::<TreStackItem>()) else {
        unsafe { cabi_free(stack.cast()) };
        return ptr::null_mut();
    };
    let entries = unsafe { cabi_malloc(bytes) }.cast::<TreStackItem>();
    if entries.is_null() {
        unsafe { cabi_free(stack.cast()) };
        return ptr::null_mut();
    }
    unsafe {
        (*stack).stack = entries;
        (*stack).size = size;
        (*stack).max_size = max_size;
        (*stack).increment = increment;
        (*stack).pointer = 0;
    }
    stack
}

unsafe fn tre_stack_destroy(stack: *mut TreStack) {
    if stack.is_null() {
        return;
    }
    unsafe {
        cabi_free((*stack).stack.cast());
        cabi_free(stack.cast());
    }
}

#[inline]
unsafe fn tre_stack_num_objects(stack: *const TreStack) -> c_int {
    unsafe { (*stack).pointer }
}

unsafe fn tre_stack_push(stack: *mut TreStack, value: TreStackItem) -> c_int {
    if unsafe { (*stack).pointer < (*stack).size } {
        unsafe {
            (*stack).stack.add((*stack).pointer as usize).write(value);
            (*stack).pointer += 1;
        }
        return REG_OK;
    }
    if unsafe { (*stack).size >= (*stack).max_size } {
        return REG_ESPACE;
    }
    let mut new_size = unsafe { (*stack).size }.saturating_add(unsafe { (*stack).increment });
    if new_size > unsafe { (*stack).max_size } {
        new_size = unsafe { (*stack).max_size };
    }
    let Some(bytes) = (new_size as usize).checked_mul(size_of::<TreStackItem>()) else {
        return REG_ESPACE;
    };
    let replacement = unsafe { cabi_realloc((*stack).stack.cast(), bytes) }.cast::<TreStackItem>();
    if replacement.is_null() {
        return REG_ESPACE;
    }
    unsafe {
        (*stack).size = new_size;
        (*stack).stack = replacement;
    }
    // The source recurs once after a successful growth; its bounds make the
    // retry immediately take the first branch.
    unsafe { tre_stack_push(stack, value) }
}

#[inline]
unsafe fn tre_stack_push_int(stack: *mut TreStack, value: c_int) -> c_int {
    unsafe { tre_stack_push(stack, TreStackItem { int_value: value }) }
}

#[inline]
unsafe fn tre_stack_push_voidptr(stack: *mut TreStack, value: *mut c_void) -> c_int {
    unsafe { tre_stack_push(stack, TreStackItem { voidptr_value: value }) }
}

#[inline]
unsafe fn tre_stack_pop_int(stack: *mut TreStack) -> c_int {
    unsafe {
        (*stack).pointer -= 1;
        (*(*stack).stack.add((*stack).pointer as usize)).int_value
    }
}

#[inline]
unsafe fn tre_stack_pop_voidptr(stack: *mut TreStack) -> *mut c_void {
    unsafe {
        (*stack).pointer -= 1;
        (*(*stack).stack.add((*stack).pointer as usize)).voidptr_value
    }
}

// regcomp.c:390-1090, the complete BRE/ERE parser. The resulting nodes are
// consumed only by the later source tag, expansion, and TNFA passes.
#[repr(C)]
struct TreParseContext {
    memory: *mut TreMem,
    stack: *mut TreStack,
    node: *mut TreAstNode,
    string: *const c_char,
    start: *const c_char,
    submatch_id: c_int,
    position: c_int,
    max_backref: c_int,
    cflags: c_int,
}

#[repr(C)]
struct Literals {
    memory: *mut TreMem,
    entries: *mut *mut TreLiteral,
    length: c_int,
    capacity: c_int,
}

#[repr(C)]
struct NegatedClasses {
    negate: c_int,
    length: c_int,
    entries: [tre_ctype_t; MAX_NEG_CLASSES],
}

#[inline]
unsafe fn source_byte(pointer: *const c_char) -> u8 {
    unsafe { pointer.read() as u8 }
}

#[inline]
unsafe fn source_add(pointer: *const c_char, offset: usize) -> *const c_char {
    unsafe { pointer.add(offset) }
}

#[inline]
fn ascii_digit(byte: u8) -> bool {
    byte.wrapping_sub(b'0') < 10
}

static MACRO_TAB: [u8; 2] = *b"\t\0";
static MACRO_NEWLINE: [u8; 2] = *b"\n\0";
static MACRO_RETURN: [u8; 2] = *b"\r\0";
static MACRO_FORM_FEED: [u8; 2] = *b"\x0c\0";
static MACRO_ALERT: [u8; 2] = *b"\x07\0";
static MACRO_ESCAPE: [u8; 2] = *b"\x1b\0";
static MACRO_WORD: [u8; 13] = *b"[[:alnum:]_]\0";
static MACRO_NOT_WORD: [u8; 14] = *b"[^[:alnum:]_]\0";
static MACRO_SPACE: [u8; 12] = *b"[[:space:]]\0";
static MACRO_NOT_SPACE: [u8; 13] = *b"[^[:space:]]\0";
static MACRO_DIGIT: [u8; 12] = *b"[[:digit:]]\0";
static MACRO_NOT_DIGIT: [u8; 13] = *b"[^[:digit:]]\0";

/// `tre_expand_macro` from regcomp.c:430-435.
unsafe fn tre_expand_macro(string: *const c_char) -> *const c_char {
    let value = unsafe { source_byte(string) };
    let expansion = match value {
        b't' => Some(&MACRO_TAB[..]),
        b'n' => Some(&MACRO_NEWLINE[..]),
        b'r' => Some(&MACRO_RETURN[..]),
        b'f' => Some(&MACRO_FORM_FEED[..]),
        b'a' => Some(&MACRO_ALERT[..]),
        b'e' => Some(&MACRO_ESCAPE[..]),
        b'w' => Some(&MACRO_WORD[..]),
        b'W' => Some(&MACRO_NOT_WORD[..]),
        b's' => Some(&MACRO_SPACE[..]),
        b'S' => Some(&MACRO_NOT_SPACE[..]),
        b'd' => Some(&MACRO_DIGIT[..]),
        b'D' => Some(&MACRO_NOT_DIGIT[..]),
        _ => None,
    };
    expansion.map_or(ptr::null(), |bytes| bytes.as_ptr().cast())
}

unsafe extern "C" fn tre_compare_literal(
    left: *const c_void,
    right: *const c_void,
) -> c_int {
    let left_literal = unsafe { *(left.cast::<*mut TreLiteral>()) };
    let right_literal = unsafe { *(right.cast::<*mut TreLiteral>()) };
    // regcomp.c establishes code_min within c_int before this subtraction.
    unsafe { (*left_literal).code_min as c_int - (*right_literal).code_min as c_int }
}

unsafe extern "C" {
    #[link_name = "qsort"]
    fn source_qsort(
        base: *mut c_void,
        count: usize,
        width: usize,
        compare: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    );
}

/// `tre_new_lit` from regcomp.c:452-466.
unsafe fn tre_new_literal(literals: *mut Literals) -> *mut TreLiteral {
    if unsafe { (*literals).length >= (*literals).capacity } {
        if unsafe { (*literals).capacity >= (1 << 15) } {
            return ptr::null_mut();
        }
        unsafe { (*literals).capacity *= 2 };
        let Some(bytes) = (unsafe { (*literals).capacity as usize })
            .checked_mul(size_of::<*mut TreLiteral>())
        else {
            return ptr::null_mut();
        };
        let replacement = unsafe { cabi_realloc((*literals).entries.cast(), bytes) }
            .cast::<*mut TreLiteral>();
        if replacement.is_null() {
            return ptr::null_mut();
        }
        unsafe { (*literals).entries = replacement };
    }
    let entry = unsafe { (*literals).entries.add((*literals).length as usize) };
    unsafe { (*literals).length += 1 };
    let literal = unsafe { tre_mem_calloc((*literals).memory, size_of::<TreLiteral>()) }
        .cast::<TreLiteral>();
    unsafe { entry.write(literal) };
    literal
}

/// `add_icase_literals` from regcomp.c:469-497.
unsafe fn add_icase_literals(literals: *mut Literals, minimum: c_int, maximum: c_int) -> c_int {
    let mut scalar = minimum;
    while scalar <= maximum {
        let lower = super::super::wide_character::iswlower(scalar as u32) != 0;
        let (begin, mut end) = if lower {
            let converted = super::super::wide_character::towupper(scalar as u32) as c_int;
            (converted, converted)
        } else if super::super::wide_character::iswupper(scalar as u32) != 0 {
            let converted = super::super::wide_character::towlower(scalar as u32) as c_int;
            (converted, converted)
        } else {
            scalar += 1;
            continue;
        };
        scalar += 1;
        end += 1;
        while scalar <= maximum {
            let next = if lower {
                super::super::wide_character::towupper(scalar as u32) as c_int
            } else {
                super::super::wide_character::towlower(scalar as u32) as c_int
            };
            if next != end {
                break;
            }
            scalar += 1;
            end += 1;
        }
        let literal = unsafe { tre_new_literal(literals) };
        if literal.is_null() {
            return -1;
        }
        unsafe {
            (*literal).code_min = begin as c_long;
            (*literal).code_max = (end - 1) as c_long;
            (*literal).position = -1;
        }
    }
    0
}

/// `parse_bracket_terms` from regcomp.c:537-615.
unsafe fn parse_bracket_terms(
    context: *mut TreParseContext,
    mut string: *const c_char,
    literals: *mut Literals,
    negated: *mut NegatedClasses,
) -> c_int {
    let start = string;
    loop {
        let mut class = 0usize;
        let mut wide = 0i32;
        let mut length = unsafe {
            super::super::locale_multibyte::mbtowc(&mut wide, string, usize::MAX)
        };
        let byte = unsafe { source_byte(string) };
        if length <= 0 {
            return if byte != 0 { REG_BADPAT } else { super::types::REG_EBRACK };
        }
        if byte == b']' && string != start {
            unsafe { (*context).string = source_add(string, 1) };
            return REG_OK;
        }
        if byte == b'-'
            && string != start
            && unsafe { source_byte(source_add(string, 1)) } != b']'
            && (unsafe { source_byte(source_add(string, 1)) } != b'-'
                || unsafe { source_byte(source_add(string, 2)) } == b']')
        {
            return REG_ERANGE;
        }
        if byte == b'['
            && matches!(unsafe { source_byte(source_add(string, 1)) }, b'.' | b'=')
        {
            return REG_ECOLLATE;
        }

        let (minimum, maximum) = if byte == b'['
            && unsafe { source_byte(source_add(string, 1)) } == b':'
        {
            let mut temporary = [0 as c_char; CHARCLASS_NAME_MAX + 1];
            string = unsafe { source_add(string, 2) };
            let mut name_length = 0usize;
            while name_length < CHARCLASS_NAME_MAX && unsafe { source_byte(source_add(string, name_length)) } != 0 {
                if unsafe { source_byte(source_add(string, name_length)) } == b':' {
                    let mut index = 0usize;
                    while index < name_length {
                        temporary[index] = unsafe { source_add(string, index).read() };
                        index += 1;
                    }
                    temporary[name_length] = 0;
                    class = unsafe { super::super::wide_character::wctype(temporary.as_ptr()) };
                    break;
                }
                name_length += 1;
            }
            if class == 0 || unsafe { source_byte(source_add(string, name_length + 1)) } != b']' {
                return REG_ECTYPE;
            }
            string = unsafe { source_add(string, name_length + 2) };
            (0, TRE_CHAR_MAX)
        } else {
            let minimum = wide;
            let mut maximum = wide;
            string = unsafe { source_add(string, length as usize) };
            if unsafe { source_byte(string) } == b'-'
                && unsafe { source_byte(source_add(string, 1)) } != b']'
            {
                string = unsafe { source_add(string, 1) };
                wide = 0;
                length = unsafe {
                    super::super::locale_multibyte::mbtowc(&mut wide, string, usize::MAX)
                };
                maximum = wide;
                if length <= 0 || minimum > maximum {
                    return REG_ERANGE;
                }
                string = unsafe { source_add(string, length as usize) };
            }
            (minimum, maximum)
        };

        if class != 0 && unsafe { (*negated).negate } != 0 {
            if unsafe { (*negated).length as usize } >= MAX_NEG_CLASSES {
                return REG_ESPACE;
            }
            unsafe {
                (*negated).entries[(*negated).length as usize] = class;
                (*negated).length += 1;
            }
        } else {
            let literal = unsafe { tre_new_literal(literals) };
            if literal.is_null() {
                return REG_ESPACE;
            }
            unsafe {
                (*literal).code_min = minimum as c_long;
                (*literal).code_max = maximum as c_long;
                (*literal).class = class;
                (*literal).position = -1;
            }
            if unsafe { (*context).cflags & REG_ICASE } != 0
                && class == 0
                && unsafe { add_icase_literals(literals, minimum, maximum) } != 0
            {
                return REG_ESPACE;
            }
        }
    }
}

/// `parse_bracket` from regcomp.c:617-706.
unsafe fn parse_bracket(context: *mut TreParseContext, mut string: *const c_char) -> c_int {
    let mut node = ptr::null_mut();
    let mut negated = NegatedClasses {
        negate: unsafe { (source_byte(string) == b'^') as c_int },
        length: 0,
        entries: [0; MAX_NEG_CLASSES],
    };
    if negated.negate != 0 {
        string = unsafe { source_add(string, 1) };
    }
    let mut literals = Literals {
        memory: unsafe { (*context).memory },
        entries: ptr::null_mut(),
        length: 0,
        capacity: 32,
    };
    let Some(bytes) = (literals.capacity as usize).checked_mul(size_of::<*mut TreLiteral>()) else {
        return REG_ESPACE;
    };
    literals.entries = unsafe { cabi_malloc(bytes) }.cast::<*mut TreLiteral>();
    if literals.entries.is_null() {
        return REG_ESPACE;
    }

    let mut error = unsafe { parse_bracket_terms(context, string, &mut literals, &mut negated) };
    let mut negative_classes = ptr::null_mut();
    if error == REG_OK && negated.negate != 0 {
        if unsafe { (*context).cflags & REG_NEWLINE } != 0 {
            let literal = unsafe { tre_new_literal(&mut literals) };
            if literal.is_null() {
                error = REG_ESPACE;
            } else {
                unsafe {
                    (*literal).code_min = b'\n' as c_long;
                    (*literal).code_max = b'\n' as c_long;
                    (*literal).position = -1;
                }
            }
        }
        if error == REG_OK {
            unsafe {
                source_qsort(
                    literals.entries.cast(),
                    literals.length as usize,
                    size_of::<*mut TreLiteral>(),
                    tre_compare_literal,
                );
            }
            let literal = unsafe { tre_new_literal(&mut literals) };
            if literal.is_null() {
                error = REG_ESPACE;
            } else {
                unsafe {
                    (*literal).code_min = (TRE_CHAR_MAX + 1) as c_long;
                    (*literal).code_max = (TRE_CHAR_MAX + 1) as c_long;
                    (*literal).position = -1;
                }
            }
        }
        if error == REG_OK && negated.length != 0 {
            let size = (negated.length as usize + 1).checked_mul(size_of::<tre_ctype_t>());
            let Some(size) = size else {
                error = REG_ESPACE;
                unsafe { cabi_free(literals.entries.cast()) };
                (*context).position += 1;
                (*context).node = node;
                return error;
            };
            negative_classes = unsafe { tre_mem_alloc((*context).memory, size) }
                .cast::<tre_ctype_t>();
            if negative_classes.is_null() {
                error = REG_ESPACE;
            } else {
                unsafe {
                    ptr::copy_nonoverlapping(
                        negated.entries.as_ptr(),
                        negative_classes,
                        negated.length as usize,
                    );
                    negative_classes.add(negated.length as usize).write(0);
                }
            }
        }
    }

    if error == REG_OK {
        let mut negated_minimum = 0 as c_int;
        let mut negated_maximum = 0 as c_int;
        let mut index = 0 as c_int;
        while index < literals.length {
            let literal = unsafe { *literals.entries.add(index as usize) };
            let mut minimum = unsafe { (*literal).code_min as c_int };
            let maximum = unsafe { (*literal).code_max as c_int };
            if negated.negate != 0 {
                if minimum <= negated_minimum {
                    negated_minimum = core::cmp::max(maximum + 1, negated_minimum);
                    index += 1;
                    continue;
                }
                negated_maximum = minimum - 1;
                minimum = negated_minimum;
                unsafe {
                    (*literal).code_min = minimum as c_long;
                    (*literal).code_max = negated_maximum as c_long;
                }
                negated_minimum = maximum + 1;
            }
            unsafe {
                (*literal).position = (*context).position;
                (*literal).neg_classes = negative_classes;
            }
            let child = unsafe { tre_ast_new_node((*context).memory, LITERAL, literal.cast()) };
            node = unsafe { tre_ast_new_union((*context).memory, node, child) };
            if node.is_null() {
                error = REG_ESPACE;
                break;
            }
            index += 1;
        }
    }

    unsafe {
        cabi_free(literals.entries.cast());
        (*context).position += 1;
        (*context).node = node;
    }
    error
}

/// `parse_dup_count` and `parse_dup` from regcomp.c:708-750.
unsafe fn parse_dup_count(mut string: *const c_char, result: *mut c_int) -> *const c_char {
    unsafe { result.write(-1) };
    if !ascii_digit(unsafe { source_byte(string) }) {
        return string;
    }
    unsafe { result.write(0) };
    loop {
        unsafe { result.write(10 * result.read() + (source_byte(string) - b'0') as c_int) };
        string = unsafe { source_add(string, 1) };
        if !ascii_digit(unsafe { source_byte(string) }) || unsafe { result.read() } > RE_DUP_MAX {
            break;
        }
    }
    string
}

unsafe fn parse_dup(
    mut string: *const c_char,
    extended: bool,
    minimum: *mut c_int,
    maximum: *mut c_int,
) -> *const c_char {
    string = unsafe { parse_dup_count(string, minimum) };
    if unsafe { source_byte(string) } == b',' {
        string = unsafe { parse_dup_count(source_add(string, 1), maximum) };
    } else {
        unsafe { maximum.write(minimum.read()) };
    }
    let invalid = (unsafe { maximum.read() < minimum.read() && maximum.read() >= 0 })
        || unsafe { maximum.read() > RE_DUP_MAX }
        || unsafe { minimum.read() > RE_DUP_MAX }
        || unsafe { minimum.read() < 0 };
    if invalid {
        return ptr::null();
    }
    if !extended {
        if unsafe { source_byte(string) } != b'\\' {
            return ptr::null();
        }
        string = unsafe { source_add(string, 1) };
    }
    if unsafe { source_byte(string) } != b'}' {
        return ptr::null();
    }
    unsafe { source_add(string, 1) }
}

#[inline]
fn hexval(value: u8) -> c_int {
    if value.wrapping_sub(b'0') < 10 {
        return (value - b'0') as c_int;
    }
    let folded = value | 32;
    if folded.wrapping_sub(b'a') < 6 {
        return (folded - b'a' + 10) as c_int;
    }
    -1
}

/// `marksub` from regcomp.c:760-775.
unsafe fn marksub(
    context: *mut TreParseContext,
    mut node: *mut TreAstNode,
    submatch_id: c_int,
) -> c_int {
    if unsafe { (*node).submatch_id } >= 0 {
        let empty = unsafe { tre_ast_new_literal((*context).memory, EMPTY, -1, -1) };
        if empty.is_null() {
            return REG_ESPACE;
        }
        let expanded = unsafe { tre_ast_new_catenation((*context).memory, empty, node) };
        if expanded.is_null() {
            return REG_ESPACE;
        }
        unsafe { (*expanded).num_submatches = (*node).num_submatches };
        node = expanded;
    }
    unsafe {
        (*node).submatch_id = submatch_id;
        (*node).num_submatches += 1;
        (*context).node = node;
    }
    REG_OK
}

/// `parse_atom` from regcomp.c:780-955.
unsafe fn parse_atom(context: *mut TreParseContext, mut string: *const c_char) -> c_int {
    let extended = unsafe { (*context).cflags & REG_EXTENDED } != 0;
    let mut node = ptr::null_mut();
    match unsafe { source_byte(string) } {
        b'[' => return unsafe { parse_bracket(context, source_add(string, 1)) },
        b'\\' => {
            let expanded = unsafe { tre_expand_macro(source_add(string, 1)) };
            if !expanded.is_null() {
                let error = unsafe { parse_atom(context, expanded) };
                unsafe { (*context).string = source_add(string, 2) };
                return error;
            }
            string = unsafe { source_add(string, 1) };
            match unsafe { source_byte(string) } {
                0 => return REG_EESCAPE,
                b'b' => {
                    node = unsafe {
                        tre_ast_new_literal((*context).memory, ASSERTION, ASSERT_AT_WB as c_long, -1)
                    };
                }
                b'B' => {
                    node = unsafe {
                        tre_ast_new_literal((*context).memory, ASSERTION, ASSERT_AT_WB_NEG as c_long, -1)
                    };
                }
                b'<' => {
                    node = unsafe {
                        tre_ast_new_literal((*context).memory, ASSERTION, ASSERT_AT_BOW as c_long, -1)
                    };
                }
                b'>' => {
                    node = unsafe {
                        tre_ast_new_literal((*context).memory, ASSERTION, ASSERT_AT_EOW as c_long, -1)
                    };
                }
                b'x' => {
                    string = unsafe { source_add(string, 1) };
                    let mut digits = 2usize;
                    if unsafe { source_byte(string) } == b'{' {
                        digits = 8;
                        string = unsafe { source_add(string, 1) };
                    }
                    let mut index = 0usize;
                    let mut scalar = 0 as c_int;
                    while index < digits && scalar < 0x110000 {
                        let value = hexval(unsafe { source_byte(source_add(string, index)) });
                        if value < 0 {
                            break;
                        }
                        scalar = 16 * scalar + value;
                        index += 1;
                    }
                    string = unsafe { source_add(string, index) };
                    if digits == 8 {
                        if unsafe { source_byte(string) } != b'}' {
                            return REG_EBRACE;
                        }
                        string = unsafe { source_add(string, 1) };
                    }
                    node = unsafe {
                        tre_ast_new_literal(
                            (*context).memory,
                            scalar as c_long,
                            scalar as c_long,
                            (*context).position,
                        )
                    };
                    unsafe { (*context).position += 1 };
                    // The shared post-switch increment consumes the final
                    // hex byte exactly as `s--` then `s++` in source.
                    string = unsafe { string.sub(1) };
                }
                b'{' | b'+' | b'?' => {
                    if !extended {
                        return REG_BADRPT;
                    }
                    // In an ERE the escaped spelling falls through
                    // regcomp.c:855-871 to `goto parse_literal`, which
                    // consumes the escaped character itself (with its
                    // REG_ICASE pairing) instead of the common increment.
                    return unsafe { parse_literal_atom(context, string) };
                }
                b'|' => {
                    if !extended {
                        node = unsafe { tre_ast_new_literal((*context).memory, EMPTY, -1, -1) };
                        string = unsafe { string.sub(1) };
                        if node.is_null() {
                            return REG_ESPACE;
                        }
                        // `goto end` in source leaves `s` at the backslash,
                        // letting tre_parse recognize the BRE alternation.
                        unsafe {
                            (*context).node = node;
                            (*context).string = string;
                        }
                        return REG_OK;
                    } else {
                        // ERE `\|` falls through to `goto parse_literal`.
                        return unsafe { parse_literal_atom(context, string) };
                    }
                }
                value if !extended && value.wrapping_sub(b'1') < 9 => {
                    let backreference = (value - b'0') as c_int;
                    node = unsafe {
                        tre_ast_new_literal(
                            (*context).memory,
                            BACKREF,
                            backreference as c_long,
                            (*context).position,
                        )
                    };
                    unsafe {
                        (*context).position += 1;
                        (*context).max_backref = core::cmp::max((*context).max_backref, backreference);
                    }
                }
                _ => {
                    // "extension: accept unknown escaped char as a literal":
                    // the source reaches the shared `parse_literal` label, so
                    // REG_ICASE pairs an escaped letter exactly as it pairs
                    // an unescaped one.
                    return unsafe { parse_literal_atom(context, string) };
                }
            }
            string = unsafe { source_add(string, 1) };
        }
        b'.' => {
            if unsafe { (*context).cflags & REG_NEWLINE } != 0 {
                let left = unsafe {
                    tre_ast_new_literal(
                        (*context).memory,
                        0,
                        b'\n' as c_long - 1,
                        (*context).position,
                    )
                };
                unsafe { (*context).position += 1 };
                let right = unsafe {
                    tre_ast_new_literal(
                        (*context).memory,
                        b'\n' as c_long + 1,
                        TRE_CHAR_MAX as c_long,
                        (*context).position,
                    )
                };
                unsafe { (*context).position += 1 };
                node = if !left.is_null() && !right.is_null() {
                    unsafe { tre_ast_new_union((*context).memory, left, right) }
                } else {
                    ptr::null_mut()
                };
            } else {
                node = unsafe {
                    tre_ast_new_literal(
                        (*context).memory,
                        0,
                        TRE_CHAR_MAX as c_long,
                        (*context).position,
                    )
                };
                unsafe { (*context).position += 1 };
            }
            string = unsafe { source_add(string, 1) };
        }
        b'^' => {
            if !extended && string != unsafe { (*context).start } {
                return unsafe { parse_literal_atom(context, string) };
            }
            node = unsafe {
                tre_ast_new_literal((*context).memory, ASSERTION, ASSERT_AT_BOL as c_long, -1)
            };
            string = unsafe { source_add(string, 1) };
        }
        b'$' => {
            let next = unsafe { source_byte(source_add(string, 1)) };
            let next_after_escape = unsafe { source_byte(source_add(string, 2)) };
            if !extended && next != 0 && (next != b'\\' || (next_after_escape != b')' && next_after_escape != b'|')) {
                return unsafe { parse_literal_atom(context, string) };
            }
            node = unsafe {
                tre_ast_new_literal((*context).memory, ASSERTION, ASSERT_AT_EOL as c_long, -1)
            };
            string = unsafe { source_add(string, 1) };
        }
        b'*' | b'{' | b'+' | b'?' => {
            if extended {
                return REG_BADRPT;
            }
            return unsafe { parse_literal_atom(context, string) };
        }
        b'|' => {
            if !extended {
                return unsafe { parse_literal_atom(context, string) };
            }
            node = unsafe { tre_ast_new_literal((*context).memory, EMPTY, -1, -1) };
        }
        0 => node = unsafe { tre_ast_new_literal((*context).memory, EMPTY, -1, -1) },
        _ => return unsafe { parse_literal_atom(context, string) },
    }
    if node.is_null() {
        return REG_ESPACE;
    }
    unsafe {
        (*context).node = node;
        (*context).string = string;
    }
    REG_OK
}

/// The `parse_literal:` suffix shared by `parse_atom`'s source switch.
unsafe fn parse_literal_atom(context: *mut TreParseContext, string: *const c_char) -> c_int {
    let mut wide = 0i32;
    let length = unsafe { super::super::locale_multibyte::mbtowc(&mut wide, string, usize::MAX) };
    if length < 0 {
        return REG_BADPAT;
    }
    let node = if unsafe { (*context).cflags & REG_ICASE } != 0
        && (super::super::wide_character::iswupper(wide as u32) != 0
            || super::super::wide_character::iswlower(wide as u32) != 0)
    {
        let upper = unsafe {
            tre_ast_new_literal(
                (*context).memory,
                super::super::wide_character::towupper(wide as u32) as c_long,
                super::super::wide_character::towupper(wide as u32) as c_long,
                (*context).position,
            )
        };
        let lower = unsafe {
            tre_ast_new_literal(
                (*context).memory,
                super::super::wide_character::towlower(wide as u32) as c_long,
                super::super::wide_character::towlower(wide as u32) as c_long,
                (*context).position,
            )
        };
        if !upper.is_null() && !lower.is_null() {
            unsafe { tre_ast_new_union((*context).memory, upper, lower) }
        } else {
            ptr::null_mut()
        }
    } else {
        unsafe { tre_ast_new_literal((*context).memory, wide as c_long, wide as c_long, (*context).position) }
    };
    unsafe {
        (*context).position += 1;
        (*context).string = source_add(string, length as usize);
    }
    if node.is_null() {
        REG_ESPACE
    } else {
        unsafe { (*context).node = node };
        REG_OK
    }
}

/// `tre_parse` from regcomp.c:957-1085.
unsafe fn tre_parse(context: *mut TreParseContext) -> c_int {
    let mut branch: *mut TreAstNode = ptr::null_mut();
    let mut union: *mut TreAstNode = ptr::null_mut();
    let extended = unsafe { (*context).cflags & REG_EXTENDED } != 0;
    let mut string = unsafe { (*context).start };
    let mut submatch_id = 0 as c_int;
    let mut depth = 0 as c_int;
    let stack = unsafe { (*context).stack };
    if unsafe { tre_stack_push_int(stack, submatch_id) } != REG_OK {
        return REG_ESPACE;
    }
    submatch_id += 1;
    // Set after closing a group to reproduce source's `goto parse_iter`:
    // the already-built group is allowed to take a following repetition.
    let mut reuse_current_node = false;

    loop {
        if !reuse_current_node {
            let byte = unsafe { source_byte(string) };
            let second = unsafe { source_byte(source_add(string, 1)) };
            if (!extended && byte == b'\\' && second == b'(') || (extended && byte == b'(') {
                if unsafe { tre_stack_push_voidptr(stack, union.cast()) } != REG_OK
                    || unsafe { tre_stack_push_voidptr(stack, branch.cast()) } != REG_OK
                    || unsafe { tre_stack_push_int(stack, submatch_id) } != REG_OK
                {
                    return REG_ESPACE;
                }
                submatch_id += 1;
                string = unsafe { source_add(string, if extended { 1 } else { 2 }) };
                depth += 1;
                branch = ptr::null_mut();
                union = ptr::null_mut();
                unsafe { (*context).start = string };
                continue;
            }
            if (!extended && byte == b'\\' && second == b')') || (extended && byte == b')' && depth != 0) {
                let node = unsafe { tre_ast_new_literal((*context).memory, EMPTY, -1, -1) };
                if node.is_null() {
                    return REG_ESPACE;
                }
                unsafe { (*context).node = node };
            } else {
                let error = unsafe { parse_atom(context, string) };
                if error != REG_OK {
                    return error;
                }
                string = unsafe { (*context).string };
            }
        }
        reuse_current_node = false;

        // `parse_iter:` in source.
        loop {
            let byte = unsafe { source_byte(string) };
            if byte != b'\\' && byte != b'*' {
                if !extended || (byte != b'+' && byte != b'?' && byte != b'{') {
                    break;
                }
            }
            if byte == b'\\' && extended {
                break;
            }
            let second = unsafe { source_byte(source_add(string, 1)) };
            if byte == b'\\' && second != b'+' && second != b'?' && second != b'{' {
                break;
            }
            if byte == b'\\' {
                string = unsafe { source_add(string, 1) };
            }
            if !extended
                && string == unsafe { source_add((*context).start, 1) }
                && unsafe { source_byte(string.sub(1)) } == b'^'
            {
                break;
            }
            let (minimum, maximum) = if unsafe { source_byte(string) } == b'{' {
                let mut minimum = 0 as c_int;
                let mut maximum = 0 as c_int;
                let parsed = unsafe { parse_dup(source_add(string, 1), extended, &mut minimum, &mut maximum) };
                if parsed.is_null() {
                    return REG_BADBR;
                }
                string = parsed;
                (minimum, maximum)
            } else {
                let operator = unsafe { source_byte(string) };
                string = unsafe { source_add(string, 1) };
                (if operator == b'+' { 1 } else { 0 }, if operator == b'?' { 1 } else { -1 })
            };
            let current = if maximum == 0 {
                unsafe { tre_ast_new_literal((*context).memory, EMPTY, -1, -1) }
            } else {
                unsafe { tre_ast_new_iter((*context).memory, (*context).node, minimum, maximum, 0) }
            };
            if current.is_null() {
                return REG_ESPACE;
            }
            unsafe { (*context).node = current };
        }

        branch = unsafe { tre_ast_new_catenation((*context).memory, branch, (*context).node) };
        let byte = unsafe { source_byte(string) };
        let second = unsafe { source_byte(source_add(string, 1)) };
        let boundary = (extended && byte == b'|')
            || (extended && byte == b')' && depth != 0)
            || (!extended && byte == b'\\' && second == b')')
            || (!extended && byte == b'\\' && second == b'|')
            || byte == 0;
        if !boundary {
            continue;
        }
        union = unsafe { tre_ast_new_union((*context).memory, union, branch) };
        branch = ptr::null_mut();
        if byte == b'\\' && second == b'|' {
            string = unsafe { source_add(string, 2) };
            unsafe { (*context).start = string };
            continue;
        }
        if byte == b'|' {
            string = unsafe { source_add(string, 1) };
            unsafe { (*context).start = string };
            continue;
        }
        if byte == b'\\' {
            if depth == 0 {
                return REG_EPAREN;
            }
            string = unsafe { source_add(string, 2) };
        } else if byte == b')' {
            string = unsafe { source_add(string, 1) };
        }
        depth -= 1;
        let error = unsafe { marksub(context, union, tre_stack_pop_int(stack)) };
        if error != REG_OK {
            return error;
        }
        if byte == 0 && depth < 0 {
            unsafe { (*context).submatch_id = submatch_id };
            return REG_OK;
        }
        if byte == 0 || depth < 0 {
            return REG_EPAREN;
        }
        branch = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
        union = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
        reuse_current_node = true;
    }
}

// `regcomp.c:1104-1668`, tag placement and submatch bookkeeping.  The
// source deliberately performs this walk twice: the first walk counts and
// orders tags without mutating the AST, then the second writes the same tags
// into the tree and records the compiled TNFA ownership data.
#[inline]
unsafe fn tre_copy_node_header(destination: *mut TreAstNode, source: *const TreAstNode) {
    unsafe {
        (*destination).object = (*source).object;
        (*destination).node_type = (*source).node_type;
        (*destination).nullable = -1;
        (*destination).submatch_id = -1;
        (*destination).firstpos = ptr::null_mut();
        (*destination).lastpos = ptr::null_mut();
        (*destination).num_tags = 0;
        (*destination).num_submatches = 0;
    }
}

/// `tre_add_tag_left` from regcomp.c:1104-1130.
unsafe fn tre_add_tag_left(memory: *mut TreMem, node: *mut TreAstNode, tag: c_int) -> c_int {
    let catenation = unsafe { tre_mem_alloc(memory, size_of::<TreCatenation>()) }
        .cast::<TreCatenation>();
    if catenation.is_null() {
        return REG_ESPACE;
    }
    let left = unsafe { tre_ast_new_literal(memory, TAG, tag as c_long, -1) };
    if left.is_null() {
        return REG_ESPACE;
    }
    let right = unsafe { tre_mem_alloc(memory, size_of::<TreAstNode>()) }.cast::<TreAstNode>();
    if right.is_null() {
        return REG_ESPACE;
    }
    unsafe {
        tre_copy_node_header(right, node);
        (*catenation).left = left;
        (*catenation).right = right;
        (*node).object = catenation.cast();
        (*node).node_type = CATENATION;
    }
    REG_OK
}

/// `tre_add_tag_right` from regcomp.c:1135-1161.
unsafe fn tre_add_tag_right(memory: *mut TreMem, node: *mut TreAstNode, tag: c_int) -> c_int {
    let catenation = unsafe { tre_mem_alloc(memory, size_of::<TreCatenation>()) }
        .cast::<TreCatenation>();
    if catenation.is_null() {
        return REG_ESPACE;
    }
    let right = unsafe { tre_ast_new_literal(memory, TAG, tag as c_long, -1) };
    if right.is_null() {
        return REG_ESPACE;
    }
    let left = unsafe { tre_mem_alloc(memory, size_of::<TreAstNode>()) }.cast::<TreAstNode>();
    if left.is_null() {
        return REG_ESPACE;
    }
    unsafe {
        tre_copy_node_header(left, node);
        (*catenation).left = left;
        (*catenation).right = right;
        (*node).object = catenation.cast();
        (*node).node_type = CATENATION;
    }
    REG_OK
}

const ADDTAGS_RECURSE: c_int = 0;
const ADDTAGS_AFTER_ITERATION: c_int = 1;
const ADDTAGS_AFTER_UNION_LEFT: c_int = 2;
const ADDTAGS_AFTER_UNION_RIGHT: c_int = 3;
const ADDTAGS_AFTER_CAT_LEFT: c_int = 4;
const ADDTAGS_AFTER_CAT_RIGHT: c_int = 5;
const ADDTAGS_SET_SUBMATCH_END: c_int = 6;

#[repr(C)]
struct TreTagStates {
    tag: c_int,
    next_tag: c_int,
}

/// `tre_purge_regset` from regcomp.c:1183-1197.
unsafe fn tre_purge_regset(regset: *mut c_int, tnfa: *mut TreTnfa, tag: c_int) {
    let mut index = 0usize;
    while unsafe { *regset.add(index) } >= 0 {
        let value = unsafe { *regset.add(index) };
        let id = value / 2;
        if value % 2 == 0 {
            unsafe { (*(*tnfa).submatch_data.add(id as usize)).so_tag = tag };
        } else {
            unsafe { (*(*tnfa).submatch_data.add(id as usize)).eo_tag = tag };
        }
        index += 1;
    }
    unsafe { regset.write(-1) };
}

#[inline]
unsafe fn c_int_array_len(values: *const c_int) -> usize {
    let mut length = 0usize;
    while unsafe { *values.add(length) } >= 0 {
        length += 1;
    }
    length
}

#[inline]
unsafe fn tag_minimal_pair(tnfa: *mut TreTnfa, tag: c_int, minimal_tag: c_int) {
    let values = unsafe { (*tnfa).minimal_tags };
    let index = unsafe { c_int_array_len(values) };
    unsafe {
        values.add(index).write(tag);
        values.add(index + 1).write(minimal_tag);
        values.add(index + 2).write(-1);
    }
}

/// `tre_add_tags` from regcomp.c:1203-1668.
///
/// This keeps TRE's tagged-leftmost ordering walk in its iterative form.  In
/// particular, the stack stores raw source AST pointers and continuation
/// symbols rather than replacing the algorithm with a recursive Rust walk.
unsafe fn tre_add_tags(
    memory: *mut TreMem,
    stack: *mut TreStack,
    tree: *mut TreAstNode,
    tnfa: *mut TreTnfa,
) -> c_int {
    let first_pass = memory.is_null() || tnfa.is_null();
    if !first_pass {
        unsafe {
            (*tnfa).end_tag = 0;
            (*tnfa).minimal_tags.write(-1);
        }
    }

    let submatches = unsafe { (*tnfa).num_submatches as usize };
    let Some(regset_count) = submatches.checked_add(1).and_then(|count| count.checked_mul(2)) else {
        return REG_ESPACE;
    };
    let Some(regset_bytes) = regset_count.checked_mul(size_of::<c_int>()) else {
        return REG_ESPACE;
    };
    let regset = unsafe { cabi_malloc(regset_bytes) }.cast::<c_int>();
    if regset.is_null() {
        return REG_ESPACE;
    }
    unsafe { regset.write(-1) };

    let Some(parents_count) = submatches.checked_add(1) else {
        unsafe { cabi_free(regset.cast()) };
        return REG_ESPACE;
    };
    let Some(parents_bytes) = parents_count.checked_mul(size_of::<c_int>()) else {
        unsafe { cabi_free(regset.cast()) };
        return REG_ESPACE;
    };
    let parents = unsafe { cabi_malloc(parents_bytes) }.cast::<c_int>();
    if parents.is_null() {
        unsafe { cabi_free(regset.cast()) };
        return REG_ESPACE;
    }
    unsafe { parents.write(-1) };

    let Some(states_bytes) = parents_count.checked_mul(size_of::<TreTagStates>()) else {
        unsafe {
            cabi_free(regset.cast());
            cabi_free(parents.cast());
        }
        return REG_ESPACE;
    };
    let saved_states = unsafe { cabi_malloc(states_bytes) }.cast::<TreTagStates>();
    if saved_states.is_null() {
        unsafe {
            cabi_free(regset.cast());
            cabi_free(parents.cast());
        }
        return REG_ESPACE;
    }
    for index in 0..parents_count {
        unsafe { (*saved_states.add(index)).tag = -1 };
    }

    let bottom = unsafe { tre_stack_num_objects(stack) };
    let mut status = REG_OK;
    let mut node = tree;
    let mut num_tags = 0;
    let mut num_minimals = 0;
    let mut tag = 0;
    let mut next_tag = 1;
    let mut minimal_tag = -1;
    let mut direction = TRE_TAG_MINIMIZE;
    let mut active_regset = regset;

    if unsafe { tre_stack_push_voidptr(stack, node.cast()) } != REG_OK
        || unsafe { tre_stack_push_int(stack, ADDTAGS_RECURSE) } != REG_OK
    {
        status = REG_ESPACE;
    }

    while status == REG_OK && unsafe { tre_stack_num_objects(stack) } > bottom {
        let symbol = unsafe { tre_stack_pop_int(stack) };
        match symbol {
            ADDTAGS_SET_SUBMATCH_END => {
                let id = unsafe { tre_stack_pop_int(stack) };
                let index = unsafe { c_int_array_len(active_regset) };
                unsafe {
                    active_regset.add(index).write(id * 2 + 1);
                    active_regset.add(index + 1).write(-1);
                    let parent_length = c_int_array_len(parents);
                    parents.add(parent_length - 1).write(-1);
                }
            }
            ADDTAGS_RECURSE => {
                node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                if unsafe { (*node).submatch_id } >= 0 {
                    let id = unsafe { (*node).submatch_id };
                    let index = unsafe { c_int_array_len(active_regset) };
                    unsafe {
                        active_regset.add(index).write(id * 2);
                        active_regset.add(index + 1).write(-1);
                    }
                    if !first_pass {
                        let parents_length = unsafe { c_int_array_len(parents) };
                        unsafe { (*(*tnfa).submatch_data.add(id as usize)).parents = ptr::null_mut() };
                        if parents_length > 0 {
                            let Some(bytes) = parents_length.checked_add(1).and_then(|count| count.checked_mul(size_of::<c_int>())) else {
                                status = REG_ESPACE;
                                break;
                            };
                            let copied = unsafe { cabi_malloc(bytes) }.cast::<c_int>();
                            if copied.is_null() {
                                status = REG_ESPACE;
                                break;
                            }
                            unsafe {
                                (*(*tnfa).submatch_data.add(id as usize)).parents = copied;
                                ptr::copy_nonoverlapping(parents, copied, parents_length);
                                copied.add(parents_length).write(-1);
                            }
                        }
                    }
                    if unsafe { tre_stack_push_int(stack, id) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, ADDTAGS_SET_SUBMATCH_END) } != REG_OK
                    {
                        status = REG_ESPACE;
                        break;
                    }
                }

                match unsafe { (*node).node_type } {
                    LITERAL => {
                        let literal = unsafe { (*node).object.cast::<TreLiteral>() };
                        if !unsafe { literal_is_special(literal) } || unsafe { literal_is_backref(literal) } {
                            if unsafe { *active_regset } >= 0 {
                                if !first_pass {
                                    status = unsafe { tre_add_tag_left(memory, node, tag) };
                                    if status != REG_OK {
                                        break;
                                    }
                                    unsafe { *(*tnfa).tag_directions.add(tag as usize) = direction };
                                    if minimal_tag >= 0 {
                                        unsafe { tag_minimal_pair(tnfa, tag, minimal_tag) };
                                        minimal_tag = -1;
                                        num_minimals += 1;
                                    }
                                    unsafe { tre_purge_regset(active_regset, tnfa, tag) };
                                } else {
                                    unsafe { (*node).num_tags = 1 };
                                }
                                unsafe { active_regset.write(-1) };
                                tag = next_tag;
                                num_tags += 1;
                                next_tag += 1;
                            }
                        }
                    }
                    CATENATION => {
                        let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                        let left = unsafe { (*catenation).left };
                        let right = unsafe { (*catenation).right };
                        let mut reserved_tag = -1;
                        let result = (|| unsafe {
                            if tre_stack_push_voidptr(stack, node.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_AFTER_CAT_RIGHT) != REG_OK
                                || tre_stack_push_voidptr(stack, right.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_RECURSE) != REG_OK
                                || tre_stack_push_int(stack, next_tag + (*left).num_tags) != REG_OK
                            {
                                return REG_ESPACE;
                            }
                            if (*left).num_tags > 0 && (*right).num_tags > 0 {
                                reserved_tag = next_tag;
                                next_tag += 1;
                            }
                            if tre_stack_push_int(stack, reserved_tag) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_AFTER_CAT_LEFT) != REG_OK
                                || tre_stack_push_voidptr(stack, left.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_RECURSE) != REG_OK
                            {
                                return REG_ESPACE;
                            }
                            REG_OK
                        })();
                        if result != REG_OK {
                            status = result;
                            break;
                        }
                    }
                    ITERATION => {
                        let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                        let first_value = if first_pass {
                            (unsafe { *active_regset } >= 0 || unsafe { (*iteration).minimal } != 0) as c_int
                        } else {
                            tag
                        };
                        let result = (|| unsafe {
                            if tre_stack_push_int(stack, first_value) != REG_OK {
                                return REG_ESPACE;
                            }
                            if !first_pass && tre_stack_push_int(stack, (*iteration).minimal as c_int) != REG_OK {
                                return REG_ESPACE;
                            }
                            if tre_stack_push_voidptr(stack, node.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_AFTER_ITERATION) != REG_OK
                                || tre_stack_push_voidptr(stack, (*iteration).argument.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_RECURSE) != REG_OK
                            {
                                return REG_ESPACE;
                            }
                            REG_OK
                        })();
                        if result != REG_OK {
                            status = result;
                            break;
                        }
                        if unsafe { *active_regset } >= 0 || unsafe { (*iteration).minimal } != 0 {
                            if !first_pass {
                                status = unsafe { tre_add_tag_left(memory, node, tag) };
                                if status != REG_OK {
                                    break;
                                }
                                unsafe {
                                    *(*tnfa).tag_directions.add(tag as usize) = if (*iteration).minimal != 0 {
                                        TRE_TAG_MAXIMIZE
                                    } else {
                                        direction
                                    };
                                }
                                if minimal_tag >= 0 {
                                    unsafe { tag_minimal_pair(tnfa, tag, minimal_tag) };
                                    minimal_tag = -1;
                                    num_minimals += 1;
                                }
                                unsafe { tre_purge_regset(active_regset, tnfa, tag) };
                            }
                            unsafe { active_regset.write(-1) };
                            tag = next_tag;
                            num_tags += 1;
                            next_tag += 1;
                        }
                        direction = TRE_TAG_MINIMIZE;
                    }
                    UNION => {
                        let union = unsafe { (*node).object.cast::<TreUnion>() };
                        let left = unsafe { (*union).left };
                        let right = unsafe { (*union).right };
                        let nonempty = unsafe { *active_regset } >= 0;
                        let left_tag = if nonempty { next_tag } else { tag };
                        let right_tag = if nonempty { next_tag + 1 } else { next_tag };
                        let result = (|| unsafe {
                            if tre_stack_push_int(stack, right_tag) != REG_OK
                                || tre_stack_push_int(stack, left_tag) != REG_OK
                                || tre_stack_push_voidptr(stack, active_regset.cast()) != REG_OK
                                || tre_stack_push_int(stack, nonempty as c_int) != REG_OK
                                || tre_stack_push_voidptr(stack, node.cast()) != REG_OK
                                || tre_stack_push_voidptr(stack, right.cast()) != REG_OK
                                || tre_stack_push_voidptr(stack, left.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_AFTER_UNION_RIGHT) != REG_OK
                                || tre_stack_push_voidptr(stack, right.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_RECURSE) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_AFTER_UNION_LEFT) != REG_OK
                                || tre_stack_push_voidptr(stack, left.cast()) != REG_OK
                                || tre_stack_push_int(stack, ADDTAGS_RECURSE) != REG_OK
                            {
                                return REG_ESPACE;
                            }
                            REG_OK
                        })();
                        if result != REG_OK {
                            status = result;
                            break;
                        }
                        if nonempty {
                            if !first_pass {
                                status = unsafe { tre_add_tag_left(memory, node, tag) };
                                if status != REG_OK {
                                    break;
                                }
                                unsafe { *(*tnfa).tag_directions.add(tag as usize) = direction };
                                if minimal_tag >= 0 {
                                    unsafe { tag_minimal_pair(tnfa, tag, minimal_tag) };
                                    minimal_tag = -1;
                                    num_minimals += 1;
                                }
                                unsafe { tre_purge_regset(active_regset, tnfa, tag) };
                            }
                            unsafe { active_regset.write(-1) };
                            tag = next_tag;
                            num_tags += 1;
                            next_tag += 1;
                        }
                        if unsafe { (*node).num_submatches } > 0 {
                            next_tag += 1;
                            tag = next_tag;
                            next_tag += 1;
                        }
                    }
                    _ => {
                        status = REG_BADPAT;
                        break;
                    }
                }
                if unsafe { (*node).submatch_id } >= 0 {
                    let index = unsafe { c_int_array_len(parents) };
                    unsafe {
                        parents.add(index).write((*node).submatch_id);
                        parents.add(index + 1).write(-1);
                    }
                }
            }
            ADDTAGS_AFTER_ITERATION => {
                node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                if first_pass {
                    let had_regset = unsafe { tre_stack_pop_int(stack) };
                    let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                    unsafe { (*node).num_tags = (*(*iteration).argument).num_tags + had_regset };
                    minimal_tag = -1;
                } else {
                    let minimal = unsafe { tre_stack_pop_int(stack) };
                    let enter_tag = unsafe { tre_stack_pop_int(stack) };
                    if minimal != 0 {
                        minimal_tag = enter_tag;
                    }
                    direction = if minimal != 0 {
                        TRE_TAG_MINIMIZE
                    } else {
                        TRE_TAG_MAXIMIZE
                    };
                }
            }
            ADDTAGS_AFTER_CAT_LEFT => {
                let new_tag = unsafe { tre_stack_pop_int(stack) };
                next_tag = unsafe { tre_stack_pop_int(stack) };
                if new_tag >= 0 {
                    tag = new_tag;
                }
            }
            ADDTAGS_AFTER_CAT_RIGHT => {
                node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                if first_pass {
                    let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                    unsafe {
                        (*node).num_tags = (*(*catenation).left).num_tags + (*(*catenation).right).num_tags;
                    }
                }
            }
            ADDTAGS_AFTER_UNION_LEFT => {
                while unsafe { *active_regset } >= 0 {
                    active_regset = unsafe { active_regset.add(1) };
                }
            }
            ADDTAGS_AFTER_UNION_RIGHT => {
                let left = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                let right = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                let added_tags = unsafe { tre_stack_pop_int(stack) };
                if first_pass {
                    let union = unsafe { (*node).object.cast::<TreUnion>() };
                    unsafe {
                        (*node).num_tags = (*(*union).left).num_tags
                            + (*(*union).right).num_tags
                            + added_tags
                            + if (*node).num_submatches > 0 { 2 } else { 0 };
                    }
                }
                active_regset = unsafe { tre_stack_pop_voidptr(stack) }.cast::<c_int>();
                let tag_left = unsafe { tre_stack_pop_int(stack) };
                let tag_right = unsafe { tre_stack_pop_int(stack) };
                if unsafe { (*node).num_submatches } > 0 {
                    if !first_pass {
                        status = unsafe { tre_add_tag_right(memory, left, tag_left) };
                        if status == REG_OK {
                            unsafe { *(*tnfa).tag_directions.add(tag_left as usize) = TRE_TAG_MAXIMIZE };
                            status = unsafe { tre_add_tag_right(memory, right, tag_right) };
                            unsafe { *(*tnfa).tag_directions.add(tag_right as usize) = TRE_TAG_MAXIMIZE };
                        }
                    }
                    num_tags += 2;
                }
                direction = TRE_TAG_MAXIMIZE;
            }
            _ => {
                status = REG_BADPAT;
            }
        }
    }

    if status == REG_OK && !first_pass {
        unsafe { tre_purge_regset(active_regset, tnfa, tag) };
    }
    if status == REG_OK && !first_pass && minimal_tag >= 0 {
        unsafe { tag_minimal_pair(tnfa, tag, minimal_tag) };
        num_minimals += 1;
    }
    if status == REG_OK {
        unsafe {
            (*tnfa).end_tag = num_tags;
            (*tnfa).num_tags = num_tags;
            (*tnfa).num_minimals = num_minimals;
        }
    }
    unsafe {
        cabi_free(regset.cast());
        cabi_free(parents.cast());
        cabi_free(saved_states.cast());
    }
    status
}

const COPY_RECURSE: c_int = 0;
const COPY_SET_RESULT_PTR: c_int = 1;
const COPY_REMOVE_TAGS: c_int = 1;
const COPY_MAXIMIZE_FIRST_TAG: c_int = 2;

/// `tre_copy_ast` from regcomp.c:1687-1825.
unsafe fn tre_copy_ast(
    memory: *mut TreMem,
    stack: *mut TreStack,
    ast: *mut TreAstNode,
    flags: c_int,
    position_add: *mut c_int,
    tag_directions: *mut TreTagDirection,
    copy: *mut *mut TreAstNode,
    maximum_position: *mut c_int,
) -> c_int {
    let bottom = unsafe { tre_stack_num_objects(stack) };
    let mut status = REG_OK;
    let mut copied_count = 0;
    let mut first_tag = true;
    let mut result = copy;
    if unsafe { tre_stack_push_voidptr(stack, ast.cast()) } != REG_OK
        || unsafe { tre_stack_push_int(stack, COPY_RECURSE) } != REG_OK
    {
        return REG_ESPACE;
    }
    while status == REG_OK && unsafe { tre_stack_num_objects(stack) } > bottom {
        match unsafe { tre_stack_pop_int(stack) } {
            COPY_SET_RESULT_PTR => {
                result = unsafe { tre_stack_pop_voidptr(stack) }.cast::<*mut TreAstNode>();
            }
            COPY_RECURSE => {
                let node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
                match unsafe { (*node).node_type } {
                    LITERAL => {
                        let literal = unsafe { (*node).object.cast::<TreLiteral>() };
                        let mut position = unsafe { (*literal).position };
                        let mut minimum = unsafe { (*literal).code_min };
                        let mut maximum = unsafe { (*literal).code_max };
                        if !unsafe { literal_is_special(literal) } || unsafe { literal_is_backref(literal) } {
                            position += unsafe { *position_add };
                            copied_count += 1;
                        } else if unsafe { literal_is_tag(literal) } && flags & COPY_REMOVE_TAGS != 0 {
                            minimum = EMPTY;
                            maximum = -1;
                            position = -1;
                        } else if unsafe { literal_is_tag(literal) }
                            && flags & COPY_MAXIMIZE_FIRST_TAG != 0
                            && first_tag
                        {
                            unsafe {
                                *tag_directions.add(maximum as usize) = TRE_TAG_MAXIMIZE;
                            }
                            first_tag = false;
                        }
                        let output = unsafe { tre_ast_new_literal(memory, minimum, maximum, position) };
                        unsafe { result.write(output) };
                        if output.is_null() {
                            status = REG_ESPACE;
                        } else {
                            let output_literal = unsafe { (*output).object.cast::<TreLiteral>() };
                            unsafe {
                                (*output_literal).class = (*literal).class;
                                (*output_literal).neg_classes = (*literal).neg_classes;
                            }
                        }
                        if position > unsafe { *maximum_position } {
                            unsafe { maximum_position.write(position) };
                        }
                    }
                    UNION => {
                        let union = unsafe { (*node).object.cast::<TreUnion>() };
                        let output = unsafe { tre_ast_new_union(memory, (*union).left, (*union).right) };
                        unsafe { result.write(output) };
                        if output.is_null() {
                            status = REG_ESPACE;
                            continue;
                        }
                        let temporary = unsafe { (*output).object.cast::<TreUnion>() };
                        result = unsafe { &mut (*temporary).left };
                        let pushed = (|| unsafe {
                            if tre_stack_push_voidptr(stack, (*union).right.cast()) != REG_OK
                                || tre_stack_push_int(stack, COPY_RECURSE) != REG_OK
                                || tre_stack_push_voidptr(stack, (&mut (*temporary).right as *mut *mut TreAstNode).cast()) != REG_OK
                                || tre_stack_push_int(stack, COPY_SET_RESULT_PTR) != REG_OK
                                || tre_stack_push_voidptr(stack, (*union).left.cast()) != REG_OK
                                || tre_stack_push_int(stack, COPY_RECURSE) != REG_OK
                            {
                                return REG_ESPACE;
                            }
                            REG_OK
                        })();
                        if pushed != REG_OK {
                            status = pushed;
                        }
                    }
                    CATENATION => {
                        let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                        let output = unsafe {
                            tre_ast_new_catenation(memory, (*catenation).left, (*catenation).right)
                        };
                        unsafe { result.write(output) };
                        if output.is_null() {
                            status = REG_ESPACE;
                            continue;
                        }
                        let temporary = unsafe { (*output).object.cast::<TreCatenation>() };
                        unsafe {
                            (*temporary).left = ptr::null_mut();
                            (*temporary).right = ptr::null_mut();
                        }
                        result = unsafe { &mut (*temporary).left };
                        let pushed = (|| unsafe {
                            if tre_stack_push_voidptr(stack, (*catenation).right.cast()) != REG_OK
                                || tre_stack_push_int(stack, COPY_RECURSE) != REG_OK
                                || tre_stack_push_voidptr(stack, (&mut (*temporary).right as *mut *mut TreAstNode).cast()) != REG_OK
                                || tre_stack_push_int(stack, COPY_SET_RESULT_PTR) != REG_OK
                                || tre_stack_push_voidptr(stack, (*catenation).left.cast()) != REG_OK
                                || tre_stack_push_int(stack, COPY_RECURSE) != REG_OK
                            {
                                return REG_ESPACE;
                            }
                            REG_OK
                        })();
                        if pushed != REG_OK {
                            status = pushed;
                        }
                    }
                    ITERATION => {
                        let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                        if unsafe { tre_stack_push_voidptr(stack, (*iteration).argument.cast()) } != REG_OK
                            || unsafe { tre_stack_push_int(stack, COPY_RECURSE) } != REG_OK
                        {
                            status = REG_ESPACE;
                            continue;
                        }
                        let output = unsafe {
                            tre_ast_new_iter(
                                memory,
                                (*iteration).argument,
                                (*iteration).minimum,
                                (*iteration).maximum,
                                (*iteration).minimal as c_int,
                            )
                        };
                        unsafe { result.write(output) };
                        if output.is_null() {
                            status = REG_ESPACE;
                        } else {
                            let output_iteration = unsafe { (*output).object.cast::<TreIteration>() };
                            result = unsafe { &mut (*output_iteration).argument };
                        }
                    }
                    _ => status = REG_BADPAT,
                }
            }
            _ => status = REG_BADPAT,
        }
    }
    unsafe { *position_add += copied_count };
    status
}

const EXPAND_RECURSE: c_int = 0;
const EXPAND_AFTER_ITER: c_int = 1;

/// `tre_expand_ast` from regcomp.c:1835-2017.
unsafe fn tre_expand_ast(
    memory: *mut TreMem,
    stack: *mut TreStack,
    ast: *mut TreAstNode,
    position: *mut c_int,
    tag_directions: *mut TreTagDirection,
) -> c_int {
    let bottom = unsafe { tre_stack_num_objects(stack) };
    let mut status = REG_OK;
    let mut position_add = 0;
    let mut total_position_add = 0;
    let mut maximum_position = 0;
    let mut iteration_depth = 0;
    if unsafe { tre_stack_push_voidptr(stack, ast.cast()) } != REG_OK
        || unsafe { tre_stack_push_int(stack, EXPAND_RECURSE) } != REG_OK
    {
        return REG_ESPACE;
    }
    while status == REG_OK && unsafe { tre_stack_num_objects(stack) } > bottom {
        let symbol = unsafe { tre_stack_pop_int(stack) };
        let node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
        match symbol {
            EXPAND_RECURSE => match unsafe { (*node).node_type } {
                LITERAL => {
                    let literal = unsafe { (*node).object.cast::<TreLiteral>() };
                    if !unsafe { literal_is_special(literal) } || unsafe { literal_is_backref(literal) } {
                        unsafe { (*literal).position += position_add };
                        if unsafe { (*literal).position } > maximum_position {
                            maximum_position = unsafe { (*literal).position };
                        }
                    }
                }
                UNION => {
                    let union = unsafe { (*node).object.cast::<TreUnion>() };
                    if unsafe { tre_stack_push_voidptr(stack, (*union).right.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, EXPAND_RECURSE) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*union).left.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, EXPAND_RECURSE) } != REG_OK
                    {
                        status = REG_ESPACE;
                    }
                }
                CATENATION => {
                    let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                    if unsafe { tre_stack_push_voidptr(stack, (*catenation).right.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, EXPAND_RECURSE) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*catenation).left.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, EXPAND_RECURSE) } != REG_OK
                    {
                        status = REG_ESPACE;
                    }
                }
                ITERATION => {
                    let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                    if unsafe { tre_stack_push_int(stack, position_add) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, node.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, EXPAND_AFTER_ITER) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*iteration).argument.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, EXPAND_RECURSE) } != REG_OK
                    {
                        status = REG_ESPACE;
                        continue;
                    }
                    if unsafe { (*iteration).minimum } > 1 || unsafe { (*iteration).maximum } > 1 {
                        position_add = 0;
                    }
                    iteration_depth += 1;
                }
                _ => status = REG_BADPAT,
            },
            EXPAND_AFTER_ITER => {
                let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                position_add = unsafe { tre_stack_pop_int(stack) };
                let last_position_add = position_add;
                if unsafe { (*iteration).minimum } > 1 || unsafe { (*iteration).maximum } > 1 {
                    let mut sequence_one: *mut TreAstNode = ptr::null_mut();
                    let mut sequence_two: *mut TreAstNode = ptr::null_mut();
                    let mut saved_position_add = position_add;
                    let mut index = 0;
                    while index < unsafe { (*iteration).minimum } {
                        let flags = if index + 1 < unsafe { (*iteration).minimum } {
                            COPY_REMOVE_TAGS
                        } else {
                            COPY_MAXIMIZE_FIRST_TAG
                        };
                        saved_position_add = position_add;
                        let mut copy = ptr::null_mut();
                        status = unsafe {
                            tre_copy_ast(
                                memory,
                                stack,
                                (*iteration).argument,
                                flags,
                                &mut position_add,
                                tag_directions,
                                &mut copy,
                                &mut maximum_position,
                            )
                        };
                        if status != REG_OK {
                            break;
                        }
                        sequence_one = if sequence_one.is_null() {
                            copy
                        } else {
                            unsafe { tre_ast_new_catenation(memory, sequence_one, copy) }
                        };
                        if sequence_one.is_null() {
                            status = REG_ESPACE;
                            break;
                        }
                        index += 1;
                    }
                    if status == REG_OK {
                        if unsafe { (*iteration).maximum } == -1 {
                            saved_position_add = position_add;
                            let mut copy = ptr::null_mut();
                            status = unsafe {
                                tre_copy_ast(
                                    memory,
                                    stack,
                                    (*iteration).argument,
                                    0,
                                    &mut position_add,
                                    ptr::null_mut(),
                                    &mut copy,
                                    &mut maximum_position,
                                )
                            };
                            if status == REG_OK {
                                sequence_two = unsafe { tre_ast_new_iter(memory, copy, 0, -1, 0) };
                                if sequence_two.is_null() {
                                    status = REG_ESPACE;
                                }
                            }
                        } else {
                            let mut optional = unsafe { (*iteration).minimum };
                            while optional < unsafe { (*iteration).maximum } {
                                saved_position_add = position_add;
                                let mut copy = ptr::null_mut();
                                status = unsafe {
                                    tre_copy_ast(
                                        memory,
                                        stack,
                                        (*iteration).argument,
                                        0,
                                        &mut position_add,
                                        ptr::null_mut(),
                                        &mut copy,
                                        &mut maximum_position,
                                    )
                                };
                                if status != REG_OK {
                                    break;
                                }
                                sequence_two = if sequence_two.is_null() {
                                    copy
                                } else {
                                    unsafe { tre_ast_new_catenation(memory, copy, sequence_two) }
                                };
                                if sequence_two.is_null() {
                                    status = REG_ESPACE;
                                    break;
                                }
                                let empty = unsafe { tre_ast_new_literal(memory, EMPTY, -1, -1) };
                                if empty.is_null() {
                                    status = REG_ESPACE;
                                    break;
                                }
                                sequence_two = unsafe { tre_ast_new_union(memory, empty, sequence_two) };
                                if sequence_two.is_null() {
                                    status = REG_ESPACE;
                                    break;
                                }
                                optional += 1;
                            }
                        }
                    }
                    if status == REG_OK {
                        position_add = saved_position_add;
                        if sequence_one.is_null() {
                            sequence_one = sequence_two;
                        } else if !sequence_two.is_null() {
                            sequence_one = unsafe { tre_ast_new_catenation(memory, sequence_one, sequence_two) };
                        }
                        if sequence_one.is_null() {
                            status = REG_ESPACE;
                        } else {
                            unsafe {
                                (*node).object = (*sequence_one).object;
                                (*node).node_type = (*sequence_one).node_type;
                            }
                        }
                    }
                }
                iteration_depth -= 1;
                total_position_add += position_add - last_position_add;
                if iteration_depth == 0 {
                    position_add = total_position_add;
                }
            }
            _ => status = REG_BADPAT,
        }
    }
    unsafe {
        *position += total_position_add;
        if maximum_position > *position {
            *position = maximum_position;
        }
    }
    status
}

/// `tre_set_empty` from regcomp.c:2020-2033.
unsafe fn tre_set_empty(memory: *mut TreMem) -> *mut TrePosAndTags {
    let values = unsafe { tre_mem_calloc(memory, size_of::<TrePosAndTags>()) }
        .cast::<TrePosAndTags>();
    if values.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*values).position = -1;
        (*values).code_min = -1;
        (*values).code_max = -1;
    }
    values
}

/// `tre_set_one` from regcomp.c:2036-2056.
unsafe fn tre_set_one(
    memory: *mut TreMem,
    position: c_int,
    minimum: c_int,
    maximum: c_int,
    class: tre_ctype_t,
    negative_classes: *mut tre_ctype_t,
    backreference: c_int,
) -> *mut TrePosAndTags {
    let Some(size) = size_of::<TrePosAndTags>().checked_mul(2) else {
        return ptr::null_mut();
    };
    let values = unsafe { tre_mem_calloc(memory, size) }.cast::<TrePosAndTags>();
    if values.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*values).position = position;
        (*values).code_min = minimum;
        (*values).code_max = maximum;
        (*values).class = class;
        (*values).neg_classes = negative_classes;
        (*values).backref = backreference;
        (*values.add(1)).position = -1;
        (*values.add(1)).code_min = -1;
        (*values.add(1)).code_max = -1;
    }
    values
}

#[inline]
unsafe fn pos_set_len(values: *const TrePosAndTags) -> usize {
    let mut length = 0usize;
    while unsafe { (*values.add(length)).position } >= 0 {
        length += 1;
    }
    length
}

/// `tre_set_union` from regcomp.c:2059-2127.
unsafe fn tre_set_union(
    memory: *mut TreMem,
    first: *const TrePosAndTags,
    second: *const TrePosAndTags,
    tags: *const c_int,
    assertions: c_int,
) -> *mut TrePosAndTags {
    let added_tags = if tags.is_null() {
        0
    } else {
        unsafe { c_int_array_len(tags) }
    };
    let first_len = unsafe { pos_set_len(first) };
    let second_len = unsafe { pos_set_len(second) };
    let Some(count) = first_len.checked_add(second_len).and_then(|count| count.checked_add(1)) else {
        return ptr::null_mut();
    };
    let Some(size) = count.checked_mul(size_of::<TrePosAndTags>()) else {
        return ptr::null_mut();
    };
    let output = unsafe { tre_mem_calloc(memory, size) }.cast::<TrePosAndTags>();
    if output.is_null() {
        return ptr::null_mut();
    }
    for index in 0..first_len {
        let source = unsafe { first.add(index) };
        let destination = unsafe { output.add(index) };
        unsafe {
            (*destination).position = (*source).position;
            (*destination).code_min = (*source).code_min;
            (*destination).code_max = (*source).code_max;
            (*destination).assertions = (*source).assertions | assertions;
            (*destination).class = (*source).class;
            (*destination).neg_classes = (*source).neg_classes;
            (*destination).backref = (*source).backref;
        }
        let old_tags = unsafe { (*source).tags };
        if !old_tags.is_null() || !tags.is_null() {
            let old_length = if old_tags.is_null() {
                0
            } else {
                unsafe { c_int_array_len(old_tags) }
            };
            let Some(tag_count) = old_length.checked_add(added_tags).and_then(|count| count.checked_add(1)) else {
                return ptr::null_mut();
            };
            let Some(tag_size) = tag_count.checked_mul(size_of::<c_int>()) else {
                return ptr::null_mut();
            };
            let new_tags = unsafe { tre_mem_alloc(memory, tag_size) }.cast::<c_int>();
            if new_tags.is_null() {
                return ptr::null_mut();
            }
            if old_length != 0 {
                unsafe { ptr::copy_nonoverlapping(old_tags, new_tags, old_length) };
            }
            if added_tags != 0 {
                unsafe { ptr::copy_nonoverlapping(tags, new_tags.add(old_length), added_tags) };
            }
            unsafe {
                new_tags.add(old_length + added_tags).write(-1);
                (*destination).tags = new_tags;
            }
        }
    }
    for index in 0..second_len {
        let source = unsafe { second.add(index) };
        let destination = unsafe { output.add(first_len + index) };
        unsafe {
            (*destination).position = (*source).position;
            (*destination).code_min = (*source).code_min;
            (*destination).code_max = (*source).code_max;
            // This asymmetry is literal source behavior: `assertions` is
            // carried only onto the copied first set.
            (*destination).assertions = (*source).assertions;
            (*destination).class = (*source).class;
            (*destination).neg_classes = (*source).neg_classes;
            (*destination).backref = (*source).backref;
        }
        let old_tags = unsafe { (*source).tags };
        if !old_tags.is_null() {
            let old_length = unsafe { c_int_array_len(old_tags) };
            let Some(tag_size) = old_length.checked_add(1).and_then(|count| count.checked_mul(size_of::<c_int>())) else {
                return ptr::null_mut();
            };
            let new_tags = unsafe { tre_mem_alloc(memory, tag_size) }.cast::<c_int>();
            if new_tags.is_null() {
                return ptr::null_mut();
            }
            unsafe {
                ptr::copy_nonoverlapping(old_tags, new_tags, old_length);
                new_tags.add(old_length).write(-1);
                (*destination).tags = new_tags;
            }
        }
    }
    unsafe { (*output.add(first_len + second_len)).position = -1 };
    output
}

/// `tre_match_empty` from regcomp.c:2134-2230.
unsafe fn tre_match_empty(
    stack: *mut TreStack,
    mut node: *mut TreAstNode,
    tags: *mut c_int,
    assertions: *mut c_int,
    tag_count: *mut c_int,
) -> c_int {
    if !tag_count.is_null() {
        unsafe { tag_count.write(0) };
    }
    let bottom = unsafe { tre_stack_num_objects(stack) };
    let mut status = unsafe { tre_stack_push_voidptr(stack, node.cast()) };
    while status == REG_OK && unsafe { tre_stack_num_objects(stack) } > bottom {
        node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
        match unsafe { (*node).node_type } {
            LITERAL => {
                let literal = unsafe { (*node).object.cast::<TreLiteral>() };
                match unsafe { (*literal).code_min } {
                    TAG => {
                        let value = unsafe { (*literal).code_max as c_int };
                        if value >= 0 {
                            if !tags.is_null() {
                                let mut index = 0usize;
                                while unsafe { *tags.add(index) } >= 0 && unsafe { *tags.add(index) } != value {
                                    index += 1;
                                }
                                if unsafe { *tags.add(index) } < 0 {
                                    unsafe {
                                        tags.add(index).write(value);
                                        tags.add(index + 1).write(-1);
                                    }
                                }
                            }
                            if !tag_count.is_null() {
                                unsafe { *tag_count += 1 };
                            }
                        }
                    }
                    ASSERTION => {
                        if !assertions.is_null() {
                            unsafe { *assertions |= (*literal).code_max as c_int };
                        }
                    }
                    EMPTY => {}
                    _ => return REG_BADPAT,
                }
            }
            UNION => {
                let union = unsafe { (*node).object.cast::<TreUnion>() };
                let selected = if unsafe { (*(*union).left).nullable } != 0 {
                    unsafe { (*union).left }
                } else if unsafe { (*(*union).right).nullable } != 0 {
                    unsafe { (*union).right }
                } else {
                    return REG_BADPAT;
                };
                status = unsafe { tre_stack_push_voidptr(stack, selected.cast()) };
            }
            CATENATION => {
                let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                if unsafe { (*(*catenation).left).nullable } == 0 || unsafe { (*(*catenation).right).nullable } == 0 {
                    return REG_BADPAT;
                }
                if unsafe { tre_stack_push_voidptr(stack, (*catenation).left.cast()) } != REG_OK
                    || unsafe { tre_stack_push_voidptr(stack, (*catenation).right.cast()) } != REG_OK
                {
                    status = REG_ESPACE;
                }
            }
            ITERATION => {
                let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                if unsafe { (*(*iteration).argument).nullable } != 0 {
                    status = unsafe { tre_stack_push_voidptr(stack, (*iteration).argument.cast()) };
                }
            }
            _ => return REG_BADPAT,
        }
    }
    status
}

const NFL_RECURSE: c_int = 0;
const NFL_POST_UNION: c_int = 1;
const NFL_POST_CATENATION: c_int = 2;
const NFL_POST_ITERATION: c_int = 3;

/// `tre_compute_nfl` from regcomp.c:2244-2465.
unsafe fn tre_compute_nfl(memory: *mut TreMem, stack: *mut TreStack, tree: *mut TreAstNode) -> c_int {
    let bottom = unsafe { tre_stack_num_objects(stack) };
    if unsafe { tre_stack_push_voidptr(stack, tree.cast()) } != REG_OK
        || unsafe { tre_stack_push_int(stack, NFL_RECURSE) } != REG_OK
    {
        return REG_ESPACE;
    }
    while unsafe { tre_stack_num_objects(stack) } > bottom {
        let symbol = unsafe { tre_stack_pop_int(stack) };
        let node = unsafe { tre_stack_pop_voidptr(stack) }.cast::<TreAstNode>();
        match symbol {
            NFL_RECURSE => match unsafe { (*node).node_type } {
                LITERAL => {
                    let literal = unsafe { (*node).object.cast::<TreLiteral>() };
                    if unsafe { literal_is_backref(literal) } {
                        unsafe {
                            (*node).nullable = 0;
                            (*node).firstpos = tre_set_one(
                                memory,
                                (*literal).position,
                                0,
                                TRE_CHAR_MAX,
                                0,
                                ptr::null_mut(),
                                -1,
                            );
                            (*node).lastpos = tre_set_one(
                                memory,
                                (*literal).position,
                                0,
                                TRE_CHAR_MAX,
                                0,
                                ptr::null_mut(),
                                (*literal).code_max as c_int,
                            );
                        }
                    } else if unsafe { (*literal).code_min } < 0 {
                        unsafe {
                            (*node).nullable = 1;
                            (*node).firstpos = tre_set_empty(memory);
                            (*node).lastpos = tre_set_empty(memory);
                        }
                    } else {
                        unsafe {
                            (*node).nullable = 0;
                            (*node).firstpos = tre_set_one(
                                memory,
                                (*literal).position,
                                (*literal).code_min as c_int,
                                (*literal).code_max as c_int,
                                0,
                                ptr::null_mut(),
                                -1,
                            );
                            (*node).lastpos = tre_set_one(
                                memory,
                                (*literal).position,
                                (*literal).code_min as c_int,
                                (*literal).code_max as c_int,
                                (*literal).class,
                                (*literal).neg_classes,
                                -1,
                            );
                        }
                    }
                    if unsafe { (*node).firstpos }.is_null() || unsafe { (*node).lastpos }.is_null() {
                        return REG_ESPACE;
                    }
                }
                UNION => {
                    let union = unsafe { (*node).object.cast::<TreUnion>() };
                    if unsafe { tre_stack_push_voidptr(stack, node.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_POST_UNION) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*union).right.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_RECURSE) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*union).left.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_RECURSE) } != REG_OK
                    {
                        return REG_ESPACE;
                    }
                }
                CATENATION => {
                    let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                    if unsafe { tre_stack_push_voidptr(stack, node.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_POST_CATENATION) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*catenation).right.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_RECURSE) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*catenation).left.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_RECURSE) } != REG_OK
                    {
                        return REG_ESPACE;
                    }
                }
                ITERATION => {
                    let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                    if unsafe { tre_stack_push_voidptr(stack, node.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_POST_ITERATION) } != REG_OK
                        || unsafe { tre_stack_push_voidptr(stack, (*iteration).argument.cast()) } != REG_OK
                        || unsafe { tre_stack_push_int(stack, NFL_RECURSE) } != REG_OK
                    {
                        return REG_ESPACE;
                    }
                }
                _ => return REG_BADPAT,
            },
            NFL_POST_UNION => {
                let union = unsafe { (*node).object.cast::<TreUnion>() };
                unsafe {
                    (*node).nullable = ((*(*union).left).nullable != 0 || (*(*union).right).nullable != 0) as c_int;
                    (*node).firstpos = tre_set_union(memory, (*(*union).left).firstpos, (*(*union).right).firstpos, ptr::null(), 0);
                    (*node).lastpos = tre_set_union(memory, (*(*union).left).lastpos, (*(*union).right).lastpos, ptr::null(), 0);
                }
                if unsafe { (*node).firstpos }.is_null() || unsafe { (*node).lastpos }.is_null() {
                    return REG_ESPACE;
                }
            }
            NFL_POST_ITERATION => {
                let iteration = unsafe { (*node).object.cast::<TreIteration>() };
                unsafe {
                    (*node).nullable = ((*iteration).minimum == 0 || (*(*iteration).argument).nullable != 0) as c_int;
                    (*node).firstpos = (*(*iteration).argument).firstpos;
                    (*node).lastpos = (*(*iteration).argument).lastpos;
                }
            }
            NFL_POST_CATENATION => {
                let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
                unsafe {
                    (*node).nullable = ((*(*catenation).left).nullable != 0 && (*(*catenation).right).nullable != 0) as c_int;
                }
                if unsafe { (*(*catenation).left).nullable } != 0 {
                    let mut tag_count = 0;
                    let status = unsafe {
                        tre_match_empty(stack, (*catenation).left, ptr::null_mut(), ptr::null_mut(), &mut tag_count)
                    };
                    if status != REG_OK {
                        return status;
                    }
                    let Some(size) = (tag_count as usize).checked_add(1).and_then(|count| count.checked_mul(size_of::<c_int>())) else {
                        return REG_ESPACE;
                    };
                    let tags = unsafe { cabi_malloc(size) }.cast::<c_int>();
                    if tags.is_null() {
                        return REG_ESPACE;
                    }
                    unsafe { tags.write(-1) };
                    let mut assertions = 0;
                    let status = unsafe {
                        tre_match_empty(stack, (*catenation).left, tags, &mut assertions, ptr::null_mut())
                    };
                    if status != REG_OK {
                        unsafe { cabi_free(tags.cast()) };
                        return status;
                    }
                    let firstpos = unsafe {
                        tre_set_union(memory, (*(*catenation).right).firstpos, (*(*catenation).left).firstpos, tags, assertions)
                    };
                    unsafe { cabi_free(tags.cast()) };
                    if firstpos.is_null() {
                        return REG_ESPACE;
                    }
                    unsafe { (*node).firstpos = firstpos };
                } else {
                    unsafe { (*node).firstpos = (*(*catenation).left).firstpos };
                }
                if unsafe { (*(*catenation).right).nullable } != 0 {
                    let mut tag_count = 0;
                    let status = unsafe {
                        tre_match_empty(stack, (*catenation).right, ptr::null_mut(), ptr::null_mut(), &mut tag_count)
                    };
                    if status != REG_OK {
                        return status;
                    }
                    let Some(size) = (tag_count as usize).checked_add(1).and_then(|count| count.checked_mul(size_of::<c_int>())) else {
                        return REG_ESPACE;
                    };
                    let tags = unsafe { cabi_malloc(size) }.cast::<c_int>();
                    if tags.is_null() {
                        return REG_ESPACE;
                    }
                    unsafe { tags.write(-1) };
                    let mut assertions = 0;
                    let status = unsafe {
                        tre_match_empty(stack, (*catenation).right, tags, &mut assertions, ptr::null_mut())
                    };
                    if status != REG_OK {
                        unsafe { cabi_free(tags.cast()) };
                        return status;
                    }
                    let lastpos = unsafe {
                        tre_set_union(memory, (*(*catenation).left).lastpos, (*(*catenation).right).lastpos, tags, assertions)
                    };
                    unsafe { cabi_free(tags.cast()) };
                    if lastpos.is_null() {
                        return REG_ESPACE;
                    }
                    unsafe { (*node).lastpos = lastpos };
                } else {
                    unsafe { (*node).lastpos = (*(*catenation).right).lastpos };
                }
            }
            _ => return REG_BADPAT,
        }
    }
    REG_OK
}

/// `tre_make_trans` from regcomp.c:2470-2617.
unsafe fn tre_make_trans(
    mut first: *mut TrePosAndTags,
    second: *mut TrePosAndTags,
    transitions: *mut TreTnfaTransition,
    counts: *mut c_int,
    offsets: *mut c_int,
) -> c_int {
    if !transitions.is_null() {
        while unsafe { (*first).position } >= 0 {
            let mut next = second;
            let mut previous_position = -1;
            while unsafe { (*next).position } >= 0 {
                if unsafe { (*next).position } == previous_position {
                    next = unsafe { next.add(1) };
                    continue;
                }
                previous_position = unsafe { (*next).position };
                let mut transition = unsafe { transitions.add(*offsets.add((*first).position as usize) as usize) };
                while !unsafe { (*transition).state }.is_null() {
                    transition = unsafe { transition.add(1) };
                }
                if unsafe { (*transition).state }.is_null() {
                    unsafe { (*transition.add(1)).state = ptr::null_mut() };
                }
                unsafe {
                    (*transition).code_min = (*first).code_min as u32;
                    (*transition).code_max = (*first).code_max as u32;
                    (*transition).state = transitions.add(*offsets.add((*next).position as usize) as usize);
                    (*transition).state_id = (*next).position;
                    (*transition).assertions = (*first).assertions
                        | (*next).assertions
                        | if (*first).class != 0 { ASSERT_CHAR_CLASS } else { 0 }
                        | if !(*first).neg_classes.is_null() { ASSERT_CHAR_CLASS_NEG } else { 0 };
                }
                if unsafe { (*first).backref } >= 0 {
                    unsafe {
                        (*transition).assertion_parameter = TreAssertionParameter {
                            backref: (*first).backref,
                        };
                        (*transition).assertions |= ASSERT_BACKREF;
                    }
                } else {
                    unsafe {
                        (*transition).assertion_parameter = TreAssertionParameter {
                            class: (*first).class,
                        };
                    }
                }
                if !unsafe { (*first).neg_classes }.is_null() {
                    let negative_count = unsafe { ctype_array_len((*first).neg_classes) };
                    let Some(bytes) = negative_count.checked_add(1).and_then(|count| count.checked_mul(size_of::<tre_ctype_t>())) else {
                        return REG_ESPACE;
                    };
                    let copied = unsafe { cabi_malloc(bytes) }.cast::<tre_ctype_t>();
                    if copied.is_null() {
                        return REG_ESPACE;
                    }
                    unsafe {
                        ptr::copy_nonoverlapping((*first).neg_classes, copied, negative_count);
                        copied.add(negative_count).write(0);
                        (*transition).neg_classes = copied;
                    }
                } else {
                    unsafe { (*transition).neg_classes = ptr::null_mut() };
                }

                let first_tag_count = if unsafe { (*first).tags }.is_null() {
                    0
                } else {
                    unsafe { c_int_array_len((*first).tags) }
                };
                let second_tag_count = if unsafe { (*next).tags }.is_null() {
                    0
                } else {
                    unsafe { c_int_array_len((*next).tags) }
                };
                if !unsafe { (*transition).tags }.is_null() {
                    unsafe { cabi_free((*transition).tags.cast()) };
                }
                unsafe { (*transition).tags = ptr::null_mut() };
                if first_tag_count + second_tag_count > 0 {
                    let Some(bytes) = first_tag_count
                        .checked_add(second_tag_count)
                        .and_then(|count| count.checked_add(1))
                        .and_then(|count| count.checked_mul(size_of::<c_int>()))
                    else {
                        return REG_ESPACE;
                    };
                    let tags = unsafe { cabi_malloc(bytes) }.cast::<c_int>();
                    if tags.is_null() {
                        return REG_ESPACE;
                    }
                    let mut write_index = 0usize;
                    if first_tag_count != 0 {
                        unsafe {
                            ptr::copy_nonoverlapping((*first).tags, tags, first_tag_count);
                        }
                        write_index = first_tag_count;
                    }
                    if second_tag_count != 0 {
                        for source_index in 0..second_tag_count {
                            let candidate = unsafe { *(*next).tags.add(source_index) };
                            let mut duplicate = false;
                            for previous_index in 0..first_tag_count {
                                if unsafe { *tags.add(previous_index) } == candidate {
                                    duplicate = true;
                                    break;
                                }
                            }
                            if !duplicate {
                                unsafe { tags.add(write_index).write(candidate) };
                                write_index += 1;
                            }
                        }
                    }
                    unsafe {
                        tags.add(write_index).write(-1);
                        (*transition).tags = tags;
                    }
                }
                next = unsafe { next.add(1) };
            }
            first = unsafe { first.add(1) };
        }
    } else {
        while unsafe { (*first).position } >= 0 {
            let mut next = second;
            while unsafe { (*next).position } >= 0 {
                unsafe { *counts.add((*first).position as usize) += 1 };
                next = unsafe { next.add(1) };
            }
            first = unsafe { first.add(1) };
        }
    }
    REG_OK
}

#[inline]
unsafe fn ctype_array_len(values: *const tre_ctype_t) -> usize {
    let mut length = 0usize;
    while unsafe { *values.add(length) } != 0 {
        length += 1;
    }
    length
}

/// `tre_ast_to_tnfa` from regcomp.c:2624-2677.
unsafe fn tre_ast_to_tnfa(
    node: *mut TreAstNode,
    transitions: *mut TreTnfaTransition,
    counts: *mut c_int,
    offsets: *mut c_int,
) -> c_int {
    match unsafe { (*node).node_type } {
        LITERAL => REG_OK,
        UNION => {
            let union = unsafe { (*node).object.cast::<TreUnion>() };
            let status = unsafe { tre_ast_to_tnfa((*union).left, transitions, counts, offsets) };
            if status != REG_OK {
                return status;
            }
            unsafe { tre_ast_to_tnfa((*union).right, transitions, counts, offsets) }
        }
        CATENATION => {
            let catenation = unsafe { (*node).object.cast::<TreCatenation>() };
            let status = unsafe {
                tre_make_trans(
                    (*(*catenation).left).lastpos,
                    (*(*catenation).right).firstpos,
                    transitions,
                    counts,
                    offsets,
                )
            };
            if status != REG_OK {
                return status;
            }
            let status = unsafe { tre_ast_to_tnfa((*catenation).left, transitions, counts, offsets) };
            if status != REG_OK {
                return status;
            }
            unsafe { tre_ast_to_tnfa((*catenation).right, transitions, counts, offsets) }
        }
        ITERATION => {
            let iteration = unsafe { (*node).object.cast::<TreIteration>() };
            if unsafe { (*iteration).maximum } == -1 {
                let status = unsafe {
                    tre_make_trans(
                        (*(*iteration).argument).lastpos,
                        (*(*iteration).argument).firstpos,
                        transitions,
                        counts,
                        offsets,
                    )
                };
                if status != REG_OK {
                    return status;
                }
            }
            unsafe { tre_ast_to_tnfa((*iteration).argument, transitions, counts, offsets) }
        }
        _ => REG_BADPAT,
    }
}

// `regcomp.c` uses C `int` expressions for its state and transition-table
// sizes and leaves overflowing arithmetic undefined. These checked Rust
// products add no semantic capacity: an unrepresentable allocation follows
// the same `NULL`/`REG_ESPACE` path as a source allocation failure. The source
// constants remain literal elsewhere (512 initial stack entries, 1,024,000
// maximum entries, `1 << 15` bracket literals, and `RE_DUP_MAX == 255`).
#[inline]
unsafe fn source_array_malloc<T>(count: usize) -> *mut T {
    let Some(bytes) = count.checked_mul(size_of::<T>()) else {
        return ptr::null_mut();
    };
    unsafe { cabi_malloc(bytes) }.cast::<T>()
}

#[inline]
unsafe fn source_array_calloc<T>(count: usize) -> *mut T {
    unsafe { cabi_calloc(count, size_of::<T>()) }.cast::<T>()
}

/// Full `regcomp` from musl 1.2.6 `src/regex/regcomp.c:2691-2901`.
///
/// The caller supplies the POSIX `regex_t` storage and a readable terminated
/// pattern.  As in the source ABI, successful compilation transfers one TNFA
/// allocation graph into `regex_t.__opaque`; [`regfree`] consumes it.
///
/// # Safety
///
/// `preg` must designate one writable, properly aligned `regex_t` that is not
/// concurrently accessed and does not currently own a live compiled
/// expression. `expression` must designate a readable NUL-terminated C byte
/// string. On `REG_OK`, the caller must retain both the record and its compiled
/// graph until exactly one later [`regfree`] after all concurrent `regexec`
/// calls have completed; a failed call leaves no graph for the caller to free.
#[no_mangle]
pub unsafe extern "C" fn regcomp(
    preg: *mut regex_t,
    expression: *const c_char,
    cflags: c_int,
) -> c_int {
    let mut stack: *mut TreStack = ptr::null_mut();
    let mut memory: *mut TreMem = ptr::null_mut();
    let mut counts: *mut c_int = ptr::null_mut();
    let mut offsets: *mut c_int = ptr::null_mut();
    let mut tnfa: *mut TreTnfa = ptr::null_mut();
    let mut error = REG_OK;

    stack = unsafe { tre_stack_new(512, 1_024_000, 128) };
    if stack.is_null() {
        return REG_ESPACE;
    }
    memory = unsafe { tre_mem_new() };
    if memory.is_null() {
        unsafe { tre_stack_destroy(stack) };
        return REG_ESPACE;
    }

    let mut parse = unsafe { core::mem::zeroed::<TreParseContext>() };
    unsafe {
        parse.memory = memory;
        parse.stack = stack;
        parse.start = expression;
        parse.cflags = cflags;
        parse.max_backref = -1;
    }
    error = unsafe { tre_parse(&mut parse) };
    if error != REG_OK {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
    }
    unsafe { (*preg).re_nsub = (parse.submatch_id - 1) as usize };
    let mut tree = parse.node;
    if parse.max_backref > unsafe { (*preg).re_nsub as c_int } {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESUBREG) };
    }

    tnfa = unsafe { source_array_calloc::<TreTnfa>(1) };
    if tnfa.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    unsafe {
        (*tnfa).have_backrefs = (parse.max_backref >= 0) as c_int;
        (*tnfa).have_approx = 0;
        (*tnfa).num_submatches = parse.submatch_id as u32;
    }

    if unsafe { (*tnfa).have_backrefs } != 0 || cflags & REG_NOSUB == 0 {
        error = unsafe { tre_add_tags(ptr::null_mut(), stack, tree, tnfa) };
        if error != REG_OK {
            return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
        }
        if unsafe { (*tnfa).num_tags } > 0 {
            let count = unsafe { (*tnfa).num_tags as usize + 1 };
            let directions = unsafe { source_array_malloc::<TreTagDirection>(count) };
            if directions.is_null() {
                return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
            }
            // `memset(..., -1, ...)` is source state, not a Rust enum.
            unsafe {
                ptr::write_bytes(directions.cast::<u8>(), 0xff, count * size_of::<TreTagDirection>());
                (*tnfa).tag_directions = directions;
            }
        }
        let minimal_count = unsafe { (*tnfa).num_tags as usize }
            .checked_mul(2)
            .and_then(|count| count.checked_add(1));
        let Some(minimal_count) = minimal_count else {
            return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
        };
        let minimal_tags = unsafe { source_array_calloc::<c_int>(minimal_count) };
        if minimal_tags.is_null() {
            return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
        }
        unsafe { (*tnfa).minimal_tags = minimal_tags };
        let submatch_data = unsafe { source_array_calloc::<TreSubmatchData>(parse.submatch_id as usize) };
        if submatch_data.is_null() {
            return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
        }
        unsafe { (*tnfa).submatch_data = submatch_data };
        error = unsafe { tre_add_tags(memory, stack, tree, tnfa) };
        if error != REG_OK {
            return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
        }
    }

    error = unsafe { tre_expand_ast(memory, stack, tree, &mut parse.position, (*tnfa).tag_directions) };
    if error != REG_OK {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
    }
    let final_node = unsafe { tre_ast_new_literal(memory, 0, 0, parse.position) };
    parse.position += 1;
    if final_node.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    tree = unsafe { tre_ast_new_catenation(memory, tree, final_node) };
    if tree.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    error = unsafe { tre_compute_nfl(memory, stack, tree) };
    if error != REG_OK {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
    }
    let position_count = parse.position as usize;
    counts = unsafe { source_array_malloc::<c_int>(position_count) };
    if counts.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    offsets = unsafe { source_array_malloc::<c_int>(position_count) };
    if offsets.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    for index in 0..position_count {
        unsafe { counts.add(index).write(0) };
    }
    error = unsafe { tre_ast_to_tnfa(tree, ptr::null_mut(), counts, ptr::null_mut()) };
    if error != REG_OK {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
    }
    let mut transition_count: c_int = 0;
    for index in 0..position_count {
        unsafe {
            offsets.add(index).write(transition_count);
            transition_count = transition_count.checked_add(*counts.add(index)).and_then(|value| value.checked_add(1)).unwrap_or(-1);
            *counts.add(index) = 0;
        }
        if transition_count < 0 {
            return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
        }
    }
    let transition_storage = (transition_count as usize).checked_add(1);
    let Some(transition_storage) = transition_storage else {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    };
    let transitions = unsafe { source_array_calloc::<TreTnfaTransition>(transition_storage) };
    if transitions.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    unsafe {
        (*tnfa).transitions = transitions;
        (*tnfa).num_transitions = transition_count as u32;
    }
    error = unsafe { tre_ast_to_tnfa(tree, transitions, counts, offsets) };
    if error != REG_OK {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, error) };
    }
    unsafe { (*tnfa).firstpos_chars = ptr::null_mut() };
    let initial_count = unsafe { pos_set_len((*tree).firstpos) };
    let initial = unsafe { source_array_calloc::<TreTnfaTransition>(initial_count + 1) };
    if initial.is_null() {
        return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
    }
    unsafe { (*tnfa).initial = initial };
    for index in 0..initial_count {
        let position = unsafe { (*(*tree).firstpos.add(index)).position as usize };
        unsafe {
            (*initial.add(index)).state = transitions.add(*offsets.add(position) as usize);
            (*initial.add(index)).state_id = (*(*tree).firstpos.add(index)).position;
            (*initial.add(index)).tags = ptr::null_mut();
        }
        let source_tags = unsafe { (*(*tree).firstpos.add(index)).tags };
        if !source_tags.is_null() {
            let length = unsafe { c_int_array_len(source_tags) };
            let copied = unsafe { source_array_malloc::<c_int>(length + 1) };
            if copied.is_null() {
                return unsafe { regcomp_error_exit(preg, memory, stack, counts, offsets, tnfa, REG_ESPACE) };
            }
            unsafe {
                ptr::copy_nonoverlapping(source_tags, copied, length + 1);
                (*initial.add(index)).tags = copied;
            }
        }
        unsafe { (*initial.add(index)).assertions = (*(*tree).firstpos.add(index)).assertions };
    }
    unsafe {
        (*initial.add(initial_count)).state = ptr::null_mut();
        (*tnfa).num_transitions = transition_count as u32;
        (*tnfa).final_state = transitions.add(*offsets.add((*(*tree).lastpos).position as usize) as usize);
        (*tnfa).num_states = parse.position;
        (*tnfa).cflags = cflags;
        tre_mem_destroy(memory);
        tre_stack_destroy(stack);
        cabi_free(counts.cast());
        cabi_free(offsets.cast());
        (*preg).__opaque = tnfa.cast();
    }
    REG_OK
}

unsafe fn regcomp_error_exit(
    preg: *mut regex_t,
    memory: *mut TreMem,
    stack: *mut TreStack,
    counts: *mut c_int,
    offsets: *mut c_int,
    tnfa: *mut TreTnfa,
    error: c_int,
) -> c_int {
    unsafe {
        tre_mem_destroy(memory);
        if !stack.is_null() {
            tre_stack_destroy(stack);
        }
        if !counts.is_null() {
            cabi_free(counts.cast());
        }
        if !offsets.is_null() {
            cabi_free(offsets.cast());
        }
        (*preg).__opaque = tnfa.cast();
        regfree(preg);
    }
    error
}

/// Full `regfree` from musl 1.2.6 `src/regex/regcomp.c:2907-2953`.
///
/// # Safety
///
/// `preg` must designate a readable, properly aligned `regex_t` whose
/// `__opaque` member is either null or a still-live graph produced by a
/// successful [`regcomp`]. A non-null graph is consumed exactly once. The
/// caller must exclude concurrent `regexec`, `regfree`, and direct access to
/// the compiled record while this function releases its source allocation
/// graph.
#[no_mangle]
pub unsafe extern "C" fn regfree(preg: *mut regex_t) {
    let tnfa = unsafe { (*preg).__opaque.cast::<TreTnfa>() };
    if tnfa.is_null() {
        return;
    }
    let transition_count = unsafe { (*tnfa).num_transitions as usize };
    for index in 0..transition_count {
        let transition = unsafe { (*tnfa).transitions.add(index) };
        if !unsafe { (*transition).state }.is_null() {
            if !unsafe { (*transition).tags }.is_null() {
                unsafe { cabi_free((*transition).tags.cast()) };
            }
            if !unsafe { (*transition).neg_classes }.is_null() {
                unsafe { cabi_free((*transition).neg_classes.cast()) };
            }
        }
    }
    if !unsafe { (*tnfa).transitions }.is_null() {
        unsafe { cabi_free((*tnfa).transitions.cast()) };
    }
    if !unsafe { (*tnfa).initial }.is_null() {
        let mut transition = unsafe { (*tnfa).initial };
        while !unsafe { (*transition).state }.is_null() {
            if !unsafe { (*transition).tags }.is_null() {
                unsafe { cabi_free((*transition).tags.cast()) };
            }
            transition = unsafe { transition.add(1) };
        }
        unsafe { cabi_free((*tnfa).initial.cast()) };
    }
    if !unsafe { (*tnfa).submatch_data }.is_null() {
        for index in 0..unsafe { (*tnfa).num_submatches as usize } {
            let data = unsafe { (*tnfa).submatch_data.add(index) };
            if !unsafe { (*data).parents }.is_null() {
                unsafe { cabi_free((*data).parents.cast()) };
            }
        }
        unsafe { cabi_free((*tnfa).submatch_data.cast()) };
    }
    if !unsafe { (*tnfa).tag_directions }.is_null() {
        unsafe { cabi_free((*tnfa).tag_directions.cast()) };
    }
    if !unsafe { (*tnfa).firstpos_chars }.is_null() {
        unsafe { cabi_free((*tnfa).firstpos_chars.cast()) };
    }
    if !unsafe { (*tnfa).minimal_tags }.is_null() {
        unsafe { cabi_free((*tnfa).minimal_tags.cast()) };
    }
    unsafe { cabi_free(tnfa.cast()) };
}
