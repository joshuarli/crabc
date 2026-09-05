//! TRE executor port from musl 1.2.6 `src/regex/regexec.c`.
//!
//! This module consumes only the `TreTnfa` allocation graph materialized by
//! [`super::compile`].  It keeps the source's two routes separate: the
//! tag-ordered parallel TNFA walk for expressions without backreferences and
//! the source backtracking walk when `have_backrefs` is set.  Both routes use
//! byte offsets, `mbtowc`, and the existing C/C.UTF-8 wide-character owner.

use core::ffi::{c_char, c_int, c_long};
use core::mem::{align_of, size_of};
use core::ptr;

use super::{cabi_calloc, cabi_free, cabi_malloc};
use super::memory::{tre_mem_alloc, tre_mem_destroy, tre_mem_new};
use super::types::{
    regex_t, regmatch_t, regoff_t, tre_cint_t,
    TreSubmatchData, TreTnfa, TreTnfaTransition, ASSERT_AT_BOL, ASSERT_AT_BOW,
    ASSERT_AT_EOL, ASSERT_AT_EOW, ASSERT_AT_WB, ASSERT_AT_WB_NEG, ASSERT_BACKREF,
    ASSERT_CHAR_CLASS, ASSERT_CHAR_CLASS_NEG, REG_ESPACE, REG_ICASE, REG_NEWLINE,
    REG_NOMATCH, REG_NOSUB, REG_NOTBOL, REG_NOTEOL, REG_OK,
};

#[repr(C)]
struct TreTnfaReach {
    state: *mut TreTnfaTransition,
    tags: *mut regoff_t,
}

#[repr(C)]
struct TreReachPos {
    pos: regoff_t,
    tags: *mut *mut regoff_t,
}

#[inline]
unsafe fn tag_order(num_tags: c_int, directions: *mut c_int, left: *const regoff_t, right: *const regoff_t) -> bool {
    for index in 0..num_tags as usize {
        let left_value = unsafe { *left.add(index) };
        let right_value = unsafe { *right.add(index) };
        if unsafe { *directions.add(index) } == 0 {
            if left_value < right_value { return true; }
            if left_value > right_value { return false; }
        } else {
            if left_value > right_value { return true; }
            if left_value < right_value { return false; }
        }
    }
    false
}

#[inline]
fn is_word(character: c_int) -> bool {
    character == b'_' as c_int
        || super::super::wide_character::iswalnum(character as u32) != 0
}

unsafe fn neg_classes_match(mut classes: *const usize, character: tre_cint_t, icase: bool) -> bool {
    while unsafe { *classes } != 0 {
        let class = unsafe { *classes };
        let match_direct = super::super::wide_character::iswctype(character, class) != 0;
        let match_folded =
            super::super::wide_character::iswctype(
                super::super::wide_character::towupper(character), class,
            ) != 0 || super::super::wide_character::iswctype(
                super::super::wide_character::towlower(character), class,
            ) != 0;
        if if icase { match_folded } else { match_direct } { return true; }
        classes = unsafe { classes.add(1) };
    }
    false
}

unsafe fn assertions_fail(
    assertions: c_int,
    tnfa: *const TreTnfa,
    previous: c_int,
    next: c_int,
    position: regoff_t,
    not_bol: bool,
    not_eol: bool,
) -> bool {
    let newline = unsafe { (*tnfa).cflags & REG_NEWLINE } != 0;
    if assertions & ASSERT_AT_BOL != 0
        && (position > 0 || not_bol)
        && (previous != b'\n' as c_int || !newline) { return true; }
    if assertions & ASSERT_AT_EOL != 0
        && (next != 0 || not_eol)
        && (next != b'\n' as c_int || !newline) { return true; }
    if assertions & ASSERT_AT_BOW != 0 && (is_word(previous) || !is_word(next)) { return true; }
    if assertions & ASSERT_AT_EOW != 0 && (!is_word(previous) || is_word(next)) { return true; }
    if assertions & ASSERT_AT_WB != 0
        && (position != 0 && next != 0 && is_word(previous) == is_word(next)) { return true; }
    if assertions & ASSERT_AT_WB_NEG != 0
        && (position == 0 || next == 0 || is_word(previous) != is_word(next)) { return true; }
    false
}

unsafe fn classes_fail(transition: *const TreTnfaTransition, tnfa: *const TreTnfa, character: c_int) -> bool {
    let assertions = unsafe { (*transition).assertions };
    let icase = unsafe { (*tnfa).cflags & REG_ICASE } != 0;
    if assertions & ASSERT_CHAR_CLASS != 0 {
        let class = unsafe { (*transition).assertion_parameter.class };
        let direct = super::super::wide_character::iswctype(character as u32, class) != 0;
        let folded =
            super::super::wide_character::iswctype(
                super::super::wide_character::towlower(character as u32), class,
            ) != 0 || super::super::wide_character::iswctype(
                super::super::wide_character::towupper(character as u32), class,
            ) != 0;
        if !(if icase { folded } else { direct }) { return true; }
    }
    assertions & ASSERT_CHAR_CLASS_NEG != 0
        && unsafe { neg_classes_match((*transition).neg_classes, character as u32, icase) }
}

// `GET_NEXT_WCHAR` from regexec.c:40-48.  Its return value reports the
// source's `goto error_exit` condition; `pos` remains a byte offset.
unsafe fn get_next_wchar(
    previous: &mut c_int,
    next: &mut c_int,
    string: &mut *const c_char,
    position: &mut regoff_t,
    advance: &mut regoff_t,
) -> Result<(), c_int> {
    *previous = *next;
    *position += *advance;
    let decoded = unsafe { super::super::locale_multibyte::mbtowc(next, *string, usize::MAX) };
    if decoded <= 0 {
        if decoded < 0 { return Err(REG_NOMATCH); }
        *advance = 1;
    } else {
        *advance = decoded as regoff_t;
    }
    *string = unsafe { (*string).add(*advance as usize) };
    Ok(())
}

#[inline]
fn aligned_padding(address: usize) -> usize {
    let alignment = align_of::<c_long>();
    (alignment - address % alignment) % alignment
}

unsafe fn apply_tags(tags: *mut regoff_t, mut added: *const c_int, num_tags: usize, position: regoff_t) {
    if added.is_null() { return; }
    while unsafe { *added } >= 0 {
        let tag = unsafe { *added } as usize;
        if tag < num_tags { unsafe { *tags.add(tag) = position; } }
        added = unsafe { added.add(1) };
    }
}

/// `tre_tnfa_run_parallel` from musl `regexec.c:169-461`.
unsafe fn run_parallel(
    tnfa: *const TreTnfa,
    string: *const c_char,
    match_tags: *mut regoff_t,
    eflags: c_int,
    match_end: *mut regoff_t,
) -> c_int {
    let mut previous = 0;
    let mut next = 0;
    let mut string_byte = string;
    let mut position = -1;
    let mut advance = 1;
    let not_bol = eflags & REG_NOTBOL != 0;
    let not_eol = eflags & REG_NOTEOL != 0;
    let num_tags = if match_tags.is_null() { 0usize } else { unsafe { (*tnfa).num_tags as usize } };
    let states = unsafe { (*tnfa).num_states as usize };
    let tbytes = match num_tags.checked_mul(size_of::<regoff_t>()) { Some(value) => value, None => return REG_ESPACE };
    if num_tags > usize::MAX / (8 * size_of::<regoff_t>() * states) { return REG_ESPACE; }
    if states.checked_add(1).map_or(true, |count| count > usize::MAX / (8 * size_of::<TreTnfaReach>())) { return REG_ESPACE; }
    if states > usize::MAX / (8 * size_of::<TreReachPos>()) { return REG_ESPACE; }
    let rbytes = match states.checked_add(1).and_then(|count| count.checked_mul(size_of::<TreTnfaReach>())) { Some(value) => value, None => return REG_ESPACE };
    let pbytes = match states.checked_mul(size_of::<TreReachPos>()) { Some(value) => value, None => return REG_ESPACE };
    let xbytes = match num_tags.checked_mul(size_of::<regoff_t>()) { Some(value) => value, None => return REG_ESPACE };
    let total = match (size_of::<c_long>() - 1).checked_mul(4)
        .and_then(|value| value.checked_add(rbytes.checked_add(xbytes.checked_mul(states)?)?.checked_mul(2)?))
        .and_then(|value| value.checked_add(tbytes))
        .and_then(|value| value.checked_add(pbytes)) { Some(value) => value, None => return REG_ESPACE };
    let buffer = unsafe { cabi_calloc(total, 1) }.cast::<u8>();
    if buffer.is_null() { return REG_ESPACE; }
    let mut cursor = unsafe { buffer.add(tbytes) };
    cursor = unsafe { cursor.add(aligned_padding(cursor as usize)) };
    let mut reach_next = cursor.cast::<TreTnfaReach>();
    cursor = unsafe { cursor.add(rbytes) };
    cursor = unsafe { cursor.add(aligned_padding(cursor as usize)) };
    let mut reach = cursor.cast::<TreTnfaReach>();
    cursor = unsafe { cursor.add(rbytes) };
    cursor = unsafe { cursor.add(aligned_padding(cursor as usize)) };
    let reach_position = cursor.cast::<TreReachPos>();
    cursor = unsafe { cursor.add(pbytes) };
    cursor = unsafe { cursor.add(aligned_padding(cursor as usize)) };
    for index in 0..states {
        unsafe {
            (*reach.add(index)).tags = cursor.cast(); cursor = cursor.add(xbytes);
            (*reach_next.add(index)).tags = cursor.cast(); cursor = cursor.add(xbytes);
            (*reach_position.add(index)).pos = -1;
        }
    }
    let mut temporary_tags = buffer.cast::<regoff_t>();
    if unsafe { get_next_wchar(&mut previous, &mut next, &mut string_byte, &mut position, &mut advance) }.is_err() {
        unsafe { cabi_free(buffer.cast()) }; return REG_NOMATCH;
    }
    position = 0;
    let mut reach_next_end = reach_next;
    let mut match_end_offset = -1;
    let mut new_match = false;
    loop {
        if match_end_offset < 0 {
            let mut transition = unsafe { (*tnfa).initial };
            while !unsafe { (*transition).state }.is_null() {
                let state_id = unsafe { (*transition).state_id as usize };
                if unsafe { (*reach_position.add(state_id)).pos } < position {
                    if unsafe { (*transition).assertions } != 0 && unsafe { assertions_fail((*transition).assertions, tnfa, previous, next, position, not_bol, not_eol) } {
                        transition = unsafe { transition.add(1) }; continue;
                    }
                    unsafe {
                        (*reach_next_end).state = (*transition).state;
                        for index in 0..num_tags { *(*reach_next_end).tags.add(index) = -1; }
                        apply_tags((*reach_next_end).tags, (*transition).tags, num_tags, position);
                        if (*reach_next_end).state == (*tnfa).final_state {
                            match_end_offset = position; new_match = true;
                            for index in 0..num_tags { *match_tags.add(index) = *(*reach_next_end).tags.add(index); }
                        }
                        (*reach_position.add(state_id)).pos = position;
                        (*reach_position.add(state_id)).tags = ptr::addr_of_mut!((*reach_next_end).tags);
                        reach_next_end = reach_next_end.add(1);
                    }
                }
                transition = unsafe { transition.add(1) };
            }
            unsafe { (*reach_next_end).state = ptr::null_mut(); }
        } else if num_tags == 0 || reach_next_end == reach_next {
            break;
        }
        if next == 0 { break; }
        if unsafe { get_next_wchar(&mut previous, &mut next, &mut string_byte, &mut position, &mut advance) }.is_err() {
            unsafe { cabi_free(buffer.cast()) }; return REG_NOMATCH;
        }
        core::mem::swap(&mut reach, &mut reach_next);
        if unsafe { (*tnfa).num_minimals } != 0 && new_match {
            new_match = false;
            reach_next_end = reach_next;
            let mut item = reach;
            while !unsafe { (*item).state }.is_null() {
                let mut skip = false;
                let mut index = 0usize;
                while unsafe { *(*tnfa).minimal_tags.add(index) } >= 0 {
                    let end = unsafe { *(*tnfa).minimal_tags.add(index) } as usize;
                    let start = unsafe { *(*tnfa).minimal_tags.add(index + 1) } as usize;
                    if end >= num_tags || (unsafe { *(*item).tags.add(start) == *match_tags.add(start) && *(*item).tags.add(end) < *match_tags.add(end) }) { skip = true; break; }
                    index += 2;
                }
                if !skip {
                    unsafe { (*reach_next_end).state = (*item).state; }
                    core::mem::swap(unsafe { &mut (*reach_next_end).tags }, unsafe { &mut (*item).tags });
                    reach_next_end = unsafe { reach_next_end.add(1) };
                }
                item = unsafe { item.add(1) };
            }
            unsafe { (*reach_next_end).state = ptr::null_mut(); }
            core::mem::swap(&mut reach, &mut reach_next);
        }
        reach_next_end = reach_next;
        let mut item = reach;
        while !unsafe { (*item).state }.is_null() {
            let mut transition = unsafe { (*item).state };
            while !unsafe { (*transition).state }.is_null() {
                if unsafe { (*transition).code_min <= previous as u32 && (*transition).code_max >= previous as u32 }
                    && !(unsafe { (*transition).assertions } != 0 && unsafe { assertions_fail((*transition).assertions, tnfa, previous, next, position, not_bol, not_eol) || classes_fail(transition, tnfa, previous) }) {
                    unsafe {
                        for index in 0..num_tags { *temporary_tags.add(index) = *(*item).tags.add(index); }
                        apply_tags(temporary_tags, (*transition).tags, num_tags, position);
                    }
                    let state_id = unsafe { (*transition).state_id as usize };
                    if unsafe { (*reach_position.add(state_id)).pos } < position {
                        unsafe {
                            (*reach_next_end).state = (*transition).state;
                            core::mem::swap(&mut (*reach_next_end).tags, &mut temporary_tags);
                            (*reach_position.add(state_id)).pos = position;
                            (*reach_position.add(state_id)).tags = ptr::addr_of_mut!((*reach_next_end).tags);
                            if (*reach_next_end).state == (*tnfa).final_state && (match_end_offset == -1 || (num_tags > 0 && *(*reach_next_end).tags <= *match_tags)) {
                                match_end_offset = position; new_match = true;
                                for index in 0..num_tags { *match_tags.add(index) = *(*reach_next_end).tags.add(index); }
                            }
                            reach_next_end = reach_next_end.add(1);
                        }
                    } else if unsafe { tag_order(num_tags as c_int, (*tnfa).tag_directions, temporary_tags, *(*reach_position.add(state_id)).tags) } {
                        unsafe {
                            core::mem::swap(&mut *(*reach_position.add(state_id)).tags, &mut temporary_tags);
                            if (*transition).state == (*tnfa).final_state {
                                match_end_offset = position; new_match = true;
                                for index in 0..num_tags { *match_tags.add(index) = *temporary_tags.add(index); }
                            }
                        }
                    }
                }
                transition = unsafe { transition.add(1) };
            }
            item = unsafe { item.add(1) };
        }
        unsafe { (*reach_next_end).state = ptr::null_mut(); }
    }
    unsafe { *match_end = match_end_offset; cabi_free(buffer.cast()); }
    if match_end_offset >= 0 { REG_OK } else { REG_NOMATCH }
}

#[repr(C)]
struct TreBacktrackItem {
    pos: regoff_t,
    str_byte: *const c_char,
    state: *mut TreTnfaTransition,
    state_id: c_int,
    next_c: c_int,
    tags: *mut regoff_t,
}

#[repr(C)]
struct TreBacktrack {
    item: TreBacktrackItem,
    prev: *mut TreBacktrack,
    next: *mut TreBacktrack,
}

// `BT_STACK_PUSH` from regexec.c:523-571.  The backtracking stack's records
// and its tag snapshots belong to one `tre_mem` arena and retain the source's
// grow-on-first-use / reuse-on-later-use behavior.
unsafe fn push_backtrack(
    memory: *mut super::types::TreMem,
    tnfa: *const TreTnfa,
    stack: &mut *mut TreBacktrack,
    position: regoff_t,
    string_byte: *const c_char,
    state: *mut TreTnfaTransition,
    state_id: c_int,
    next: c_int,
    tags: *const regoff_t,
) -> bool {
    if unsafe { (**stack).next }.is_null() {
        let added = unsafe { tre_mem_alloc(memory, size_of::<TreBacktrack>()) }.cast::<TreBacktrack>();
        if added.is_null() { return false; }
        let tag_count = unsafe { (*tnfa).num_tags as usize };
        let bytes = match tag_count.checked_mul(size_of::<regoff_t>()) { Some(value) => value, None => return false };
        let saved_tags = unsafe { tre_mem_alloc(memory, bytes) }.cast::<regoff_t>();
        if saved_tags.is_null() { return false; }
        unsafe {
            (*added).prev = *stack;
            (*added).next = ptr::null_mut();
            (*added).item.tags = saved_tags;
            (**stack).next = added;
        }
    }
    *stack = unsafe { (**stack).next };
    unsafe {
        (**stack).item.pos = position;
        (**stack).item.str_byte = string_byte;
        (**stack).item.state = state;
        (**stack).item.state_id = state_id;
        (**stack).item.next_c = next;
        for index in 0..(*tnfa).num_tags as usize {
            *(*(*stack)).item.tags.add(index) = *tags.add(index);
        }
    }
    true
}

unsafe fn pop_backtrack(
    stack: &mut *mut TreBacktrack,
    position: &mut regoff_t,
    string_byte: &mut *const c_char,
    state: &mut *mut TreTnfaTransition,
    next: &mut c_int,
    tags: *mut regoff_t,
    num_tags: usize,
) {
    unsafe {
        *position = (**stack).item.pos;
        *string_byte = (**stack).item.str_byte;
        *state = (**stack).item.state;
        *next = (**stack).item.next_c;
        for index in 0..num_tags { *tags.add(index) = *(*(*stack)).item.tags.add(index); }
        *stack = (**stack).prev;
    }
}

unsafe fn byte_prefix_equal(left: *const c_char, right: *const c_char, count: usize) -> bool {
    for index in 0..count {
        if unsafe { *left.add(index) != *right.add(index) } { return false; }
    }
    true
}

/// `tre_tnfa_run_backtrack` from musl `regexec.c:592-920`.
unsafe fn run_backtrack(
    tnfa: *const TreTnfa,
    string: *const c_char,
    match_tags: *mut regoff_t,
    eflags: c_int,
    match_end: *mut regoff_t,
) -> c_int {
    let mut previous = 0;
    let mut next = 0;
    let mut string_byte = string;
    let mut position = 0;
    let mut advance = 1;
    let not_bol = eflags & REG_NOTBOL != 0;
    let not_eol = eflags & REG_NOTEOL != 0;
    let mut next_start = 0;
    let mut string_start = ptr::null();
    let mut position_start = -1;
    let mut match_end_offset = -1;
    let tags_count = unsafe { (*tnfa).num_tags as usize };
    let states_count = unsafe { (*tnfa).num_states as usize };
    let memory = unsafe { tre_mem_new() };
    if memory.is_null() { return REG_ESPACE; }
    let mut status = REG_NOMATCH;
    let mut tags: *mut regoff_t = ptr::null_mut();
    let mut pmatch: *mut regmatch_t = ptr::null_mut();
    let mut states_seen: *mut c_int = ptr::null_mut();
    let mut stack = unsafe { tre_mem_alloc(memory, size_of::<TreBacktrack>()) }.cast::<TreBacktrack>();
    if stack.is_null() { status = REG_ESPACE; return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, status) }; }
    unsafe { (*stack).prev = ptr::null_mut(); (*stack).next = ptr::null_mut(); }
    if tags_count != 0 {
        let bytes = match tags_count.checked_mul(size_of::<regoff_t>()) { Some(value) => value, None => return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, REG_ESPACE) } };
        tags = unsafe { cabi_malloc(bytes) }.cast();
        if tags.is_null() { return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, REG_ESPACE) }; }
    }
    let submatches = unsafe { (*tnfa).num_submatches as usize };
    if submatches != 0 {
        let bytes = match submatches.checked_mul(size_of::<regmatch_t>()) { Some(value) => value, None => return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, REG_ESPACE) } };
        pmatch = unsafe { cabi_malloc(bytes) }.cast();
        if pmatch.is_null() { return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, REG_ESPACE) }; }
    }
    if states_count != 0 {
        let bytes = match states_count.checked_mul(size_of::<c_int>()) { Some(value) => value, None => return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, REG_ESPACE) } };
        states_seen = unsafe { cabi_malloc(bytes) }.cast();
        if states_seen.is_null() { return unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, REG_ESPACE) }; }
    }

    'retry: loop {
        unsafe {
            for index in 0..tags_count {
                *tags.add(index) = -1;
                if !match_tags.is_null() { *match_tags.add(index) = -1; }
            }
            for index in 0..states_count { *states_seen.add(index) = 0; }
        }
        let mut state: *mut TreTnfaTransition = ptr::null_mut();
        position = position_start;
        if unsafe { get_next_wchar(&mut previous, &mut next, &mut string_byte, &mut position, &mut advance) }.is_err() {
            status = REG_NOMATCH; break;
        }
        position_start = position;
        next_start = next;
        string_start = string_byte;
        let mut next_tags: *mut c_int = ptr::null_mut();
        let mut transition = unsafe { (*tnfa).initial };
        while !unsafe { (*transition).state }.is_null() {
            if unsafe { (*transition).assertions } == 0
                || !unsafe { assertions_fail((*transition).assertions, tnfa, previous, next, position, not_bol, not_eol) } {
                if state.is_null() {
                    state = unsafe { (*transition).state };
                    next_tags = unsafe { (*transition).tags };
                } else {
                    if !unsafe { push_backtrack(memory, tnfa, &mut stack, position, string_byte, (*transition).state, (*transition).state_id, next, tags) } {
                        status = REG_ESPACE; break 'retry;
                    }
                    unsafe { apply_tags((*stack).item.tags, (*transition).tags, tags_count, position); }
                }
            }
            transition = unsafe { transition.add(1) };
        }
        unsafe { apply_tags(tags, next_tags, tags_count, position); }
        loop {
            // `backtrack:` is deliberately at the bottom of this loop, as in
            // the source: absent initial states, final states, failed
            // backreferences, input exhaustion, and no transition all share
            // the same saved-alternative/retry behavior.
            if !state.is_null() && state == unsafe { (*tnfa).final_state } {
                if match_end_offset < position || (match_end_offset == position && !match_tags.is_null() && unsafe { tag_order((*tnfa).num_tags, (*tnfa).tag_directions, tags, match_tags) }) {
                    match_end_offset = position;
                    if !match_tags.is_null() { unsafe { ptr::copy_nonoverlapping(tags, match_tags, tags_count); } }
                }
            } else if !state.is_null() {
                transition = state;
                if !unsafe { (*transition).state }.is_null() && unsafe { (*transition).assertions & ASSERT_BACKREF } != 0 {
                    let backref = unsafe { (*transition).assertion_parameter.backref } as usize;
                    unsafe { fill_pmatch(backref + 1, pmatch, (*tnfa).cflags & !REG_NOSUB, tnfa, tags, position); }
                    let start = unsafe { (*pmatch.add(backref)).rm_so };
                    let end = unsafe { (*pmatch.add(backref)).rm_eo };
                    let length = end - start;
                    let state_id = unsafe { (*transition).state_id as usize };
                    if length >= 0
                        && unsafe { byte_prefix_equal(string.add(start as usize), string_byte.sub(1), length as usize) }
                        && !(length == 0 && unsafe { *states_seen.add(state_id) } != 0) {
                        unsafe { *states_seen.add(state_id) = (length == 0) as c_int; }
                        string_byte = unsafe { string_byte.offset((length - 1) as isize) };
                        position += length - 1;
                        if unsafe { get_next_wchar(&mut previous, &mut next, &mut string_byte, &mut position, &mut advance) }.is_err() {
                            status = REG_NOMATCH; break 'retry;
                        }
                        match unsafe { backtrack_step(tnfa, memory, &mut stack, &mut state, &mut next_tags, position, string_byte, next, tags, tags_count, previous, not_bol, not_eol) } {
                            BacktrackStep::Transition => { unsafe { apply_tags(tags, next_tags, tags_count, position); } continue; }
                            BacktrackStep::AllocationFailure => { status = REG_ESPACE; break 'retry; }
                            BacktrackStep::NoTransition => {}
                        }
                    }
                } else if next != 0 {
                    if unsafe { get_next_wchar(&mut previous, &mut next, &mut string_byte, &mut position, &mut advance) }.is_err() {
                        status = REG_NOMATCH; break 'retry;
                    }
                    match unsafe { backtrack_step(tnfa, memory, &mut stack, &mut state, &mut next_tags, position, string_byte, next, tags, tags_count, previous, not_bol, not_eol) } {
                        BacktrackStep::Transition => { unsafe { apply_tags(tags, next_tags, tags_count, position); } continue; }
                        BacktrackStep::AllocationFailure => { status = REG_ESPACE; break 'retry; }
                        BacktrackStep::NoTransition => {}
                    }
                }
            }
            if !unsafe { (*stack).prev }.is_null() {
                unsafe {
                    if (*stack).item.state != ptr::null_mut() && (*(*stack).item.state).assertions & ASSERT_BACKREF != 0 {
                        *states_seen.add((*stack).item.state_id as usize) = 0;
                    }
                    pop_backtrack(&mut stack, &mut position, &mut string_byte, &mut state, &mut next, tags, tags_count);
                }
                continue;
            }
            if match_end_offset < 0 && next != 0 {
                next = next_start;
                string_byte = string_start;
                continue 'retry;
            }
            break;
        }
        status = if match_end_offset >= 0 { REG_OK } else { REG_NOMATCH };
        break;
    }
    unsafe { *match_end = match_end_offset; }
    unsafe { backtrack_cleanup(memory, tags, pmatch, states_seen, status) }
}

// The source's two transition-selection sites have the same candidate loop.
// Keep allocator exhaustion distinct from the ordinary `goto backtrack` path:
// `tre_bt_mem_alloc` failure exits `tre_tnfa_run_backtrack` with REG_ESPACE.
enum BacktrackStep {
    NoTransition,
    Transition,
    AllocationFailure,
}

unsafe fn backtrack_step(
    tnfa: *const TreTnfa, memory: *mut super::types::TreMem, stack: &mut *mut TreBacktrack,
    state: &mut *mut TreTnfaTransition, next_tags: &mut *mut c_int, position: regoff_t,
    string_byte: *const c_char, next: c_int, tags: *mut regoff_t, tags_count: usize,
    previous: c_int, not_bol: bool, not_eol: bool,
) -> BacktrackStep {
    let mut candidate: *mut TreTnfaTransition = ptr::null_mut();
    let mut transition = *state;
    while !unsafe { (*transition).state }.is_null() {
        if unsafe { (*transition).code_min <= previous as u32 && (*transition).code_max >= previous as u32 }
            && !(unsafe { (*transition).assertions } != 0 && unsafe { assertions_fail((*transition).assertions, tnfa, previous, next, position, not_bol, not_eol) || classes_fail(transition, tnfa, previous) }) {
            if candidate.is_null() {
                candidate = unsafe { (*transition).state };
                *next_tags = unsafe { (*transition).tags };
            } else {
                if !unsafe { push_backtrack(memory, tnfa, stack, position, string_byte, (*transition).state, (*transition).state_id, next, tags) } { return BacktrackStep::AllocationFailure; }
                unsafe { apply_tags((**stack).item.tags, (*transition).tags, tags_count, position); }
            }
        }
        transition = unsafe { transition.add(1) };
    }
    if candidate.is_null() {
        BacktrackStep::NoTransition
    } else {
        *state = candidate;
        BacktrackStep::Transition
    }
}

unsafe fn backtrack_cleanup(memory: *mut super::types::TreMem, tags: *mut regoff_t, pmatch: *mut regmatch_t, states_seen: *mut c_int, status: c_int) -> c_int {
    unsafe {
        tre_mem_destroy(memory);
        if !tags.is_null() { cabi_free(tags.cast()); }
        if !pmatch.is_null() { cabi_free(pmatch.cast()); }
        if !states_seen.is_null() { cabi_free(states_seen.cast()); }
    }
    status
}

/// `tre_fill_pmatch` from musl `regexec.c:930-988`.
unsafe fn fill_pmatch(nmatch: usize, pmatch: *mut regmatch_t, cflags: c_int, tnfa: *const TreTnfa, tags: *const regoff_t, match_end: regoff_t) {
    let mut index = 0usize;
    if match_end >= 0 && cflags & REG_NOSUB == 0 {
        let submatches = unsafe { (*tnfa).num_submatches as usize };
        while index < submatches && index < nmatch {
            let data: *const TreSubmatchData = unsafe { (*tnfa).submatch_data.add(index) };
            unsafe {
                (*pmatch.add(index)).rm_so = if (*data).so_tag == (*tnfa).end_tag { match_end } else { *tags.add((*data).so_tag as usize) };
                (*pmatch.add(index)).rm_eo = if (*data).eo_tag == (*tnfa).end_tag { match_end } else { *tags.add((*data).eo_tag as usize) };
                if (*pmatch.add(index)).rm_so == -1 || (*pmatch.add(index)).rm_eo == -1 { (*pmatch.add(index)).rm_so = -1; (*pmatch.add(index)).rm_eo = -1; }
            }
            index += 1;
        }
        index = 0;
        while index < submatches && index < nmatch {
            let data = unsafe { (*tnfa).submatch_data.add(index) };
            let mut parents = unsafe { (*data).parents };
            if !parents.is_null() {
                while unsafe { *parents } >= 0 {
                    let parent = unsafe { *parents } as usize;
                    if unsafe { (*pmatch.add(index)).rm_so < (*pmatch.add(parent)).rm_so || (*pmatch.add(index)).rm_eo > (*pmatch.add(parent)).rm_eo } {
                        unsafe { (*pmatch.add(index)).rm_so = -1; (*pmatch.add(index)).rm_eo = -1; }
                    }
                    parents = unsafe { parents.add(1) };
                }
            }
            index += 1;
        }
    }
    while index < nmatch {
        unsafe { (*pmatch.add(index)).rm_so = -1; (*pmatch.add(index)).rm_eo = -1; }
        index += 1;
    }
}

/// Full `regexec` from musl 1.2.6 `src/regex/regexec.c:996-1028`.
///
/// # Safety
///
/// `preg` must be a successfully compiled live `regex_t`, `string` must be a
/// readable NUL-terminated multibyte string, and nonzero `nmatch` requires a
/// writable `pmatch` array of that many native `regmatch_t` records.  Callers
/// must exclude a concurrent `regfree` for this expression.
#[no_mangle]
pub unsafe extern "C" fn regexec(preg: *const regex_t, string: *const c_char, mut nmatch: usize, pmatch: *mut regmatch_t, eflags: c_int) -> c_int {
    let tnfa = unsafe { (*preg).__opaque.cast::<TreTnfa>() };
    if unsafe { (*tnfa).cflags & REG_NOSUB } != 0 { nmatch = 0; }
    let mut tags: *mut regoff_t = ptr::null_mut();
    let tag_count = unsafe { (*tnfa).num_tags as usize };
    if tag_count != 0 && nmatch != 0 {
        let Some(bytes) = tag_count.checked_mul(size_of::<regoff_t>()) else { return REG_ESPACE; };
        tags = unsafe { cabi_malloc(bytes) }.cast();
        if tags.is_null() { return REG_ESPACE; }
    }
    let mut end = -1;
    let status = if unsafe { (*tnfa).have_backrefs } != 0 {
        unsafe { run_backtrack(tnfa, string, tags, eflags, &mut end) }
    } else {
        unsafe { run_parallel(tnfa, string, tags, eflags, &mut end) }
    };
    if status == REG_OK { unsafe { fill_pmatch(nmatch, pmatch, (*tnfa).cflags, tnfa, tags, end); } }
    if !tags.is_null() { unsafe { cabi_free(tags.cast()); } }
    status
}
