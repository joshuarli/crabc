// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/options.c:214-337,347-608`
// (`mi_options_print_out`, the `mi_option_*` accessors and mutators,
// `mi_register_output`, `mi_register_error`), `src/page.c:999-1003`
// (`mi_register_deferred_free`), `src/stats.c:640-653` (`mi_stats_get`),
// and `src/init.c:17-19` (`mi_version`).

//! Pinned mimalloc option, callback, and statistics public entries of the
//! M7 contract over the native runtime's process option table and output
//! owner.
//!
//! Each function is the source entry of the same `mi_` name, with a raw
//! `mi_option_t` value where the source takes one: an out-of-range option
//! reads as zero and ignores mutation, as `mi_option_get`/`mi_option_set`
//! do. Before the process has published its option table (which x86 startup
//! does before any allocation), reads return the pinned release default and
//! mutations are ignored.

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::config::SourceOption;
use crate::diagnostic_output::OutputOwner;

/// `mi_output_fun`.
pub type OutputFunction = unsafe extern "C" fn(*const c_char, *mut c_void);
/// `mi_error_fun`.
pub type ErrorFunction = unsafe extern "C" fn(c_int, *mut c_void);
/// `mi_deferred_free_fun`.
pub type DeferredFreeFunction = unsafe extern "C" fn(bool, u64, *mut c_void);

/// `MI_MALLOC_VERSION` of the pinned `include/mimalloc.h:11`.
const SOURCE_VERSION: c_int = 30_500;

#[inline]
fn owner() -> Option<&'static OutputOwner> {
    crate::process_init::process_output_owner()
}

/// `mi_version`.
pub fn version() -> c_int {
    SOURCE_VERSION
}

/// `mi_option_get`.
pub fn option_get(option: c_int) -> c_long {
    let Some(option) = SourceOption::from_source_value(option) else { return 0 };
    match owner() {
        // SAFETY: a published owner has an installed table; a lazy retry's
        // warning is delivered through the process output route, as in C.
        Some(owner) => unsafe { owner.option_value(option) },
        None => option.default_value(),
    }
}

/// `mi_option_get_clamp`.
pub fn option_get_clamp(option: c_int, min: c_long, max: c_long) -> c_long {
    let value = option_get(option);
    if value < min { min } else if value > max { max } else { value }
}

/// `mi_option_get_size`.
pub fn option_get_size(option: c_int) -> usize {
    let Some(source) = SourceOption::from_source_value(option) else { return 0 };
    let value = option_get(option);
    let size = if value < 0 { 0 } else { value as usize };
    if source.has_size_in_kib() {
        size.checked_mul(crate::config::KIB).unwrap_or(crate::config::MAX_ALLOC_SIZE)
    } else {
        size
    }
}

/// `mi_option_is_enabled`.
pub fn option_is_enabled(option: c_int) -> bool {
    option_get(option) != 0
}

/// `mi_option_set`.
pub fn option_set(option: c_int, value: c_long) {
    let (Some(option), Some(owner)) = (SourceOption::from_source_value(option), owner()) else { return };
    // SAFETY: a published owner; the lock serializes the store.
    let _ = unsafe { owner.option_set(option, value) };
}

/// `mi_option_set_default`.
pub fn option_set_default(option: c_int, value: c_long) {
    let (Some(option), Some(owner)) = (SourceOption::from_source_value(option), owner()) else { return };
    // SAFETY: as `option_set`.
    let _ = unsafe { owner.option_set_default(option, value) };
}

/// `mi_option_set_enabled`; `mi_option_enable`/`mi_option_disable` are its
/// `true`/`false` forms.
pub fn option_set_enabled(option: c_int, enable: bool) {
    option_set(option, c_long::from(enable));
}

/// `mi_option_set_enabled_default`.
pub fn option_set_enabled_default(option: c_int, enable: bool) {
    option_set_default(option, c_long::from(enable));
}

/// `mi_options_print_out`; a null `output` is the default output route.
///
/// # Safety
/// A non-null `output` and the objects reachable from `argument` stay valid
/// for every printed line.
pub unsafe fn options_print_out(output: Option<OutputFunction>, argument: *mut c_void) {
    let Some(owner) = owner() else { return };
    // SAFETY: forwarded callback contract; the page record size is the
    // source `sizeof(mi_page_t)` its last line prints.
    let _ = unsafe { owner.options_print_out(output, argument, core::mem::size_of::<crate::types::Page>()) };
}

/// `mi_register_output`.
///
/// # Safety
/// The `mi_register_output` contract: `output` and `argument` stay valid
/// until a replacement is registered and in-flight deliveries finish, and
/// registration is serialized with every other output.
pub unsafe fn register_output(output: Option<OutputFunction>, argument: *mut c_void) {
    let Some(owner) = owner() else { return };
    // SAFETY: forwarded.
    unsafe { owner.register_output(output, argument) };
}

/// `mi_register_error`.
///
/// # Safety
/// The `mi_register_error` contract: `handler` and `argument` stay valid for
/// every later report, and registration does not race a report.
pub unsafe fn register_error(handler: Option<ErrorFunction>, argument: *mut c_void) {
    let Some(owner) = owner() else { return };
    // SAFETY: forwarded.
    unsafe { owner.register_error(handler, argument) };
}

/// `mi_register_deferred_free`.
///
/// # Safety
/// As [`crate::runtime_lifecycle::register_native_deferred_free_callback`].
pub unsafe fn register_deferred_free(callback: Option<DeferredFreeFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::register_native_deferred_free_callback(callback, argument) };
}

/// `mi_stats_get`.
///
/// # Safety
/// `stats` is null or valid for reads and writes of a source `mi_stats_t`.
pub unsafe fn stats_get(stats: *mut c_void) -> bool {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_stats_get(stats.cast()) }
}

pub use crate::diagnostic_output::SourceProcessInfo;

/// `mi_stats_print_out`; a null `out` is the process default route.
///
/// # Safety
/// A non-null `out` is callable with each message and `argument`.
pub unsafe fn stats_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_stats_print_out(out, argument) }
}

/// `mi_thread_stats_print_out`.
///
/// # Safety
/// As [`stats_print_out`].
pub unsafe fn thread_stats_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_thread_stats_print_out(out, argument) }
}

/// `mi_process_info_print_out`.
///
/// # Safety
/// As [`stats_print_out`].
pub unsafe fn process_info_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_process_info_print_out(out, argument) }
}

/// `mi_process_info`'s eight results.
pub fn process_info() -> SourceProcessInfo {
    crate::runtime_lifecycle::native_process_info()
}

/// `mi_stats_get_json` (null `stats`) and `mi_stats_as_json`.
///
/// # Safety
/// As [`crate::runtime_lifecycle::native_stats_json`].
pub unsafe fn stats_json(stats: *const c_void, size: usize, buffer: *mut c_char) -> *mut c_char {
    // SAFETY: forwarded.
    unsafe { crate::runtime_lifecycle::native_stats_json(stats.cast(), size, buffer.cast()) }.cast()
}

/// `mi_stats_get_bin_size`.
pub const fn stats_get_bin_size(bin: usize) -> usize {
    crate::runtime_lifecycle::native_stats_bin_size(bin)
}

/// `mi_stats_reset`.
pub fn stats_reset() {
    crate::runtime_lifecycle::native_stats_reset();
}
