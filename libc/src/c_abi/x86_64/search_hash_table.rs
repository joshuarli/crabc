//! Selected static Linux/x86-64 `<search.h>` hash-table boundary.
//!
//! This leaf owns exactly musl's process-global `hcreate`/`hsearch`/`hdestroy`
//! table and GNU caller-record `_r` siblings. It is an open-addressed,
//! power-of-two table with an unsigned-byte hash and quadratic probing,
//! caller-owned key/data pointers, musl's duplicate-preserves-first-entry
//! behavior, and resize rollback after `ENOMEM`. The global and each
//! reentrant record own independent state. This is not callback tree search,
//! iteration, key/value ownership, a public C allocator, libc.so, CRT, loader,
//! sysroot, family completion, promotion, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/search/hsearch.c` maps to the hash, lookup, grow/rehash/rollback,
//! global wrappers, and weak GNU entries below; `include/search.h` owns the
//! public `ENTRY`, `ACTION`, and `struct hsearch_data` spellings and feature
//! profile.
//!
//! Musl allocates its opaque 24-byte table record and entry array through
//! `calloc` and releases them through `free`. Installed owned products
//! (`crabc_x86_owned_runtime`) keep exactly those public edges, including
//! `free(NULL)` from a repeated destroy, so an executable's malloc-family
//! replacement observes the same calls as under musl's `dynamic.list`.
//!
//! The frozen dependency-free selected-static archive has no C allocator.
//! There, and only there, each opaque record owns one zero-filled private
//! mapping for its table and one for its current entry array; growth maps the
//! replacement before rehashing and unmaps the old array only after success.
//! That mechanism difference is unobservable through the specified API except
//! VM granularity and is exercised under a temporary address-space ceiling
//! with mapping-liveness probes in the native differential. Both routes keep
//! musl's grow-then-release order. Repeated `hcreate[_r]` on a live record
//! intentionally retains musl's overwrite-and-leak behavior; `hdestroy[_r]`
//! releases only the currently recorded table and is idempotent after
//! clearing that record.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, null_mut};

#[cfg(not(crabc_x86_owned_runtime))]
use super::errno;

const MINIMUM_SIZE: usize = 8;
const MAXIMUM_SIZE: usize = usize::MAX / 2 + 1;
#[cfg(not(crabc_x86_owned_runtime))]
const PAGE_SIZE: usize = 4_096;
#[cfg(not(crabc_x86_owned_runtime))]
const PAGE_MASK: usize = PAGE_SIZE - 1;
#[cfg(not(crabc_x86_owned_runtime))]
const TABLE_MAPPING_SIZE: usize = PAGE_SIZE;
#[cfg(not(crabc_x86_owned_runtime))]
const PROT_READ: c_int = 0x1;
#[cfg(not(crabc_x86_owned_runtime))]
const PROT_WRITE: c_int = 0x2;
#[cfg(not(crabc_x86_owned_runtime))]
const MAP_PRIVATE: c_int = 0x02;
#[cfg(not(crabc_x86_owned_runtime))]
const MAP_ANONYMOUS: c_int = 0x20;
#[cfg(not(crabc_x86_owned_runtime))]
const ENOMEM: c_int = 12;

// Musl's hcreate/hsearch/hdestroy call public calloc/free, and musl keeps
// both preemptible in libc.so. Keep these calls at the ELF lookup boundary:
// LTO could otherwise bind a Rust extern spelling directly to this crate's
// own allocator definitions and bypass an executable's replacement.
#[cfg(crabc_x86_owned_runtime)]
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .globl __crabc_x86_hsearch_cabi_calloc
    .hidden __crabc_x86_hsearch_cabi_calloc
    .type __crabc_x86_hsearch_cabi_calloc,@function
__crabc_x86_hsearch_cabi_calloc:
    jmp calloc
    .size __crabc_x86_hsearch_cabi_calloc, .-__crabc_x86_hsearch_cabi_calloc

    .p2align 4
    .globl __crabc_x86_hsearch_cabi_free
    .hidden __crabc_x86_hsearch_cabi_free
    .type __crabc_x86_hsearch_cabi_free,@function
__crabc_x86_hsearch_cabi_free:
    jmp free
    .size __crabc_x86_hsearch_cabi_free, .-__crabc_x86_hsearch_cabi_free
"#
);

#[cfg(crabc_x86_owned_runtime)]
unsafe extern "C" {
    #[link_name = "__crabc_x86_hsearch_cabi_calloc"]
    fn table_calloc(count: usize, size: usize) -> *mut c_void;
    #[link_name = "__crabc_x86_hsearch_cabi_free"]
    fn table_free(pointer: *mut c_void);
}

#[cfg(not(crabc_x86_owned_runtime))]
unsafe extern "C" {
    #[link_name = "__mmap"]
    fn selected_mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        descriptor: c_int,
        offset: i64,
    ) -> *mut c_void;

    #[link_name = "__munmap"]
    fn selected_munmap(address: *mut c_void, length: usize) -> c_int;
}

/// Public C `ENTRY` argument/result layout from `<search.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    key: *mut c_char,
    data: *mut c_void,
}

/// Private table state addressed by the public opaque GNU record.
///
/// The owned layout is musl's 24-byte `struct __tab`; the allocator-free
/// archive additionally records its current entry mapping length.
#[repr(C)]
struct Table {
    entries: *mut Entry,
    mask: usize,
    used: usize,
    #[cfg(not(crabc_x86_owned_runtime))]
    entries_mapping_size: usize,
}

/// Public GNU `struct hsearch_data` layout from `<search.h>`.
#[repr(C)]
pub struct HsearchData {
    table: *mut Table,
    unused1: c_uint,
    unused2: c_uint,
}

const _: () = {
    assert!(size_of::<Entry>() == 16);
    assert!(align_of::<Entry>() == 8);
    assert!(offset_of!(Entry, key) == 0);
    assert!(offset_of!(Entry, data) == 8);
    assert!(size_of::<HsearchData>() == 16);
    assert!(align_of::<HsearchData>() == 8);
    assert!(offset_of!(HsearchData, table) == 0);
    assert!(offset_of!(HsearchData, unused1) == 8);
    assert!(offset_of!(HsearchData, unused2) == 12);
};

#[cfg(not(crabc_x86_owned_runtime))]
const _: () = assert!(size_of::<Table>() <= TABLE_MAPPING_SIZE);

#[cfg(crabc_x86_owned_runtime)]
const _: () = assert!(size_of::<Table>() == 24);

static mut GLOBAL_TABLE: HsearchData = HsearchData {
    table: null_mut(),
    unused1: 0,
    unused2: 0,
};

#[inline]
unsafe fn state_table(state: *mut HsearchData) -> *mut Table {
    unsafe { ptr::addr_of!((*state).table).read() }
}

#[inline]
unsafe fn set_state_table(state: *mut HsearchData, table: *mut Table) {
    unsafe { ptr::addr_of_mut!((*state).table).write(table) };
}

#[inline]
unsafe fn table_entries(table: *mut Table) -> *mut Entry {
    unsafe { ptr::addr_of!((*table).entries).read() }
}

#[inline]
unsafe fn set_table_entries(table: *mut Table, entries: *mut Entry) {
    unsafe { ptr::addr_of_mut!((*table).entries).write(entries) };
}

#[inline]
unsafe fn table_mask(table: *mut Table) -> usize {
    unsafe { ptr::addr_of!((*table).mask).read() }
}

#[inline]
unsafe fn set_table_mask(table: *mut Table, mask: usize) {
    unsafe { ptr::addr_of_mut!((*table).mask).write(mask) };
}

#[inline]
unsafe fn table_used(table: *mut Table) -> usize {
    unsafe { ptr::addr_of!((*table).used).read() }
}

#[inline]
unsafe fn set_table_used(table: *mut Table, used: usize) {
    unsafe { ptr::addr_of_mut!((*table).used).write(used) };
}

#[cfg(not(crabc_x86_owned_runtime))]
#[inline]
unsafe fn table_entries_mapping_size(table: *mut Table) -> usize {
    unsafe { ptr::addr_of!((*table).entries_mapping_size).read() }
}

#[cfg(not(crabc_x86_owned_runtime))]
#[inline]
unsafe fn set_table_entries_mapping_size(table: *mut Table, length: usize) {
    unsafe { ptr::addr_of_mut!((*table).entries_mapping_size).write(length) };
}

#[inline]
unsafe fn entry_key(entry: *mut Entry) -> *mut c_char {
    unsafe { ptr::addr_of!((*entry).key).read() }
}

#[inline]
unsafe fn clear_entry_key(entry: *mut Entry) {
    unsafe { ptr::addr_of_mut!((*entry).key).write(null_mut()) };
}

#[cfg(not(crabc_x86_owned_runtime))]
#[inline]
fn mapping_size(bytes: usize) -> Option<usize> {
    let rounded = bytes.checked_add(PAGE_MASK)? & !PAGE_MASK;
    if rounded == 0 || rounded >= isize::MAX as usize {
        None
    } else {
        Some(rounded)
    }
}

#[cfg(not(crabc_x86_owned_runtime))]
#[inline]
unsafe fn map_zeroed(length: usize) -> *mut c_void {
    // SAFETY: the private owner requests a fresh anonymous writable mapping.
    let mapping = unsafe {
        selected_mmap(
            null_mut(),
            length,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapping as usize == usize::MAX {
        null_mut()
    } else if mapping.is_null() {
        // A null address cannot represent a successful owned C object.
        let _ = unsafe { selected_munmap(mapping, length) };
        unsafe { errno::set_errno(ENOMEM) };
        null_mut()
    } else {
        mapping
    }
}

#[cfg(not(crabc_x86_owned_runtime))]
#[inline]
unsafe fn release_mapping(address: *mut c_void, length: usize) {
    let saved_errno = unsafe { errno::get_errno() };
    let _ = unsafe { selected_munmap(address, length) };
    unsafe { errno::set_errno(saved_errno) };
}

#[inline]
unsafe fn key_hash(key: *const c_char) -> usize {
    let mut cursor = key.cast::<u8>();
    let mut hash = 0usize;
    loop {
        let byte = unsafe { cursor.read() };
        if byte == 0 {
            return hash;
        }
        hash = hash.wrapping_mul(31).wrapping_add(usize::from(byte));
        cursor = unsafe { cursor.add(1) };
    }
}

#[inline]
unsafe fn keys_equal(mut left: *const c_char, mut right: *const c_char) -> bool {
    loop {
        let left_byte = unsafe { left.cast::<u8>().read() };
        let right_byte = unsafe { right.cast::<u8>().read() };
        if left_byte != right_byte {
            return false;
        }
        if left_byte == 0 {
            return true;
        }
        left = unsafe { left.add(1) };
        right = unsafe { right.add(1) };
    }
}

#[inline]
unsafe fn lookup(key: *const c_char, hash: usize, state: *mut HsearchData) -> *mut Entry {
    let table = unsafe { state_table(state) };
    let mask = unsafe { table_mask(table) };
    let entries = unsafe { table_entries(table) };
    let mut index = hash;
    let mut step = 1usize;
    loop {
        let entry = unsafe { entries.add(index & mask) };
        let stored_key = unsafe { entry_key(entry) };
        if stored_key.is_null() || unsafe { keys_equal(stored_key, key) } {
            return entry;
        }
        index = index.wrapping_add(step);
        step = step.wrapping_add(1);
    }
}

/// Grow the current entry array, keeping the old array usable on failure.
///
/// # Safety
///
/// `state` addresses an exclusively accessible live table record.
unsafe fn resize(requested: usize, state: *mut HsearchData) -> c_int {
    let table = unsafe { state_table(state) };
    let old_entries = unsafe { table_entries(table) };
    let old_size = unsafe { table_mask(table).wrapping_add(1) };
    #[cfg(not(crabc_x86_owned_runtime))]
    let old_mapping_size = unsafe { table_entries_mapping_size(table) };
    let requested = requested.min(MAXIMUM_SIZE);
    let mut new_size = MINIMUM_SIZE;
    while new_size < requested {
        new_size = new_size.wrapping_mul(2);
    }
    let Some(new_entries) = (unsafe { allocate_entries(new_size) }) else {
        return 0;
    };

    unsafe { set_table_entries(table, new_entries.entries) };
    unsafe { set_table_mask(table, new_size.wrapping_sub(1)) };
    #[cfg(not(crabc_x86_owned_runtime))]
    unsafe { set_table_entries_mapping_size(table, new_entries.mapping_size) };
    if old_entries.is_null() {
        return 1;
    }

    let mut old_index = 0usize;
    while old_index < old_size {
        let old_entry = unsafe { old_entries.add(old_index) };
        let old_key = unsafe { entry_key(old_entry) };
        if !old_key.is_null() {
            let hash = unsafe { key_hash(old_key) };
            let destination = unsafe { lookup(old_key, hash, state) };
            unsafe { destination.write(old_entry.read()) };
        }
        old_index = old_index.wrapping_add(1);
    }
    #[cfg(not(crabc_x86_owned_runtime))]
    unsafe { release_mapping(old_entries.cast::<c_void>(), old_mapping_size) };
    #[cfg(crabc_x86_owned_runtime)]
    // SAFETY: the rehash copied every live entry out of the old array.
    unsafe { table_free(old_entries.cast::<c_void>()) };
    1
}

/// One zero-filled entry array and, without a C allocator, its mapping size.
struct EntryArray {
    entries: *mut Entry,
    #[cfg(not(crabc_x86_owned_runtime))]
    mapping_size: usize,
}

/// Allocate musl's `calloc(newsize, sizeof(ENTRY))` entry array.
///
/// The public `calloc` owns multiplication overflow and its `ENOMEM`.
#[cfg(crabc_x86_owned_runtime)]
unsafe fn allocate_entries(count: usize) -> Option<EntryArray> {
    // SAFETY: the tail forwards both counts to the selected C `calloc`.
    let entries = unsafe { table_calloc(count, size_of::<Entry>()) }.cast::<Entry>();
    (!entries.is_null()).then_some(EntryArray { entries })
}

#[cfg(not(crabc_x86_owned_runtime))]
unsafe fn allocate_entries(count: usize) -> Option<EntryArray> {
    let Some(entry_bytes) = count.checked_mul(size_of::<Entry>()) else {
        unsafe { errno::set_errno(ENOMEM) };
        return None;
    };
    let Some(mapping_size) = mapping_size(entry_bytes) else {
        unsafe { errno::set_errno(ENOMEM) };
        return None;
    };
    let entries = unsafe { map_zeroed(mapping_size) }.cast::<Entry>();
    (!entries.is_null()).then_some(EntryArray { entries, mapping_size })
}

/// Create a table record and its minimum entry array, as musl's `__hcreate_r`.
#[cfg(crabc_x86_owned_runtime)]
unsafe fn create(requested: usize, state: *mut HsearchData) -> c_int {
    // SAFETY: the tail forwards one zero-filled record request to `calloc`.
    let table = unsafe { table_calloc(1, size_of::<Table>()) }.cast::<Table>();
    unsafe { set_state_table(state, table) };
    if table.is_null() {
        return 0;
    }
    if unsafe { resize(requested, state) } == 0 {
        unsafe { table_free(table.cast::<c_void>()) };
        unsafe { set_state_table(state, null_mut()) };
        return 0;
    }
    1
}

/// Release the current record through musl's exact `__hdestroy_r` calls,
/// including `free(NULL)` when no table is recorded.
#[cfg(crabc_x86_owned_runtime)]
unsafe fn destroy(state: *mut HsearchData) {
    let table = unsafe { state_table(state) };
    if !table.is_null() {
        unsafe { table_free(table_entries(table).cast::<c_void>()) };
    }
    unsafe { table_free(table.cast::<c_void>()) };
    unsafe { set_state_table(state, null_mut()) };
}

#[cfg(not(crabc_x86_owned_runtime))]
unsafe fn create(requested: usize, state: *mut HsearchData) -> c_int {
    let table = unsafe { map_zeroed(TABLE_MAPPING_SIZE) }.cast::<Table>();
    unsafe { set_state_table(state, table) };
    if table.is_null() {
        return 0;
    }
    if unsafe { resize(requested, state) } == 0 {
        unsafe { release_mapping(table.cast::<c_void>(), TABLE_MAPPING_SIZE) };
        unsafe { set_state_table(state, null_mut()) };
        return 0;
    }
    1
}

#[cfg(not(crabc_x86_owned_runtime))]
unsafe fn destroy(state: *mut HsearchData) {
    let table = unsafe { state_table(state) };
    if !table.is_null() {
        let entries = unsafe { table_entries(table) };
        if !entries.is_null() {
            let length = unsafe { table_entries_mapping_size(table) };
            unsafe { release_mapping(entries.cast::<c_void>(), length) };
        }
        unsafe { release_mapping(table.cast::<c_void>(), TABLE_MAPPING_SIZE) };
        unsafe { set_state_table(state, null_mut()) };
    }
}

unsafe fn search(
    item: Entry,
    action: c_int,
    result: *mut *mut Entry,
    state: *mut HsearchData,
) -> c_int {
    let hash = unsafe { key_hash(item.key) };
    let entry = unsafe { lookup(item.key, hash, state) };
    if !unsafe { entry_key(entry).is_null() } {
        unsafe { result.write(entry) };
        return 1;
    }
    if action == 0 {
        unsafe { result.write(null_mut()) };
        return 0;
    }

    unsafe { entry.write(item) };
    let table = unsafe { state_table(state) };
    let incremented_used = unsafe { table_used(table).wrapping_add(1) };
    unsafe { set_table_used(table, incremented_used) };
    let mask = unsafe { table_mask(table) };
    let resize_threshold = mask.wrapping_sub(mask / 4);
    if incremented_used > resize_threshold {
        let requested = incremented_used.wrapping_mul(2);
        if unsafe { resize(requested, state) } == 0 {
            unsafe { set_table_used(table, incremented_used.wrapping_sub(1)) };
            unsafe { clear_entry_key(entry) };
            unsafe { result.write(null_mut()) };
            return 0;
        }
        let relocated = unsafe { lookup(item.key, hash, state) };
        unsafe { result.write(relocated) };
        return 1;
    }
    unsafe { result.write(entry) };
    1
}

/// Create or overwrite the process-global hash-table record.
///
/// # Safety
///
/// The caller must exclude every concurrent global `hcreate`, `hsearch`, and
/// `hdestroy` access. Replacing a live table intentionally leaks its prior
/// opaque state, matching musl; callers that require cleanup must destroy it
/// first.
#[no_mangle]
pub unsafe extern "C" fn hcreate(requested: usize) -> c_int {
    unsafe { create(requested, ptr::addr_of_mut!(GLOBAL_TABLE)) }
}

/// Release the current process-global hash table, if any.
///
/// # Safety
///
/// The caller must exclude concurrent access and must not dereference any
/// `ENTRY *` previously returned from the global table after this call.
#[no_mangle]
pub unsafe extern "C" fn hdestroy() {
    unsafe { destroy(ptr::addr_of_mut!(GLOBAL_TABLE)) };
}

/// Find or enter one caller-owned item in the process-global table.
///
/// # Safety
///
/// A global table must have been created and remain exclusively accessible.
/// `item.key` must address a readable NUL-terminated byte string for this
/// call; for `ENTER`, that key and the caller-chosen data pointer must remain
/// valid for every later operation that can observe the stored entry.
#[no_mangle]
pub unsafe extern "C" fn hsearch(item: Entry, action: c_int) -> *mut Entry {
    let mut result = null_mut();
    let _ = unsafe { search(item, action, &mut result, ptr::addr_of_mut!(GLOBAL_TABLE)) };
    result
}

/// Create or overwrite the table addressed by one GNU caller record.
///
/// # Safety
///
/// `state` must address one writable, suitably aligned `struct hsearch_data`
/// record that was zero-initialized before its first create and is exclusively
/// accessible for the call. Replacing a live record intentionally leaks its
/// prior table, matching musl.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn hcreate_r(requested: usize, state: *mut HsearchData) -> c_int {
    unsafe { create(requested, state) }
}

/// Release the current table addressed by one GNU caller record, if any.
///
/// # Safety
///
/// `state` must address an exclusively accessible record that is zeroed or
/// was initialized by this implementation. No returned entry pointer from
/// its current table may be dereferenced after this call.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn hdestroy_r(state: *mut HsearchData) {
    unsafe { destroy(state) };
}

/// Find or enter one caller-owned item in a GNU caller-record table.
///
/// # Safety
///
/// `state` must address an exclusively accessible live table created by
/// `hcreate_r`, and `result` must be writable for one `ENTRY *`. `item.key`
/// must address a readable NUL-terminated byte string; for `ENTER`, that key
/// and the caller-chosen data pointer must remain valid for later operations
/// that can observe the stored entry.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn hsearch_r(
    item: Entry,
    action: c_int,
    result: *mut *mut Entry,
    state: *mut HsearchData,
) -> c_int {
    unsafe { search(item, action, result, state) }
}
