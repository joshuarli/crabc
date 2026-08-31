//! Selected static Linux/x86-64 intrusive queue C ABI boundary.
//!
//! This leaf owns exactly musl's paired `insque` and `remque` entries: they
//! rewire only the caller-owned first two pointer words of one intrusive
//! doubly linked node. `insque(element, predecessor)` clears both links when
//! its predecessor is null; otherwise it inserts `element` directly after the
//! predecessor. `remque(element)` reconnects non-null neighbors but leaves
//! the removed element's own link words unchanged, exactly as musl does.
//!
//! The functions do not allocate or free nodes, search a container, retain a
//! head/tail/global queue, validate pointers, call callbacks, synchronize, or
//! touch errno, TLS, locale, syscalls, process state, or runtime state. The
//! caller owns node representation, reachability, lifetime, and exclusion of
//! concurrent mutation. Null or invalid `element` pointers and nodes whose
//! first two words are not writable link pointers are outside the C-defined
//! contract; this leaf does not invent validation behavior for them.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/search/insque.c` defines both public entries in the one `insque.lo`
//! object. Its private two-pointer `struct node` maps directly to
//! [`QueueNode`]'s private prefix below. The AArch64 static ABI inventory
//! records strong `insque` and `remque` in that same `insque.lo` owner.
//!
//! This capability-free leaf is not `lfind`/`lsearch`, bsearch, qsort,
//! search-tree/hash state, a queue container, allocator, filesystem/process
//! behavior, libc.so, CRT, loader, sysroot, family completion, promotion, or
//! public x86 support.

use core::{
    ffi::c_void,
    ptr::{self, null_mut},
};

/// Private prefix of the caller-owned intrusive node representation.
///
/// Musl exposes only `void *` spellings. The caller supplies storage whose
/// first two pointer-sized fields have this exact next/previous layout.
#[repr(C)]
struct QueueNode {
    next: *mut QueueNode,
    previous: *mut QueueNode,
}

/// Insert one caller-owned element immediately after its optional predecessor.
///
/// # Safety
///
/// `element` must address writable storage whose first two pointer words are
/// a `QueueNode` prefix. If `predecessor` is non-null, it must address a live
/// writable node with the same prefix; its current successor, if non-null,
/// must also be writable. Every node must remain valid for the call, and the
/// caller must exclude concurrent mutation of the affected links.
#[no_mangle]
pub unsafe extern "C" fn insque(element: *mut c_void, predecessor: *mut c_void) {
    let element = element.cast::<QueueNode>();
    let predecessor = predecessor.cast::<QueueNode>();

    if predecessor.is_null() {
        // SAFETY: the caller supplies one writable intrusive-node prefix.
        unsafe {
            // `ptr::{read,write}` carries the caller's alignment and validity
            // preconditions without adding a Rust debug panic path to musl's
            // valid C node domain.
            ptr::write(ptr::addr_of_mut!((*element).next), null_mut());
            ptr::write(ptr::addr_of_mut!((*element).previous), null_mut());
        }
        return;
    }

    // SAFETY: the caller supplies writable compatible prefixes for element,
    // predecessor, and any existing successor. This preserves musl's exact
    // insertion order: save successor, publish both element links, then
    // reconnect predecessor and successor.
    unsafe {
        let successor = ptr::read(ptr::addr_of!((*predecessor).next));
        ptr::write(ptr::addr_of_mut!((*element).next), successor);
        ptr::write(ptr::addr_of_mut!((*element).previous), predecessor);
        ptr::write(ptr::addr_of_mut!((*predecessor).next), element);
        if !successor.is_null() {
            ptr::write(ptr::addr_of_mut!((*successor).previous), element);
        }
    }
}

/// Remove one caller-owned element from its current neighbor links.
///
/// # Safety
///
/// `element` must address a live writable `QueueNode` prefix. Each non-null
/// neighbor stored in that prefix must address a live writable compatible
/// prefix. The caller owns node lifetime and concurrent-mutation exclusion.
/// This function deliberately does not clear the removed element's own links.
#[no_mangle]
pub unsafe extern "C" fn remque(element: *mut c_void) {
    let element = element.cast::<QueueNode>();

    // SAFETY: the caller supplies the writable node prefix and any non-null
    // writable neighbor prefixes. The source reconnects neighbors only.
    unsafe {
        let successor = ptr::read(ptr::addr_of!((*element).next));
        let predecessor = ptr::read(ptr::addr_of!((*element).previous));
        if !successor.is_null() {
            ptr::write(ptr::addr_of_mut!((*successor).previous), predecessor);
        }
        if !predecessor.is_null() {
            ptr::write(ptr::addr_of_mut!((*predecessor).next), successor);
        }
    }
}
