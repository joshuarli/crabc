//! Selected static Linux/x86-64 C intrusive-queue ABI boundary.
//!
//! This leaf owns exactly `insque` and `remque`: the two-link mutation of a
//! caller-owned intrusive queue node. It owns neither node allocation,
//! lifetime, search/tree/hash algorithms, a container type, iteration,
//! callbacks, synchronization, errno, TLS, locale, libc.so, a CRT, a loader,
//! a sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT license:
//! `src/search/insque.c::{insque,remque}` maps directly to the assignments
//! below. Musl treats the first two fields of each valid caller node as
//! `next` and `prev` pointers. A null predecessor resets only the inserted
//! node's two links; a non-null predecessor splices after it; and `remque`
//! repairs neighboring links without clearing the removed node's own links.
//! Null element pointers and invalid/non-writable caller links remain outside
//! the C-defined caller contract rather than receiving a Rust fallback.
//!
//! No path reads or writes TLS, errno, allocation, locks, locale, callback
//! registries, process state, or a syscall boundary.

use core::{
    ffi::c_void,
    mem::{align_of, offset_of, size_of},
    ptr::null_mut,
};

#[repr(C)]
struct Node {
    next: *mut Node,
    prev: *mut Node,
}

const _: () = {
    assert!(size_of::<Node>() == 16);
    assert!(align_of::<Node>() == 8);
    assert!(offset_of!(Node, next) == 0);
    assert!(offset_of!(Node, prev) == 8);
};

const NEXT_OFFSET: usize = offset_of!(Node, next);
const PREV_OFFSET: usize = offset_of!(Node, prev);

#[inline]
unsafe fn link_slot(node: *mut Node, offset: usize) -> *mut *mut Node {
    node.cast::<u8>().wrapping_add(offset).cast::<*mut Node>()
}

#[inline]
unsafe fn next(node: *mut Node) -> *mut Node {
    unsafe { core::ptr::read_unaligned(link_slot(node, NEXT_OFFSET)) }
}

#[inline]
unsafe fn prev(node: *mut Node) -> *mut Node {
    unsafe { core::ptr::read_unaligned(link_slot(node, PREV_OFFSET)) }
}

#[inline]
unsafe fn set_next(node: *mut Node, value: *mut Node) {
    unsafe { core::ptr::write_unaligned(link_slot(node, NEXT_OFFSET), value) };
}

#[inline]
unsafe fn set_prev(node: *mut Node, value: *mut Node) {
    unsafe { core::ptr::write_unaligned(link_slot(node, PREV_OFFSET), value) };
}

/// Insert element immediately after predecessor, or initialize it when pred is null.
///
/// # Safety
///
/// element must be non-null, writable, and begin with two pointer-sized,
/// suitably aligned link fields in `next`, then `prev` order. If pred is
/// non-null it must denote another valid writable node in the same
/// caller-owned intrusive queue, and any non-null neighbor links reached by
/// the operation must likewise be writable valid nodes.
#[no_mangle]
pub unsafe extern "C" fn insque(element: *mut c_void, pred: *mut c_void) {
    let element = element.cast::<Node>();
    let pred = pred.cast::<Node>();

    if pred.is_null() {
        unsafe {
            set_next(element, null_mut());
            set_prev(element, null_mut());
        }
        return;
    }

    // Preserve musl's field-write order, including the final read through the
    // element after predecessor publication for all caller-valid aliasing.
    unsafe {
        set_next(element, next(pred));
        set_prev(element, pred);
        set_next(pred, element);
        if !next(element).is_null() {
            set_prev(next(element), element);
        }
    }
}

/// Unlink element from its neighbors without clearing element's two links.
///
/// # Safety
///
/// element must be non-null and begin with the valid two-link caller layout.
/// Any non-null next or previous link must denote a writable valid node whose
/// opposite link can be updated. The caller retains node lifetime and all
/// higher-level queue invariants.
#[no_mangle]
pub unsafe extern "C" fn remque(element: *mut c_void) {
    let element = element.cast::<Node>();

    unsafe {
        if !next(element).is_null() {
            set_prev(next(element), prev(element));
        }
        if !prev(element).is_null() {
            set_next(prev(element), next(element));
        }
    }
}
