//! Selected static Linux/x86-64 `<search.h>` callback-tree boundary.
//!
//! This is a direct semantic translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/search/tsearch.c`, `tdelete.c`, `tfind.c`, `twalk.c`, `tdestroy.c`,
//! and private `tsearch.h` map to the AVL node, rotations, path-bounded
//! balancing, comparator order, traversal, deletion, and destruction below.
//! The internal `__tsearch_balance` helper remains a strong hidden ELF symbol;
//! the five `<search.h>` functions are strong and have no weak aliases.
//! The exact compatibility invariants include allocation failure rollback and
//! parent-return deletion, including musl's arbitrary root-deletion result.
//!
//! The caller owns the root pointer and every key. Musl obtains each private
//! 32-byte node with `malloc` and releases it with `free`. This selected x86
//! archive keeps public and hidden C allocator exports absent: each node owns
//! one zero-filled private 4096-byte mapping, released by `tdelete` or
//! `tdestroy`. This intentional mechanism difference retains allocation
//! failure rollback, node identity, key ownership, and lifetime semantics; the
//! native differential proves it with RLIMIT_AS and mincore. It does not select
//! a public allocator, general containers, process/environment state,
//! stdio/locale, libc.so, CRT, loader, sysroot, family promotion, or public x86
//! support.

use core::arch::global_asm;
use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, null_mut};

use super::errno;

const MAX_HEIGHT: usize = size_of::<*mut c_void>() * 8 * 3 / 2;
const NODE_MAPPING_SIZE: usize = 4_096;
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_PRIVATE: c_int = 0x02;
const MAP_ANONYMOUS: c_int = 0x20;
const ENOMEM: c_int = 12;

const PREORDER: c_int = 0;
const POSTORDER: c_int = 1;
const ENDORDER: c_int = 2;
const LEAF: c_int = 3;

type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
type WalkAction = unsafe extern "C" fn(*const c_void, c_int, c_int);
type FreeKey = Option<unsafe extern "C" fn(*mut c_void)>;

unsafe extern "C" {
    #[link_name = "mmap"]
    fn selected_mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        descriptor: c_int,
        offset: i64,
    ) -> *mut c_void;

    #[link_name = "munmap"]
    fn selected_munmap(address: *mut c_void, length: usize) -> c_int;
}

#[repr(C)]
struct Node {
    key: *const c_void,
    children: [*mut Node; 2],
    height: c_int,
}

const _: () = {
    assert!(MAX_HEIGHT == 96);
    assert!(size_of::<Node>() == 32);
    assert!(align_of::<Node>() == 8);
    assert!(offset_of!(Node, key) == 0);
    assert!(offset_of!(Node, children) == 8);
    assert!(offset_of!(Node, height) == 24);
};

global_asm!(".hidden __tsearch_balance");

#[inline]
unsafe fn node_key(node: *mut Node) -> *const c_void {
    unsafe { ptr::addr_of!((*node).key).read() }
}

#[inline]
unsafe fn set_node_key(node: *mut Node, key: *const c_void) {
    unsafe { ptr::addr_of_mut!((*node).key).write(key) };
}

#[inline]
unsafe fn child(node: *mut Node, direction: usize) -> *mut Node {
    unsafe {
        ptr::addr_of!((*node).children)
            .cast::<*mut Node>()
            .add(direction)
            .read()
    }
}

#[inline]
unsafe fn child_link(node: *mut Node, direction: usize) -> *mut *mut Node {
    unsafe {
        ptr::addr_of_mut!((*node).children)
            .cast::<*mut Node>()
            .add(direction)
    }
}

#[inline]
unsafe fn set_child(node: *mut Node, direction: usize, value: *mut Node) {
    unsafe { child_link(node, direction).write(value) };
}

#[inline]
unsafe fn node_height(node: *mut Node) -> c_int {
    if node.is_null() {
        0
    } else {
        unsafe { ptr::addr_of!((*node).height).read() }
    }
}

#[inline]
unsafe fn set_node_height(node: *mut Node, height: c_int) {
    unsafe { ptr::addr_of_mut!((*node).height).write(height) };
}

#[inline]
unsafe fn allocate_node(key: *const c_void) -> *mut Node {
    let mapping = unsafe {
        selected_mmap(
            null_mut(),
            NODE_MAPPING_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapping as usize == usize::MAX {
        return null_mut();
    }
    if mapping.is_null() {
        let _ = unsafe { selected_munmap(mapping, NODE_MAPPING_SIZE) };
        unsafe { errno::set_errno(ENOMEM) };
        return null_mut();
    }
    let node = mapping.cast::<Node>();
    unsafe { set_node_key(node, key) };
    unsafe { set_child(node, 0, null_mut()) };
    unsafe { set_child(node, 1, null_mut()) };
    unsafe { set_node_height(node, 1) };
    node
}

#[inline]
unsafe fn release_node(node: *mut Node) {
    let saved_errno = unsafe { errno::get_errno() };
    let _ = unsafe { selected_munmap(node.cast::<c_void>(), NODE_MAPPING_SIZE) };
    unsafe { errno::set_errno(saved_errno) };
}

unsafe fn rotate(link: *mut *mut Node, node: *mut Node, direction: usize) -> c_int {
    let opposite = direction ^ 1;
    let deeper = unsafe { child(node, direction) };
    let mut middle = unsafe { child(deeper, opposite) };
    let old_height = unsafe { node_height(node) };
    let middle_height = unsafe { node_height(middle) };
    if middle_height > unsafe { node_height(child(deeper, direction)) } {
        unsafe { set_child(node, direction, child(middle, opposite)) };
        unsafe { set_child(deeper, opposite, child(middle, direction)) };
        unsafe { set_child(middle, opposite, node) };
        unsafe { set_child(middle, direction, deeper) };
        unsafe { set_node_height(node, middle_height) };
        unsafe { set_node_height(deeper, middle_height) };
        unsafe { set_node_height(middle, middle_height.wrapping_add(1)) };
    } else {
        unsafe { set_child(node, direction, middle) };
        unsafe { set_child(deeper, opposite, node) };
        unsafe { set_node_height(node, middle_height.wrapping_add(1)) };
        unsafe { set_node_height(deeper, middle_height.wrapping_add(2)) };
        middle = deeper;
    }
    unsafe { link.write(middle) };
    unsafe { node_height(middle).wrapping_sub(old_height) }
}

/// Rebalance one internal musl AVL link and report its height change.
///
/// # Safety
///
/// `link` must address a writable non-null link to a valid tree node created
/// by this implementation. The complete reachable tree must be exclusively
/// accessible and retain internally consistent child links and heights.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __tsearch_balance(link: *mut *mut c_void) -> c_int {
    let typed_link = link.cast::<*mut Node>();
    let node = unsafe { typed_link.read() };
    let left_height = unsafe { node_height(child(node, 0)) };
    let right_height = unsafe { node_height(child(node, 1)) };
    if (left_height.wrapping_sub(right_height).wrapping_add(1) as u32) < 3 {
        let old_height = unsafe { node_height(node) };
        let new_height = if left_height < right_height {
            right_height.wrapping_add(1)
        } else {
            left_height.wrapping_add(1)
        };
        unsafe { set_node_height(node, new_height) };
        new_height.wrapping_sub(old_height)
    } else {
        unsafe { rotate(typed_link, node, usize::from(left_height < right_height)) }
    }
}

#[inline]
unsafe fn balance(link: *mut *mut Node) -> c_int {
    unsafe { __tsearch_balance(link.cast::<*mut c_void>()) }
}

/// Find an equal key or insert one caller-owned key in a musl-compatible AVL tree.
///
/// # Safety
///
/// A non-null `root` must address a writable caller-owned root pointer that is
/// null or was produced by this implementation. `key` and every previously
/// inserted key must remain readable whenever `compare` can observe them. The
/// caller must exclude concurrent mutation and `compare` must obey a stable
/// total ordering without unwinding across C ABI frames.
#[no_mangle]
pub unsafe extern "C" fn tsearch(
    key: *const c_void,
    root: *mut *mut c_void,
    compare: Compare,
) -> *mut c_void {
    if root.is_null() {
        return null_mut();
    }

    let mut path = [null_mut::<*mut Node>(); MAX_HEIGHT];
    let path_base = path.as_mut_ptr();
    let mut count = 0usize;
    let typed_root = root.cast::<*mut Node>();
    unsafe { path_base.add(count).write(typed_root) };
    count = count.wrapping_add(1);
    let mut node = unsafe { typed_root.read() };
    while !node.is_null() {
        let order = unsafe { compare(key, node_key(node)) };
        if order == 0 {
            return node.cast::<c_void>();
        }
        let direction = usize::from(order > 0);
        let link = unsafe { child_link(node, direction) };
        unsafe { path_base.add(count).write(link) };
        count = count.wrapping_add(1);
        node = unsafe { link.read() };
    }

    let inserted = unsafe { allocate_node(key) };
    if inserted.is_null() {
        return null_mut();
    }
    count = count.wrapping_sub(1);
    let insertion_link = unsafe { path_base.add(count).read() };
    unsafe { insertion_link.write(inserted) };
    while count != 0 {
        count = count.wrapping_sub(1);
        let ancestor = unsafe { path_base.add(count).read() };
        if unsafe { balance(ancestor) } == 0 {
            break;
        }
    }
    inserted.cast::<c_void>()
}

/// Find one equal key in a musl-compatible callback tree.
///
/// # Safety
///
/// A non-null `root` must address a caller-owned root pointer that is null or
/// was produced by this implementation. The tree and keys must remain valid,
/// `compare` must obey their stable total ordering, and no concurrent mutation
/// may occur during this call.
#[no_mangle]
pub unsafe extern "C" fn tfind(
    key: *const c_void,
    root: *const *mut c_void,
    compare: Compare,
) -> *mut c_void {
    if root.is_null() {
        return null_mut();
    }
    let mut node = unsafe { root.cast::<*mut Node>().read() };
    while !node.is_null() {
        let order = unsafe { compare(key, node_key(node)) };
        if order == 0 {
            break;
        }
        node = unsafe { child(node, usize::from(order > 0)) };
    }
    node.cast::<c_void>()
}

/// Delete one equal key and return musl's parent identity.
///
/// # Safety
///
/// The `root`, key, comparator, ordering, exclusivity, and lifetime obligations
/// are those of `tsearch`. A successful deletion invalidates the removed node
/// pointer; when deleting the root, the specified arbitrary non-null return may
/// itself be that invalidated pointer and must never be dereferenced.
#[no_mangle]
pub unsafe extern "C" fn tdelete(
    key: *const c_void,
    root: *mut *mut c_void,
    compare: Compare,
) -> *mut c_void {
    if root.is_null() {
        return null_mut();
    }

    let mut path = [null_mut::<*mut Node>(); MAX_HEIGHT + 1];
    let path_base = path.as_mut_ptr();
    let typed_root = root.cast::<*mut Node>();
    let mut count = 0usize;
    unsafe { path_base.add(count).write(typed_root) };
    count = count.wrapping_add(1);
    unsafe { path_base.add(count).write(typed_root) };
    count = count.wrapping_add(1);
    let mut node = unsafe { typed_root.read() };
    loop {
        if node.is_null() {
            return null_mut();
        }
        let order = unsafe { compare(key, node_key(node)) };
        if order == 0 {
            break;
        }
        let link = unsafe { child_link(node, usize::from(order > 0)) };
        unsafe { path_base.add(count).write(link) };
        count = count.wrapping_add(1);
        node = unsafe { link.read() };
    }

    let parent_link = unsafe { path_base.add(count.wrapping_sub(2)).read() };
    let parent = unsafe { parent_link.read() };
    let replacement;
    let left = unsafe { child(node, 0) };
    if !left.is_null() {
        let deleted = node;
        let left_link = unsafe { child_link(node, 0) };
        unsafe { path_base.add(count).write(left_link) };
        count = count.wrapping_add(1);
        node = left;
        loop {
            let right = unsafe { child(node, 1) };
            if right.is_null() {
                break;
            }
            let right_link = unsafe { child_link(node, 1) };
            unsafe { path_base.add(count).write(right_link) };
            count = count.wrapping_add(1);
            node = right;
        }
        unsafe { set_node_key(deleted, node_key(node)) };
        replacement = unsafe { child(node, 0) };
    } else {
        replacement = unsafe { child(node, 1) };
    }

    unsafe { release_node(node) };
    count = count.wrapping_sub(1);
    let removed_link = unsafe { path_base.add(count).read() };
    unsafe { removed_link.write(replacement) };
    loop {
        count = count.wrapping_sub(1);
        if count == 0 {
            break;
        }
        let ancestor = unsafe { path_base.add(count).read() };
        if unsafe { balance(ancestor) } == 0 {
            break;
        }
    }
    parent.cast::<c_void>()
}

unsafe fn walk(node: *mut Node, action: WalkAction, depth: c_int) {
    if node.is_null() {
        return;
    }
    if unsafe { node_height(node) } == 1 {
        unsafe { action(node.cast::<c_void>(), LEAF, depth) };
    } else {
        unsafe { action(node.cast::<c_void>(), PREORDER, depth) };
        unsafe { walk(child(node, 0), action, depth.wrapping_add(1)) };
        unsafe { action(node.cast::<c_void>(), POSTORDER, depth) };
        unsafe { walk(child(node, 1), action, depth.wrapping_add(1)) };
        unsafe { action(node.cast::<c_void>(), ENDORDER, depth) };
    }
}

/// Traverse one musl-compatible AVL tree in `preorder`/`postorder`/`endorder` order.
///
/// # Safety
///
/// A non-null `root` must be a valid tree node returned by this implementation.
/// The complete tree and keys must remain stable for the call, and `action`
/// must not unwind or invalidate the traversal.
#[no_mangle]
pub unsafe extern "C" fn twalk(root: *const c_void, action: WalkAction) {
    unsafe { walk(root.cast_mut().cast::<Node>(), action, 0) };
}

unsafe fn destroy(node: *mut Node, free_key: FreeKey) {
    if node.is_null() {
        return;
    }
    unsafe { destroy(child(node, 0), free_key) };
    unsafe { destroy(child(node, 1), free_key) };
    if let Some(callback) = free_key {
        unsafe { callback(node_key(node).cast_mut()) };
    }
    unsafe { release_node(node) };
}

/// Destroy a complete musl-compatible AVL tree and optionally release each key.
///
/// # Safety
///
/// A non-null `root` must exclusively own a complete valid tree produced by
/// this implementation and must not be used afterward. `free_key`, when
/// present, must accept every stored key exactly once, must not unwind, and
/// must not invalidate nodes that remain to be traversed.
#[no_mangle]
pub unsafe extern "C" fn tdestroy(root: *mut c_void, free_key: FreeKey) {
    unsafe { destroy(root.cast::<Node>(), free_key) };
}
