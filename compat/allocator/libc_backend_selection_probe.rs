//! Compile-only adapter ownership check. Backend stubs make an accidental
//! dependency on the other allocator fail to compile; no allocation executes.
//! In the pinned native container, compile with `rustc --edition=2021
//! --crate-type=lib --emit=obj` once with defaults and once with
//! `--cfg 'feature="native-mimalloc-shadow"'`.
#![feature(linkage)]
#![allow(dead_code, non_camel_case_types)]

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
#[cfg(feature = "native-mimalloc-shadow")]
use core::ptr::NonNull;
type SizeT = usize;
static mut ERRNO: c_int = 0;
const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;
unsafe fn cabi_allocator_errno() -> c_int { unsafe { ERRNO } }
unsafe fn cabi_set_allocator_errno(value: c_int) { unsafe { ERRNO = value; } }
unsafe fn abort() -> ! { loop { core::hint::spin_loop(); } }

#[cfg(not(feature = "native-mimalloc-shadow"))]
mod libmimalloc_sys {
    use super::*;
    unsafe extern "C" {
        pub fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void;
        pub fn mi_realloc_aligned(ptr: *mut c_void, size: usize, alignment: usize) -> *mut c_void;
        pub fn mi_zalloc(size: usize) -> *mut c_void;
        pub fn mi_free(ptr: *mut c_void);
        pub fn mi_usable_size(ptr: *mut c_void) -> usize;
    }
}

#[cfg(feature = "native-mimalloc-shadow")]
mod crabc_mimalloc {
    pub mod __crabc_runtime {
        use super::super::*;
        pub enum NativePageAllocationResult {
            Allocated(NonNull<u8>), Unavailable, AllocationFailed, Retained,
        }
        pub enum NativePageFreeResult { Freed, InvalidPointer, Unavailable, Retained }
        unsafe extern "Rust" {
            pub fn native_allocate_aligned(size: usize, alignment: usize, zero: bool) -> NativePageAllocationResult;
            pub fn native_free(ptr: NonNull<u8>) -> NativePageFreeResult;
            pub fn native_reallocate(ptr: Option<NonNull<u8>>, size: usize) -> NativePageAllocationResult;
            pub fn native_usable_size(ptr: NonNull<u8>) -> Option<usize>;
        }
    }
}

#[cfg(not(feature = "native-mimalloc-shadow"))]
include!("../../libc/src/allocator_mimalloc.rs");
#[cfg(feature = "native-mimalloc-shadow")]
include!("../../libc/src/allocator_native_mimalloc.rs");
include!("../../libc/src/allocator_observability_mimalloc.rs");

// Both feature selections must supply these public adapters exactly once.
#[used]
static MEMALIGN: unsafe extern "C" fn(usize, usize) -> *mut c_void = memalign;
#[used]
static VALLOC: unsafe extern "C" fn(usize) -> *mut c_void = valloc;
#[used]
static USABLE_SIZE: unsafe extern "C" fn(*mut c_void) -> usize = malloc_usable_size;
