// Public allocator observation over the selected mimalloc backend.
//
// Keep this leaf separate from the allocation entries: `malloc_usable_size`
// is its own AArch64 capability and has strong ELF binding, while the basic
// allocation entries deliberately retain their weak interposition contract.

#[no_mangle]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    #[cfg(feature = "native-mimalloc-shadow")]
    {
        // SAFETY: the null case returned above. The caller supplies a live
        // allocation from the selected backend; native observation must not
        // send that pointer to the ordinary C allocator.
        let block = unsafe { core::ptr::NonNull::new_unchecked(ptr.cast::<u8>()) };
        return unsafe { crabc_mimalloc::__crabc_runtime::native_usable_size(block) }
            .unwrap_or(0);
    }
    #[cfg(not(feature = "native-mimalloc-shadow"))]
    libmimalloc_sys::mi_usable_size(ptr)
}
