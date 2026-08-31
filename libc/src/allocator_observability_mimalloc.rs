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
    libmimalloc_sys::mi_usable_size(ptr)
}
