// Public musl TLS ABI entry point.
//
// The ELF TLS ABI puts a module number and an offset in the two words passed
// to `__tls_get_addr`. The actual TLS block belongs to the dynamic linker,
// so libc cannot implement this operation independently. This ABI-facing shim
// obtains ldso's resolver through the established private dlsym callback.
// Keeping the state in ldso is important for TLS DSOs loaded after the initial
// thread block was created: ldso can then expand that block and initialize the
// new image before returning the address.

/// Function-pointer ABI shared by libc and ldso for the TLS resolver bridge.
/// The pointed-to object is the ELF `tls_index` (two `size_t` words); using a
/// byte pointer here keeps this private registration interface independent of
/// either crate's Rust-side spelling of that C ABI structure.
type LdsoTlsGetAddr = unsafe extern "C" fn(*const u8) -> *mut u8;

/// Resolve an ELF TLS descriptor using the process-wide ldso TLS state.
///
/// A program using libc without crabc's interpreter has no resolver to call;
/// returning null in that configuration is the same fail-closed behavior as
/// the other ldso-backed libc entry points.  Normal musl-linked programs are
/// started by crabc ldso, which installs the callback before this can be
/// reached.
#[no_mangle]
pub unsafe extern "C" fn __tls_get_addr(ti: *const usize) -> *mut c_void {
    let address = cabi_ldso_tls_get_addr();
    if address.is_null() {
        return core::ptr::null_mut();
    }
    let resolve: LdsoTlsGetAddr = core::mem::transmute(address);
    resolve(ti.cast::<u8>()).cast::<c_void>()
}
