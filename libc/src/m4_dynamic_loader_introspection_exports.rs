// M4 dynamic-loader introspection.
//
// The dynamic linker owns the process-wide object list.  These public libc
// entry points therefore use a small registration bridge, just like dlopen
// and dlsym above, so that the data reported here is the linker's actual
// relocated state.  The bridge is intentionally narrow: it carries the
// public callback/result layouts, while all object, program-header, symbol,
// TLS, and link-map traversal remains in ldso.

// The loader/debugger rendezvous belongs to ldso, but musl exposes these
// names from the combined libc/ldso image.  Crabc keeps the authoritative
// `struct r_debug` in ldso and writes its address to the expected public
// `_dl_debug_addr` slot during loader startup.  The libc symbol is therefore
// an ABI view of the real loader state, not a second or fabricated state.

/// Pointer-valued libc-side ABI slot populated by ldso before application
/// constructors run.  Its C layout is the same as `struct r_debug *` from
/// `<link.h>`; only ldso owns and mutates the pointee.
#[no_mangle]
pub static mut _dl_debug_addr: *mut c_void = core::ptr::null_mut();

/// Musl's default debugger rendezvous hook is intentionally inert.
///
/// This function has no startup-entry semantics; `_dlstart` below is kept as
/// a separate raw-stack assembly trampoline.  The authoritative loader hook
/// remains the `r_brk` address inside the ldso-owned `struct r_debug`.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _dl_debug_state() {}

// `libc.a` is also used for ordinary static executables, where the dynamic
// linker object that provides this bridge is intentionally not linked.  Keep
// the bridge weak at the libc boundary: a dynamic image still resolves it to
// crabc's ldso, while static archive consumers can link without importing an
// interpreter-only symbol.  `_dlstart` is only reached by the dynamic-loader
// entry path; static crt1 startup enters `__libc_start_main` directly.
extern "C" {
    #[linkage = "weak"]
    fn __ldso_dlstart() -> !;
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    // The raw trampoline below names the bridge in assembly, so declare the
    // relocation weak there as well as in Rust's extern declaration.
    ".weak __ldso_dlstart",
);

// In musl `_dlstart` is the non-returning interpreter entry and receives the
// initial process stack in the machine's raw entry convention.  Crabc's
// interpreter is `libldso.so`, whose `_start` performs that work.  This libc
// symbol is an ABI-real tail trampoline for consumers that locate `_dlstart`
// through libc: it jumps through a GOT entry to ldso's raw-entry bridge and never
// returns.  It must not be called as a C function with ordinary arguments.
#[no_mangle]
#[unsafe(naked)]
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn _dlstart() -> ! {
    core::arch::naked_asm!(
        "adrp x16, :got:__ldso_dlstart",
        "ldr x16, [x16, :got_lo12:__ldso_dlstart]",
        "br x16",
    );
}

#[repr(C)]
pub struct Dl_info {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

#[repr(C)]
pub struct dl_phdr_info {
    pub dlpi_addr: usize,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const c_void,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut c_void,
}

#[repr(C)]
pub struct M4DladdrResult {
    fname: *const c_char,
    fbase: usize,
    sname: *const c_char,
    saddr: usize,
}

pub type M4DlIterateCallback = unsafe extern "C" fn(
    *mut dl_phdr_info,
    usize,
    *mut c_void,
) -> c_int;
pub type M4LdsoIteratePhdr = unsafe extern "C" fn(
    M4DlIterateCallback,
    *mut c_void,
) -> c_int;
pub type M4LdsoDladdr = unsafe extern "C" fn(
    *const c_void,
    *mut M4DladdrResult,
) -> c_int;
pub type M4LdsoDlinfo = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *mut c_void,
) -> c_int;

// `LDSO_DLSYM` is the established private libc/ldso callback.  Keep newer
// loader operations behind its private selector rather than leaking a fresh
// public registration symbol for each one into libc's ELF ABI.
const M4_LDSO_PRIVATE_HANDLE: *mut c_void = 2usize as *mut c_void;

unsafe fn m4_ldso_private_symbol(name: *const c_char) -> *mut c_void {
    let Some(resolve) = LDSO_DLSYM else {
        return core::ptr::null_mut();
    };
    resolve(M4_LDSO_PRIVATE_HANDLE, name)
}

unsafe fn m4_ldso_iterate_phdr() -> Option<M4LdsoIteratePhdr> {
    let address = m4_ldso_private_symbol(b"__crabc_ldso_iterate_phdr\0".as_ptr().cast());
    (!address.is_null()).then(|| core::mem::transmute(address))
}

unsafe fn m4_ldso_dladdr() -> Option<M4LdsoDladdr> {
    let address = m4_ldso_private_symbol(b"__crabc_ldso_dladdr\0".as_ptr().cast());
    (!address.is_null()).then(|| core::mem::transmute(address))
}

unsafe fn m4_ldso_dlinfo() -> Option<M4LdsoDlinfo> {
    let address = m4_ldso_private_symbol(b"__crabc_ldso_dlinfo\0".as_ptr().cast());
    (!address.is_null()).then(|| core::mem::transmute(address))
}

unsafe fn m4_ldso_tls_get_addr() -> *mut c_void {
    m4_ldso_private_symbol(b"__crabc_ldso_tls_get_addr\0".as_ptr().cast())
}

/// Visit the loader's current object list in load order.
///
/// The callback receives a temporary `dl_phdr_info`; callers must not retain
/// its address after returning.  A nonzero callback return is propagated
/// unchanged, matching musl's `dl_iterate_phdr` contract.
#[no_mangle]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<M4DlIterateCallback>,
    data: *mut c_void,
) -> c_int {
    let Some(callback) = callback else {
        return 0;
    };
    match m4_ldso_iterate_phdr() {
        Some(iterate) => iterate(callback, data),
        None => -1,
    }
}

/// Resolve an address against the loaded objects and their dynamic symbols.
#[no_mangle]
pub unsafe extern "C" fn dladdr(
    address: *const c_void,
    info: *mut Dl_info,
) -> c_int {
    if address.is_null() || info.is_null() {
        return 0;
    }
    let Some(dladdr_impl) = m4_ldso_dladdr() else {
        return 0;
    };

    let mut result = M4DladdrResult {
        fname: core::ptr::null(),
        fbase: 0,
        sname: core::ptr::null(),
        saddr: 0,
    };
    let matched = dladdr_impl(address, &mut result);
    if matched == 0 {
        return 0;
    }
    (*info).dli_fname = result.fname;
    (*info).dli_fbase = result.fbase as *mut c_void;
    (*info).dli_sname = result.sname;
    (*info).dli_saddr = result.saddr as *mut c_void;
    matched
}

/// Query loader metadata.  The first supported request is
/// `RTLD_DI_LINKMAP` (value 2), whose argument is a `struct link_map **`.
#[no_mangle]
pub unsafe extern "C" fn dlinfo(
    handle: *mut c_void,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    let Some(dlinfo_impl) = m4_ldso_dlinfo() else {
        return -1;
    };
    dlinfo_impl(handle, request, arg)
}
