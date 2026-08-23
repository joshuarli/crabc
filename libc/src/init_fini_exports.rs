// musl 1.2.6 exports `_init` and `_fini` as weak aliases of a private dummy
// function.  The aliases are part of the crt1/__libc_start_main ABI: an
// executable's startup objects may provide stronger definitions, while a
// shared-libc consumer still gets a valid no-op target when it does not.
//
// Keep these functions deliberately inert.  Constructor/destructor work is
// supplied by the executable's passed callbacks (and by the dynamic linker
// for shared objects); making the fallback call into exit or atexit would
// change the weak-alias contract and recurse during process startup.

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _init() {}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _fini() {}
