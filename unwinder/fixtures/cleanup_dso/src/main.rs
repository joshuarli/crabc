use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const PLUGIN: &[u8] = b"libcrabc_owned_cleanup_plugin.so\0";
const ENTRY: &[u8] = b"crabc_owned_cleanup_dso\0";

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

fn main() {
    // The explicit loader invocation supplies the plugin directory as its
    // first library-path element. Loading the basename therefore proves
    // owned-loader DSO discovery, rather than a direct-path open.
    unsafe {
        let handle = dlopen(PLUGIN.as_ptr().cast(), RTLD_NOW);
        if handle.is_null() {
            std::process::exit(1);
        }
        let symbol = dlsym(handle, ENTRY.as_ptr().cast());
        if symbol.is_null() {
            std::process::exit(2);
        }
        let run: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        if run() != 0 {
            std::process::exit(3);
        }
        if dlclose(handle) != 0 {
            std::process::exit(4);
        }
    }
}
