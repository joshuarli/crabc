use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const PLUGIN: &[u8] = b"libcrabc_owned_cleanup_plugin.so\0";
const ENTRY: &[u8] = b"crabc_owned_cleanup_dso\0";
const READY: &[u8] = b"crabc_owned_cleanup_dso_ready\0";
const RELEASE: &[u8] = b"crabc_owned_cleanup_dso_release\0";

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

fn main() {
    assert_eq!(crabc_cleanup_dependency::dependency_marker(), 73);
    // The explicit loader invocation supplies the plugin directory as its
    // first library-path element. Loading the basename therefore proves
    // owned-loader DSO discovery, rather than a direct-path open.
    unsafe {
        let handle = dlopen(PLUGIN.as_ptr().cast(), RTLD_NOW);
        if handle.is_null() {
            std::process::exit(1);
        }
        let entry_symbol = dlsym(handle, ENTRY.as_ptr().cast());
        let ready_symbol = dlsym(handle, READY.as_ptr().cast());
        let release_symbol = dlsym(handle, RELEASE.as_ptr().cast());
        if entry_symbol.is_null() || ready_symbol.is_null() || release_symbol.is_null() {
            std::process::exit(2);
        }
        let run: unsafe extern "C" fn() -> c_int = std::mem::transmute(entry_symbol);
        let ready: unsafe extern "C" fn() -> c_int = std::mem::transmute(ready_symbol);
        let release: unsafe extern "C" fn() -> c_int = std::mem::transmute(release_symbol);
        let running = std::thread::spawn(move || unsafe { run() });
        for _ in 0..10_000 {
            if ready() == 1 {
                break;
            }
            std::thread::yield_now();
        }
        if ready() != 1 {
            std::process::exit(3);
        }
        let last_handle = handle as usize;
        let close_status = std::thread::spawn(move || unsafe { dlclose(last_handle as *mut c_void) })
            .join()
            .unwrap_or(-1);
        if close_status != 0 {
            std::process::exit(4);
        }
        // The host's last handle is gone. The loader contract retains the
        // admitted mapping, so these saved function pointers may finish the
        // in-flight internal cleanup and exercise it once more after close.
        if release() != 0 || !matches!(running.join(), Ok(0)) || run() != 0 {
            std::process::exit(5);
        }
    }
}
