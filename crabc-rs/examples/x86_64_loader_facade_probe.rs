//! Native x86-64 `dl` facade operations for the installed-product differential.
//!
//! `compat/x86_64/runtime_private_facades_loader.c` calls each entry below,
//! then repeats the same request through the product's public dlfcn API in
//! the same process and compares the copied values. This archive itself
//! reaches only the private `__crabc_runtime_v1` table.

#![no_std]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr::NonNull;

use crabc_rs::dl::{Library, LoadedImageSnapshot, LoaderText, OpenFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `ud2` raises SIGILL, ending this probe process immediately.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Mirrors `struct facade_image` in the C driver.
#[repr(C)]
pub struct FacadeImage {
    base: *mut c_void,
    program_headers: *mut c_void,
    program_header_count: usize,
    additions: u64,
    removals: u64,
    tls_module: usize,
    tls_data: *mut c_void,
    name: [u8; 257],
}

const CLOSE_DSO: &CStr = c"libloader_dlfcn_close.so";
const DROP_DSO: &CStr = c"libloader_dlfcn_drop.so";
const CLOSE_STATE: &CStr = c"loader_dlfcn_close_state";
const DROP_STATE: &CStr = c"loader_dlfcn_drop_state";
const VALUE: &CStr = c"loader_dlfcn_value";

type StateFn = unsafe extern "C" fn() -> c_int;

/// # Safety
/// `name` is null or a NUL-terminated C string.
unsafe fn requested<'a>(name: *const c_char) -> Option<&'a CStr> {
    // SAFETY: guaranteed by the caller.
    (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) })
}

/// Copies bytes plus a NUL into C storage; false when they do not fit.
///
/// # Safety
/// `output` is writable for `capacity` bytes.
unsafe fn copy_out(bytes: &[u8], output: *mut c_char, capacity: usize) -> bool {
    if output.is_null() || bytes.len() >= capacity {
        return false;
    }
    // SAFETY: the range fits the caller's writable storage.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), bytes.len());
        *output.add(bytes.len()) = 0;
    }
    true
}

/// # Safety
/// As for [`copy_out`].
unsafe fn copy_text(text: Option<&LoaderText>, output: *mut c_char, capacity: usize) -> bool {
    match text {
        Some(text) if text.is_truncated() => false,
        Some(text) => unsafe { copy_out(text.as_bytes(), output, capacity) },
        None => unsafe { copy_out(b"", output, capacity) },
    }
}

fn open(name: Option<&CStr>, flags: OpenFlags) -> Result<Library, c_int> {
    match name {
        Some(name) => Library::open(name, flags).map_err(|_| 10),
        None => Library::open_main(flags).map_err(|_| 11),
    }
}

/// Opens `name`, which must fail, and copies the owned diagnostic.
///
/// # Safety
/// `name` is a C string and `text` is writable for `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_facade_open_error(
    name: *const c_char,
    text: *mut c_char,
    capacity: usize,
) -> c_int {
    let Some(name) = (unsafe { requested(name) }) else { return 1 };
    match Library::open(name, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(_) => 2,
        Err(error) if error.is_truncated() => 3,
        Err(error) => if unsafe { copy_out(error.as_bytes(), text, capacity) } { 0 } else { 4 },
    }
}

/// Looks up `symbol` in `library` (null: the main handle); the lookup must
/// fail and its owned diagnostic is copied.
///
/// # Safety
/// C strings are NUL-terminated and `text` is writable for `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_facade_symbol_error(
    library: *const c_char,
    symbol: *const c_char,
    text: *mut c_char,
    capacity: usize,
) -> c_int {
    let Some(symbol) = (unsafe { requested(symbol) }) else { return 1 };
    let library = match open(unsafe { requested(library) }, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(library) => library,
        Err(code) => return code,
    };
    // SAFETY: the lookup must fail; no value is interpreted.
    match unsafe { library.symbol::<*mut c_void>(symbol) } {
        Ok(_) => 2,
        Err(error) if error.is_truncated() => 3,
        Err(error) => if unsafe { copy_out(error.as_bytes(), text, capacity) } { 0 } else { 4 },
    }
}

/// Resolves `symbol` in `library` (null: the main handle) and returns its
/// address. TLS symbols resolve to the calling thread's object.
///
/// # Safety
/// C strings are NUL-terminated and `address` is writable.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_facade_symbol(
    library: *const c_char,
    symbol: *const c_char,
    address: *mut *mut c_void,
) -> c_int {
    let Some(symbol) = (unsafe { requested(symbol) }) else { return 1 };
    if address.is_null() {
        return 1;
    }
    let library = match open(unsafe { requested(library) }, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(library) => library,
        Err(code) => return code,
    };
    // SAFETY: the address is returned as an opaque value only.
    match unsafe { library.symbol::<*mut c_void>(symbol) } {
        Ok(value) => {
            unsafe { *address = value.address().as_ptr() };
            0
        }
        Err(_) => 2,
    }
}

/// Copies owned `dladdr`-like metadata for `address`.
///
/// # Safety
/// Outputs are writable; name buffers hold `capacity` bytes each.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_facade_address(
    address: *mut c_void,
    base: *mut *mut c_void,
    symbol_address: *mut *mut c_void,
    image_name: *mut c_char,
    symbol_name: *mut c_char,
    capacity: usize,
) -> c_int {
    let Some(address) = NonNull::new(address) else { return 1 };
    let info = match Library::address_of(address) {
        Ok(info) => info,
        Err(_) => return 2,
    };
    unsafe {
        *base = info.image_base().map_or(core::ptr::null_mut(), NonNull::as_ptr);
        *symbol_address = info.symbol_address().map_or(core::ptr::null_mut(), NonNull::as_ptr);
    }
    if !unsafe { copy_text(info.image_name(), image_name, capacity) }
        || !unsafe { copy_text(info.symbol_name(), symbol_name, capacity) }
    {
        return 3;
    }
    0
}

/// Copies owned handle metadata for `library` (null: the main handle).
///
/// # Safety
/// Outputs are writable; `name` holds `capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_facade_information(
    library: *const c_char,
    base: *mut *mut c_void,
    dynamic: *mut *mut c_void,
    name: *mut c_char,
    capacity: usize,
) -> c_int {
    let library = match open(unsafe { requested(library) }, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(library) => library,
        Err(code) => return code,
    };
    let information = match library.information() {
        Ok(information) => information,
        Err(_) => return 2,
    };
    unsafe {
        *base = information.image_base().map_or(core::ptr::null_mut(), NonNull::as_ptr);
        *dynamic = information.dynamic_address().map_or(core::ptr::null_mut(), NonNull::as_ptr);
    }
    if !unsafe { copy_text(information.image_name(), name, capacity) } {
        return 3;
    }
    0
}

/// Captures one owned loaded-image snapshot into C records.
///
/// # Safety
/// `records` is writable for `capacity` records; the scalars are writable.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_x86_64_facade_snapshot(
    records: *mut FacadeImage,
    capacity: usize,
    count: *mut usize,
    generation: *mut u64,
) -> c_int {
    let snapshot = match LoadedImageSnapshot::capture() {
        Ok(snapshot) => snapshot,
        Err(_) => return 1,
    };
    if snapshot.len() > capacity {
        return 2;
    }
    for (index, image) in snapshot.images().iter().enumerate() {
        // SAFETY: `index < capacity` by the check above.
        let record = unsafe { &mut *records.add(index) };
        record.base = image.image_base().map_or(core::ptr::null_mut(), NonNull::as_ptr);
        record.program_headers = image.program_headers().map_or(core::ptr::null_mut(), NonNull::as_ptr);
        record.program_header_count = image.program_header_count();
        record.additions = image.additions();
        record.removals = image.removals();
        record.tls_module = image.tls_module().unwrap_or(0);
        record.tls_data = image.tls_data().map_or(core::ptr::null_mut(), NonNull::as_ptr);
        if !unsafe { copy_text(image.image_name(), record.name.as_mut_ptr().cast(), record.name.len()) } {
            return 3;
        }
    }
    unsafe {
        *count = snapshot.len();
        *generation = snapshot.generation();
    }
    0
}

fn state(library: &Library, name: &CStr) -> Result<c_int, ()> {
    // SAFETY: both fixture symbols are `int (void)` functions.
    let symbol = unsafe { library.symbol::<StateFn>(name) }.map_err(|_| ())?;
    // SAFETY: the symbol is a live fixture function with that C ABI.
    Ok(unsafe { symbol.get()() })
}

/// Proves reference ownership and musl's retained-close lifecycle.
#[no_mangle]
pub extern "C" fn crabc_rs_x86_64_facade_lifecycle() -> c_int {
    let Ok(main) = Library::open_main(OpenFlags::NOW | OpenFlags::LOCAL) else { return 1 };
    let Ok(first) = Library::open(CLOSE_DSO, OpenFlags::NOW | OpenFlags::GLOBAL) else { return 2 };
    let Ok(second) = Library::open(CLOSE_DSO, OpenFlags::NOW | OpenFlags::GLOBAL) else { return 3 };
    // The constructor ran exactly once for two references.
    if state(&first, CLOSE_STATE) != Ok(1) || state(&second, VALUE) != Ok(73) {
        return 4;
    }
    if first.close().is_err() {
        return 5;
    }
    // The remaining reference still resolves through its own scope.
    if state(&second, CLOSE_STATE) != Ok(1) {
        return 6;
    }
    if second.close().is_err() {
        return 7;
    }
    // Musl retains a closed object: it stays in global scope and its
    // destructor waits for process exit.
    if state(&main, CLOSE_STATE) != Ok(1) {
        return 8;
    }
    let Ok(dropped) = Library::open(DROP_DSO, OpenFlags::NOW | OpenFlags::GLOBAL) else { return 9 };
    if state(&dropped, DROP_STATE) != Ok(1) {
        return 10;
    }
    drop(dropped);
    if state(&main, DROP_STATE) != Ok(1) {
        return 11;
    }
    // The permanent main handle is not released by its owner.
    if main.close().is_err() {
        return 12;
    }
    0
}
