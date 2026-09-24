//! Private RuntimeV1 native-facade table for the owned dynamic x86 product.
//!
//! `crabc-rs`'s `dl`, `runtime_thread`, and `cfile` facades cannot link a
//! second loader graph, pthread registry, or stream engine into an
//! application. They reach this libc's one owner of each through the single
//! versioned private table declared by `crabc_core::runtime::RuntimeV1`,
//! which is the frozen AArch64 `runtime.private-facades` protocol. The table
//! is deliberately absent from installed headers.
//!
//! Every callback reports failure as a copied `TextV1` diagnostic (loader)
//! or a positive Linux/pthread error number (thread and memory stream). None
//! transports a public C sentinel, borrowed loader string, `link_map`, `FILE`
//! layout, or TLS `errno` across the boundary. The table itself neither
//! reports through the caller's C `errno` nor touches its pending `dlerror`
//! (application constructors run by a load remain free to change `errno`):
//!
//! - Loader callbacks call the interpreter's private runtime operations that
//!   `general_dlfcn` also uses, under the same cancellation guard. Their
//!   diagnostics are `general_dlfcn`'s pinned-musl texts, written into
//!   caller-owned wire storage instead of the per-thread `dlerror` slot.
//! - Thread callbacks call the selected pthread owners directly. Handles are
//!   the same opaque thread-pointer identities as `pthread_t`.
//! - Memory-stream callbacks call the owned stream engine and translate its
//!   C status plus `errno` into a positive status, then restore the caller's
//!   `errno`.
//!
//! Only the installed dynamic product selects this table: the static product
//! has no loader owner for the table's loader half.
//!
//! Output pointers are checked for null where the wire permits it; any other
//! pointer argument is caller-owned storage with its exact `crabc_core::runtime`
//! layout, valid and unaliased for the synchronous call, by the table contract
//! the facade upholds. The per-call SAFETY notes below cover only the ownership
//! boundaries beyond that contract.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crabc_core::runtime::{
    CFileHandleV1, LoaderAddressV1, LoaderImageV1, LoaderInformationV1, RuntimeV1, TextV1,
    ThreadDestructorV1, ThreadHandleV1, ThreadStartV1, CFILE_MODE_APPEND, CFILE_MODE_APPEND_UPDATE,
    CFILE_MODE_READ, CFILE_MODE_READ_UPDATE, CFILE_MODE_WRITE, CFILE_MODE_WRITE_UPDATE,
    CFILE_SEEK_CURRENT, CFILE_SEEK_END, CFILE_SEEK_START, TEXT_CAPACITY, THREAD_KEY_CAPACITY,
    V1_ABI_VERSION,
};

use super::errno::{get_errno, set_errno};
use super::fixed_graph_dlfcn::{
    invalid_handle, open_object, symbol_not_found, CancellationGuard, SYMBOL_INVALID_HANDLE,
};
use super::stdio_standard::StandardStream;

const EINVAL: c_int = 22;
const EAGAIN: c_int = 11;
const EIO: c_int = 5;
const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;
/// musl's `RTLD_NEXT`; the facade never forms it and the table rejects it
/// rather than resolving relative to this libc's own code address.
const RTLD_NEXT: usize = usize::MAX;
/// A consistent loaded-image copy normally succeeds on its first pass. A
/// runtime load published between two record copies restarts the pass.
const SNAPSHOT_ATTEMPTS: usize = 8;

extern "C" {
    fn __crabc_x86_64_runtime_symbol(handle: *mut c_void, name: *const u8, caller: usize, error: *mut c_int) -> *mut c_void;
    fn __crabc_x86_64_runtime_close(handle: *mut c_void) -> c_int;
    // These declarations repeat `general_dlfcn`'s untyped spellings; the
    // typed layouts below are projected at each call.
    fn __crabc_x86_64_runtime_address(address: usize, output: *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_information(handle: *mut c_void, output: *mut *mut c_void) -> c_int;
    fn __crabc_x86_64_runtime_iterate(callback: unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> c_int, data: *mut c_void) -> c_int;
}

// Both sides of this call are this crate's Rust `StandardStream`; the pointer
// never crosses a foreign layout boundary.
#[allow(improper_ctypes)]
unsafe extern "C" {
    // The fixed-buffer backend is private to the stream engine module; its
    // one C definition in this libc binds locally in the shared link. This
    // repeats `owned_usershell`'s declaration of the same symbol.
    fn fmemopen(buffer: *mut c_void, size: usize, mode: *const c_char) -> *mut StandardStream;
}

// Installed LP64 `<dlfcn.h>`/`<link.h>` layouts produced by the loader's
// private operations. Their strings and headers belong to retained mappings.
#[repr(C)]
struct DlInfo {
    file_name: *const c_char,
    file_base: *mut c_void,
    symbol_name: *const c_char,
    symbol_address: *mut c_void,
}

#[repr(C)]
struct LinkMap {
    address: usize,
    name: *const c_char,
    dynamic: *mut c_void,
    next: *mut LinkMap,
    previous: *mut LinkMap,
}

#[repr(C)]
struct DlPhdrInfo {
    address: usize,
    name: *const c_char,
    headers: *const c_void,
    count: u16,
    additions: u64,
    removals: u64,
    tls_module: usize,
    tls_data: *mut c_void,
}

/// Bounded copy of byte parts into one wire text value. A source longer than
/// the fixed capacity sets the v1 truncation bit.
struct TextWriter {
    text: TextV1,
    len: usize,
}

impl TextWriter {
    const fn new() -> Self {
        Self { text: TextV1::empty(), len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.len == TEXT_CAPACITY {
                self.text.flags = 1;
                return;
            }
            self.text.bytes[self.len] = byte;
            self.len += 1;
        }
    }

    /// # Safety
    /// Non-null `source` is a NUL-terminated string readable for at least
    /// `limit` bytes or up to its terminator.
    unsafe fn push_c_string(&mut self, source: *const c_char, limit: usize) {
        if source.is_null() {
            return;
        }
        for index in 0..limit {
            // SAFETY: the caller guarantees readability through the NUL.
            let byte = unsafe { *source.cast::<u8>().add(index) };
            if byte == 0 {
                return;
            }
            self.push(&[byte]);
            if self.text.flags != 0 {
                return;
            }
        }
    }

    fn finish(mut self) -> TextV1 {
        self.text.len = self.len as u16;
        self.text
    }
}

/// # Safety
/// Non-null `output` is writable caller-owned `TextV1` storage.
unsafe fn write_text(output: *mut TextV1, text: TextV1) {
    if !output.is_null() {
        // SAFETY: guaranteed by this helper's caller.
        unsafe { ptr::write(output, text) };
    }
}

/// # Safety
/// As for [`write_text`].
unsafe fn write_message(output: *mut TextV1, message: &[u8]) {
    let mut text = TextWriter::new();
    text.push(message);
    // SAFETY: forwarded caller contract.
    unsafe { write_text(output, text.finish()) };
}

/// # Safety
/// Non-null `source` is a NUL-terminated string with process lifetime: the
/// loader never unmaps or rewrites a published object's name.
unsafe fn copied_name(source: *const c_char) -> TextV1 {
    let mut text = TextWriter::new();
    // A name at least one byte longer than the wire capacity is truncated;
    // reading no further keeps the copy bounded.
    unsafe { text.push_c_string(source, TEXT_CAPACITY + 1) };
    text.finish()
}

unsafe extern "C" fn loader_open(
    path: *const c_char,
    flags: c_int,
    handle: *mut *mut c_void,
    error: *mut TextV1,
) -> c_int {
    unsafe { write_text(error, TextV1::empty()) };
    if handle.is_null() {
        unsafe { write_message(error, b"invalid loader handle output") };
        return -1;
    }
    unsafe { *handle = ptr::null_mut() };
    let _cancellation = unsafe { CancellationGuard::enter() };
    // SAFETY: a null path is the global-handle request; otherwise the facade
    // supplies a NUL-terminated `CStr`.
    match unsafe { open_object(path, flags) } {
        Ok(opened) => {
            unsafe { *handle = opened };
            0
        }
        Err(diagnostic) => {
            unsafe { write_message(error, diagnostic.as_bytes()) };
            -1
        }
    }
}

unsafe extern "C" fn loader_symbol(
    handle: *mut c_void,
    name: *const c_char,
    address: *mut *mut c_void,
    error: *mut TextV1,
) -> c_int {
    unsafe { write_text(error, TextV1::empty()) };
    if address.is_null() || name.is_null() {
        unsafe { write_message(error, b"invalid loader symbol request") };
        return -1;
    }
    unsafe { *address = ptr::null_mut() };
    // Null and RTLD_NEXT are pseudo-handles whose meaning depends on the C
    // caller; only a handle returned by loader_open is admitted here.
    if handle.is_null() || handle as usize == RTLD_NEXT {
        unsafe { write_message(error, invalid_handle(handle).as_bytes()) };
        return -1;
    }
    let mut code = 0;
    // SAFETY: the name is a NUL-terminated `CStr`; the loader validates the
    // handle by identity before any dereference.
    let resolved = unsafe { __crabc_x86_64_runtime_symbol(handle, name.cast(), 0, &mut code) };
    if code != 0 || resolved.is_null() {
        let diagnostic = if code == SYMBOL_INVALID_HANDLE { invalid_handle(handle) }
            else { unsafe { symbol_not_found(name) } };
        unsafe { write_message(error, diagnostic.as_bytes()) };
        return -1;
    }
    unsafe { *address = resolved };
    0
}

unsafe extern "C" fn loader_close(handle: *mut c_void, error: *mut TextV1) -> c_int {
    unsafe { write_text(error, TextV1::empty()) };
    // Musl retains the object on close; the loader validates the handle.
    if unsafe { __crabc_x86_64_runtime_close(handle) } != 0 {
        unsafe { write_message(error, invalid_handle(handle).as_bytes()) };
        return -1;
    }
    0
}

unsafe extern "C" fn loader_address(
    address: *const c_void,
    info: *mut LoaderAddressV1,
    error: *mut TextV1,
) -> c_int {
    unsafe { write_text(error, TextV1::empty()) };
    if address.is_null() || info.is_null() {
        unsafe { write_message(error, b"invalid loader address lookup") };
        return -1;
    }
    unsafe { ptr::write(info, LoaderAddressV1::empty()) };
    let mut raw = DlInfo {
        file_name: ptr::null(),
        file_base: ptr::null_mut(),
        symbol_name: ptr::null(),
        symbol_address: ptr::null_mut(),
    };
    if unsafe { __crabc_x86_64_runtime_address(address as usize, ptr::addr_of_mut!(raw).cast()) } == 0 {
        unsafe { write_message(error, b"loader address not found") };
        return -1;
    }
    // SAFETY: object and symbol names borrow retained mappings.
    let image_name = unsafe { copied_name(raw.file_name) };
    let symbol_name = unsafe { copied_name(raw.symbol_name) };
    unsafe {
        ptr::write(info, LoaderAddressV1 {
            image_base: raw.file_base,
            symbol_address: raw.symbol_address,
            image_name,
            symbol_name,
        })
    };
    0
}

/// Accumulates one iterate pass. `stable` becomes false when a runtime load
/// published between two record copies, which the next pass repeats.
struct SnapshotPass {
    records: *mut LoaderImageV1,
    capacity: usize,
    total: usize,
    additions: u64,
    removals: u64,
    stable: bool,
    malformed: bool,
}

/// Copies one borrowed record. It calls no application code and reads only
/// immutable published metadata plus the current thread's TLS address.
unsafe extern "C" fn copy_image(info: *mut c_void, size: usize, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the live pass owned by `loader_snapshot`, and the
    // loader passes one complete public `dl_phdr_info` for this callback.
    let pass = unsafe { &mut *data.cast::<SnapshotPass>() };
    if info.is_null() || size < core::mem::size_of::<DlPhdrInfo>() {
        pass.malformed = true;
        return 1;
    }
    let info = unsafe { &*info.cast::<DlPhdrInfo>() };
    if pass.total == 0 {
        pass.additions = info.additions;
        pass.removals = info.removals;
    } else if info.additions != pass.additions || info.removals != pass.removals {
        pass.stable = false;
        return 1;
    }
    if pass.total < pass.capacity {
        let record = LoaderImageV1 {
            image_base: info.address as *mut c_void,
            program_headers: info.headers,
            program_header_count: info.count,
            _reserved: 0,
            additions: info.additions,
            removals: info.removals,
            tls_module: info.tls_module,
            tls_data: info.tls_data,
            // SAFETY: published object names have process lifetime.
            image_name: unsafe { copied_name(info.name) },
        };
        unsafe { ptr::write(pass.records.add(pass.total), record) };
    }
    pass.total += 1;
    0
}

unsafe extern "C" fn loader_snapshot(
    records: *mut LoaderImageV1,
    capacity: usize,
    count: *mut usize,
    generation: *mut u64,
    error: *mut TextV1,
) -> c_int {
    unsafe { write_text(error, TextV1::empty()) };
    if count.is_null() || generation.is_null() || (capacity != 0 && records.is_null()) {
        unsafe { write_message(error, b"loader snapshot output is invalid") };
        return -1;
    }
    unsafe {
        *count = 0;
        *generation = 0;
    }
    for _ in 0..SNAPSHOT_ATTEMPTS {
        let mut pass = SnapshotPass {
            records,
            capacity,
            total: 0,
            additions: 0,
            removals: 0,
            stable: true,
            malformed: false,
        };
        // SAFETY: the callback only writes records below `capacity` and the
        // pass outlives this synchronous traversal.
        let _ = unsafe { __crabc_x86_64_runtime_iterate(copy_image, ptr::addr_of_mut!(pass).cast()) };
        if pass.malformed {
            unsafe { write_message(error, b"loader image record is malformed") };
            return -1;
        }
        if !pass.stable {
            continue;
        }
        unsafe { *generation = pass.additions.wrapping_add(pass.removals) };
        if pass.total > capacity {
            unsafe { write_message(error, b"loader snapshot capacity is too small") };
            return -1;
        }
        unsafe { *count = pass.total };
        return 0;
    }
    unsafe { write_message(error, b"loader snapshot changed during every copy") };
    -1
}

unsafe extern "C" fn loader_information(
    handle: *mut c_void,
    info: *mut LoaderInformationV1,
    error: *mut TextV1,
) -> c_int {
    unsafe { write_text(error, TextV1::empty()) };
    if info.is_null() {
        unsafe { write_message(error, b"loader information output is invalid") };
        return -1;
    }
    unsafe { ptr::write(info, LoaderInformationV1::empty()) };
    let mut link_map = ptr::null_mut::<c_void>();
    if unsafe { __crabc_x86_64_runtime_information(handle, &mut link_map) } != 0 || link_map.is_null() {
        unsafe { write_message(error, invalid_handle(handle).as_bytes()) };
        return -1;
    }
    // SAFETY: a validated handle's link-map address, name, and dynamic
    // fields are immutable after publication; only its links change.
    let link_map = link_map.cast::<LinkMap>();
    let (image_base, dynamic_address, name) =
        unsafe { ((*link_map).address, (*link_map).dynamic, (*link_map).name) };
    unsafe {
        ptr::write(info, LoaderInformationV1 {
            image_base: image_base as *mut c_void,
            dynamic_address,
            image_name: copied_name(name),
        })
    };
    0
}

unsafe extern "C" fn thread_create(
    start: ThreadStartV1,
    argument: *mut c_void,
    handle: *mut ThreadHandleV1,
) -> c_int {
    if handle.is_null() {
        return EINVAL;
    }
    let mut thread = ptr::null_mut();
    // SAFETY: the facade's unsafe spawn contract owns callback validity.
    let result = unsafe { super::pthread_create_join::pthread_create(&mut thread, ptr::null(), Some(start), argument) };
    if result != 0 {
        return result;
    }
    if thread.is_null() {
        return EAGAIN;
    }
    unsafe { *handle = thread as ThreadHandleV1 };
    0
}

unsafe extern "C" fn thread_join(handle: ThreadHandleV1, result: *mut *mut c_void) -> c_int {
    if handle == 0 {
        return EINVAL;
    }
    // SAFETY: the pthread owner admits only its own live joinable handles.
    unsafe { super::pthread_create_join::pthread_join(handle as usize as *mut c_void, result) }
}

unsafe extern "C" fn thread_detach(handle: ThreadHandleV1) -> c_int {
    if handle == 0 {
        return EINVAL;
    }
    // SAFETY: as for `thread_join`.
    unsafe { super::pthread_create_join::pthread_detach(handle as usize as *mut c_void) }
}

unsafe extern "C" fn thread_self(handle: *mut ThreadHandleV1) -> c_int {
    if handle.is_null() {
        return EINVAL;
    }
    let thread = super::pthread_identity::current_thread_pointer();
    if thread.is_null() {
        return EAGAIN;
    }
    unsafe { *handle = thread as usize as ThreadHandleV1 };
    0
}

unsafe extern "C" fn thread_cancel(handle: ThreadHandleV1) -> c_int {
    if handle == 0 {
        return EINVAL;
    }
    // SAFETY: the facade's unsafe cancel contract names a live runtime thread.
    unsafe { super::pthread_cancel::pthread_cancel(handle as usize as *mut c_void) }
}

unsafe extern "C" fn thread_setcancelstate(state: u32, old_state: *mut u32) -> c_int {
    // musl's internal masked state is not a facade value.
    if state > 1 {
        return EINVAL;
    }
    let mut previous = 0;
    let result = unsafe { super::pthread_cancel::pthread_setcancelstate(state as c_int, &mut previous) };
    if result == 0 && !old_state.is_null() {
        unsafe { *old_state = previous as u32 };
    }
    result
}

unsafe extern "C" fn thread_setcanceltype(cancel_type: u32, old_type: *mut u32) -> c_int {
    if cancel_type > 1 {
        return EINVAL;
    }
    let mut previous = 0;
    let result = unsafe { super::pthread_cancel::pthread_setcanceltype(cancel_type as c_int, &mut previous) };
    if result == 0 && !old_type.is_null() {
        unsafe { *old_type = previous as u32 };
    }
    result
}

unsafe extern "C" fn thread_testcancel() {
    // SAFETY: the facade's unsafe contract admits a cancellation point here.
    unsafe { super::pthread_cancel::pthread_testcancel() };
}

unsafe extern "C" fn thread_key_create(key: *mut u32, destructor: Option<ThreadDestructorV1>) -> c_int {
    if key.is_null() {
        return EINVAL;
    }
    let mut raw: c_uint = 0;
    let result = unsafe { super::pthread_tsd::pthread_key_create(&mut raw, destructor) };
    if result == 0 {
        unsafe { *key = raw };
    }
    result
}

unsafe extern "C" fn thread_key_delete(key: u32) -> c_int {
    if key >= THREAD_KEY_CAPACITY {
        return EINVAL;
    }
    unsafe { super::pthread_tsd::pthread_key_delete(key) }
}

unsafe extern "C" fn thread_getspecific(key: u32) -> *mut c_void {
    if key >= THREAD_KEY_CAPACITY {
        return ptr::null_mut();
    }
    unsafe { super::pthread_tsd::pthread_getspecific(key) }
}

unsafe extern "C" fn thread_setspecific(key: u32, value: *const c_void) -> c_int {
    if key >= THREAD_KEY_CAPACITY {
        return EINVAL;
    }
    unsafe { super::pthread_tsd::pthread_setspecific(key, value) }
}

/// Saves the caller's C `errno` for one stream operation, exposes the
/// operation's own failure as a positive status, and restores it on exit.
struct ErrnoScope(c_int);

impl ErrnoScope {
    fn enter() -> Self {
        // SAFETY: this libc owns the current thread's errno slot.
        let saved = unsafe { get_errno() };
        unsafe { set_errno(0) };
        Self(saved)
    }

    fn failure(&self) -> c_int {
        let current = unsafe { get_errno() };
        if (1..=4095).contains(&current) { current } else { EIO }
    }
}

impl Drop for ErrnoScope {
    fn drop(&mut self) {
        unsafe { set_errno(self.0) };
    }
}

fn stream(handle: CFileHandleV1) -> Result<*mut StandardStream, c_int> {
    if handle.is_null() { Err(EINVAL) } else { Ok(handle.cast()) }
}

unsafe extern "C" fn cfile_open_memory(
    buffer: *mut u8,
    length: usize,
    mode: u32,
    handle: *mut CFileHandleV1,
) -> c_int {
    if buffer.is_null() || handle.is_null() {
        return EINVAL;
    }
    let mode: &[u8] = match mode {
        CFILE_MODE_READ => b"r\0",
        CFILE_MODE_WRITE => b"w\0",
        CFILE_MODE_APPEND => b"a\0",
        CFILE_MODE_READ_UPDATE => b"r+\0",
        CFILE_MODE_WRITE_UPDATE => b"w+\0",
        CFILE_MODE_APPEND_UPDATE => b"a+\0",
        _ => return EINVAL,
    };
    let scope = ErrnoScope::enter();
    // SAFETY: the facade lends an exclusive buffer borrow for the stream's
    // lifetime; the mode is one static NUL-terminated spelling.
    let file = unsafe { fmemopen(buffer.cast(), length, mode.as_ptr().cast()) };
    if file.is_null() {
        return scope.failure();
    }
    unsafe { *handle = file.cast() };
    0
}

unsafe extern "C" fn cfile_read(handle: CFileHandleV1, buffer: *mut u8, length: usize, read: *mut usize) -> c_int {
    if read.is_null() || (length != 0 && buffer.is_null()) {
        return EINVAL;
    }
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    // SAFETY: a live facade handle and a writable destination range.
    let count = unsafe { super::stdio_standard::fread(buffer.cast(), 1, length, file) };
    unsafe { *read = count };
    if count < length && unsafe { super::stdio_standard::ferror(file) } != 0 {
        return scope.failure();
    }
    0
}

unsafe extern "C" fn cfile_write(handle: CFileHandleV1, buffer: *const u8, length: usize, written: *mut usize) -> c_int {
    if written.is_null() || (length != 0 && buffer.is_null()) {
        return EINVAL;
    }
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    // SAFETY: a live facade handle and a readable source range.
    let count = unsafe { super::stdio_standard::fwrite(buffer.cast(), 1, length, file) };
    unsafe { *written = count };
    if count < length && unsafe { super::stdio_standard::ferror(file) } != 0 {
        return scope.failure();
    }
    0
}

unsafe extern "C" fn cfile_flush(handle: CFileHandleV1) -> c_int {
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    if unsafe { super::stdio_standard::fflush(file) } == 0 { 0 } else { scope.failure() }
}

/// # Safety
/// `file` is a live facade stream and `position` is writable.
unsafe fn tell_into(file: *mut StandardStream, position: *mut u64, scope: &ErrnoScope) -> c_int {
    let current = unsafe { super::stdio_standard::__ftello(file) };
    if current < 0 {
        return scope.failure();
    }
    unsafe { *position = current as u64 };
    0
}

unsafe extern "C" fn cfile_seek(handle: CFileHandleV1, offset: i64, origin: u32, position: *mut u64) -> c_int {
    if position.is_null() {
        return EINVAL;
    }
    let whence = match origin {
        CFILE_SEEK_START => SEEK_SET,
        CFILE_SEEK_CURRENT => SEEK_CUR,
        CFILE_SEEK_END => SEEK_END,
        _ => return EINVAL,
    };
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    if unsafe { super::stdio_standard::__fseeko(file, offset, whence) } != 0 {
        return scope.failure();
    }
    unsafe { tell_into(file, position, &scope) }
}

unsafe extern "C" fn cfile_tell(handle: CFileHandleV1, position: *mut u64) -> c_int {
    if position.is_null() {
        return EINVAL;
    }
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    unsafe { tell_into(file, position, &scope) }
}

unsafe extern "C" fn cfile_eof(handle: CFileHandleV1, eof: *mut u8) -> c_int {
    if eof.is_null() {
        return EINVAL;
    }
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    unsafe { *eof = (super::stdio_standard::feof(file) != 0) as u8 };
    0
}

unsafe extern "C" fn cfile_error(handle: CFileHandleV1, error: *mut u8) -> c_int {
    if error.is_null() {
        return EINVAL;
    }
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    unsafe { *error = (super::stdio_standard::ferror(file) != 0) as u8 };
    0
}

unsafe extern "C" fn cfile_reset(handle: CFileHandleV1) -> c_int {
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    if unsafe { super::stdio_standard::__fseeko(file, 0, SEEK_SET) } != 0 {
        return scope.failure();
    }
    unsafe { super::stdio_standard::clearerr(file) };
    0
}

unsafe extern "C" fn cfile_close(handle: CFileHandleV1) -> c_int {
    let file = match stream(handle) { Ok(file) => file, Err(status) => return status };
    let scope = ErrnoScope::enter();
    // fclose releases the FILE on every result path; `file` is dead after it.
    if unsafe { super::stdio_standard::fclose(file) } == 0 { 0 } else { scope.failure() }
}

static RUNTIME_V1: RuntimeV1 = RuntimeV1 {
    abi_version: V1_ABI_VERSION,
    abi_size: core::mem::size_of::<RuntimeV1>() as u32,
    loader_open,
    loader_symbol,
    loader_close,
    loader_address,
    thread_create,
    thread_join,
    thread_detach,
    thread_self,
    thread_cancel,
    thread_setcancelstate,
    thread_setcanceltype,
    thread_testcancel,
    thread_key_create,
    thread_key_delete,
    thread_getspecific,
    thread_setspecific,
    cfile_open_memory,
    cfile_read,
    cfile_write,
    cfile_flush,
    cfile_seek,
    cfile_tell,
    cfile_eof,
    cfile_error,
    cfile_reset,
    cfile_close,
    loader_snapshot,
    loader_information,
};

/// Returns crabc's first private process-singleton runtime table.
///
/// The exported ELF name is intentionally absent from installed headers.
/// Native consumers check the version and size before use; the table is
/// immutable process-lifetime data owned by this shared libc.
#[no_mangle]
pub extern "C" fn __crabc_runtime_v1() -> *const RuntimeV1 {
    &raw const RUNTIME_V1
}
