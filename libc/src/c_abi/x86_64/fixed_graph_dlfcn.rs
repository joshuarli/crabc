//! Public C dlfcn bridge for the bounded x86 loader graph.
//!
//! The interpreter remains the sole owner of object identities, symbol
//! lookup, reference counts, and post-relocation metadata. This archive leaf
//! imports only its exact weak `RuntimeV1` loader prefix. It deliberately does
//! not fall back to an ambient loader when that record is absent or malformed.
//!
//! The graph has no loader TLS. C `dlerror` and the borrowed names
//! returned by `dladdr` therefore live in a 32-entry process table keyed by
//! Linux TID. Dead entries are reclaimed lazily with `tgkill(pid, tid, 0)`.
//! Calls from more than 32 simultaneously live threads fail closed with a
//! stable exhaustion diagnostic. The loader may append one contract-bounded
//! no-TLS DSO. Its sibling may `RTLD_NOLOAD`-acquire that identity and accept
//! `RTLD_NODELETE` only there, where process-lifetime mapping makes it a
//! lifecycle-neutral compatibility flag; copied snapshots carry a runtime
//! count and generation. This diagnostic bound, RTLD_NEXT, general filesystem search/graph mutation,
//! global promotion, finalization, and unload remain explicit reasons this
//! staged leaf does not select the public dlfcn capabilities.

use core::ffi::{c_char, c_int, c_void};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use super::raw_syscall;

const RECORD_MAGIC: u64 = 0x4352_4142_435f_5844;
const RECORD_VERSION: u32 = 1;
const RECORD_SIZE: u32 = 64;
const TEXT_CAPACITY: usize = 256;
const IMAGE_CAPACITY: usize = 4;
const DIAGNOSTIC_SLOT_COUNT: usize = 32;
const C_TEXT_CAPACITY: usize = TEXT_CAPACITY + 1;
const RTLD_NOW: c_int = 2;
const RTLD_NEXT_BITS: usize = usize::MAX;
const RTLD_DI_LINKMAP: c_int = 2;
const SYS_GETPID: i64 = 39;
const SYS_GETTID: i64 = 186;
const SYS_TGKILL: i64 = 234;
const ESRCH: i64 = 3;

const UNAVAILABLE: &[u8] = b"crabc fixed-graph loader runtime unavailable";
const NEXT_UNSUPPORTED: &[u8] = b"crabc fixed graph does not support RTLD_NEXT";
static EXHAUSTED: &[u8] = b"crabc dlfcn diagnostic slots exhausted\0";

#[repr(C)]
struct RuntimeRecordV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    open: *const c_void,
    symbol: *const c_void,
    close: *const c_void,
    address: *const c_void,
    snapshot: *const c_void,
    information: *const c_void,
}

unsafe impl Sync for RuntimeRecordV1 {}

core::arch::global_asm!(
    ".weak __crabc_x86_64_fixed_graph_dlfcn_v1",
    ".hidden __crabc_x86_fixed_graph_dlfcn_record",
    ".global __crabc_x86_fixed_graph_dlfcn_record",
    ".type __crabc_x86_fixed_graph_dlfcn_record,@function",
    "__crabc_x86_fixed_graph_dlfcn_record:",
    "mov rax, qword ptr [rip + __crabc_x86_64_fixed_graph_dlfcn_v1@GOTPCREL]",
    "ret",
    ".size __crabc_x86_fixed_graph_dlfcn_record, .-__crabc_x86_fixed_graph_dlfcn_record",
);

extern "C" {
    fn __crabc_x86_fixed_graph_dlfcn_record() -> *const RuntimeRecordV1;
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TextV1 {
    len: u16,
    flags: u16,
    bytes: [u8; TEXT_CAPACITY],
}

const EMPTY_TEXT: TextV1 = TextV1 {
    len: 0,
    flags: 0,
    bytes: [0; TEXT_CAPACITY],
};

#[repr(C)]
#[derive(Copy, Clone)]
struct ImageV1 {
    image_base: *mut c_void,
    program_headers: *const c_void,
    program_header_count: u16,
    reserved: u16,
    additions: u64,
    removals: u64,
    tls_module: usize,
    tls_data: *mut c_void,
    image_name: TextV1,
}

const EMPTY_IMAGE: ImageV1 = ImageV1 {
    image_base: ptr::null_mut(),
    program_headers: ptr::null(),
    program_header_count: 0,
    reserved: 0,
    additions: 0,
    removals: 0,
    tls_module: 0,
    tls_data: ptr::null_mut(),
    image_name: EMPTY_TEXT,
};

#[repr(C)]
struct AddressV1 {
    image_base: *mut c_void,
    symbol_address: *mut c_void,
    image_name: TextV1,
    symbol_name: TextV1,
}

#[repr(C)]
struct InformationV1 {
    image_base: *mut c_void,
    dynamic_address: *mut c_void,
    image_name: TextV1,
}

type OpenFn = unsafe extern "C" fn(
    *const u8,
    c_int,
    *mut *mut c_void,
    *mut TextV1,
) -> c_int;
type SymbolFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    *mut *mut c_void,
    *mut TextV1,
) -> c_int;
type CloseFn = unsafe extern "C" fn(*mut c_void, *mut TextV1) -> c_int;
type AddressFn =
    unsafe extern "C" fn(*const c_void, *mut AddressV1, *mut TextV1) -> c_int;
type SnapshotFn = unsafe extern "C" fn(
    *mut ImageV1,
    usize,
    *mut usize,
    *mut u64,
    *mut TextV1,
) -> c_int;
type InformationFn = unsafe extern "C" fn(
    *mut c_void,
    *mut InformationV1,
    *mut TextV1,
) -> c_int;

#[repr(C)]
pub struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

#[repr(C)]
pub struct DlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const c_char,
    dlpi_phdr: *const c_void,
    dlpi_phnum: u16,
    dlpi_adds: u64,
    dlpi_subs: u64,
    dlpi_tls_modid: usize,
    dlpi_tls_data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct LinkMap {
    l_addr: usize,
    l_name: *mut c_char,
    l_ld: *mut c_void,
    l_next: *mut LinkMap,
    l_prev: *mut LinkMap,
}

const EMPTY_LINK_MAP: LinkMap = LinkMap {
    l_addr: 0,
    l_name: ptr::null_mut(),
    l_ld: ptr::null_mut(),
    l_next: ptr::null_mut(),
    l_prev: ptr::null_mut(),
};

struct DiagnosticSlot {
    tid: i32,
    error_pending: bool,
    error: [u8; C_TEXT_CAPACITY],
    image_name: [u8; C_TEXT_CAPACITY],
    symbol_name: [u8; C_TEXT_CAPACITY],
}

const EMPTY_DIAGNOSTIC_SLOT: DiagnosticSlot = DiagnosticSlot {
    tid: 0,
    error_pending: false,
    error: [0; C_TEXT_CAPACITY],
    image_name: [0; C_TEXT_CAPACITY],
    symbol_name: [0; C_TEXT_CAPACITY],
};

static DLFCN_STATE_LOCK: AtomicBool = AtomicBool::new(false);
static mut DIAGNOSTIC_SLOTS: [DiagnosticSlot; DIAGNOSTIC_SLOT_COUNT] =
    [const { EMPTY_DIAGNOSTIC_SLOT }; DIAGNOSTIC_SLOT_COUNT];
static mut LINK_MAPS: [LinkMap; IMAGE_CAPACITY] = [EMPTY_LINK_MAP; IMAGE_CAPACITY];
static mut LINK_MAP_NAMES: [[u8; C_TEXT_CAPACITY]; IMAGE_CAPACITY] =
    [[0; C_TEXT_CAPACITY]; IMAGE_CAPACITY];

struct StateGuard;

impl StateGuard {
    fn lock() -> Self {
        while DLFCN_STATE_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        DLFCN_STATE_LOCK.store(false, Ordering::Release);
    }
}

unsafe fn runtime_record() -> Option<&'static RuntimeRecordV1> {
    let record = __crabc_x86_fixed_graph_dlfcn_record();
    if record.is_null() {
        return None;
    }
    let record = &*record;
    if record.magic != RECORD_MAGIC
        || record.version != RECORD_VERSION
        || record.abi_size != RECORD_SIZE
        || record.open.is_null()
        || record.symbol.is_null()
        || record.close.is_null()
        || record.address.is_null()
        || record.snapshot.is_null()
        || record.information.is_null()
    {
        None
    } else {
        Some(record)
    }
}

unsafe fn linux_tid() -> i32 {
    raw_syscall::syscall0(SYS_GETTID) as i32
}

unsafe fn linux_pid() -> i32 {
    raw_syscall::syscall0(SYS_GETPID) as i32
}

unsafe fn tid_is_dead(pid: i32, tid: i32) -> bool {
    raw_syscall::syscall3(SYS_TGKILL, pid as i64, tid as i64, 0) == -ESRCH
}

unsafe fn diagnostic_slot() -> Option<usize> {
    let tid = linux_tid();
    let pid = linux_pid();
    let _guard = StateGuard::lock();
    for index in 0..DIAGNOSTIC_SLOT_COUNT {
        if DIAGNOSTIC_SLOTS[index].tid == tid {
            return Some(index);
        }
    }
    let mut available = None;
    for index in 0..DIAGNOSTIC_SLOT_COUNT {
        let owner = DIAGNOSTIC_SLOTS[index].tid;
        if owner == 0 || tid_is_dead(pid, owner) {
            available = Some(index);
            break;
        }
    }
    let index = available?;
    DIAGNOSTIC_SLOTS[index] = EMPTY_DIAGNOSTIC_SLOT;
    DIAGNOSTIC_SLOTS[index].tid = tid;
    Some(index)
}

unsafe fn copy_bytes_to_c(destination: *mut u8, source: &[u8]) {
    let length = core::cmp::min(source.len(), TEXT_CAPACITY);
    ptr::copy_nonoverlapping(source.as_ptr(), destination, length);
    *destination.add(length) = 0;
}

unsafe fn copy_text_to_c(destination: *mut u8, source: &TextV1) {
    let length = core::cmp::min(source.len as usize, TEXT_CAPACITY);
    copy_bytes_to_c(destination, &source.bytes[..length]);
}

unsafe fn set_error_bytes(slot: usize, message: &[u8]) {
    let _guard = StateGuard::lock();
    let storage = &mut DIAGNOSTIC_SLOTS[slot];
    copy_bytes_to_c(storage.error.as_mut_ptr(), message);
    storage.error_pending = true;
}

unsafe fn set_error_text(slot: usize, message: &TextV1) {
    let length = core::cmp::min(message.len as usize, TEXT_CAPACITY);
    set_error_bytes(slot, &message.bytes[..length]);
}

unsafe fn unavailable(slot: usize) {
    set_error_bytes(slot, UNAVAILABLE);
}

unsafe fn open_fn(record: &RuntimeRecordV1) -> OpenFn {
    mem::transmute(record.open)
}

unsafe fn symbol_fn(record: &RuntimeRecordV1) -> SymbolFn {
    mem::transmute(record.symbol)
}

unsafe fn close_fn(record: &RuntimeRecordV1) -> CloseFn {
    mem::transmute(record.close)
}

unsafe fn address_fn(record: &RuntimeRecordV1) -> AddressFn {
    mem::transmute(record.address)
}

unsafe fn snapshot_fn(record: &RuntimeRecordV1) -> SnapshotFn {
    mem::transmute(record.snapshot)
}

unsafe fn information_fn(record: &RuntimeRecordV1) -> InformationFn {
    mem::transmute(record.information)
}

/// Invoke the loader-owned retained-object open operation.
///
/// # Safety
///
/// `filename`, when non-null, must point to a readable NUL-terminated C
/// string. The loader's fixed 256-byte name bound still applies.
#[no_mangle]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    let Some(slot) = diagnostic_slot() else {
        return ptr::null_mut();
    };
    let Some(record) = runtime_record() else {
        unavailable(slot);
        return ptr::null_mut();
    };
    let mut handle = ptr::null_mut();
    let mut error = EMPTY_TEXT;
    if open_fn(record)(filename.cast(), flags, &mut handle, &mut error) != 0 {
        set_error_text(slot, &error);
        ptr::null_mut()
    } else {
        handle
    }
}

/// Resolve an ordinary symbol in the retained fixed scope represented by
/// `handle`; null is the public `RTLD_DEFAULT` spelling.
///
/// # Safety
///
/// `symbol` must point to a readable NUL-terminated C string, and non-special
/// handles must have been returned by this bridge and remain open.
#[no_mangle]
pub unsafe extern "C" fn dlsym(
    mut handle: *mut c_void,
    symbol: *const c_char,
) -> *mut c_void {
    let Some(slot) = diagnostic_slot() else {
        return ptr::null_mut();
    };
    let Some(record) = runtime_record() else {
        unavailable(slot);
        return ptr::null_mut();
    };
    if handle as usize == RTLD_NEXT_BITS {
        set_error_bytes(slot, NEXT_UNSUPPORTED);
        return ptr::null_mut();
    }
    let mut error = EMPTY_TEXT;
    if handle.is_null() {
        if open_fn(record)(ptr::null(), RTLD_NOW, &mut handle, &mut error) != 0 {
            set_error_text(slot, &error);
            return ptr::null_mut();
        }
    }
    let mut address = ptr::null_mut();
    if symbol_fn(record)(handle, symbol.cast(), &mut address, &mut error) != 0 {
        set_error_text(slot, &error);
        ptr::null_mut()
    } else {
        address
    }
}

/// Release one explicit retained-object acquisition.
///
/// # Safety
///
/// `handle` must be a live loader-owned handle returned by `dlopen`.
#[no_mangle]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let Some(slot) = diagnostic_slot() else {
        return -1;
    };
    let Some(record) = runtime_record() else {
        unavailable(slot);
        return -1;
    };
    let mut error = EMPTY_TEXT;
    let result = close_fn(record)(handle, &mut error);
    if result != 0 {
        set_error_text(slot, &error);
    }
    result
}

/// Consume the calling Linux thread's pending dlfcn diagnostic once.
///
/// # Safety
///
/// The returned pointer is borrowed until the calling thread's next dlfcn
/// operation. The bounded-table exhaustion pointer is immutable process data.
#[no_mangle]
pub unsafe extern "C" fn dlerror() -> *mut c_char {
    let Some(slot) = diagnostic_slot() else {
        return EXHAUSTED.as_ptr() as *mut c_char;
    };
    let _guard = StateGuard::lock();
    let storage = &mut DIAGNOSTIC_SLOTS[slot];
    if !storage.error_pending {
        return ptr::null_mut();
    }
    storage.error_pending = false;
    storage.error.as_mut_ptr().cast()
}

/// Return copied loader address metadata through the public borrowed C view.
///
/// # Safety
///
/// `information` must point to writable `Dl_info` storage. Returned names are
/// borrowed until this thread's next dlfcn operation.
#[no_mangle]
pub unsafe extern "C" fn dladdr(address: *const c_void, information: *mut DlInfo) -> c_int {
    if information.is_null() {
        return 0;
    }
    ptr::write(
        information,
        DlInfo {
            dli_fname: ptr::null(),
            dli_fbase: ptr::null_mut(),
            dli_sname: ptr::null(),
            dli_saddr: ptr::null_mut(),
        },
    );
    let Some(slot) = diagnostic_slot() else {
        return 0;
    };
    let Some(record) = runtime_record() else {
        unavailable(slot);
        return 0;
    };
    let mut found = AddressV1 {
        image_base: ptr::null_mut(),
        symbol_address: ptr::null_mut(),
        image_name: EMPTY_TEXT,
        symbol_name: EMPTY_TEXT,
    };
    let mut error = EMPTY_TEXT;
    if address_fn(record)(address, &mut found, &mut error) != 0 {
        return 0;
    }
    let _guard = StateGuard::lock();
    let storage = &mut DIAGNOSTIC_SLOTS[slot];
    copy_text_to_c(storage.image_name.as_mut_ptr(), &found.image_name);
    copy_text_to_c(storage.symbol_name.as_mut_ptr(), &found.symbol_name);
    (*information).dli_fname = storage.image_name.as_ptr().cast();
    (*information).dli_fbase = found.image_base;
    // A containing object with no finite dynamic symbol is a successful
    // musl-shaped `dladdr` result, but its two symbol fields are null rather
    // than borrowed pointers to an empty string.  The loader owns that
    // distinction in `symbol_address`; preserve it across this copied C view.
    if found.symbol_address.is_null() {
        (*information).dli_sname = ptr::null();
        (*information).dli_saddr = ptr::null_mut();
    } else {
        (*information).dli_sname = storage.symbol_name.as_ptr().cast();
        (*information).dli_saddr = found.symbol_address;
    }
    1
}

unsafe fn snapshot(
    record: &RuntimeRecordV1,
    images: &mut [ImageV1; IMAGE_CAPACITY],
) -> Option<(usize, u64)> {
    let mut count = 0usize;
    let mut generation = 0u64;
    let mut error = EMPTY_TEXT;
    if snapshot_fn(record)(
        images.as_mut_ptr(),
        images.len(),
        &mut count,
        &mut generation,
        &mut error,
    ) != 0
        || count == 0
        || count > IMAGE_CAPACITY
    {
        None
    } else {
        Some((count, generation))
    }
}

unsafe fn publish_link_maps(record: &RuntimeRecordV1) -> Option<usize> {
    let mut images = [EMPTY_IMAGE; IMAGE_CAPACITY];
    let (count, _) = snapshot(record, &mut images)?;
    let mut dynamic_addresses = [ptr::null_mut(); IMAGE_CAPACITY];
    let mut open_name = [0u8; C_TEXT_CAPACITY];
    for index in 0..count {
        let path = if index == 0 {
            ptr::null()
        } else {
            copy_text_to_c(open_name.as_mut_ptr(), &images[index].image_name);
            open_name.as_ptr()
        };
        let mut handle = ptr::null_mut();
        let mut error = EMPTY_TEXT;
        if open_fn(record)(path, RTLD_NOW, &mut handle, &mut error) != 0 {
            return None;
        }
        let mut information = InformationV1 {
            image_base: ptr::null_mut(),
            dynamic_address: ptr::null_mut(),
            image_name: EMPTY_TEXT,
        };
        let information_status =
            information_fn(record)(handle, &mut information, &mut error);
        let close_status = if index == 0 {
            0
        } else {
            close_fn(record)(handle, &mut error)
        };
        if information_status != 0
            || close_status != 0
            || information.image_base != images[index].image_base
            || information.dynamic_address.is_null()
        {
            return None;
        }
        dynamic_addresses[index] = information.dynamic_address;
    }
    let _guard = StateGuard::lock();
    for index in 0..count {
        copy_text_to_c(LINK_MAP_NAMES[index].as_mut_ptr(), &images[index].image_name);
    }
    for index in 0..count {
        LINK_MAPS[index] = LinkMap {
            l_addr: images[index].image_base as usize,
            l_name: LINK_MAP_NAMES[index].as_mut_ptr().cast(),
            l_ld: dynamic_addresses[index],
            l_next: if index + 1 < count {
                ptr::addr_of_mut!(LINK_MAPS[index + 1])
            } else {
                ptr::null_mut()
            },
            l_prev: if index == 0 {
                ptr::null_mut()
            } else {
                ptr::addr_of_mut!(LINK_MAPS[index - 1])
            },
        };
    }
    for index in count..IMAGE_CAPACITY {
        LINK_MAPS[index] = EMPTY_LINK_MAP;
        LINK_MAP_NAMES[index] = [0; C_TEXT_CAPACITY];
    }
    Some(count)
}

/// Implement the useful musl `RTLD_DI_LINKMAP` request for a live handle.
///
/// # Safety
///
/// `argument` must point to writable `struct link_map *` storage when
/// `request` is `RTLD_DI_LINKMAP`; `handle` must remain live.
#[no_mangle]
pub unsafe extern "C" fn dlinfo(
    handle: *mut c_void,
    request: c_int,
    argument: *mut c_void,
) -> c_int {
    if request != RTLD_DI_LINKMAP || argument.is_null() {
        return -1;
    }
    let Some(slot) = diagnostic_slot() else {
        return -1;
    };
    let Some(record) = runtime_record() else {
        unavailable(slot);
        return -1;
    };
    let mut information = InformationV1 {
        image_base: ptr::null_mut(),
        dynamic_address: ptr::null_mut(),
        image_name: EMPTY_TEXT,
    };
    let mut error = EMPTY_TEXT;
    if information_fn(record)(handle, &mut information, &mut error) != 0 {
        return -1;
    }
    let Some(count) = publish_link_maps(record) else { return -1; };
    let _guard = StateGuard::lock();
    for index in 0..count {
        if LINK_MAPS[index].l_addr == information.image_base as usize {
            *(argument as *mut *mut LinkMap) = ptr::addr_of_mut!(LINK_MAPS[index]);
            return 0;
        }
    }
    -1
}

/// Visit one copied snapshot of the loader graph.
///
/// # Safety
///
/// `callback`, when present, must obey the C `dl_iterate_phdr` callback
/// contract for each invocation and `data` must satisfy that callback.
#[no_mangle]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let Some(callback) = callback else {
        return 0;
    };
    let Some(record) = runtime_record() else {
        return -1;
    };
    let mut images = [EMPTY_IMAGE; IMAGE_CAPACITY];
    let Some((count, _)) = snapshot(record, &mut images) else { return -1; };
    let mut names = [[0u8; C_TEXT_CAPACITY]; IMAGE_CAPACITY];
    for index in 0..count {
        copy_text_to_c(names[index].as_mut_ptr(), &images[index].image_name);
    }
    for index in 0..count {
        let image = &images[index];
        let mut public = DlPhdrInfo {
            dlpi_addr: image.image_base as usize,
            dlpi_name: names[index].as_ptr().cast(),
            dlpi_phdr: image.program_headers,
            dlpi_phnum: image.program_header_count,
            dlpi_adds: image.additions,
            dlpi_subs: image.removals,
            dlpi_tls_modid: image.tls_module,
            dlpi_tls_data: image.tls_data,
        };
        let result = callback(
            &mut public,
            mem::size_of::<DlPhdrInfo>(),
            data,
        );
        if result != 0 {
            return result;
        }
    }
    0
}

const _: () = assert!(mem::size_of::<RuntimeRecordV1>() == RECORD_SIZE as usize);
const _: () = assert!(mem::size_of::<TextV1>() == 260);
const _: () = assert!(mem::size_of::<ImageV1>() == 320);
const _: () = assert!(mem::size_of::<AddressV1>() == 536);
const _: () = assert!(mem::size_of::<InformationV1>() == 280);
const _: () = assert!(mem::size_of::<DlInfo>() == 32);
const _: () = assert!(mem::size_of::<DlPhdrInfo>() == 64);
const _: () = assert!(mem::size_of::<LinkMap>() == 40);
