#![cfg(feature = "runtime-stdio")]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crabc_core::runtime::{
    CFileHandleV1, LoaderAddressV1, LoaderImageV1, LoaderInformationV1, RuntimeV1, TextV1,
    ThreadDestructorV1,
    ThreadHandleV1, ThreadStartV1, CFILE_MODE_APPEND, CFILE_MODE_APPEND_UPDATE,
    CFILE_MODE_READ, CFILE_MODE_READ_UPDATE, CFILE_MODE_WRITE,
    CFILE_MODE_WRITE_UPDATE, V1_ABI_VERSION,
    V1_LEGACY_SIZE,
};
use crabc_rs::cfile::{CFile, FileMode, SeekFrom};
use crabc_rs::Errno;

static OPEN_MODE: AtomicU32 = AtomicU32::new(u32::MAX);
static CLOSES: AtomicUsize = AtomicUsize::new(0);
static READS: AtomicUsize = AtomicUsize::new(0);
static WRITES: AtomicUsize = AtomicUsize::new(0);
static POSITION: AtomicUsize = AtomicUsize::new(0);
static EOF: AtomicBool = AtomicBool::new(false);

const HANDLE: CFileHandleV1 = 1usize as *mut c_void;

unsafe extern "C" fn loader_open(
    _: *const c_char,
    _: c_int,
    _: *mut *mut c_void,
    _: *mut TextV1,
) -> c_int {
    22
}

unsafe extern "C" fn loader_symbol(
    _: *mut c_void,
    _: *const c_char,
    _: *mut *mut c_void,
    _: *mut TextV1,
) -> c_int {
    22
}

unsafe extern "C" fn loader_close(_: *mut c_void, _: *mut TextV1) -> c_int {
    22
}

unsafe extern "C" fn loader_address(
    _: *const c_void,
    _: *mut LoaderAddressV1,
    _: *mut TextV1,
) -> c_int {
    22
}

unsafe extern "C" fn loader_snapshot(
    _: *mut LoaderImageV1,
    _: usize,
    _: *mut usize,
    _: *mut u64,
    _: *mut TextV1,
) -> c_int {
    22
}

unsafe extern "C" fn loader_information(
    _: *mut c_void,
    _: *mut LoaderInformationV1,
    _: *mut TextV1,
) -> c_int {
    22
}

unsafe extern "C" fn thread_create(_: ThreadStartV1, _: *mut c_void, _: *mut ThreadHandleV1) -> c_int {
    22
}

unsafe extern "C" fn thread_join(_: ThreadHandleV1, _: *mut *mut c_void) -> c_int {
    22
}

unsafe extern "C" fn thread_detach(_: ThreadHandleV1) -> c_int {
    22
}

unsafe extern "C" fn thread_self(_: *mut ThreadHandleV1) -> c_int {
    22
}

unsafe extern "C" fn thread_cancel(_: ThreadHandleV1) -> c_int {
    22
}

unsafe extern "C" fn thread_setcancelstate(_: u32, _: *mut u32) -> c_int {
    22
}

unsafe extern "C" fn thread_setcanceltype(_: u32, _: *mut u32) -> c_int {
    22
}

unsafe extern "C" fn thread_testcancel() {}

unsafe extern "C" fn thread_key_create(_: *mut u32, _: Option<ThreadDestructorV1>) -> c_int {
    22
}

unsafe extern "C" fn thread_key_delete(_: u32) -> c_int {
    22
}

unsafe extern "C" fn thread_getspecific(_: u32) -> *mut c_void {
    core::ptr::null_mut()
}

unsafe extern "C" fn thread_setspecific(_: u32, _: *const c_void) -> c_int {
    22
}

unsafe extern "C" fn cfile_open_memory(
    _: *mut u8,
    _: usize,
    mode: u32,
    handle: *mut CFileHandleV1,
) -> c_int {
    OPEN_MODE.store(mode, Ordering::SeqCst);
    *handle = HANDLE;
    0
}

unsafe extern "C" fn cfile_read(
    handle: CFileHandleV1,
    buffer: *mut u8,
    length: usize,
    read: *mut usize,
) -> c_int {
    assert_eq!(handle, HANDLE);
    READS.fetch_add(1, Ordering::SeqCst);
    if length == 0 {
        *read = 0;
    } else {
        *buffer = b'R';
        *read = 1;
        EOF.store(true, Ordering::SeqCst);
    }
    0
}

unsafe extern "C" fn cfile_write(
    handle: CFileHandleV1,
    _: *const u8,
    length: usize,
    written: *mut usize,
) -> c_int {
    assert_eq!(handle, HANDLE);
    WRITES.fetch_add(1, Ordering::SeqCst);
    *written = length;
    0
}

unsafe extern "C" fn cfile_flush(handle: CFileHandleV1) -> c_int {
    assert_eq!(handle, HANDLE);
    0
}

unsafe extern "C" fn cfile_seek(
    handle: CFileHandleV1,
    offset: i64,
    origin: u32,
    position: *mut u64,
) -> c_int {
    assert_eq!(handle, HANDLE);
    let next = match origin {
        0 => offset,
        1 => POSITION.load(Ordering::SeqCst) as i64 + offset,
        2 => 8 + offset,
        _ => return 22,
    };
    if next < 0 {
        return 22;
    }
    POSITION.store(next as usize, Ordering::SeqCst);
    *position = next as u64;
    0
}

unsafe extern "C" fn cfile_tell(handle: CFileHandleV1, position: *mut u64) -> c_int {
    assert_eq!(handle, HANDLE);
    *position = POSITION.load(Ordering::SeqCst) as u64;
    0
}

unsafe extern "C" fn cfile_eof(handle: CFileHandleV1, eof: *mut u8) -> c_int {
    assert_eq!(handle, HANDLE);
    *eof = EOF.load(Ordering::SeqCst) as u8;
    0
}

unsafe extern "C" fn cfile_error(handle: CFileHandleV1, error: *mut u8) -> c_int {
    assert_eq!(handle, HANDLE);
    *error = 0;
    0
}

unsafe extern "C" fn cfile_reset(handle: CFileHandleV1) -> c_int {
    assert_eq!(handle, HANDLE);
    POSITION.store(0, Ordering::SeqCst);
    EOF.store(false, Ordering::SeqCst);
    0
}

unsafe extern "C" fn cfile_close(handle: CFileHandleV1) -> c_int {
    assert_eq!(handle, HANDLE);
    CLOSES.fetch_add(1, Ordering::SeqCst);
    0
}

fn runtime() -> RuntimeV1 {
    RuntimeV1 {
        abi_version: V1_ABI_VERSION,
        // Exercise append-only compatibility: CFile only needs the v1
        // prefix and must remain usable when introspection fields are absent.
        abi_size: V1_LEGACY_SIZE as u32,
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
    }
}

#[no_mangle]
extern "C" fn __crabc_runtime_v1() -> *const RuntimeV1 {
    static RUNTIME: std::sync::OnceLock<RuntimeV1> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(runtime)
}

#[test]
fn cfile_uses_the_private_runtime_for_lifetime_io_and_mode_contracts() {
    OPEN_MODE.store(u32::MAX, Ordering::SeqCst);
    CLOSES.store(0, Ordering::SeqCst);
    READS.store(0, Ordering::SeqCst);
    WRITES.store(0, Ordering::SeqCst);
    POSITION.store(0, Ordering::SeqCst);
    EOF.store(false, Ordering::SeqCst);

    let mut storage = [0u8; 16];
    let mut stream = CFile::from_memory(&mut storage, FileMode::ReadUpdate).expect("open update stream");
    assert_eq!(OPEN_MODE.load(Ordering::SeqCst), CFILE_MODE_READ_UPDATE);
    assert_eq!(stream.write(b"abc").expect("write"), 3);
    stream.flush().expect("flush");
    assert_eq!(stream.seek(SeekFrom::Start(2)).expect("seek from start"), 2);
    assert_eq!(stream.tell().expect("tell"), 2);
    let mut byte = [0; 1];
    assert_eq!(stream.read(&mut byte).expect("read"), 1);
    assert_eq!(byte, [b'R']);
    assert!(stream.eof().expect("EOF indicator"));
    assert!(!stream.error().expect("error indicator"));
    stream.reset().expect("reset");
    assert_eq!(stream.tell().expect("reset position"), 0);
    assert!(!stream.eof().expect("reset EOF indicator"));
    stream.close().expect("explicit close");
    assert_eq!(CLOSES.load(Ordering::SeqCst), 1, "explicit close consumes the handle once");

    let mut write_storage = [0u8; 4];
    let mut write_only = CFile::from_memory(&mut write_storage, FileMode::Write).expect("open write stream");
    assert_eq!(OPEN_MODE.load(Ordering::SeqCst), CFILE_MODE_WRITE);
    let reads = READS.load(Ordering::SeqCst);
    assert_eq!(write_only.read(&mut byte), Err(Errno::BADF));
    assert_eq!(READS.load(Ordering::SeqCst), reads, "wrong-direction read never reaches libc");
    drop(write_only);

    let mut read_storage = [0u8; 4];
    let mut read_only = CFile::from_memory(&mut read_storage, FileMode::Read).expect("open read stream");
    assert_eq!(OPEN_MODE.load(Ordering::SeqCst), CFILE_MODE_READ);
    let writes = WRITES.load(Ordering::SeqCst);
    assert_eq!(read_only.write(b"x"), Err(Errno::BADF));
    assert_eq!(WRITES.load(Ordering::SeqCst), writes, "wrong-direction write never reaches libc");
    drop(read_only);

    let mut append_storage = [0u8; 4];
    let append = CFile::from_memory(&mut append_storage, FileMode::Append).expect("open append stream");
    assert_eq!(OPEN_MODE.load(Ordering::SeqCst), CFILE_MODE_APPEND);
    drop(append);
    let mut write_update_storage = [0u8; 4];
    let write_update = CFile::from_memory(&mut write_update_storage, FileMode::WriteUpdate).expect("open write-update stream");
    assert_eq!(OPEN_MODE.load(Ordering::SeqCst), CFILE_MODE_WRITE_UPDATE);
    drop(write_update);
    let mut append_update_storage = [0u8; 4];
    let append_update = CFile::from_memory(&mut append_update_storage, FileMode::AppendUpdate).expect("open append-update stream");
    assert_eq!(OPEN_MODE.load(Ordering::SeqCst), CFILE_MODE_APPEND_UPDATE);
    drop(append_update);

    assert_eq!(CLOSES.load(Ordering::SeqCst), 6, "drop closes every remaining libc stream exactly once");
}

#[test]
fn std_io_adapters_preserve_the_no_std_cfile_contract() {
    use std::io::{Read, Seek, Write};

    let mut storage = [0u8; 8];
    let mut stream = CFile::from_memory(&mut storage, FileMode::ReadUpdate).expect("open update stream");
    stream.write_all(b"std").expect("std write");
    assert_eq!(Seek::seek(&mut stream, std::io::SeekFrom::End(-2)).expect("std seek"), 6);
    let mut byte = [0; 1];
    assert_eq!(Read::read(&mut stream, &mut byte).expect("std read"), 1);
    Write::flush(&mut stream).expect("std flush");
}
