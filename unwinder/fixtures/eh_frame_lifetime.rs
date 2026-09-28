//! EH-frame bytes removed after the discovery callback must not fault a later read.
use std::ffi::c_void;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[repr(C)]
struct Phdr {
    kind: u32, flags: u32, offset: u64, address: u64, physical: u64,
    file_size: u64, memory_size: u64, alignment: u64,
}

#[repr(C)]
struct Info {
    address: usize, name: *const u8, headers: *const Phdr, count: u16,
}

#[repr(C)]
struct UnwindException {
    exception_class: u64,
    exception_cleanup: Option<unsafe extern "C" fn(i32, *mut UnwindException)>,
    private: [usize; 8],
}

const PAGE: usize = 4096;
const HEADER: usize = 64;
const EH_FRAME: usize = 256;
const TEXT_SPAN: usize = 65536;
const END_OF_STACK: i32 = 5;
const FATAL_PHASE1_ERROR: i32 = 3;

static MAPPING: AtomicUsize = AtomicUsize::new(0);
static TEXT: AtomicUsize = AtomicUsize::new(0);
static REMOVE_AFTER_CALLBACK: AtomicBool = AtomicBool::new(false);
static HEADER_SIZE: AtomicUsize = AtomicUsize::new(12);
static LOAD_SIZE: AtomicUsize = AtomicUsize::new(PAGE);
static MAPPING_SIZE: AtomicUsize = AtomicUsize::new(PAGE);

unsafe extern "C" {
    fn mmap(address: *mut c_void, size: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    fn munmap(address: *mut c_void, size: usize) -> i32;
    fn mprotect(address: *mut c_void, size: usize, protection: i32) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

unsafe extern "C-unwind" {
    fn _Unwind_RaiseException(exception: *mut UnwindException) -> i32;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dl_iterate_phdr(
    callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> i32,
    data: *mut c_void,
) -> i32 {
    let base = MAPPING.load(Ordering::SeqCst);
    let text = TEXT.load(Ordering::SeqCst);
    let headers = [
        Phdr { kind: 1, flags: 4, offset: 0, address: base as u64, physical: 0, file_size: LOAD_SIZE.load(Ordering::SeqCst) as u64, memory_size: LOAD_SIZE.load(Ordering::SeqCst) as u64, alignment: PAGE as u64 },
        Phdr { kind: 1, flags: 5, offset: 0, address: text as u64, physical: 0, file_size: TEXT_SPAN as u64, memory_size: TEXT_SPAN as u64, alignment: PAGE as u64 },
        Phdr { kind: 0x6474e550, flags: 4, offset: HEADER as u64, address: (base + HEADER) as u64, physical: 0, file_size: HEADER_SIZE.load(Ordering::SeqCst) as u64, memory_size: HEADER_SIZE.load(Ordering::SeqCst) as u64, alignment: 4 },
    ];
    let mut info = Info { address: 0, name: c"fixture".as_ptr().cast(), headers: headers.as_ptr(), count: 3 };
    let result = unsafe { callback(&mut info, std::mem::size_of::<Info>(), data) };
    if REMOVE_AFTER_CALLBACK.swap(false, Ordering::SeqCst) {
        assert_eq!(unsafe { munmap(base as *mut c_void, MAPPING_SIZE.load(Ordering::SeqCst)) }, 0);
    }
    result
}

unsafe fn write_frame(base: *mut u8, text: usize, extra_nops: usize) {
    let header = unsafe { base.add(HEADER) };
    unsafe {
        header.write(1);
        header.add(1).write(0);
        header.add(2).write(0xff);
        header.add(3).write(0xff);
        (header.add(4) as *mut u64).write_unaligned((base as usize + EH_FRAME) as u64);
    }
    // CFA is RSP+8 and RIP is undefined, so a readable frame ends the stack.
    let cie = [0, 0, 0, 0, 1, 0, 1, 0x78, 16, 0x0c, 7, 8, 0x07, 16];
    let mut frame = (cie.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&cie);
    let fde_start = frame.len();
    frame.extend_from_slice(&(20u32 + extra_nops as u32).to_le_bytes());
    frame.extend_from_slice(&((fde_start + 4) as u32).to_le_bytes());
    frame.extend_from_slice(&(text as u64).to_le_bytes());
    frame.extend_from_slice(&(TEXT_SPAN as u64).to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend(std::iter::repeat_n(0u8, extra_nops));
    unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), base.add(EH_FRAME), frame.len()); }
}

unsafe fn run_child(mode: usize) -> i32 {
    unsafe {
        let length = if mode == 4 { 2 * PAGE } else if mode == 5 { 4 * PAGE } else { PAGE };
        let base = mmap(std::ptr::null_mut(), length, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(base as usize, usize::MAX);
        let text = (_Unwind_RaiseException as usize) & !(PAGE - 1);
        write_frame(base, text, if mode == 5 { 8192 } else { 0 });
        MAPPING.store(base as usize, Ordering::SeqCst);
        TEXT.store(text, Ordering::SeqCst);
        REMOVE_AFTER_CALLBACK.store(mode == 1, Ordering::SeqCst);
        MAPPING_SIZE.store(length, Ordering::SeqCst);
        HEADER_SIZE.store(if mode == 3 { 2 * 1024 * 1024 } else { 12 }, Ordering::SeqCst);
        LOAD_SIZE.store(if mode == 3 { 2 * 1024 * 1024 + HEADER } else { length }, Ordering::SeqCst);
        if mode == 2 { assert_eq!(mprotect(base.cast(), PAGE, 0), 0); }
        if mode == 4 { assert_eq!(mprotect(base.add(PAGE).cast(), PAGE, 0), 0); }
        let mut exception = UnwindException { exception_class: 0, exception_cleanup: None, private: [0; 8] };
        let result = _Unwind_RaiseException(&mut exception);
        if mode != 1 { assert_eq!(munmap(base.cast(), length), 0); }
        result
    }
}

fn child_case(label: &str, mode: usize, expected: i32) {
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let result = unsafe { run_child(mode) };
        println!("{label} unwind={result}");
        std::io::stdout().flush().unwrap();
        std::process::exit(if result == expected { 0 } else { 1 });
    }
    let mut status = -1;
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    println!("{label} wait={status}");
    if status != 0 { std::process::exit(1); }
}

fn main() {
    child_case("mapped", 0, END_OF_STACK);
    child_case("unmapped", 1, FATAL_PHASE1_ERROR);
    child_case("unreadable", 2, FATAL_PHASE1_ERROR);
    child_case("oversized", 3, FATAL_PHASE1_ERROR);
    child_case("truncated", 4, FATAL_PHASE1_ERROR);
    child_case("long-fde", 5, END_OF_STACK);
    println!("EH frame lifetime guarded");
}
