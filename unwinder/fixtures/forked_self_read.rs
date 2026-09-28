//! A denied self-memory read must fail the unwind phase after fork without a fault.
use std::ffi::c_void;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

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

#[repr(C)]
struct Iovec { base: *mut c_void, len: usize }

#[repr(C)]
struct Filter { code: u16, jt: u8, jf: u8, value: u32 }

#[repr(C)]
struct FilterProgram { len: u16, filter: *const Filter }

const PAGE: usize = 4096;
const HEADER: usize = 64;
const EH_FRAME: usize = 256;
const TEXT_SPAN: usize = 65536;
const END_OF_STACK: i32 = 5;
const FATAL_PHASE1_ERROR: i32 = 3;
const PROCESS_VM_READV: u32 = 310;

static MAPPING: AtomicUsize = AtomicUsize::new(0);
static TEXT: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
unsafe extern "C" fn dl_iterate_phdr(
    callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> i32,
    data: *mut c_void,
) -> i32 {
    let base = MAPPING.load(Ordering::SeqCst);
    let text = TEXT.load(Ordering::SeqCst);
    let headers = [
        Phdr { kind: 1, flags: 4, offset: 0, address: base as u64, physical: 0, file_size: PAGE as u64, memory_size: PAGE as u64, alignment: PAGE as u64 },
        Phdr { kind: 1, flags: 5, offset: 0, address: text as u64, physical: 0, file_size: TEXT_SPAN as u64, memory_size: TEXT_SPAN as u64, alignment: PAGE as u64 },
        Phdr { kind: 0x6474e550, flags: 4, offset: HEADER as u64, address: (base + HEADER) as u64, physical: 0, file_size: 12, memory_size: 12, alignment: 4 },
    ];
    let mut info = Info { address: 0, name: c"fixture".as_ptr().cast(), headers: headers.as_ptr(), count: 3 };
    unsafe { callback(&mut info, std::mem::size_of::<Info>(), data) }
}

unsafe extern "C" {
    fn mmap(address: *mut c_void, size: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    fn munmap(address: *mut c_void, size: usize) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn getpid() -> i32;
    fn process_vm_readv(pid: i32, local: *const Iovec, local_count: usize, remote: *const Iovec, remote_count: usize, flags: usize) -> isize;
    fn prctl(option: i32, ...) -> i32;
    fn __errno_location() -> *mut i32;
}

unsafe extern "C-unwind" {
    fn _Unwind_RaiseException(exception: *mut UnwindException) -> i32;
}

unsafe fn write_frame(base: *mut u8, text: usize, saved_ra: usize) {
    let header = unsafe { base.add(HEADER) };
    unsafe {
        header.write(1);
        header.add(1).write(0);
        header.add(2).write(0xff);
        header.add(3).write(0xff);
        (header.add(4) as *mut u64).write_unaligned((base as usize + EH_FRAME) as u64);
    }
    // CFA comes from RSP. RIP is read from a valid word on this child's stack.
    let mut cie = vec![0, 0, 0, 0, 1, 0, 1, 0x78, 16, 0x0c, 7, 8, 0x10, 16, 9, 0x03];
    cie.extend_from_slice(&(saved_ra as u64).to_le_bytes());
    let mut frame = (cie.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&cie);
    let fde_start = frame.len();
    frame.extend_from_slice(&20u32.to_le_bytes());
    frame.extend_from_slice(&((fde_start + 4) as u32).to_le_bytes());
    frame.extend_from_slice(&(text as u64).to_le_bytes());
    frame.extend_from_slice(&(TEXT_SPAN as u64).to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), base.add(EH_FRAME), frame.len()); }
}

unsafe fn deny_self_read() {
    // Load the syscall number, deny only process_vm_readv with EPERM, allow all else.
    let filters = [
        Filter { code: 0x20, jt: 0, jf: 0, value: 0 },
        Filter { code: 0x15, jt: 0, jf: 1, value: PROCESS_VM_READV },
        Filter { code: 0x06, jt: 0, jf: 0, value: 0x0005_0001 },
        Filter { code: 0x06, jt: 0, jf: 0, value: 0x7fff_0000 },
    ];
    let program = FilterProgram { len: filters.len() as u16, filter: filters.as_ptr() };
    assert_eq!(unsafe { prctl(38, 1usize, 0usize, 0usize, 0usize) }, 0);
    assert_eq!(unsafe { prctl(22, 2usize, &program as *const _, 0usize, 0usize) }, 0);
}

unsafe fn run_child(denied: bool) -> i32 {
    unsafe {
        let base = mmap(std::ptr::null_mut(), PAGE, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(base as usize, usize::MAX);
        let saved_ra = 0usize;
        let text = (_Unwind_RaiseException as usize) & !(PAGE - 1);
        write_frame(base, text, &saved_ra as *const usize as usize);
        MAPPING.store(base as usize, Ordering::SeqCst);
        TEXT.store(text, Ordering::SeqCst);
        if denied { deny_self_read(); }
        let mut copied_word = usize::MAX;
        let local = Iovec { base: (&mut copied_word as *mut usize).cast(), len: 8 };
        let remote = Iovec { base: (&saved_ra as *const usize as *mut usize).cast(), len: 8 };
        let probe = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if denied {
            let errno = *__errno_location();
            println!("denied probe={probe} errno={errno}");
            assert_eq!(errno, 1);
        } else {
            println!("allowed probe={probe}");
        }
        std::io::stdout().flush().unwrap();
        assert_eq!(probe, if denied { -1 } else { 8 });
        if !denied { assert_eq!(copied_word, 0); }
        let mut exception = UnwindException { exception_class: 0, exception_cleanup: None, private: [0; 8] };
        let result = _Unwind_RaiseException(&mut exception);
        assert_eq!(munmap(base.cast(), PAGE), 0);
        result
    }
}

fn child_case(label: &str, denied: bool, expected: i32) {
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let result = unsafe { run_child(denied) };
        println!("{label} unwind={result}");
        std::io::stdout().flush().unwrap();
        std::process::exit(if result == expected { 0 } else { 1 });
    }
    let mut status = -1;
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    println!("{label} wait={status}");
    assert_eq!(status, 0, "{label} child did not exit normally");
}

fn main() {
    child_case("allowed", false, END_OF_STACK);
    child_case("denied", true, FATAL_PHASE1_ERROR);
    println!("forked self-read policy respected");
}
