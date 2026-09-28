//! A register expression that names an unreadable page must fail the unwind phase.
use std::ffi::c_void;
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

const PAGE: usize = 4096;
const HEADER: usize = 64;
const EH_FRAME: usize = 256;
const TEXT_SPAN: usize = 65536;
const FATAL_PHASE1_ERROR: i32 = 3;

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
    fn mprotect(address: *mut c_void, size: usize, protection: i32) -> i32;
    fn munmap(address: *mut c_void, size: usize) -> i32;
}

unsafe extern "C-unwind" {
    fn _Unwind_RaiseException(exception: *mut UnwindException) -> i32;
}

unsafe fn write_frame(base: *mut u8, text: usize, instructions: &[u8]) {
    let header = unsafe { base.add(HEADER) };
    unsafe {
        header.write(1);
        header.add(1).write(0);
        header.add(2).write(0xff);
        header.add(3).write(0xff);
        (header.add(4) as *mut u64).write_unaligned((base as usize + EH_FRAME) as u64);
    }

    let mut cie = vec![0, 0, 0, 0, 1, 0, 1, 0x78, 16];
    cie.extend_from_slice(instructions);
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

unsafe fn run_case(case: &str) {
    unsafe {
        let base = mmap(std::ptr::null_mut(), 2 * PAGE, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(base as usize, usize::MAX);
        let text = (_Unwind_RaiseException as usize) & !(PAGE - 1);
        let guarded = base.add(PAGE) as usize;
        let mut instructions = match case {
            "register-expression" => {
                // CFA comes from RSP; DW_CFA_expression names unreadable RIP storage.
                vec![0x0c, 7, 8, 0x10, 16, 9, 0x03]
            }
            "register-offset" => {
                // The CFA expression yields guard+8; RIP's offset is -8.
                vec![0x0f, 9, 0x03]
            }
            "expression-memory" => {
                // DW_OP_deref_size itself attempts an eight-byte guarded read.
                vec![0x0f, 11, 0x03]
            }
            _ => panic!("unknown case"),
        };
        let address = guarded + if case == "register-offset" { 8 } else { 0 };
        instructions.extend_from_slice(&(address as u64).to_le_bytes());
        match case {
            "register-offset" => instructions.extend_from_slice(&[0x90, 1]),
            "expression-memory" => instructions.extend_from_slice(&[0x94, 8, 0x07, 16]),
            _ => (),
        }
        write_frame(base, text, &instructions);
        assert_eq!(mprotect(base.add(PAGE).cast(), PAGE, 0), 0);
        MAPPING.store(base as usize, Ordering::SeqCst);
        TEXT.store(text, Ordering::SeqCst);
        let mut exception = UnwindException { exception_class: 0, exception_cleanup: None, private: [0; 8] };
        assert_eq!(_Unwind_RaiseException(&mut exception), FATAL_PHASE1_ERROR, "{case}");
        assert_eq!(munmap(base.cast(), 2 * PAGE), 0);
    }
}

fn main() {
    for case in ["register-expression", "register-offset", "expression-memory"] {
        unsafe { run_case(case); }
    }
    println!("guarded register rule rejected");
}
