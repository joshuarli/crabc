//! CFI and DWARF expression failures must return a phase error, not panic or fault.
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

const HEADER: usize = 64;
const EH_FRAME: usize = 256;
const PAGE: usize = 4096;
const TEXT_SPAN: usize = 65536;
const FATAL_PHASE1_ERROR: i32 = 3;
const END_OF_STACK: i32 = 5;

static MAPPING: AtomicUsize = AtomicUsize::new(0);
static TEXT: AtomicUsize = AtomicUsize::new(0);

// The metadata page is readable and the provider code range is executable.
// The next page is mapped but omitted from the declared loads, so it is a
// target that neither metadata readers nor expression dereferences may read.
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

unsafe fn write_header(header: *mut u8, eh_frame: usize) {
    unsafe {
        header.write(1);
        header.add(1).write(0);
        header.add(2).write(0xff);
        header.add(3).write(0xff);
        (header.add(4) as *mut u64).write_unaligned(eh_frame as u64);
    }
}

// Build a CIE with caller-selected CFI instructions and a matching FDE.
unsafe fn write_frame(eh_frame: *mut u8, text: usize, instructions: &[u8]) {
    let mut cie = vec![0, 0, 0, 0, 1, 0, 1, 0x78, 16];
    cie.extend_from_slice(instructions);
    let mut bytes = (cie.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&cie);
    let fde_start = bytes.len();
    bytes.extend_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&((fde_start + 4) as u32).to_le_bytes());
    bytes.extend_from_slice(&(text as u64).to_le_bytes());
    bytes.extend_from_slice(&(TEXT_SPAN as u64).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), eh_frame, bytes.len()); }
}

fn cfa_expression(expression: &[u8]) -> Vec<u8> {
    // DW_CFA_def_cfa_expression followed by undefined return address.
    let mut instructions = vec![0x0f, expression.len() as u8];
    instructions.extend_from_slice(expression);
    instructions.extend_from_slice(&[0x07, 16]);
    instructions
}

unsafe fn run_case(case: &str) {
    unsafe {
        let allocation = mmap(std::ptr::null_mut(), 2 * PAGE, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(allocation as usize, usize::MAX);
        let text = (_Unwind_RaiseException as usize) & !(PAGE - 1);
        let (instructions, expected) = match case {
            "unsupported-cfa-register" => (vec![0x0c, 127, 8], FATAL_PHASE1_ERROR),
            "unsupported-rule-register" => (vec![0x0c, 7, 8, 0x09, 16, 127], FATAL_PHASE1_ERROR),
            "unsupported-destination-register" => (vec![0x0c, 7, 8, 0x07, 127], FATAL_PHASE1_ERROR),
            "unsupported-expression-register" => (cfa_expression(&[0x92, 127, 0]), FATAL_PHASE1_ERROR),
            "unsupported-frame-base" => (cfa_expression(&[0x91, 0]), FATAL_PHASE1_ERROR),
            "unsupported-result" => (cfa_expression(&[0x30, 0x9f]), FATAL_PHASE1_ERROR),
            "expression-loop" => (cfa_expression(&[0x2f, 0xfd, 0xff]), FATAL_PHASE1_ERROR),
            "valid-register-arithmetic" => (cfa_expression(&[0x77, 0, 0x38, 0x22]), END_OF_STACK),
            "memory-width-1" | "memory-width-2" | "memory-width-3" | "memory-width-4"
            | "memory-width-5" | "memory-width-6" | "memory-width-7" | "memory-width-8" => {
                let width: usize = case.rsplit('-').next().unwrap().parse().unwrap();
                let bytes = [0x91, 0x82, 0xf3, 0xa4, 0xd5, 0xb6, 0xe7, 0xc8];
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), allocation.add(PAGE - width), width);
                let mut expected = [0u8; 8];
                expected[..width].copy_from_slice(&bytes[..width]);
                let mut expr = vec![0x0e]; // DW_OP_const8u, not relocated DW_OP_addr.
                expr.extend_from_slice(&(allocation.add(PAGE - width) as u64).to_le_bytes());
                expr.extend_from_slice(&[0x94, width as u8]); // DW_OP_deref_size.
                expr.push(0x0e);
                expr.extend_from_slice(&u64::from_le_bytes(expected).to_le_bytes());
                // DW_OP_eq; branch over unsupported bregx only on exact value.
                // A sign-extended or incorrect value produces a phase error.
                expr.extend_from_slice(&[0x29, 0x28, 3, 0, 0x92, 127, 0, 0x30]);
                (cfa_expression(&expr), END_OF_STACK)
            }
            "relocated-address" => {
                // DW_OP_addr returns an address; it must never read its target.
                let mut expr = vec![0x03];
                expr.extend_from_slice(&(allocation.add(PAGE) as u64).to_le_bytes());
                (cfa_expression(&expr), END_OF_STACK)
            }
            _ => panic!("unknown case"),
        };
        write_header(allocation.add(HEADER), allocation.add(EH_FRAME) as usize);
        write_frame(allocation.add(EH_FRAME), text, &instructions);
        assert_eq!(mprotect(allocation.add(PAGE).cast(), PAGE, 0), 0);
        MAPPING.store(allocation as usize, Ordering::SeqCst);
        TEXT.store(text, Ordering::SeqCst);
        let mut exception = UnwindException { exception_class: 0, exception_cleanup: None, private: [0; 8] };
        assert_eq!(_Unwind_RaiseException(&mut exception), expected, "{case}");
        assert_eq!(munmap(allocation.cast(), 2 * PAGE), 0);
    }
}

fn main() {
    if let Some(case) = std::env::args().nth(1) {
        unsafe { run_case(&case); }
        return;
    }
    for case in [
        "unsupported-cfa-register", "unsupported-rule-register",
        "unsupported-destination-register", "unsupported-expression-register",
        "unsupported-frame-base", "unsupported-result", "expression-loop",
        "relocated-address", "valid-register-arithmetic", "memory-width-1",
        "memory-width-2", "memory-width-3", "memory-width-4", "memory-width-5",
        "memory-width-6", "memory-width-7", "memory-width-8",
    ] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(case).spawn().unwrap();
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{case}: {status}");
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{case}: expression failed to terminate");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    println!("CFI and expression errors rejected");
}
