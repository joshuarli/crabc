//! An indirect CIE personality pointer must not dereference a guard page.
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
const END_OF_STACK: i32 = 5;

static MAPPING: AtomicUsize = AtomicUsize::new(0);
static TEXT: AtomicUsize = AtomicUsize::new(0);

// The fixture admits one synthetic read-only metadata load and the page
// containing the selected provider's phase-one return address. It exposes an
// indirect CIE personality cell in the protected following page.
#[unsafe(no_mangle)]
unsafe extern "C" fn dl_iterate_phdr(
    callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> i32,
    data: *mut c_void,
) -> i32 {
    let base = MAPPING.load(Ordering::SeqCst);
    let text = TEXT.load(Ordering::SeqCst);
    let headers = [
        Phdr { kind: 1, flags: 4, offset: 0, address: base as u64, physical: 0, file_size: PAGE as u64, memory_size: PAGE as u64, alignment: PAGE as u64 },
        Phdr { kind: 1, flags: 4, offset: 0, address: text as u64, physical: 0, file_size: TEXT_SPAN as u64, memory_size: TEXT_SPAN as u64, alignment: PAGE as u64 },
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

unsafe fn write_eh_frame(eh_frame: *mut u8, text: usize, indirect_personality: usize) {
    unsafe {
        // CIE: zP with an absolute indirect 64-bit personality pointer.
        (eh_frame as *mut u32).write_unaligned(26);
        (eh_frame.add(4) as *mut u32).write_unaligned(0);
        eh_frame.add(8).write(1);
        eh_frame.add(9).write(b'z');
        eh_frame.add(10).write(b'P');
        eh_frame.add(11).write(0);
        eh_frame.add(12).write(1);
        eh_frame.add(13).write(0x78);
        eh_frame.add(14).write(16);
        eh_frame.add(15).write(9);
        eh_frame.add(16).write(0x80);
        (eh_frame.add(17) as *mut u64).write_unaligned(indirect_personality as u64);
        // cfa = rsp + 8; the caller return address is cfa - 8.
        eh_frame.add(25).write(0x0c);
        eh_frame.add(26).write(7);
        eh_frame.add(27).write(8);
        eh_frame.add(28).write(0x90);
        eh_frame.add(29).write(1);

        // FDE covers the provider's captured phase-one return address.
        let fde = eh_frame.add(30);
        (fde as *mut u32).write_unaligned(21);
        (fde.add(4) as *mut u32).write_unaligned(34);
        (fde.add(8) as *mut u64).write_unaligned(text as u64);
        (fde.add(16) as *mut u64).write_unaligned(TEXT_SPAN as u64);
        fde.add(24).write(0);
        (fde.add(25) as *mut u32).write_unaligned(0);
    }
}

fn main() {
    unsafe {
        let allocation = mmap(std::ptr::null_mut(), 2 * PAGE, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(allocation as usize, usize::MAX);
        let text = (_Unwind_RaiseException as usize) & !(PAGE - 1);
        write_header(allocation.add(HEADER), allocation.add(EH_FRAME) as usize);
        write_eh_frame(allocation.add(EH_FRAME), text, allocation.add(PAGE) as usize);
        assert_eq!(mprotect(allocation.add(PAGE).cast(), PAGE, 0), 0);
        MAPPING.store(allocation as usize, Ordering::SeqCst);
        TEXT.store(text, Ordering::SeqCst);

        let mut exception = UnwindException {
            exception_class: 0,
            exception_cleanup: None,
            private: [0; 8],
        };
        assert_eq!(_Unwind_RaiseException(&mut exception), END_OF_STACK);

        assert_eq!(munmap(allocation.cast(), 2 * PAGE), 0);
    }
    println!("indirect personality pointer rejected");
}
