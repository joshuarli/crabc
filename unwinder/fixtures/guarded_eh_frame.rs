//! Decoded .eh_frame pointers must not read beyond their readable PT_LOAD.
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

const DIRECT_HEADER: usize = 64;
const INDIRECT_HEADER: usize = 128;
const HEADER_SIZE: usize = 12;
const DIRECT: usize = 1;
const INDIRECT: usize = 2;

static MAPPING: AtomicUsize = AtomicUsize::new(0);
static CASE: AtomicUsize = AtomicUsize::new(0);

// This isolated callback exposes only the first mapped page as a readable
// load. The direct target occupies its last byte; the indirect pointer cell is
// on the protected next page. It does not substitute loader evidence.
#[unsafe(no_mangle)]
unsafe extern "C" fn dl_iterate_phdr(
    callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> i32,
    data: *mut c_void,
) -> i32 {
    let base = MAPPING.load(Ordering::SeqCst);
    let header = match CASE.load(Ordering::SeqCst) {
        DIRECT => DIRECT_HEADER,
        INDIRECT => INDIRECT_HEADER,
        _ => return 0,
    };
    let headers = [
        Phdr { kind: 1, flags: 4, offset: 0, address: base as u64, physical: 0, file_size: 4096, memory_size: 4096, alignment: 4096 },
        Phdr { kind: 0x6474e550, flags: 4, offset: header as u64, address: (base + header) as u64, physical: 0, file_size: HEADER_SIZE as u64, memory_size: HEADER_SIZE as u64, alignment: 4 },
    ];
    let mut info = Info { address: 0, name: c"fixture".as_ptr().cast(), headers: headers.as_ptr(), count: 2 };
    unsafe { callback(&mut info, std::mem::size_of::<Info>(), data) }
}

unsafe extern "C" {
    fn mmap(address: *mut c_void, size: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    fn mprotect(address: *mut c_void, size: usize, protection: i32) -> i32;
    fn munmap(address: *mut c_void, size: usize) -> i32;
    fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void;
}

unsafe fn write_header(header: *mut u8, encoding: u8, pointer: usize) {
    unsafe {
        header.write(1);
        header.add(1).write(encoding);
        header.add(2).write(0xff);
        header.add(3).write(0xff);
        (header.add(4) as *mut u64).write_unaligned(pointer as u64);
    }
}

fn main() {
    unsafe {
        let allocation = mmap(std::ptr::null_mut(), 8192, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(allocation as usize, usize::MAX);
        write_header(allocation.add(DIRECT_HEADER), 0, allocation.add(4095) as usize);
        write_header(allocation.add(INDIRECT_HEADER), 0x80, allocation.add(4096) as usize);
        assert_eq!(mprotect(allocation.add(4096).cast(), 4096, 0), 0);
        MAPPING.store(allocation as usize, Ordering::SeqCst);

        CASE.store(INDIRECT, Ordering::SeqCst);
        assert!(_Unwind_FindEnclosingFunction(allocation.add(1).cast()).is_null());
        CASE.store(DIRECT, Ordering::SeqCst);
        assert!(_Unwind_FindEnclosingFunction(allocation.add(1).cast()).is_null());

        assert_eq!(munmap(allocation.cast(), 8192), 0);
    }
    println!("guarded EH frame pointers rejected");
}
