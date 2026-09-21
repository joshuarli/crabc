//! A PT_DYNAMIC table without a terminator must not read across a guard page.
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

const HEADER: usize = 64;
const EH_FRAME: usize = 256;
const GOT_EH_FRAME: usize = 320;
const TRUNCATED_DYNAMIC: usize = 4080;
const NULL_DYNAMIC: usize = 512;
const GOT_DYNAMIC: usize = 544;
const DYN_RECORD: usize = 16;
const TRUNCATED: usize = 1;
const NULL_ONLY: usize = 2;
const PLTGOT: usize = 3;

static MAPPING: AtomicUsize = AtomicUsize::new(0);
static CASE: AtomicUsize = AtomicUsize::new(0);

// The callback makes the first page the whole readable PT_LOAD. The truncated
// case exposes one non-null dynamic record in its final bytes, then a protected
// page. The other cases retain a DT_NULL-only table and a DT_PLTGOT table.
#[unsafe(no_mangle)]
unsafe extern "C" fn dl_iterate_phdr(
    callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> i32,
    data: *mut c_void,
) -> i32 {
    let base = MAPPING.load(Ordering::SeqCst);
    let (dynamic, dynamic_size) = match CASE.load(Ordering::SeqCst) {
        TRUNCATED => (TRUNCATED_DYNAMIC, DYN_RECORD),
        NULL_ONLY => (NULL_DYNAMIC, DYN_RECORD),
        PLTGOT => (GOT_DYNAMIC, 2 * DYN_RECORD),
        _ => return 0,
    };
    let headers = [
        Phdr { kind: 1, flags: 4, offset: 0, address: base as u64, physical: 0, file_size: 4096, memory_size: 4096, alignment: 4096 },
        Phdr { kind: 0x6474e550, flags: 4, offset: HEADER as u64, address: (base + HEADER) as u64, physical: 0, file_size: 12, memory_size: 12, alignment: 4 },
        Phdr { kind: 2, flags: 4, offset: dynamic as u64, address: (base + dynamic) as u64, physical: 0, file_size: dynamic_size as u64, memory_size: dynamic_size as u64, alignment: 8 },
    ];
    let mut info = Info { address: 0, name: c"fixture".as_ptr().cast(), headers: headers.as_ptr(), count: 3 };
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

unsafe fn write_dynamic(record: *mut u8, tag: usize, value: usize) {
    unsafe {
        (record as *mut usize).write_unaligned(tag);
        (record.add(std::mem::size_of::<usize>()) as *mut usize).write_unaligned(value);
    }
}

unsafe fn write_eh_frame(eh_frame: *mut u8, pc: usize) {
    unsafe {
        // CIE: version 1, empty augmentation, code/data alignment 1/-8, RA=16.
        (eh_frame as *mut u32).write_unaligned(9);
        (eh_frame.add(4) as *mut u32).write_unaligned(0);
        eh_frame.add(8).write(1);
        eh_frame.add(9).write(0);
        eh_frame.add(10).write(1);
        eh_frame.add(11).write(0x78);
        eh_frame.add(12).write(16);
        // FDE refers back to the CIE and covers the fixture lookup PC.
        let fde = eh_frame.add(13);
        (fde as *mut u32).write_unaligned(20);
        (fde.add(4) as *mut u32).write_unaligned(17);
        (fde.add(8) as *mut usize).write_unaligned(pc);
        (fde.add(8 + std::mem::size_of::<usize>()) as *mut usize).write_unaligned(64);
    }
}

unsafe fn write_got_eh_frame(eh_frame: *mut u8) {
    unsafe {
        // CIE with zR declares data-relative FDE initial-location addresses.
        (eh_frame as *mut u32).write_unaligned(13);
        (eh_frame.add(4) as *mut u32).write_unaligned(0);
        eh_frame.add(8).write(1);
        eh_frame.add(9).write(b'z');
        eh_frame.add(10).write(b'R');
        eh_frame.add(11).write(0);
        eh_frame.add(12).write(1);
        eh_frame.add(13).write(0x78);
        eh_frame.add(14).write(16);
        eh_frame.add(15).write(1);
        eh_frame.add(16).write(0x30);
        let fde = eh_frame.add(17);
        (fde as *mut u32).write_unaligned(21);
        (fde.add(4) as *mut u32).write_unaligned(21);
        (fde.add(8) as *mut usize).write_unaligned(0);
        (fde.add(8 + std::mem::size_of::<usize>()) as *mut usize).write_unaligned(64);
        fde.add(8 + 2 * std::mem::size_of::<usize>()).write(0);
    }
}

fn main() {
    unsafe {
        let allocation = mmap(std::ptr::null_mut(), 8192, 3, 0x22, -1, 0).cast::<u8>();
        assert_ne!(allocation as usize, usize::MAX);
        let pc = allocation.add(2);
        write_eh_frame(allocation.add(EH_FRAME), allocation.add(1) as usize);
        write_got_eh_frame(allocation.add(GOT_EH_FRAME));
        write_dynamic(allocation.add(TRUNCATED_DYNAMIC), 1, 0);
        write_dynamic(allocation.add(NULL_DYNAMIC), 0, 0);
        write_dynamic(allocation.add(GOT_DYNAMIC), 3, allocation.add(1) as usize);
        write_dynamic(allocation.add(GOT_DYNAMIC + DYN_RECORD), 0, 0);
        assert_eq!(mprotect(allocation.add(4096).cast(), 4096, 0), 0);
        MAPPING.store(allocation as usize, Ordering::SeqCst);

        CASE.store(TRUNCATED, Ordering::SeqCst);
        write_header(allocation.add(HEADER), 0, allocation.add(EH_FRAME) as usize);
        assert!(_Unwind_FindEnclosingFunction(pc.cast()).is_null());

        CASE.store(NULL_ONLY, Ordering::SeqCst);
        assert_eq!(_Unwind_FindEnclosingFunction(pc.cast()), allocation.add(1).cast());

        CASE.store(PLTGOT, Ordering::SeqCst);
        write_header(allocation.add(HEADER), 0, allocation.add(GOT_EH_FRAME) as usize);
        assert_eq!(_Unwind_FindEnclosingFunction(pc.cast()), allocation.add(1).cast());

        assert_eq!(munmap(allocation.cast(), 8192), 0);
    }
    println!("guarded dynamic table rejected");
}
