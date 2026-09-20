//! A one-byte EH header at a guard-page boundary must fail without a read fault.
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

static MAPPING: AtomicUsize = AtomicUsize::new(0);

// This isolated regression supplies a declared loaded-image boundary to the
// provider. Its PT_LOAD intentionally continues past the one-byte header, but
// the following page is inaccessible: p_memsz, not trailing PT_LOAD bytes, is
// the header authority. It does not substitute the runtime's loader in
// consumer evidence.
#[unsafe(no_mangle)]
unsafe extern "C" fn dl_iterate_phdr(
    callback: unsafe extern "C" fn(*mut Info, usize, *mut c_void) -> i32,
    data: *mut c_void,
) -> i32 {
    let base = MAPPING.load(Ordering::SeqCst);
    let headers = [
        Phdr { kind: 1, flags: 4, offset: 0, address: base as u64, physical: 0, file_size: 8192, memory_size: 8192, alignment: 4096 },
        Phdr { kind: 0x6474e550, flags: 4, offset: 4095, address: (base + 4095) as u64, physical: 0, file_size: 1, memory_size: 1, alignment: 1 },
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

fn main() {
    unsafe {
        let allocation = mmap(std::ptr::null_mut(), 8192, 3, 0x22, -1, 0);
        assert_ne!(allocation as usize, usize::MAX);
        assert_eq!(mprotect(allocation.add(4096), 4096, 0), 0);
        *(allocation.add(4095) as *mut u8) = 1;
        MAPPING.store(allocation as usize, Ordering::SeqCst);
        assert!(_Unwind_FindEnclosingFunction(allocation.add(1)).is_null());
        assert_eq!(munmap(allocation, 8192), 0);
    }
    println!("truncated EH header rejected");
}
