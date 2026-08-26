#![cfg(target_arch = "x86_64")]

use core::ffi::{c_void, CStr};

use crabc_rs::{io, mm, OwnedFd};

const PAGE_SIZE: usize = 4096;
const SPARSE_OFFSET: u64 = 4 * 1024 * 1024 * 1024;

struct Mapping {
    pointer: *mut c_void,
    length: usize,
}

impl Mapping {
    fn anonymous() -> Self {
        let pointer = unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::PRIVATE,
            )
        }
        .expect("create an x86-64 anonymous mapping");

        Self {
            pointer,
            length: PAGE_SIZE,
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: This owner consumes the one mapping created above, after
        // the test has stopped using pointers into it.
        let _ = unsafe { mm::munmap(self.pointer, self.length) };
    }
}

fn anonymous_file() -> OwnedFd {
    let name = CStr::from_bytes_with_nul(b"crabc-rs-x86-64-mm\0")
        .expect("the fixed memfd name is NUL-terminated");
    let raw = crabc_core::fs::memfd_create(name, 0).expect("create anonymous mapping file");
    crabc_core::fs::ftruncate(raw, (SPARSE_OFFSET + PAGE_SIZE as u64) as i64)
        .expect("size sparse anonymous mapping file");

    // SAFETY: `memfd_create` returned one newly-open descriptor whose unique
    // ownership transfers to this RAII value.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

#[test]
fn x86_64_mapping_flags_match_the_linux_abi() {
    assert_eq!(mm::ProtFlags::empty().bits(), 0x0);
    assert_eq!(mm::ProtFlags::READ.bits(), 0x1);
    assert_eq!(mm::ProtFlags::WRITE.bits(), 0x2);
    assert_eq!(mm::ProtFlags::EXEC.bits(), 0x4);
    assert_eq!(mm::MprotectFlags::empty().bits(), 0x0);
    assert_eq!(mm::MapFlags::SHARED.bits(), 0x1);
    assert_eq!(mm::MapFlags::PRIVATE.bits(), 0x2);
}

#[test]
fn x86_64_anonymous_mapping_preserves_permissions_and_lifetime() {
    let mapping = Mapping::anonymous();
    let byte = mapping.pointer.cast::<u8>();

    // SAFETY: `mapping` owns a writable page and no references outlive its
    // drop-based unmap.
    unsafe { byte.write(0x5a) };
    // SAFETY: no Rust reference is used while this page is `PROT_NONE`.
    unsafe { mm::mprotect(mapping.pointer, mapping.length, mm::MprotectFlags::empty()) }
        .expect("make x86-64 mapping inaccessible");
    // SAFETY: `mapping` owns the complete valid page and no Rust reference is
    // used across the `PROT_NONE` transition.
    unsafe { mm::mprotect(mapping.pointer, mapping.length, mm::MprotectFlags::READ) }
        .expect("make x86-64 mapping read-only");
    // SAFETY: the mapping remains readable after the protection transition.
    assert_eq!(unsafe { byte.read() }, 0x5a);
    // SAFETY: `mapping` still owns the complete page and no reference is
    // retained across this second transition.
    unsafe {
        mm::mprotect(
            mapping.pointer,
            mapping.length,
            mm::MprotectFlags::READ | mm::MprotectFlags::WRITE,
        )
    }
    .expect("restore x86-64 mapping write permission");
    // SAFETY: the mapping is writable again and remains owned until drop.
    unsafe { byte.write(0xa5) };
    // SAFETY: the mapping remains readable until its owner drops.
    assert_eq!(unsafe { byte.read() }, 0xa5);
}

#[test]
fn x86_64_file_mapping_uses_the_borrowed_descriptor_boundary() {
    let file = anonymous_file();
    let pointer = unsafe {
        mm::mmap(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::SHARED,
            &file,
            SPARSE_OFFSET,
        )
    }
    .expect("map a page through the borrowed descriptor");
    let mapping = Mapping {
        pointer,
        length: PAGE_SIZE,
    };

    // SAFETY: `mapping` owns a writable shared page and the file remains open
    // for the mapping's lifetime.
    unsafe { mapping.pointer.cast::<u8>().write(0x3c) };
    let mut observed = [0_u8; 1];
    assert_eq!(
        io::pread(&file, &mut observed, SPARSE_OFFSET)
            .expect("read shared sparse mapping backing file"),
        1
    );
    assert_eq!(observed, [0x3c]);
}

#[test]
fn x86_64_mapping_rejects_unadmitted_flag_bits_before_the_kernel_boundary() {
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x40),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "MAP_32BIT is x86-specific but intentionally unadmitted",
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x10),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "MAP_FIXED is intentionally unadmitted",
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x0010_0000),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "MAP_FIXED_NOREPLACE is intentionally unadmitted",
    );

    let mapping = Mapping::anonymous();
    assert_eq!(
        unsafe {
            mm::mprotect(
                mapping.pointer,
                mapping.length,
                mm::MprotectFlags::from_bits_retain(0x10),
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "unadmitted protection bits must not reach the raw syscall seam",
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::SHARED | mm::MapFlags::PRIVATE,
            )
        },
        Err(crabc_rs::Errno::INVAL),
        "exactly one mapping sharing mode is required",
    );
}
