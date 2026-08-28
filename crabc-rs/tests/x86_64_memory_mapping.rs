#![cfg(target_arch = "x86_64")]

use core::ffi::c_void;

use crabc_rs::{fs, io, mm, Errno};

const PAGE_SIZE: usize = 4096;

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
        .expect("create private anonymous mapping");
        Self {
            pointer,
            length: PAGE_SIZE,
        }
    }

    fn unmap(mut self) -> crabc_rs::Result<()> {
        // SAFETY: This owner uniquely holds the mapping and no pointer-derived
        // references remain after the caller has finished its observations.
        let result = unsafe { mm::munmap(self.pointer, self.length) };
        if result.is_ok() {
            self.pointer = core::ptr::null_mut();
        }
        result
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: This fallback owns the one mapping still armed after an
            // early test failure; ordinary successful tests disarm it first.
            let _ = unsafe { mm::munmap(self.pointer, self.length) };
        }
    }
}

/// Exercises the selected anonymous mapping ownership transition without
/// widening the x86 facade into fixed mappings, remapping, or VM policy.
#[test]
fn x86_64_memory_mapping_preserves_protection_and_unique_unmap_lifetime() {
    let mapping = Mapping::anonymous();
    let byte = mapping.pointer.cast::<u8>();

    // SAFETY: The owner holds one writable page, and no reference is retained
    // across the subsequent protection transitions.
    unsafe { byte.write(0x5a) };
    // SAFETY: The complete owned range is page-aligned and mapped. No access
    // occurs while it is inaccessible or incompatible with its protection.
    unsafe { mm::mprotect(mapping.pointer, mapping.length, mm::MprotectFlags::READ) }
        .expect("make anonymous mapping read-only");
    // SAFETY: The range is readable and remains owned by `mapping`.
    assert_eq!(unsafe { byte.read() }, 0x5a);
    // SAFETY: The same complete range remains mapped and no typed reference
    // spans the transition back to read-write access.
    unsafe {
        mm::mprotect(
            mapping.pointer,
            mapping.length,
            mm::MprotectFlags::READ | mm::MprotectFlags::WRITE,
        )
    }
    .expect("restore anonymous mapping write access");
    // SAFETY: The range is writable again and is still uniquely owned.
    unsafe { byte.write(0xa5) };
    // SAFETY: The range remains readable until `unmap` consumes it below.
    assert_eq!(unsafe { byte.read() }, 0xa5);

    mapping.unmap().expect("consume mapping exactly once");
}

/// Exercises the descriptor-borrowing map form and its closed x86 flag
/// vocabulary without selecting a C file-mapping ABI.
#[test]
fn x86_64_memory_mapping_file_backed_boundary_and_direct_errors_are_precise() {
    let file = fs::memfd_create(
        b"crabc-rs-x86-memory-mapping",
        fs::MemfdFlags::CLOEXEC,
    )
    .expect("create file-backed mapping fixture");
    fs::ftruncate(&file, PAGE_SIZE as u64).expect("size mapping fixture file");
    let pointer = unsafe {
        mm::mmap(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::SHARED,
            &file,
            0,
        )
    }
    .expect("map fixture through a borrowed descriptor");
    let mapping = Mapping {
        pointer,
        length: PAGE_SIZE,
    };

    // SAFETY: The shared mapping is writable and owned until `unmap` below.
    unsafe { mapping.pointer.cast::<u8>().write(0x3c) };
    let mut observed = [0_u8; 1];
    assert_eq!(
        io::pread(&file, &mut observed, 0).expect("observe shared mapped byte"),
        1,
    );
    assert_eq!(observed, [0x3c]);
    mapping.unmap().expect("unmap borrowed-descriptor mapping");

    // Zero length is rejected by the direct Linux `mmap` contract; this does
    // not allocate a mapping or cross C errno state.
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                0,
                mm::ProtFlags::READ,
                mm::MapFlags::PRIVATE,
            )
        },
        Err(Errno::INVAL),
    );
    // The facade owns a closed map-mode vocabulary, so these fixed and
    // x86-specific placement modes are rejected before reaching the kernel.
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x10),
            )
        },
        Err(Errno::INVAL),
    );
    assert_eq!(
        unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                PAGE_SIZE,
                mm::ProtFlags::READ,
                mm::MapFlags::from_bits_retain(0x40),
            )
        },
        Err(Errno::INVAL),
    );
    // SAFETY: The deliberately unaligned pointer is an error-only direct
    // syscall fixture and is never dereferenced.
    assert_eq!(
        unsafe {
            mm::mprotect(
                core::ptr::without_provenance_mut::<c_void>(1),
                PAGE_SIZE,
                mm::MprotectFlags::READ,
            )
        },
        Err(Errno::INVAL),
    );
}
