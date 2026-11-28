#![cfg(target_os = "linux")]
use crabc_rs::{mm, Errno};

#[test]
fn fixed_noreplace_preserves_the_existing_mapping() {
    let flags = mm::MapFlags::PRIVATE;
    let protection = mm::ProtFlags::READ | mm::ProtFlags::WRITE;
    // SAFETY: The returned mapping is owned by this test until it is unmapped.
    let mapping = unsafe { crabc_core::mm::mmap_raw(core::ptr::null_mut(), 4096, protection.bits(), flags.bits() | 0x20, -1, 0) }.unwrap();
    // SAFETY: The mapping is writable and the test owns its lifetime.
    unsafe { mapping.cast::<u8>().write(0x51) };
    // SAFETY: The requested range is owned by this test and NOREPLACE forbids replacement.
    let result = unsafe { crabc_core::mm::mmap_raw(mapping, 4096, protection.bits(), flags.bits() | 0x0010_0000 | 0x20, -1, 0) };
    assert_eq!(result, Err(Errno::EXIST));
    // SAFETY: The failed call preserved the owned mapping.
    assert_eq!(unsafe { mapping.cast::<u8>().read() }, 0x51);
    // SAFETY: No references remain into this owned mapping.
    unsafe { mm::munmap(mapping.cast(), 4096) }.unwrap();
}
