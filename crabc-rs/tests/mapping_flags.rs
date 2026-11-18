use crabc_rs::{mm, Errno};

#[test]
fn fixed_noreplace_preserves_the_existing_mapping() {
    let flags = mm::MapFlags::PRIVATE;
    let protection = mm::ProtFlags::READ | mm::ProtFlags::WRITE;
    // SAFETY: The returned mapping is owned by this test until it is unmapped.
    let mapping = unsafe { mm::mmap_anonymous_with_flags(core::ptr::null_mut(), 4096, protection, flags) }.unwrap();
    // SAFETY: The mapping is writable and the test owns its lifetime.
    unsafe { mapping.cast::<u8>().write(0x51) };
    // SAFETY: The requested range is owned by this test and NOREPLACE forbids replacement.
    let result = unsafe { mm::mmap_anonymous_with_flags(mapping, 4096, protection, flags | mm::MapFlags::FIXED_NOREPLACE) };
    assert_eq!(result, Err(Errno::EXIST));
    // SAFETY: The failed call preserved the owned mapping.
    assert_eq!(unsafe { mapping.cast::<u8>().read() }, 0x51);
    // SAFETY: No references remain into this owned mapping.
    unsafe { mm::munmap(mapping, 4096) }.unwrap();
}
