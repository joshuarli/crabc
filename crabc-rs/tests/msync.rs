use crabc_rs::mm;

#[test]
fn native_msync_accepts_linux_sync_modes_for_anonymous_mapping() {
    const PAGE_SIZE: usize = 4096;

    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map an anonymous page through the direct kernel seam");
    let byte = mapping.cast::<u8>();

    // Establish a mapped page before asking Linux to synchronize it. The
    // anonymous mapping has no file to persist, but exercises the same kernel
    // range validation as a file-backed mapping without C ABI involvement.
    unsafe { byte.write(0x5a) };
    unsafe { mm::msync(mapping, PAGE_SIZE, mm::MsyncFlags::SYNC) }
        .expect("synchronize anonymous page through direct msync");
    unsafe { mm::msync(mapping, PAGE_SIZE, mm::MsyncFlags::ASYNC) }
        .expect("schedule anonymous page synchronization through direct msync");
    assert_eq!(unsafe { byte.read() }, 0x5a);

    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap synchronized page");
}
