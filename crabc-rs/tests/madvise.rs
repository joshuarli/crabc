use crabc_rs::mm;

#[test]
fn native_madvise_linux_dontneed_discards_anonymous_page_contents() {
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

    // Fault the private anonymous page and establish contents which Linux's
    // MADV_DONTNEED policy must discard before the next read.
    unsafe { byte.write(0x5a) };
    unsafe { mm::madvise(mapping, PAGE_SIZE, mm::Advice::LinuxDontNeed) }
        .expect("discard anonymous page through direct madvise");
    let observed = unsafe { byte.read() };
    unsafe { mm::munmap(mapping, PAGE_SIZE) }.expect("unmap advised page");

    assert_eq!(observed, 0);
}
