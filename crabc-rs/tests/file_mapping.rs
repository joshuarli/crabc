use crabc_rs::{fs, io, mm};

#[test]
fn file_backed_mapping_uses_the_direct_kernel_boundary() {
    const PATH: &str = "crabc-rs-descriptor-file-mapping";
    const LENGTH: usize = 4096;

    match fs::unlink(PATH) {
        Ok(()) | Err(crabc_rs::Errno::NOENT) => {}
        Err(error) => panic!("remove stale mapping fixture: {error}"),
    }

    let file = fs::open(
        PATH,
        fs::OFlags::CREATE | fs::OFlags::EXCL | fs::OFlags::RDWR,
        fs::Mode::RUSR | fs::Mode::WUSR,
    )
    .expect("create mapping backing file");
    assert_eq!(
        io::write(&file, &[0x5a; LENGTH]).expect("write mapping contents"),
        LENGTH
    );

    let mapping = unsafe {
        mm::mmap(
            core::ptr::null_mut(),
            LENGTH,
            mm::ProtFlags::READ,
            mm::MapFlags::PRIVATE,
            &file,
            0,
        )
    }
    .expect("map backing file through crabc-core");
    assert_eq!(unsafe { mapping.cast::<u8>().read() }, 0x5a);
    unsafe { mm::munmap(mapping, LENGTH) }.expect("unmap file-backed mapping");

    drop(file);
    fs::unlink(PATH).expect("remove mapping backing file");
}
