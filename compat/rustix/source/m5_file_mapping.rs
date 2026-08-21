use api::{fs, io, mm};

fn main() {
    const PATH: &str = "crabc-rs-m5-file-mapping";
    const LENGTH: usize = 4096;

    let _ = fs::unlink(PATH);
    let file = fs::open(
        PATH,
        fs::OFlags::CREATE | fs::OFlags::EXCL | fs::OFlags::RDWR,
        fs::Mode::RUSR | fs::Mode::WUSR,
    )
    .unwrap();
    assert_eq!(io::write(&file, &[0x5a; LENGTH]).unwrap(), LENGTH);

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
    .unwrap();
    println!("m5-file-mapping:{}", unsafe { mapping.cast::<u8>().read() });
    unsafe { mm::munmap(mapping, LENGTH) }.unwrap();
    drop(file);
    fs::unlink(PATH).unwrap();
}
