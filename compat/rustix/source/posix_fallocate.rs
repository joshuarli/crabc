use api::fs::{self, FallocateFlags, MemfdFlags, SeekFrom};

fn main() {
    let file = fs::memfd_create(
        &b"crabc-native-posix-fallocate-source"[..],
        MemfdFlags::CLOEXEC,
    )
    .expect("create mode-zero fallocate fixture");

    // Rustix 1.1.4 exposes the POSIX mode-zero operation through its
    // general fallocate facade. crabc-rs additionally exposes the explicit
    // posix_fallocate spelling; this common fixture compares the operation
    // itself at the shared Rustix boundary.
    fs::fallocate(&file, FallocateFlags::empty(), 4096, 4096)
        .expect("allocate a mode-zero range");
    assert_eq!(
        fs::seek(&file, SeekFrom::End(0)).expect("read allocated length"),
        8192,
    );
    println!("native-posix-fallocate ok");
}
