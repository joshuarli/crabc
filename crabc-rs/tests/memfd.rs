use crabc_rs::fs::{self, MemfdFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::Errno;

#[test]
fn memfd_owns_a_cloexec_descriptor_and_preserves_content() {
    let file = fs::memfd_create(
        "crabc-mem-content",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a sealed-capable anonymous memory file");

    assert!(
        io::fcntl_getfd(&file)
            .expect("read memfd descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "MFD_CLOEXEC must become FD_CLOEXEC on the owned descriptor",
    );
    let payload = b"memfd_buf";
    assert_eq!(
        io::write(&file, payload).expect("write memfd content"),
        9,
    );
    assert_eq!(
        fs::seek(&file, SeekFrom::Start(0)).expect("rewind memfd"),
        0,
    );
    let mut content = [0_u8; 9];
    assert_eq!(
        io::read(&file, &mut content).expect("read memfd content"),
        9,
    );
    assert_eq!(&content, payload);
}

#[test]
fn memfd_name_and_flags_keep_the_typed_boundary() {
    assert!(
        MemfdFlags::from_bits(0x0008).is_none(),
        "unknown MFD bits must not be silently forwarded",
    );
    assert_eq!(
        fs::memfd_create(&b"bad\0name"[..], MemfdFlags::empty()).unwrap_err(),
        Errno::INVAL,
        "Arg rejects an interior NUL before crossing the syscall boundary",
    );
}
