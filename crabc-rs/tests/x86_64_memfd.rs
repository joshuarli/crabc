#![cfg(target_arch = "x86_64")]

use crabc_rs::{fs, io, pipe, Errno};

#[test]
fn x86_64_memfd_owns_a_cloexec_descriptor_and_preserves_content() {
    let file = fs::memfd_create(
        "crabc-x86-64-memfd-content",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a sealing-capable anonymous memory file");

    assert!(
        io::fcntl_getfd(&file)
            .expect("read memfd descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "MFD_CLOEXEC must become FD_CLOEXEC on the owned descriptor",
    );

    let payload = b"memfd_buf";
    assert_eq!(io::write(&file, payload).expect("write memfd content"), 9);
    let mut content = [0_u8; 9];
    assert_eq!(
        io::pread(&file, &mut content, 0).expect("read memfd content"),
        9,
    );
    assert_eq!(&content, payload);
}

#[test]
fn x86_64_memfd_keeps_the_closed_name_and_flag_boundary() {
    assert!(
        fs::MemfdFlags::from_bits(0x0008).is_none(),
        "unknown MFD bits must not be silently forwarded",
    );
    assert_eq!(
        fs::memfd_create(&b"bad\0name"[..], fs::MemfdFlags::empty()).unwrap_err(),
        Errno::INVAL,
        "PathArg rejects an interior NUL before crossing the syscall boundary",
    );
    assert_eq!(
        fs::memfd_create(
            "crabc-x86-64-memfd-unknown-flags",
            fs::MemfdFlags::from_bits_retain(0x0008),
        )
        .unwrap_err(),
        Errno::INVAL,
        "retained unknown MFD bits must be rejected before the syscall boundary",
    );
}

#[test]
fn x86_64_memfd_seals_are_observable_and_enforced() {
    let file = fs::memfd_create(
        "crabc-x86-64-memfd-seals",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd that permits sealing");
    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read initial memfd seals"),
        fs::SealFlags::empty(),
    );

    let seals = fs::SealFlags::GROW | fs::SealFlags::SHRINK;
    fs::fcntl_add_seals(&file, seals).expect("add memfd seals");
    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read added memfd seals"),
        seals,
    );
    fs::fcntl_add_seals(&file, fs::SealFlags::SEAL).expect("add final seal");
    assert_eq!(
        fs::fcntl_add_seals(&file, fs::SealFlags::WRITE),
        Err(Errno::PERM),
    );

    let unsealable = fs::memfd_create("crabc-x86-64-memfd-unsealable", fs::MemfdFlags::CLOEXEC)
        .expect("create a memfd without sealing permission");
    assert_eq!(
        fs::fcntl_get_seals(&unsealable).expect("read initial unsealable memfd seals"),
        fs::SealFlags::SEAL,
    );
    assert_eq!(
        fs::fcntl_add_seals(&unsealable, fs::SealFlags::GROW),
        Err(Errno::PERM),
    );

    let (reader, _writer) = pipe::pipe().expect("create a pipe");
    assert_eq!(fs::fcntl_get_seals(&reader), Err(Errno::INVAL));
}
