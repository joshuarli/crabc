use crabc_rs::{fs, pipe, Errno};

#[test]
fn fcntl_get_seals_reads_empty_flags_from_allow_sealing_memfd() {
    let file = fs::memfd_create(
        "crabc-native-seals-empty",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd that permits sealing");

    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read initial memfd seals"),
        fs::SealFlags::empty()
    );
}

#[test]
fn fcntl_get_seals_reads_seal_seal_from_plain_memfd() {
    let file = fs::memfd_create("crabc-native-seals-locked", fs::MemfdFlags::CLOEXEC)
        .expect("create a memfd without sealing permission");

    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read initial plain memfd seals"),
        fs::SealFlags::SEAL
    );
}

#[test]
fn fcntl_get_seals_rejects_a_pipe_descriptor() {
    let (reader, _writer) = pipe::pipe().expect("create a pipe");

    assert_eq!(fs::fcntl_get_seals(&reader), Err(Errno::INVAL));
}

#[test]
fn fcntl_add_seals_adds_and_observes_flags_on_an_allow_sealing_memfd() {
    let file = fs::memfd_create(
        "crabc-native-seals-add",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd that permits sealing");

    let seals = fs::SealFlags::GROW | fs::SealFlags::SHRINK;
    fs::fcntl_add_seals(&file, seals).expect("add memfd seals");
    assert_eq!(fs::fcntl_get_seals(&file).expect("read added memfd seals"), seals);
}

#[test]
fn fcntl_add_seals_rejects_unsealable_and_already_sealed_memfds() {
    let unsealable = fs::memfd_create("crabc-native-seals-unsealable", fs::MemfdFlags::CLOEXEC)
        .expect("create a memfd without sealing permission");
    assert_eq!(
        fs::fcntl_add_seals(&unsealable, fs::SealFlags::GROW),
        Err(Errno::PERM),
    );

    let sealed = fs::memfd_create(
        "crabc-native-seals-all-sealed",
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create a memfd that permits sealing");
    fs::fcntl_add_seals(&sealed, fs::SealFlags::SEAL).expect("add the final seal");
    assert_eq!(
        fs::fcntl_add_seals(&sealed, fs::SealFlags::GROW),
        Err(Errno::PERM),
    );
}
