use api::fs;

fn main() {
    let file = fs::memfd_create(
        &b"crabc-native-add-seals-source"[..],
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create sealing-capable memfd");

    let seals = fs::SealFlags::GROW | fs::SealFlags::SHRINK;
    fs::fcntl_add_seals(&file, seals).expect("add memfd seals");
    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read added seals"),
        seals,
    );
    println!("native-fcntl-add-seals ok");
}
