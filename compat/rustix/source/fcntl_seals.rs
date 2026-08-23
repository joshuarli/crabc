use api::fs;

fn main() {
    let file = fs::memfd_create(
        &b"crabc-native-seals-source"[..],
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create sealing-capable memfd");

    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read initial seals"),
        fs::SealFlags::empty(),
    );
    println!("native-fcntl-seals ok");
}
