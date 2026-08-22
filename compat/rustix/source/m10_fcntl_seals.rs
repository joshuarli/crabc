use api::fs;

fn main() {
    let file = fs::memfd_create(
        &b"crabc-m10-seals-source"[..],
        fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
    )
    .expect("create sealing-capable memfd");

    assert_eq!(
        fs::fcntl_get_seals(&file).expect("read initial seals"),
        fs::SealFlags::empty(),
    );
    println!("m10-fcntl-seals ok");
}
