use api::{fs, process};

fn main() {
    let file = fs::memfd_create(
        &b"crabc-m10-fcntl-getlk-source"[..],
        fs::MemfdFlags::CLOEXEC,
    )
    .expect("create lock-query memfd");
    let query = process::Flock::from(process::FlockType::ReadLock);

    assert_eq!(
        process::fcntl_getlk(&file, &query).expect("query unlocked lock range"),
        None,
    );
    println!("m10-fcntl-getlk ok");
}
