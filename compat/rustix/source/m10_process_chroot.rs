use api::{io, process};

fn main() {
    assert_eq!(
        process::chroot("/crabc-rs-m10-chroot-does-not-exist"),
        Err(io::Errno::NOENT),
    );
    println!("m10-process-chroot ok");
}
