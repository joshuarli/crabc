use api::{io, process};

fn main() {
    assert_eq!(
        process::chroot("/crabc-rs-native-chroot-does-not-exist"),
        Err(io::Errno::NOENT),
    );
    println!("native-process-chroot ok");
}
