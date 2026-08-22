use api::{fs::Mode, process};

fn main() {
    let previous = process::umask(Mode::empty());
    assert_eq!(process::umask(previous), Mode::empty());
    println!("m10-process-umask ok");
}
