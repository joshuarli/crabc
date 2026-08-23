use api::{fs::Mode, process};

fn main() {
    let previous = process::umask(Mode::empty());
    assert_eq!(process::umask(previous), Mode::empty());
    println!("native-process-umask ok");
}
