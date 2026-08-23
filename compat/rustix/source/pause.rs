use api::{event, process};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn main() {
    if std::env::args().nth(1).as_deref() == Some("pause-child") {
        // The parent supplies the terminating signal after observing this
        // marker. No handler is needed here: Rustix's pause contract is that
        // the call remains blocked until an external signal arrives.
        std::io::stdout().write_all(b"pause-ready\n").unwrap();
        std::io::stdout().flush().unwrap();
        event::pause();
        unreachable!("pause returned without a signal");
    }

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("pause-child")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn pause child");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .expect("read pause child readiness");
    assert_eq!(ready, "pause-ready\n");

    let pid = process::Pid::from_raw(child.id() as i32).expect("pause child pid");
    process::kill_process(pid, process::Signal::TERM).expect("interrupt pause child");
    assert!(!child.wait().expect("wait for pause child").success());
    println!("native-pause ok");
}
