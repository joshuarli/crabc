use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_PATH: &str = "/tmp/crabc-rust-std-fixture.txt";
const DIRECTORY_PATH: &str = "/tmp/crabc-rust-std-fixture-dir";

fn child_process() {
    println!("rust-std-child:ok");
}

fn run() -> io::Result<()> {
    if env::var_os("CRABC_RUST_STD_CHILD").is_some() {
        child_process();
        return Ok(());
    }

    let values = vec![3_u32, 1, 4, 1, 5, 9];
    println!("allocation:{}", values.iter().sum::<u32>());
    let mut text = String::from("crab");
    text.push_str("c");
    println!("vec-string:{}:{}", values.len(), text);

    let _ = fs::remove_file(FILE_PATH);
    fs::write(FILE_PATH, b"musl-rust-std")?;
    let contents = fs::read_to_string(FILE_PATH)?;
    println!("filesystem:{}", contents);

    let _ = fs::remove_dir_all(DIRECTORY_PATH);
    fs::create_dir(DIRECTORY_PATH)?;
    fs::write(format!("{DIRECTORY_PATH}/a"), b"a")?;
    fs::write(format!("{DIRECTORY_PATH}/b"), b"b")?;
    let directory_count = fs::read_dir(DIRECTORY_PATH)?.count();
    println!("directories:{}", directory_count);

    let environment = env::var("CRABC_RUST_STD_TEST")
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "test environment"))?;
    println!("environment:{}", environment);
    let clock_is_after_epoch = SystemTime::now().duration_since(UNIX_EPOCH).is_ok();
    println!("time:{}", clock_is_after_epoch);

    let state = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || {
        let (lock, condition) = &*worker_state;
        let mut ready = lock.lock().expect("mutex poisoned");
        *ready = true;
        condition.notify_one();
    });
    let (lock, condition) = &*state;
    let mut ready = lock.lock().expect("mutex poisoned");
    while !*ready {
        ready = condition.wait(ready).expect("condvar poisoned");
    }
    drop(ready);
    worker.join().expect("worker panicked");
    println!("threads:ok");

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request)?;
        if request != *b"ping" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tcp request"));
        }
        stream.write_all(b"pong")
    });
    let mut client = TcpStream::connect(address)?;
    client.write_all(b"ping")?;
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    server.join().expect("tcp server panicked")?;
    println!("tcp:{}", String::from_utf8_lossy(&response));

    let sender = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver = UdpSocket::bind(("127.0.0.1", 0))?;
    sender.send_to(b"datagram", receiver.local_addr()?)?;
    let mut packet = [0_u8; 16];
    let (length, _) = receiver.recv_from(&mut packet)?;
    println!("udp:{}", String::from_utf8_lossy(&packet[..length]));

    let dns_count = ("localhost", 80).to_socket_addrs()?.count();
    println!("dns:{}", dns_count);

    let executable = env::current_exe()?;
    let child = Command::new(executable)
        .env("CRABC_RUST_STD_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other("child process failed"));
    }
    let child_stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    println!("process:{}", child_stdout);

    let _ = fs::remove_file(FILE_PATH);
    let _ = fs::remove_dir_all(DIRECTORY_PATH);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rust-std-error:{error}");
        std::process::exit(1);
    }
}
