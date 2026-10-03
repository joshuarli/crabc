use std::cell::RefCell;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_PATH: &str = "/tmp/crabc-rust-std-fixture.txt";
const DIRECTORY_PATH: &str = "/tmp/crabc-rust-std-fixture-dir";


// The TLS value owns memory received from the parent. Its destructor also
// allocates and frees on the worker before allocator thread teardown.
struct AllocationCleanup {
    completed: Arc<AtomicUsize>,
    parent_bytes: Vec<u8>,
}

impl Drop for AllocationCleanup {
    fn drop(&mut self) {
        assert!(self.parent_bytes.iter().all(|byte| *byte == 0x37));
        let worker_bytes = vec![0x71_u8; 32 * 1024];
        assert!(worker_bytes.iter().all(|byte| *byte == 0x71));
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

thread_local! {
    static ALLOCATION_CLEANUP: RefCell<Option<AllocationCleanup>> = const { RefCell::new(None) };
}

fn child_process() {
    let mut bytes = vec![0x37_u8; 4096];
    bytes.resize(64 * 1024, 0x71);
    assert!(bytes[..4096].iter().all(|byte| *byte == 0x37));
    assert!(bytes[4096..].iter().all(|byte| *byte == 0x71));
    drop(bytes);
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
    let completed = Arc::new(AtomicUsize::new(0));
    let cleanup = AllocationCleanup {
        completed: Arc::clone(&completed),
        parent_bytes: vec![0x37; 4096],
    };
    let worker = thread::spawn(move || {
        ALLOCATION_CLEANUP.with(|slot| *slot.borrow_mut() = Some(cleanup));
        let (lock, condition) = &*worker_state;
        let mut ready = lock.lock().expect("mutex poisoned");
        *ready = true;
        condition.notify_one();
        vec![0x7137_u32; 16 * 1024]
    });
    let (lock, condition) = &*state;
    let mut ready = lock.lock().expect("mutex poisoned");
    while !*ready {
        ready = condition.wait(ready).expect("condvar poisoned");
    }
    drop(ready);
    let worker_bytes = worker.join().expect("worker panicked");
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    assert_eq!(worker_bytes.len(), 16 * 1024);
    assert!(worker_bytes.iter().all(|word| *word == 0x7137));
    // Retain the worker's allocation across fork/exec after its TLS
    // destructors and allocator owner exit have completed.
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
    let mut command = Command::new(executable);
    // SAFETY: the fork-child callback allocates nothing, reads no shared
    // state, and returns directly before exec. A pre-exec callback selects
    // std's fork/exec route even when its spawn optimization is available.
    unsafe { command.pre_exec(|| Ok(())); }
    let child = command
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
    assert!(worker_bytes.iter().all(|word| *word == 0x7137));
    drop(worker_bytes);

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
