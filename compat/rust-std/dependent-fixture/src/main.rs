use async_net::{TcpListener, TcpStream};
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use smol::Task;
use std::cell::RefCell;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

const FILE_PATH: &str = "/tmp/crabc-rust-dependent-file.txt";
const DIRECTORY_PATH: &str = "/tmp/crabc-rust-dependent-dir";

type BoxError = Box<dyn Error + Send + Sync>;


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
    println!("dependent-child:ok");
}

async fn async_round_trip() -> Result<String, BoxError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let server: Task<Result<(), BoxError>> = smol::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        if request != *b"ping" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "async request").into());
        }
        stream.write_all(b"pong").await?;
        Ok(())
    });
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"ping").await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    server.await?;
    Ok(String::from_utf8(response)?)
}

fn synchronization() -> Result<(), BoxError> {
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
    let worker_bytes = worker.join().map_err(|_| io::Error::other("worker panicked"))?;
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    assert_eq!(worker_bytes.len(), 16 * 1024);
    assert!(worker_bytes.iter().all(|word| *word == 0x7137));
    // The worker's allocation remains readable after its TLS destructors
    // and allocator owner exit; its final free belongs to this parent.
    drop(worker_bytes);
    Ok(())
}

fn run() -> Result<(), BoxError> {
    if env::var_os("CRABC_RUST_DEPENDENT_CHILD").is_some() {
        child_process();
        return Ok(());
    }

    let values = vec![2_u32, 7, 1, 8, 2, 8];
    println!("allocation:{}", values.iter().sum::<u32>());

    let _ = fs::remove_file(FILE_PATH);
    fs::write(FILE_PATH, b"dependency payload\n")?;
    println!("filesystem:{}", fs::read_to_string(FILE_PATH)?.trim_end());

    let _ = fs::remove_dir_all(DIRECTORY_PATH);
    fs::create_dir(DIRECTORY_PATH)?;
    fs::write(format!("{DIRECTORY_PATH}/entry"), b"entry")?;
    println!("directories:{}", fs::read_dir(DIRECTORY_PATH)?.count());

    synchronization()?;
    println!("synchronization:ok");

    let response = smol::block_on(async_round_trip())?;
    println!("async-tcp:{response}");

    let missing = "/tmp/crabc-rust-dependent-missing";
    let _ = fs::remove_file(missing);
    let error_kind = match fs::read(missing) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => "not-found",
        Err(_) => "other-error",
        Ok(_) => "unexpected-success",
    };
    println!("error:{error_kind}");

    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    // SAFETY: the fork-child callback allocates nothing, reads no shared
    // state, and returns directly before exec. A pre-exec callback selects
    // std's fork/exec route even when its spawn optimization is available.
    unsafe { command.pre_exec(|| Ok(())); }
    let child = command
        .env("CRABC_RUST_DEPENDENT_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other("child process failed").into());
    }
    let child_stdout = String::from_utf8(output.stdout)?.trim().to_owned();
    println!("process:{child_stdout}");

    let _ = fs::remove_file(FILE_PATH);
    let _ = fs::remove_dir_all(DIRECTORY_PATH);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dependent-error:{error}");
        std::process::exit(1);
    }
}
