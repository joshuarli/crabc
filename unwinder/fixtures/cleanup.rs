use std::backtrace::{Backtrace, BacktraceStatus};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

struct Cleanup(Arc<AtomicUsize>);
impl Drop for Cleanup {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}
#[inline(never)]
fn panic_leaf(count: Arc<AtomicUsize>) {
    let _cleanup = Cleanup(count);
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    std::panic::panic_any(73usize);
}
#[inline(never)]
fn panic_middle(count: Arc<AtomicUsize>) {
    let _cleanup = Cleanup(count.clone());
    panic_leaf(count);
}
fn check_cleanup() {
    let count = Arc::new(AtomicUsize::new(0));
    let result = std::panic::catch_unwind(|| panic_middle(count.clone()));
    assert_eq!(*result.unwrap_err().downcast::<usize>().unwrap(), 73);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    check_cleanup();
    std::thread::spawn(check_cleanup).join().unwrap();
    println!("unwind: backtrace cleanup payload main thread");
}
