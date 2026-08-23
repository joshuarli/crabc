//! Link-free no-std probe for the direct futex synchronization seam.

#![no_std]

use crabc_rs::sync::{Barrier, Condvar, Mutex, Once, RwLock, Semaphore};
use crabc_rs::time::Timespec;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_synchronization_probe() -> i32 {
    let mutex = Mutex::new(7u32);
    let mut guard = match mutex.try_lock() {
        Some(guard) => guard,
        None => return 1,
    };
    *guard += 1;
    drop(guard);

    let condvar = Condvar::new();
    let guard = match mutex.lock() {
        Ok(guard) => guard,
        Err(error) => return -error.raw(),
    };
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let (guard, timed) = match condvar.wait_timeout(guard, &timeout) {
        Ok(value) => value,
        Err(error) => return -error.raw(),
    };
    drop(guard);
    if !timed.timed_out() {
        return 2;
    }
    if condvar.notify_one().is_err() || condvar.notify_all().is_err() {
        return 3;
    }

    let once = Once::new();
    if once.call_once(|| {}).is_err() || once.call_once(|| {}).is_err() {
        return 4;
    }

    let semaphore = match Semaphore::new(1) {
        Ok(semaphore) => semaphore,
        Err(error) => return -error.raw(),
    };
    if semaphore.acquire().is_err()
        || semaphore.release().is_err()
        || semaphore.try_acquire().ok() != Some(true)
    {
        return 5;
    }

    let rwlock = RwLock::new(11u32);
    let reader = match rwlock.try_read() {
        Some(reader) => reader,
        None => return 6,
    };
    if *reader != 11 || rwlock.try_write().is_some() {
        return 7;
    }
    drop(reader);
    let mut writer = match rwlock.write() {
        Ok(writer) => writer,
        Err(error) => return -error.raw(),
    };
    *writer += 1;
    drop(writer);
    let reader = match rwlock.read() {
        Ok(reader) => reader,
        Err(error) => return -error.raw(),
    };
    if *reader != 12 {
        return 8;
    }
    drop(reader);

    let barrier = match Barrier::new(1) {
        Ok(barrier) => barrier,
        Err(error) => return -error.raw(),
    };
    match barrier.wait() {
        Ok(result) if result.is_leader() => {}
        _ => return 9,
    }
    0
}
