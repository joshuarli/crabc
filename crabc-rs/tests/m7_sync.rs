use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crabc_rs::sync::{Barrier, Condvar, Mutex, Once, RwLock, Semaphore};
use crabc_rs::time::Timespec;
use crabc_rs::Errno;

#[test]
fn mutex_contention_and_reuse() {
    let value = Arc::new(Mutex::new(0u64));
    let mut workers = Vec::new();
    for _ in 0..6 {
        let value = Arc::clone(&value);
        workers.push(std::thread::spawn(move || {
            for _ in 0..2_000 {
                let mut guard = value.lock().expect("mutex lock");
                *guard += 1;
            }
        }));
    }
    for worker in workers {
        worker.join().expect("worker completed");
    }
    assert_eq!(*value.lock().expect("final mutex lock"), 12_000);

    assert!(value.try_lock().is_some());
}

#[test]
fn condvar_wakeup_reacquires_mutex() {
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_pair = Arc::clone(&pair);
    let worker = std::thread::spawn(move || {
        let (lock, condvar) = &*worker_pair;
        let mut ready = lock.lock().expect("worker mutex lock");
        *ready = true;
        condvar.notify_one().expect("notify worker");
    });

    let (lock, condvar) = &*pair;
    let mut ready = lock.lock().expect("main mutex lock");
    while !*ready {
        ready = condvar.wait(ready).expect("condition wait");
    }
    assert!(*ready);
    drop(ready);
    worker.join().expect("worker completed");
}

#[test]
fn condvar_timeout_is_reported_after_relock() {
    let lock = Mutex::new(());
    let condvar = Condvar::new();
    let guard = lock.lock().expect("mutex lock");
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let (guard, result) = condvar
        .wait_timeout(guard, &timeout)
        .expect("timed wait");
    assert!(result.timed_out());
    drop(guard);
    condvar.notify_all().expect("notify with no waiters");
}

#[test]
fn once_initializes_once_under_contention() {
    let once = Arc::new(Once::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let once = Arc::clone(&once);
        let calls = Arc::clone(&calls);
        workers.push(std::thread::spawn(move || {
            once.call_once(|| {
                calls.fetch_add(1, Ordering::SeqCst);
            })
            .expect("once call");
        }));
    }
    for worker in workers {
        worker.join().expect("worker completed");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    once.call_once(|| panic!("completed once must not run again"))
        .expect("completed once");
}

#[test]
fn semaphore_blocks_wakes_and_reports_capacity_errors() {
    let semaphore = Arc::new(Semaphore::new(0).expect("zero permits"));
    let started = Arc::new(AtomicBool::new(false));
    let worker_semaphore = Arc::clone(&semaphore);
    let worker_started = Arc::clone(&started);
    let worker = std::thread::spawn(move || {
        worker_started.store(true, Ordering::Release);
        worker_semaphore.acquire().expect("semaphore acquire");
    });
    while !started.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    std::thread::yield_now();
    semaphore.release().expect("semaphore release");
    worker.join().expect("semaphore worker completed");
    assert_eq!(semaphore.available(), 0);

    let semaphore = Semaphore::new(i32::MAX as u32).expect("maximum permits");
    assert_eq!(semaphore.release(), Err(crabc_rs::Errno::OVERFLOW));
    assert!(matches!(
        Semaphore::new(u32::MAX),
        Err(crabc_rs::Errno::INVAL)
    ));
}

#[test]
fn rwlock_excludes_writers_and_reuses_after_readers() {
    let lock = Arc::new(RwLock::new(0u32));
    let first_reader = lock.read().expect("first read lock");
    let second_reader = lock.read().expect("second read lock");
    assert_eq!(*first_reader, 0);
    assert_eq!(*second_reader, 0);
    assert!(lock.try_write().is_none(), "readers exclude a writer");

    let writer_started = Arc::new(AtomicBool::new(false));
    let writer_acquired = Arc::new(AtomicBool::new(false));
    let release_writer = Arc::new(AtomicBool::new(false));
    let writer_lock = Arc::clone(&lock);
    let writer_started_for_worker = Arc::clone(&writer_started);
    let writer_acquired_for_worker = Arc::clone(&writer_acquired);
    let release_writer_for_worker = Arc::clone(&release_writer);
    let writer = std::thread::spawn(move || {
        writer_started_for_worker.store(true, Ordering::Release);
        let mut value = writer_lock.write().expect("writer lock after readers");
        *value += 1;
        writer_acquired_for_worker.store(true, Ordering::Release);
        while !release_writer_for_worker.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    });
    while !writer_started.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    drop(first_reader);
    drop(second_reader);
    while !writer_acquired.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    assert!(lock.try_read().is_none(), "a writer excludes readers");
    release_writer.store(true, Ordering::Release);
    writer.join().expect("writer completed");

    // The background writer established the first post-contention value.
    // Reuse must then preserve that release/acquire publication over many
    // alternating exclusive/shared acquisitions.
    for expected in 2..=33 {
        {
            let mut value = lock.write().expect("reused write lock");
            assert_eq!(*value, expected - 1);
            *value = expected;
        }
        assert_eq!(*lock.read().expect("reused read lock"), expected);
    }
}

#[test]
fn barrier_releases_all_participants_and_reuses_generations() {
    const PARTICIPANTS: usize = 4;
    let barrier = Arc::new(Barrier::new(PARTICIPANTS).expect("valid participant count"));
    let arrived = Arc::new(AtomicUsize::new(0));
    let leaders = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();

    for _ in 0..PARTICIPANTS {
        let barrier = Arc::clone(&barrier);
        let arrived = Arc::clone(&arrived);
        let leaders = Arc::clone(&leaders);
        workers.push(std::thread::spawn(move || {
            arrived.fetch_add(1, Ordering::AcqRel);
            if barrier.wait().expect("first barrier generation").is_leader() {
                leaders.fetch_add(1, Ordering::AcqRel);
            }
            assert!(arrived.load(Ordering::Acquire) >= PARTICIPANTS);

            arrived.fetch_add(1, Ordering::AcqRel);
            if barrier.wait().expect("reused barrier generation").is_leader() {
                leaders.fetch_add(1, Ordering::AcqRel);
            }
        }));
    }
    for worker in workers {
        worker.join().expect("barrier participant completed");
    }

    assert_eq!(arrived.load(Ordering::Acquire), PARTICIPANTS * 2);
    assert_eq!(leaders.load(Ordering::Acquire), 2);
    assert!(matches!(Barrier::new(0), Err(Errno::INVAL)));
}
