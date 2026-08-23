//! Link-free assembly probe for the direct Linux/AArch64 boundary.
//!
//! The archive reaches descriptor positioning/durability, epoll, timerfd, and
//! file-backed mappings through `crabc-core` only. Its verifier rejects a
//! public C ABI or TLS-errno route.

#![cfg_attr(not(feature = "std"), no_std)]

use core::mem::MaybeUninit;

use crabc_rs::{event, fs, io, mm, stdio, time};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_descriptor_mapping_probe() -> i32 {
    let file = match fs::open(
        "/tmp/crabc-rs-descriptor-static-probe",
        fs::OFlags::RDWR | fs::OFlags::CREATE,
        fs::Mode::RUSR | fs::Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = fs::ftruncate(&file, 4096) {
        return -error.raw();
    }
    if let Err(error) = fs::seek(&file, fs::SeekFrom::Start(0)) {
        return -error.raw();
    }
    if let Err(error) = fs::fsync(&file) {
        return -error.raw();
    }
    if let Err(error) = fs::fdatasync(&file) {
        return -error.raw();
    }

    let duplicate = match io::dup(&file) {
        Ok(duplicate) => duplicate,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = io::fcntl_setfd(&duplicate, io::FdFlags::CLOEXEC) {
        return -error.raw();
    }
    if let Err(error) = io::fcntl_getfd(&duplicate) {
        return -error.raw();
    }
    let fcntl_duplicate = match io::fcntl_dupfd(&file, duplicate.as_raw_fd() + 1) {
        Ok(duplicate) => duplicate,
        Err(error) => return -error.raw(),
    };
    let cloexec_duplicate = match io::fcntl_dupfd_cloexec(&file, fcntl_duplicate.as_raw_fd() + 1) {
        Ok(duplicate) => duplicate,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = io::fcntl_getfd(&cloexec_duplicate) {
        return -error.raw();
    }
    let mut target = match fs::open(
        "/tmp/crabc-rs-descriptor-static-target",
        fs::OFlags::RDWR | fs::OFlags::CREATE,
        fs::Mode::RUSR | fs::Mode::WUSR,
    ) {
        Ok(target) => target,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = io::dup2(&file, &mut target) {
        return -error.raw();
    }
    if let Err(error) = io::dup3(&file, &mut target, io::DupFlags::CLOEXEC) {
        return -error.raw();
    }
    let _ = (stdio::raw_stdin(), stdio::raw_stdout(), stdio::raw_stderr());

    let mapping = match unsafe {
        mm::mmap(
            core::ptr::null_mut(),
            4096,
            mm::ProtFlags::READ,
            mm::MapFlags::PRIVATE,
            &file,
            0,
        )
    } {
        Ok(mapping) => mapping,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = unsafe { mm::munmap(mapping, 4096) } {
        return -error.raw();
    }

    let readiness = match event::eventfd(0, event::EventfdFlags::CLOEXEC) {
        Ok(readiness) => readiness,
        Err(error) => return -error.raw(),
    };
    let epoll = match event::epoll::create(event::epoll::CreateFlags::CLOEXEC) {
        Ok(epoll) => epoll,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = event::epoll::add(
        &epoll,
        &readiness,
        event::epoll::EventData::new_u64(5),
        event::epoll::EventFlags::IN,
    ) {
        return -error.raw();
    }
    let mut events = [MaybeUninit::uninit(); 1];
    if let Err(error) = event::epoll::wait(&epoll, &mut events, Some(&time::Timespec::default())) {
        return -error.raw();
    }

    let timer =
        match time::timerfd_create(time::TimerfdClockId::Monotonic, time::TimerfdFlags::CLOEXEC) {
            Ok(timer) => timer,
            Err(error) => return -error.raw(),
        };
    if let Err(error) = time::timerfd_settime(
        &timer,
        time::TimerfdTimerFlags::empty(),
        &time::Itimerspec::default(),
    ) {
        return -error.raw();
    }
    if let Err(error) = time::timerfd_gettime(&timer) {
        return -error.raw();
    }
    0
}
