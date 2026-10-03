//! Link-free no-std proof for the direct readiness slice.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::{event, time};
#[cfg(not(target_arch = "x86_64"))]
use crabc_rs::pipe;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub extern "C" fn crabc_rs_readiness_direct_probe() -> i32 {
    let (reader, _writer) = match pipe::pipe() {
        Ok(pipe) => pipe,
        Err(error) => return -error.raw(),
    };
    let epoll = match event::epoll::create_legacy(1) {
        Ok(epoll) => epoll,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(1),
        event::epoll::EventFlags::IN,
    ) {
        return -error.raw();
    }

    let timeout = time::Timespec::default();
    let empty = crabc_rs::signal::SignalSet::EMPTY;
    let mut events = [MaybeUninit::uninit(); 1];
    match event::epoll::wait_with_mask(&epoll, &mut events, Some(&timeout), Some(&empty)) {
        Ok((ready, _)) if ready.is_empty() => {}
        Ok(_) => return 1,
        Err(error) => return -error.raw(),
    }

    let nfds = reader.as_raw_fd() + 1;
    let mut readfds = [event::FdSetElement::default(); 16];
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    // SAFETY: `reader` remains open and the one-element bit vector contains
    // every descriptor below `nfds` used by this probe.
    match unsafe { event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) } {
        Ok(0) => {}
        Ok(_) => return 2,
        Err(error) => return -error.raw(),
    }
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    // SAFETY: The same descriptor and initialized bit vector remain valid for
    // the direct pselect6 call.
    match unsafe {
        event::pselect(
            nfds,
            Some(&mut readfds),
            None,
            None,
            Some(&timeout),
            Some(&empty),
        )
    } {
        Ok(0) => 0,
        Ok(_) => 3,
        Err(error) => -error.raw(),
    }
}


/// Exercises readiness ownership in an isolated writable working directory.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn crabc_rs_readiness_direct_probe() -> i32 {
    match native_readiness() {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}

#[cfg(target_arch = "x86_64")]
fn native_readiness() -> crabc_rs::Result<()> {
    use crabc_rs::{fs, io, Errno};
    use crabc_rs::system::inotify::{CreateFlags, EventMask, Inotify};
    use event::epoll;

    fn require(condition: bool) -> crabc_rs::Result<()> {
        if condition { Ok(()) } else { Err(Errno::IO) }
    }

    let zero = time::Timespec { tv_sec: 0, tv_nsec: 0 };
    let flags = event::EventfdFlags::CLOEXEC | event::EventfdFlags::NONBLOCK;
    let counter = event::eventfd(0, flags)?;
    let retained = io::dup(&counter)?;
    let poller = epoll::create(epoll::CreateFlags::CLOEXEC)?;
    let token = 0x8172_6354_4536_2718;
    epoll::add(&poller, &counter, epoll::EventData::new_u64(token), epoll::EventFlags::IN)?;
    event::eventfd_write(&counter, 3)?;
    drop(counter);

    // The registration retains its original descriptor key while the
    // duplicate keeps that open file description and ready counter alive.
    let mut observations = [event::PollFd::new(&retained, event::PollFlags::IN | event::PollFlags::OUT)];
    require(event::poll(&mut observations, Some(&zero))? == 1)?;
    require(observations[0].revents() == event::PollFlags::IN | event::PollFlags::OUT)?;
    drop(observations);
    let mut storage = [MaybeUninit::uninit(); 3];
    let (ready, untouched) = epoll::wait(&poller, &mut storage, Some(&zero))?;
    require(ready.len() == 1 && untouched.len() == 2)?;
    let copied = ready[0];
    require(copied.flags() == epoll::EventFlags::IN && copied.data().u64() == token)?;
    require(event::eventfd_read(&retained)? == 3)?;
    drop(retained);
    require(epoll::wait(&poller, &mut storage, Some(&zero))?.0.is_empty())?;
    // A result owns only its packed token bits after the last source closes.
    require(copied.data().u64() == token)?;

    let counter = event::eventfd(1, flags)?;
    let oneshot = epoll::EventFlags::IN | epoll::EventFlags::ONESHOT;
    epoll::add(&poller, &counter, epoll::EventData::new_u64(91), oneshot)?;
    require(epoll::wait(&poller, &mut storage, Some(&zero))?.0.len() == 1)?;
    require(epoll::wait(&poller, &mut storage, Some(&zero))?.0.is_empty())?;
    epoll::modify(&poller, &counter, epoll::EventData::new_u64(92), oneshot)?;
    let (ready, _) = epoll::wait(&poller, &mut storage, Some(&zero))?;
    require(ready.len() == 1 && ready[0].data().u64() == 92)?;
    epoll::delete(&poller, &counter)?;
    require(epoll::wait(&poller, &mut storage, Some(&zero))?.0.is_empty())?;
    require(event::eventfd_read(&counter)? == 1)?;
    drop(counter);

    // All watched paths are created by this probe below its private cwd.
    fs::mkdir(c"readiness-directory", fs::Mode::RUSR | fs::Mode::WUSR | fs::Mode::XUSR)?;
    let watcher = Inotify::new(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)?;
    let watch = watcher.add_watch(c"readiness-directory", EventMask::CREATE)?;
    let retained = io::dup(watcher.as_fd())?;
    epoll::add(&poller, watcher.as_fd(), epoll::EventData::new_u64(93), epoll::EventFlags::IN)?;
    let file = fs::openat(fs::CWD, c"readiness-directory/created",
        fs::OFlags::WRONLY | fs::OFlags::CREATE | fs::OFlags::EXCL | fs::OFlags::CLOEXEC,
        fs::Mode::RUSR | fs::Mode::WUSR)?;
    drop(file);
    let mut bytes = [0u8; 256];
    let mut batch = watcher.read_events(&mut bytes)?;
    let record = batch.next().ok_or(Errno::IO)??;
    require(record.watch() == Some(watch) && record.mask() == EventMask::CREATE
        && record.name() == Some(b"created".as_slice()) && batch.next().is_none())?;
    watcher.remove_watch(watch)?;
    drop(watcher);
    let (ready, _) = epoll::wait(&poller, &mut storage, Some(&zero))?;
    require(ready.len() == 1 && ready[0].data().u64() == 93)?;
    let mut ignored = [0u8; 64];
    let count = io::read(&retained, &mut ignored)?;
    require(count == 16 && i32::from_ne_bytes(ignored[..4].try_into().unwrap()) == watch.as_raw()
        && u32::from_ne_bytes(ignored[4..8].try_into().unwrap()) == EventMask::IGNORED.bits())?;
    drop(retained);
    require(epoll::wait(&poller, &mut storage, Some(&zero))?.0.is_empty())?;
    // The read record borrows caller storage independently of descriptor and
    // watch lifetime; the second read used a separate buffer.
    require(record.name() == Some(b"created".as_slice()))?;
    fs::unlink(c"readiness-directory/created")?;
    fs::rmdir(c"readiness-directory")?;
    Ok(())
}
