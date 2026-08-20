use core::mem::MaybeUninit;

use api::{io, pipe, rand, time};

fn main() {
    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::CLOEXEC).expect("pipe2");
    assert_eq!(io::write(&writer, b"m3").unwrap(), 2);
    let mut received = [MaybeUninit::uninit(); 4];
    let (received, remainder) = io::read(&reader, &mut received).unwrap();
    assert_eq!(received, b"m3");
    assert_eq!(remainder.len(), 2);

    let mut random = [MaybeUninit::uninit(); 32];
    let (random, remainder) = rand::getrandom(&mut random, rand::GetRandomFlags::empty())
        .expect("getrandom");
    assert_eq!(random.len() + remainder.len(), 32);
    assert!(!random.is_empty());

    let resolution = time::clock_getres(time::ClockId::Monotonic);
    assert!(resolution.tv_sec >= 0);
    assert!((0..1_000_000_000).contains(&resolution.tv_nsec));
    let before = time::clock_gettime(time::ClockId::Monotonic);
    let after = time::clock_gettime(time::ClockId::Monotonic);
    assert!((after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec));
    println!("m3-time-pipe-random ok");
}
