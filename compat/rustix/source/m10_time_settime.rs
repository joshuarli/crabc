use api::{io, time};

fn main() {
    // Monotonic clocks are never settable.
    match time::clock_settime(
        time::ClockId::Monotonic,
        time::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    ) {
        Err(io::Errno::INVAL | io::Errno::PERM) => (),
        _otherwise => panic!(),
    }
    println!("m10-time-settime ok");
}
