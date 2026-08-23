// syscall() - variadic forwarding through the concrete Linux/AArch64 boundary.

use super::{aarch64, c_int, c_long, ERRNO};

#[no_mangle]
pub unsafe extern "C" fn syscall(num: c_long, mut args: ...) -> c_long {
    let a: c_long = args.next_arg();
    let b: c_long = args.next_arg();
    let c: c_long = args.next_arg();
    let d: c_long = args.next_arg();
    let e: c_long = args.next_arg();
    let f: c_long = args.next_arg();

    let result = aarch64::syscall::syscall6(
        num as i64, a as i64, b as i64, c as i64, d as i64, e as i64, f as i64,
    );

    if (result as u64) > (-4096i64 as u64) {
        ERRNO = (-result) as c_int;
        return -1;
    }
    result as c_long
}
