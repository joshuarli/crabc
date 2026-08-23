// ptrace is variadic in the public ABI, but Linux always consumes the same
// request, pid, address, and data register tuple.  Keep that tuple explicit
// so the kernel, rather than libc, remains authoritative for permissions and
// request-specific validation.


const CABI_SYS_PTRACE: i64 = 117;

#[no_mangle]
pub unsafe extern "C" fn ptrace(request: c_int, mut args: ...) -> c_long {
    let pid = args.next_arg::<c_int>();
    let address = args.next_arg::<*mut c_void>();
    let data = args.next_arg::<*mut c_void>();
    syscall_result(aarch64::syscall::syscall4(
        CABI_SYS_PTRACE,
        request as i64,
        pid as i64,
        address as i64,
        data as i64,
    )) as c_long
}
