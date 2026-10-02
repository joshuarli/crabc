//! Isolate the account parsers against pinned musl FILE and cancellation owners.
//! The exported account functions come directly from the candidate source;
//! this fixture does not qualify the owned FILE or thread runtime.
#![no_std]
#![allow(dead_code, unused_assignments)]
use core::ffi::{c_char,c_int,c_void};
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop {} }
macro_rules! static_archive_member { ($name:ident {$($body:tt)*}) => { $($body)* }; }
mod x86_64_static_c_abi {
    pub mod errno {
        unsafe extern "C" { fn __errno_location() -> *mut i32; }
        pub fn get_errno() -> i32 { unsafe { *__errno_location() } }
        pub fn set_errno(value:i32) { unsafe { *__errno_location()=value; } }
    }
    pub mod pthread_cancel {
        unsafe extern "C" { pub fn pthread_setcancelstate(state:i32, previous:*mut i32)->i32; }
    }
    pub mod stdio_standard {
        use crate::{c_char,c_int,c_void};
        pub type StandardStream=c_void;
        unsafe extern "C" {
            pub fn fopen(path:*const c_char,mode:*const c_char)->*mut StandardStream;
            pub fn fclose(stream:*mut StandardStream)->c_int;
            pub fn getline(line:*mut *mut c_char,size:*mut usize,stream:*mut StandardStream)->isize;
            pub fn ferror(stream:*mut StandardStream)->c_int;
            pub fn flockfile(stream:*mut StandardStream);
            pub fn funlockfile(stream:*mut StandardStream);
            pub fn fputc(byte:c_int,stream:*mut StandardStream)->c_int;
        }
    }
    pub mod stdio_format_scan {
        use crate::{c_char,c_int};
        use super::stdio_standard::StandardStream;
        unsafe extern "C" { pub fn fprintf(stream:*mut StandardStream,format:*const c_char,...)->c_int; }
    }
    pub mod credentials {
        unsafe extern "C" { pub fn setgroups(count:usize,groups:*const u32)->i32; }
    }
    #[path="/workspace/libc/src/c_abi/x86_64/owned_passwd.rs"] pub mod owned_passwd;
    #[path="/workspace/libc/src/c_abi/x86_64/owned_group.rs"] pub mod owned_group;
    #[path="/workspace/libc/src/c_abi/x86_64/protocol_database.rs"] pub mod protocol_database;
    #[path="/workspace/libc/src/c_abi/x86_64/service_lifecycle.rs"] pub mod service_lifecycle;
}
#[no_mangle]
pub extern "C" fn rust_eh_personality() { }
