//! Common Rustix/crabc-rs source fixture for calling-thread credentials.
//!
//! All three all-ones words are Linux's no-change request, so this fixture
//! does not alter the credentials of the process running the comparison.

use api::thread;

fn main() {
    thread::set_thread_res_uid(
        Option::<thread::Uid>::None,
        Option::<thread::Uid>::None,
        Option::<thread::Uid>::None,
    )
    .expect("setresuid no-change request");
    thread::set_thread_res_gid(
        Option::<thread::Gid>::None,
        Option::<thread::Gid>::None,
        Option::<thread::Gid>::None,
    )
    .expect("setresgid no-change request");
    println!("m10-thread-credentials ok");
}
