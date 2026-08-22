use api::{io, process};

fn main() {
    match process::pidfd_open(process::getpid(), process::PidfdFlags::empty()) {
        Ok(pidfd) => {
            drop(pidfd);
            println!("m10-pidfd-open ok");
        }
        Err(io::Errno::NOSYS) => println!("m10-pidfd-open unsupported"),
        Err(error) => panic!("open a pidfd for the current process: {error:?}"),
    }
}
