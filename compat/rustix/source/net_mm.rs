use core::mem::MaybeUninit;

use api::{mm, net};

fn main() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("socketpair");
    assert_eq!(net::send(&sender, b"os", net::SendFlags::empty()).unwrap(), 2);
    let mut received = [MaybeUninit::uninit(); 4];
    let ((received, remainder), received_length) = net::recv(
        &receiver,
        &mut received,
        net::RecvFlags::empty(),
    )
    .unwrap();
    assert_eq!(received_length, 2);
    assert_eq!(received, b"os");
    assert_eq!(remainder.len(), 2);

    let length = 4096;
    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            length,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("mmap anonymous");
    let byte = mapping.cast::<u8>();
    unsafe { byte.write(0x5a) };
    unsafe { mm::mprotect(mapping, length, mm::MprotectFlags::READ) }.unwrap();
    assert_eq!(unsafe { byte.read() }, 0x5a);
    unsafe { mm::mprotect(mapping, length, mm::MprotectFlags::READ | mm::MprotectFlags::WRITE) }
        .unwrap();
    unsafe { mm::munmap(mapping, length) }.unwrap();
    println!("os-net-mm ok");
}
