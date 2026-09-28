// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from unwinding 0.2.10, src/util.rs.
// The reader never dereferences target metadata directly. It copies exact
// ranges through a kernel self-read and retains only a bounded value cache.
use gimli::{NativeEndian, Pointer};
#[cfg(target_arch = "x86_64")]
use core::convert::TryFrom;
#[cfg(target_arch = "x86_64")]
use gimli::{Reader, ReaderOffsetId};
#[cfg(target_arch = "x86_64")]
pub type StaticSlice = RemoteSlice;
#[cfg(not(target_arch = "x86_64"))]
pub type StaticSlice = gimli::EndianSlice<'static, NativeEndian>;

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteSlice {
    address: usize,
    len: usize,
    cache_address: usize,
    cache_len: usize,
    cache: [u8; 128],
}

#[cfg(target_arch = "x86_64")]
impl RemoteSlice {
    pub fn new(address: usize, len: usize, maximum: usize) -> Result<Self, gimli::Error> {
        if address == 0 || len == 0 || len > maximum || address.checked_add(len).is_none() {
            return Err(gimli::Error::OffsetOutOfBounds(address as u64));
        }
        Ok(Self { address, len, cache_address: 0, cache_len: 0, cache: [0; 128] })
    }

    pub fn probe_all(&self) -> Result<(), gimli::Error> {
        let mut bytes = [0u8; 4096];
        let mut offset = 0;
        while offset < self.len {
            let length = (self.len - offset).min(bytes.len());
            self.read_at(offset, &mut bytes[..length])?;
            offset += length;
        }
        Ok(())
    }

    fn read_at(&self, offset: usize, bytes: &mut [u8]) -> Result<(), gimli::Error> {
        use core::arch::asm;
        let remote_address = self.address.checked_add(offset)
            .ok_or(gimli::Error::OffsetOutOfBounds(self.address as u64))?;
        if bytes.is_empty() { return Ok(()); }
        if offset > self.len || bytes.len() > self.len - offset {
            return Err(gimli::Error::UnexpectedEof(ReaderOffsetId(remote_address as u64)));
        }
        let mut pid = libc::SYS_getpid as isize;
        unsafe {
            asm!("syscall", inlateout("rax") pid, lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        if pid <= 0 {
            return Err(gimli::Error::OffsetOutOfBounds(remote_address as u64));
        }
        let local = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
        let remote = libc::iovec { iov_base: remote_address as *mut _, iov_len: bytes.len() };
        let mut copied = libc::SYS_process_vm_readv as isize;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") copied,
                in("rdi") pid,
                in("rsi") &local,
                in("rdx") 1usize,
                in("r10") &remote,
                in("r8") 1usize,
                in("r9") 0usize,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if copied == bytes.len() as isize { Ok(()) }
        else { Err(gimli::Error::OffsetOutOfBounds(remote_address as u64)) }
    }
}

#[cfg(target_arch = "x86_64")]
impl Reader for RemoteSlice {
    type Endian = NativeEndian;
    type Offset = usize;

    fn endian(&self) -> NativeEndian { NativeEndian }
    fn len(&self) -> usize { self.len }
    fn empty(&mut self) { self.len = 0; }
    fn truncate(&mut self, len: usize) -> Result<(), gimli::Error> {
        if len > self.len { return Err(gimli::Error::UnexpectedEof(self.offset_id())); }
        self.len = len;
        Ok(())
    }
    fn offset_from(&self, base: &Self) -> usize { self.address.wrapping_sub(base.address) }
    fn offset_id(&self) -> ReaderOffsetId { ReaderOffsetId(self.address as u64) }
    fn lookup_offset_id(&self, id: ReaderOffsetId) -> Option<usize> {
        let addr = usize::try_from(id.0).ok()?;
        if addr >= self.address && addr <= self.address.checked_add(self.len)? {
            Some(addr - self.address)
        } else { None }
    }
    fn find(&self, byte: u8) -> Result<usize, gimli::Error> {
        let mut offset = 0;
        let mut chunk = [0u8; 128];
        while offset < self.len {
            let length = (self.len - offset).min(chunk.len());
            self.read_at(offset, &mut chunk[..length])?;
            if let Some(index) = chunk[..length].iter().position(|value| *value == byte) {
                return Ok(offset + index);
            }
            offset += length;
        }
        Err(gimli::Error::UnexpectedEof(self.offset_id()))
    }
    fn skip(&mut self, len: usize) -> Result<(), gimli::Error> {
        if len > self.len { return Err(gimli::Error::UnexpectedEof(self.offset_id())); }
        self.address += len;
        self.len -= len;
        Ok(())
    }
    fn split(&mut self, len: usize) -> Result<Self, gimli::Error> {
        if len > self.len { return Err(gimli::Error::UnexpectedEof(self.offset_id())); }
        let mut first = *self;
        first.len = len;
        self.skip(len)?;
        Ok(first)
    }
    fn read_slice(&mut self, bytes: &mut [u8]) -> Result<(), gimli::Error> {
        if bytes.len() > self.len {
            return Err(gimli::Error::UnexpectedEof(self.offset_id()));
        }
        if bytes.len() >= self.cache.len() {
            self.read_at(0, bytes)?;
            return self.skip(bytes.len());
        }
        let mut filled = 0;
        while filled < bytes.len() {
            let cache_end = self.cache_address.saturating_add(self.cache_len);
            if self.address < self.cache_address || self.address >= cache_end {
                let length = self.len.min(self.cache.len());
                let mut fresh = [0u8; 128];
                self.read_at(0, &mut fresh[..length])?;
                self.cache = fresh;
                self.cache_address = self.address;
                self.cache_len = length;
            }
            let cached = self.address - self.cache_address;
            let length = (bytes.len() - filled).min(self.cache_len - cached);
            bytes[filled..filled + length].copy_from_slice(&self.cache[cached..cached + length]);
            self.skip(length)?;
            filled += length;
        }
        Ok(())
    }
}

pub unsafe fn get_unlimited_slice<'a>(start: *const u8) -> &'a [u8] {
    // Create the largest possible slice for this address.
    let start = start as usize;
    let end = start.saturating_add(isize::MAX as _);
    let len = end - start;
    unsafe { core::slice::from_raw_parts(start as *const _, len) }
}

pub unsafe fn deref_pointer(ptr: Pointer) -> usize {
    match ptr {
        Pointer::Direct(x) => x as _,
        Pointer::Indirect(x) => unsafe { *(x as *const _) },
    }
}

#[cfg(feature = "libc")]
pub use libc::c_int;

#[cfg(not(feature = "libc"))]
#[allow(non_camel_case_types)]
pub type c_int = i32;

#[cfg(all(
    any(feature = "panic", feature = "panic-handler-dummy"),
    feature = "libc"
))]
pub fn abort() -> ! {
    unsafe { libc::abort() };
}

#[cfg(all(
    any(feature = "panic", feature = "panic-handler-dummy"),
    not(feature = "libc")
))]
pub fn abort() -> ! {
    core::intrinsics::abort();
}
