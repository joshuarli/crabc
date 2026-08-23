//! Typed access to Linux ioctl protocols.
//!
//! The kernel provides one syscall for many unrelated device protocols. The
//! generic entry point is therefore unsafe: callers must establish the exact
//! request-specific memory, lifetime, and side-effect contract. Prefer the
//! safe request-specific helpers in [`crate::io`] whenever one exists.

use core::ffi::c_void;
use core::fmt;
use core::mem::MaybeUninit;
use core::ptr;

use crate::{AsFd, Result};

/// A Linux ioctl request code on AArch64.
pub type Opcode = u32;

/// The signed integer result reported by a successful ioctl.
pub type IoctlOutput = i32;

/// The data direction encoded into a Linux ioctl request.
///
/// Direction is relative to userspace: `Read` means the kernel writes into
/// caller-provided memory and `Write` means it reads caller-provided memory.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    /// The request transfers no typed data.
    None,
    /// The kernel writes data to userspace.
    Read,
    /// The kernel reads data from userspace.
    Write,
    /// The kernel both reads and writes the same userspace object.
    ReadWrite,
}

/// Linux `_IOC` request-code constructors for AArch64.
pub mod opcode {
    use super::{Direction, Opcode};
    use core::mem;

    const NUMBER_MASK: Opcode = (1 << 8) - 1;
    const GROUP_MASK: Opcode = (1 << 8) - 1;
    const SIZE_MASK: Opcode = (1 << 14) - 1;
    const DIRECTION_MASK: Opcode = (1 << 2) - 1;
    const GROUP_SHIFT: Opcode = 8;
    const SIZE_SHIFT: Opcode = 16;
    const DIRECTION_SHIFT: Opcode = 30;

    /// Builds a Linux `_IOC` request code from its encoded components.
    #[inline]
    pub const fn from_components(
        direction: Direction,
        group: u8,
        number: u8,
        data_size: usize,
    ) -> Opcode {
        assert!(
            data_size <= SIZE_MASK as usize,
            "ioctl payload is too large"
        );
        let direction = match direction {
            Direction::None => 0,
            Direction::Read => 2,
            Direction::Write => 1,
            Direction::ReadWrite => 3,
        };
        ((number as Opcode) & NUMBER_MASK)
            | (((group as Opcode) & GROUP_MASK) << GROUP_SHIFT)
            | (((data_size as Opcode) & SIZE_MASK) << SIZE_SHIFT)
            | ((direction & DIRECTION_MASK) << DIRECTION_SHIFT)
    }

    /// Builds a Linux `_IO` request code.
    #[inline]
    pub const fn none(group: u8, number: u8) -> Opcode {
        from_components(Direction::None, group, number, 0)
    }

    /// Builds a Linux `_IOR` request code.
    #[inline]
    pub const fn read<T>(group: u8, number: u8) -> Opcode {
        from_components(Direction::Read, group, number, mem::size_of::<T>())
    }

    /// Builds a Linux `_IOW` request code.
    #[inline]
    pub const fn write<T>(group: u8, number: u8) -> Opcode {
        from_components(Direction::Write, group, number, mem::size_of::<T>())
    }

    /// Builds a Linux `_IOWR` request code.
    #[inline]
    pub const fn read_write<T>(group: u8, number: u8) -> Opcode {
        from_components(Direction::ReadWrite, group, number, mem::size_of::<T>())
    }
}

/// Describes one ioctl protocol invocation.
///
/// # Safety
///
/// Implementing this trait asserts all of the following for the target Linux
/// driver: `opcode` identifies the operation; `as_ptr` provides the exact
/// argument representation and remains valid for the call; the declared
/// mutability agrees with kernel behavior; and `output_from_ptr` reads only
/// data initialized by a successful operation. The ioctl's side effects must
/// also preserve Rust's memory and aliasing invariants.
pub unsafe trait Ioctl {
    /// The request's typed result.
    type Output;

    /// Whether the kernel may mutate memory reachable through [`Self::as_ptr`].
    const IS_MUTATING: bool;

    /// Returns the Linux request code.
    fn opcode(&self) -> Opcode;

    /// Returns the request-specific argument bits.
    fn as_ptr(&mut self) -> *mut c_void;

    /// Produces the typed result after a successful syscall.
    ///
    /// # Safety
    ///
    /// `argument` is the same pointer returned by [`Self::as_ptr`] for this
    /// request, and `output` is a successful kernel result.
    unsafe fn output_from_ptr(output: IoctlOutput, argument: *mut c_void) -> Result<Self::Output>;
}

/// Performs a typed ioctl directly through crabc-core.
///
/// # Safety
///
/// See [`Ioctl`]. The typed request narrows the raw ABI but cannot prove a
/// third-party driver follows the claimed protocol.
#[inline]
pub unsafe fn ioctl<Fd: AsFd, Request: Ioctl>(
    fd: Fd,
    mut request: Request,
) -> Result<Request::Output> {
    let fd = fd.as_fd();
    let opcode = request.opcode();
    let argument = request.as_ptr();
    // SAFETY: The caller upholds the request contract; crabc-core merely
    // performs Linux syscall 29 and does not interpret the request memory.
    let output = unsafe { crabc_core::io::ioctl_raw(fd.as_raw_fd(), opcode, argument.cast())? };
    // SAFETY: A successful direct syscall returned the same argument bits to
    // the request implementation which established its output contract.
    unsafe { Request::output_from_ptr(output, argument) }
}

/// A no-argument ioctl request.
pub struct NoArg<const OPCODE: Opcode>;

impl<const OPCODE: Opcode> NoArg<OPCODE> {
    /// Builds a no-argument request.
    ///
    /// # Safety
    ///
    /// `OPCODE` must be a valid no-argument ioctl for the supplied descriptor.
    #[inline]
    pub const unsafe fn new() -> Self {
        Self
    }
}

impl<const OPCODE: Opcode> fmt::Debug for NoArg<OPCODE> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("NoArg").field(&OPCODE).finish()
    }
}

unsafe impl<const OPCODE: Opcode> Ioctl for NoArg<OPCODE> {
    type Output = ();
    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        OPCODE
    }

    fn as_ptr(&mut self) -> *mut c_void {
        ptr::null_mut()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, _: *mut c_void) -> Result<Self::Output> {
        Ok(())
    }
}

/// A request which initializes one typed value.
pub struct Getter<const OPCODE: Opcode, Output> {
    output: MaybeUninit<Output>,
}

impl<const OPCODE: Opcode, Output> Getter<OPCODE, Output> {
    /// Builds a getter request.
    ///
    /// # Safety
    ///
    /// `OPCODE` must initialize an `Output` value when it succeeds.
    #[inline]
    pub const unsafe fn new() -> Self {
        Self {
            output: MaybeUninit::uninit(),
        }
    }
}

impl<const OPCODE: Opcode, Output> fmt::Debug for Getter<OPCODE, Output> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Getter").field(&OPCODE).finish()
    }
}

unsafe impl<const OPCODE: Opcode, Output> Ioctl for Getter<OPCODE, Output> {
    type Output = Output;
    const IS_MUTATING: bool = true;

    fn opcode(&self) -> Opcode {
        OPCODE
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.output.as_mut_ptr().cast()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, argument: *mut c_void) -> Result<Self::Output> {
        // SAFETY: The `Getter` construction contract establishes that a
        // successful request initialized an `Output` at this argument.
        Ok(unsafe { argument.cast::<Output>().read() })
    }
}

/// A request which passes one immutable typed input value.
pub struct Setter<const OPCODE: Opcode, Input> {
    input: Input,
}

impl<const OPCODE: Opcode, Input> Setter<OPCODE, Input> {
    /// Builds a setter request.
    ///
    /// # Safety
    ///
    /// `OPCODE` must accept an immutable `Input` at the provided pointer.
    #[inline]
    pub const unsafe fn new(input: Input) -> Self {
        Self { input }
    }
}

impl<const OPCODE: Opcode, Input: fmt::Debug> fmt::Debug for Setter<OPCODE, Input> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Setter")
            .field(&OPCODE)
            .field(&self.input)
            .finish()
    }
}

unsafe impl<const OPCODE: Opcode, Input> Ioctl for Setter<OPCODE, Input> {
    type Output = ();
    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        OPCODE
    }

    fn as_ptr(&mut self) -> *mut c_void {
        ptr::addr_of_mut!(self.input).cast()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, _: *mut c_void) -> Result<Self::Output> {
        Ok(())
    }
}

/// A request which may read and update one caller-owned value.
pub struct Updater<'a, const OPCODE: Opcode, Value> {
    value: &'a mut Value,
}

impl<'a, const OPCODE: Opcode, Value> Updater<'a, OPCODE, Value> {
    /// Builds an updating request.
    ///
    /// # Safety
    ///
    /// `OPCODE` must accept and update exactly the supplied `Value`.
    #[inline]
    pub unsafe fn new(value: &'a mut Value) -> Self {
        Self { value }
    }
}

unsafe impl<const OPCODE: Opcode, Value> Ioctl for Updater<'_, OPCODE, Value> {
    type Output = ();
    const IS_MUTATING: bool = true;

    fn opcode(&self) -> Opcode {
        OPCODE
    }

    fn as_ptr(&mut self) -> *mut c_void {
        (self.value as *mut Value).cast()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, _: *mut c_void) -> Result<Self::Output> {
        Ok(())
    }
}

/// A request whose third syscall argument is an immediate integer.
///
/// This intentionally keeps integer and pointer construction separate in the
/// public API. The Linux syscall ABI represents both in one register, but a
/// request author must opt into the integer interpretation explicitly.
pub struct IntegerSetter<const OPCODE: Opcode> {
    value: *mut c_void,
}

impl<const OPCODE: Opcode> IntegerSetter<OPCODE> {
    /// Builds an integer-argument request from a raw integer bit pattern.
    ///
    /// # Safety
    ///
    /// `OPCODE` must expect this integer value rather than a dereferenceable
    /// pointer.
    #[inline]
    pub const unsafe fn new_usize(value: usize) -> Self {
        Self {
            value: value as *mut c_void,
        }
    }

    /// Builds an integer-argument request from an already-provenance-bearing
    /// pointer value.
    ///
    /// # Safety
    ///
    /// `OPCODE` must interpret the argument bits as an immediate integer.
    #[inline]
    pub const unsafe fn new_pointer(value: *mut c_void) -> Self {
        Self { value }
    }
}

unsafe impl<const OPCODE: Opcode> Ioctl for IntegerSetter<OPCODE> {
    type Output = ();
    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        OPCODE
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.value
    }

    unsafe fn output_from_ptr(_: IoctlOutput, _: *mut c_void) -> Result<Self::Output> {
        Ok(())
    }
}
