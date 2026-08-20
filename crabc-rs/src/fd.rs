use core::fmt;
use core::marker::PhantomData;

/// The Linux file-descriptor integer representation.
pub type RawFd = i32;

/// A borrowed, non-owning file descriptor.
///
/// The lifetime records the requirement that some owner keeps the descriptor
/// open while this value is used. Constructing one from an integer is unsafe
/// because the type cannot verify that requirement or determine who owns the
/// underlying kernel object.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BorrowedFd<'fd> {
    fd: RawFd,
    _lifetime: PhantomData<&'fd ()>,
}

impl<'fd> BorrowedFd<'fd> {
    /// Borrows a raw descriptor for the lifetime chosen by the caller.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open file descriptor, and the resource owner must
    /// keep it open for the entire lifetime of the returned value. The value
    /// must not be closed through another alias during that lifetime. The sole
    /// exception is Linux's reserved `AT_FDCWD` token (`-100`), which is safe
    /// to borrow for use as the directory argument to `*at` operations.
    #[must_use]
    pub const unsafe fn borrow_raw(fd: RawFd) -> Self {
        assert!(
            fd >= 0 || fd == crabc_core::AT_FDCWD,
            "a borrowed file descriptor must be open or AT_FDCWD"
        );

        Self {
            fd,
            _lifetime: PhantomData,
        }
    }

    /// Returns the underlying descriptor without transferring ownership.
    #[must_use]
    pub const fn as_raw_fd(self) -> RawFd {
        self.fd
    }
}

impl fmt::Debug for BorrowedFd<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BorrowedFd")
            .field("fd", &self.fd)
            .finish()
    }
}

/// Borrows a descriptor from a value which keeps it open.
pub trait AsFd {
    /// Returns a descriptor borrow tied to `self`.
    fn as_fd(&self) -> BorrowedFd<'_>;
}

impl AsFd for BorrowedFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        *self
    }
}

impl<T: AsFd + ?Sized> AsFd for &T {
    fn as_fd(&self) -> BorrowedFd<'_> {
        (*self).as_fd()
    }
}

/// An owned file descriptor closed when it is dropped.
///
/// This type is the ownership boundary for descriptors returned by native
/// operations. Dropping it invokes the direct Linux syscall seam in
/// `crabc-core`; it never calls the public C ABI or transports an error through
/// thread-local `errno`.
#[repr(transparent)]
pub struct OwnedFd {
    fd: RawFd,
}

impl OwnedFd {
    /// Assumes ownership of an open raw descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open descriptor whose ownership is transferred to
    /// the returned value. It must be valid to release it with the Linux
    /// `close` operation, and no other owner may close it while this value
    /// exists.
    #[must_use]
    pub const unsafe fn from_raw_fd(fd: RawFd) -> Self {
        assert!(fd >= 0, "an owned file descriptor cannot be negative");

        Self { fd }
    }

    /// Returns the descriptor without transferring ownership.
    #[must_use]
    pub const fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Transfers ownership of the raw descriptor to the caller.
    #[must_use]
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }
}

impl AsFd for OwnedFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `OwnedFd` establishes that `self.fd` is open for the
        // duration of the borrow, and its constructor rejects negative values.
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl fmt::Debug for OwnedFd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedFd")
            .field("fd", &self.fd)
            .finish()
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // Closing errors cannot be returned from `Drop`. Retrying after an
        // interrupt could close a different descriptor that has been reused,
        // so the direct close result is intentionally discarded.
        let _ = crabc_core::io::close(self.fd);
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.as_raw_fd()
    }
}

#[cfg(feature = "std")]
impl std::os::fd::IntoRawFd for OwnedFd {
    fn into_raw_fd(self) -> std::os::fd::RawFd {
        OwnedFd::into_raw_fd(self)
    }
}

#[cfg(feature = "std")]
impl std::os::fd::FromRawFd for OwnedFd {
    unsafe fn from_raw_fd(fd: std::os::fd::RawFd) -> Self {
        // SAFETY: This trait has the same ownership precondition documented by
        // the inherent constructor.
        unsafe { Self::from_raw_fd(fd) }
    }
}

#[cfg(feature = "std")]
impl std::os::fd::AsFd for OwnedFd {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // SAFETY: `OwnedFd` keeps this non-negative descriptor open for the
        // returned borrow's lifetime.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.fd) }
    }
}

#[cfg(feature = "std")]
impl AsFd for std::os::fd::OwnedFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsRawFd;

        // SAFETY: std's `OwnedFd` holds an open descriptor while borrowed.
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

#[cfg(feature = "std")]
impl AsFd for std::os::fd::BorrowedFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsRawFd;

        // SAFETY: std's borrowed descriptor remains valid for `self`'s borrow.
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

#[cfg(feature = "std")]
impl From<std::os::fd::OwnedFd> for OwnedFd {
    fn from(fd: std::os::fd::OwnedFd) -> Self {
        use std::os::fd::IntoRawFd;

        // SAFETY: consuming std's RAII owner transfers its unique descriptor
        // ownership to crabc-rs.
        unsafe { Self::from_raw_fd(fd.into_raw_fd()) }
    }
}

#[cfg(feature = "std")]
impl From<OwnedFd> for std::os::fd::OwnedFd {
    fn from(fd: OwnedFd) -> Self {
        use std::os::fd::FromRawFd;

        // SAFETY: consuming crabc-rs's RAII owner transfers its unique
        // descriptor ownership to std.
        unsafe { Self::from_raw_fd(fd.into_raw_fd()) }
    }
}
