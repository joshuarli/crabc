use core::num::NonZeroUsize;

/// One configured Linux base-page size supplied by the process-start owner.
///
/// The AArch64 profile accepts 4, 16, and 64 KiB; the x86-64 profile accepts
/// only 4 KiB. Keeping the value typed prevents future page-map and OS paths
/// from accidentally relying on another profile's common configuration.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageSize(NonZeroUsize);

impl PageSize {
    /// Validates one base-page size for the selected Linux target profile.
    #[inline]
    pub(crate) const fn new(bytes: usize) -> Option<Self> {
        match bytes {
            4_096 => {
                // SAFETY: The enumerated base-page size is non-zero.
                Some(Self(unsafe { NonZeroUsize::new_unchecked(bytes) }))
            }
            #[cfg(target_arch = "aarch64")]
            16_384 | 65_536 => {
                // SAFETY: Each enumerated base-page size is non-zero.
                Some(Self(unsafe { NonZeroUsize::new_unchecked(bytes) }))
            }
            _ => None,
        }
    }

    /// Returns the base-page byte size supplied at startup.
    #[inline]
    pub(crate) const fn bytes(self) -> usize {
        self.0.get()
    }
}
