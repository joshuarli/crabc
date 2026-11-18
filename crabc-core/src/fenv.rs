//! Floating-point environment operations.

use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign};

#[cfg(target_arch = "aarch64")]
#[path = "fenv/aarch64.rs"]
mod arch;
#[cfg(target_arch = "x86_64")]
#[path = "fenv/x86_64.rs"]
mod arch;
pub use arch::*;

/// The five ISO C floating-point exception flags in the target register encoding.
///
/// On x86-64 the denormal-operand status bit is preserved but not exposed.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ExceptionFlags(u32);

impl ExceptionFlags {
    /// No pending floating-point exceptions.
    pub const EMPTY: Self = Self(0);
    /// Invalid-operation exception.
    pub const INVALID: Self = Self(0x01);
    /// Division-by-zero exception.
    pub const DIVIDE_BY_ZERO: Self = Self(arch::DIVIDE_BY_ZERO);
    /// Overflow exception.
    pub const OVERFLOW: Self = Self(arch::OVERFLOW);
    /// Underflow exception.
    pub const UNDERFLOW: Self = Self(arch::UNDERFLOW);
    /// Inexact-result exception.
    pub const INEXACT: Self = Self(arch::INEXACT);
    /// All five exception flags represented by this API.
    pub const ALL: Self = Self(arch::EXCEPTION_MASK);

    /// Creates flags if `bits` contains only the five supported flags.
    #[inline]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Creates flags after discarding bits outside the supported set.
    #[inline]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Returns the target register-compatible bit representation.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether no exception flag is selected.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns whether every flag in `other` is selected.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether at least one flag in `other` is selected.
    #[inline]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for ExceptionFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self::from_bits_truncate(self.0 | rhs.0)
    }
}

impl BitOrAssign for ExceptionFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitAnd for ExceptionFlags {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl fmt::Display for RoundingMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Nearest => "nearest",
            Self::Downward => "downward",
            Self::Upward => "upward",
            Self::TowardZero => "toward-zero",
        })
    }
}

/// Captures the environment and clears all five exception flags represented
/// by [`ExceptionFlags`].
///
/// As in the existing AArch64 core API, this leaves exception-mask/trap-enable
/// bits unchanged; it is a typed environment snapshot operation rather than a
/// C ABI implementation of every `feholdexcept` side effect.
#[inline]
pub fn hold_exceptions() -> Environment {
    let environment = get_environment();
    clear_exceptions(ExceptionFlags::ALL);
    environment
}

/// Restores `environment` and re-raises exception flags pending before the
/// restore in both x87 and MXCSR.
#[inline]
pub fn update_environment(environment: Environment) {
    let exceptions = test_exceptions(ExceptionFlags::ALL);
    set_environment(environment);
    raise_exceptions(exceptions);
}
