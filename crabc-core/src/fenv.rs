//! Direct AArch64 floating-point environment operations.
//!
//! The floating-point environment is part of the calling thread's architectural
//! state. This module snapshots and updates FPCR/FPSR directly; it does not use
//! libc's `fenv.h` functions, a process-global singleton, or TLS `errno`.

use core::arch::asm;
use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign};

const ROUNDING_MASK: u32 = 0x00c0_0000;

/// The five AArch64 floating-point exception flags exposed by musl.
///
/// The bit values intentionally match FPSR and musl's AArch64 `FE_*`
/// constants, so a captured flag set can cross this typed boundary without a
/// C ABI translation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ExceptionFlags(u32);

impl ExceptionFlags {
    /// No pending floating-point exceptions.
    pub const EMPTY: Self = Self(0);
    /// Invalid-operation exception.
    pub const INVALID: Self = Self(1);
    /// Division-by-zero exception.
    pub const DIVIDE_BY_ZERO: Self = Self(2);
    /// Overflow exception.
    pub const OVERFLOW: Self = Self(4);
    /// Underflow exception.
    pub const UNDERFLOW: Self = Self(8);
    /// Inexact-result exception.
    pub const INEXACT: Self = Self(16);
    /// All five architecturally exposed exception flags.
    pub const ALL: Self = Self(31);

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

    /// Returns the FPSR-compatible bit representation.
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

/// AArch64 floating-point rounding mode.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoundingMode {
    /// Round to nearest, ties to even.
    Nearest = 0x0000_0000,
    /// Round toward negative infinity.
    Downward = 0x0080_0000,
    /// Round toward positive infinity.
    Upward = 0x0040_0000,
    /// Round toward zero.
    TowardZero = 0x00c0_0000,
}

impl RoundingMode {
    /// Decodes the FPCR rounding field.
    ///
    /// AArch64 reserves exactly two FPCR bits for rounding, and all four
    /// encodings are defined. Masking the field therefore always produces one
    /// of these typed values; an optional or fallible representation would
    /// falsely suggest an invalid hardware state is possible here.
    #[inline]
    pub const fn from_raw(raw: u32) -> Self {
        match raw & ROUNDING_MASK {
            0x0000_0000 => Self::Nearest,
            0x0080_0000 => Self::Downward,
            0x0040_0000 => Self::Upward,
            _ => Self::TowardZero,
        }
    }

    /// Returns the FPCR-compatible rounding field.
    #[inline]
    pub const fn raw(self) -> u32 {
        self as u32
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

/// A captured AArch64 floating-point environment.
///
/// This is a thread-local architectural snapshot, not a pointer to a C
/// `fenv_t`. `Default` is the musl `FE_DFL_ENV` state (FPCR and FPSR zero).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Environment {
    fpcr: u32,
    fpsr: u32,
}

impl Environment {
    /// Reconstructs a captured AArch64 FPCR/FPSR environment from its exact
    /// architectural bit patterns.
    ///
    /// This is the shared C-facade bridge for an already-captured musl
    /// `fenv_t`; it does not expose a pointer, global object, or C ABI type.
    #[inline]
    pub const fn from_raw(fpcr: u32, fpsr: u32) -> Self {
        Self { fpcr, fpsr }
    }

    /// Returns the raw FPCR bits captured in this environment.
    #[inline]
    pub const fn fpcr(self) -> u32 {
        self.fpcr
    }

    /// Returns the raw FPSR bits captured in this environment.
    #[inline]
    pub const fn fpsr(self) -> u32 {
        self.fpsr
    }

    /// Returns the pending exception flags captured in this environment.
    #[inline]
    pub const fn exceptions(self) -> ExceptionFlags {
        ExceptionFlags::from_bits_truncate(self.fpsr)
    }

    /// Returns the rounding mode captured in this environment.
    #[inline]
    pub const fn rounding(self) -> RoundingMode {
        RoundingMode::from_raw(self.fpcr)
    }
}

#[inline]
fn read_fpcr() -> u32 {
    let fpcr: u64;
    // SAFETY: `mrs fpcr` reads the calling thread's AArch64 FPCR register into
    // an ordinary integer and has no memory or pointer preconditions.
    unsafe {
        asm!("mrs {fpcr}, fpcr", fpcr = out(reg) fpcr, options(nostack));
    }
    fpcr as u32
}

#[inline]
fn read_fpsr() -> u32 {
    let fpsr: u64;
    // SAFETY: `mrs fpsr` reads the calling thread's AArch64 FPSR register into
    // an ordinary integer and has no memory or pointer preconditions.
    unsafe {
        asm!("mrs {fpsr}, fpsr", fpsr = out(reg) fpsr, options(nostack));
    }
    fpsr as u32
}

#[inline]
fn write_fpcr(fpcr: u32) {
    let fpcr = fpcr as u64;
    // SAFETY: `msr fpcr` writes one scalar value to the calling thread's
    // architectural FPCR register; the value came from this typed module.
    unsafe {
        asm!("msr fpcr, {fpcr}", fpcr = in(reg) fpcr, options(nostack));
    }
}

#[inline]
fn write_fpsr(fpsr: u32) {
    let fpsr = fpsr as u64;
    // SAFETY: `msr fpsr` writes one scalar value to the calling thread's
    // architectural FPSR register; the value came from this typed module.
    unsafe {
        asm!("msr fpsr, {fpsr}", fpsr = in(reg) fpsr, options(nostack));
    }
}

/// Captures the calling thread's FPCR and FPSR.
#[inline]
pub fn get_environment() -> Environment {
    Environment {
        fpcr: read_fpcr(),
        fpsr: read_fpsr(),
    }
}

/// Restores a previously captured floating-point environment.
#[inline]
pub fn set_environment(environment: Environment) {
    write_fpcr(environment.fpcr);
    write_fpsr(environment.fpsr);
}

/// Returns the calling thread's current rounding mode.
#[inline]
pub fn get_rounding() -> RoundingMode {
    RoundingMode::from_raw(read_fpcr())
}

/// Sets the calling thread's rounding mode while preserving other FPCR bits.
#[inline]
pub fn set_rounding(rounding: RoundingMode) {
    write_fpcr((read_fpcr() & !ROUNDING_MASK) | rounding.raw());
}

/// Clears selected pending exception flags in the calling thread's FPSR.
#[inline]
pub fn clear_exceptions(flags: ExceptionFlags) {
    if !flags.is_empty() {
        write_fpsr(read_fpsr() & !flags.bits());
    }
}

/// Raises selected pending exception flags in the calling thread's FPSR.
#[inline]
pub fn raise_exceptions(flags: ExceptionFlags) {
    if !flags.is_empty() {
        write_fpsr(read_fpsr() | flags.bits());
    }
}

/// Tests selected pending exception flags in the calling thread's FPSR.
#[inline]
pub fn test_exceptions(flags: ExceptionFlags) -> ExceptionFlags {
    ExceptionFlags::from_bits_truncate(read_fpsr()) & flags
}

/// Captures the environment and clears all pending exception flags.
#[inline]
pub fn hold_exceptions() -> Environment {
    let environment = get_environment();
    clear_exceptions(ExceptionFlags::ALL);
    environment
}

/// Restores `environment` and re-raises exceptions pending before the restore.
#[inline]
pub fn update_environment(environment: Environment) {
    let exceptions = test_exceptions(ExceptionFlags::ALL);
    set_environment(environment);
    raise_exceptions(exceptions);
}
