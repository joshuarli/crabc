//! Direct Linux/x86-64 floating-point environment operations.
//!
//! Linux/x86-64 has two independently stored floating-point environments:
//! the legacy x87 control/status words and the SSE MXCSR register.  Scalar
//! Rust `f32`/`f64` instructions normally use MXCSR, while x87 remains part
//! of the SysV ABI and is used by x87 instructions and the target's extended
//! precision operations.  Every mutating operation in this module therefore
//! updates both units.  It does not use libc's `fenv.h` functions, a
//! process-global singleton, or TLS `errno`.

use core::arch::asm;
use core::fmt;
use core::ops::{BitAnd, BitOr, BitOrAssign};

const X87_ROUNDING_MASK: u16 = 0x0c00;
const MXCSR_ROUNDING_MASK: u32 = 0x0000_6000;
const MXCSR_ROUNDING_SHIFT: u32 = 3;

// x87 and MXCSR use the same low-bit encoding for the five ISO C exception
// flags.  Bit 1 is x86's non-portable denormal-operand status flag; it has no
// counterpart in the existing core API and remains preserved in raw snapshots.
const EXCEPTION_MASK: u32 = 0x003d;

const X87_CONTROL_WORD_OFFSET: usize = 0;
const X87_STATUS_WORD_OFFSET: usize = 2;
const MXCSR_OFFSET: usize = 24;
const MXCSR_MASK_OFFSET: usize = 28;
const DEFAULT_MXCSR_MASK: u32 = 0x0000_ffbf;

/// The five ISO C floating-point exception flags on Linux/x86-64.
///
/// The values match the low status bits in both x87 and MXCSR, and match
/// musl's x86-64 `FE_*` constants for these five exceptions.  x86 also has a
/// denormal-operand status bit (`0x02`), but it is deliberately not exposed:
/// the existing `crabc-core` fenv vocabulary has no such flag.  Raw
/// [`Environment`] snapshots preserve that bit, while operations selected by
/// this type leave it unchanged.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ExceptionFlags(u32);

impl ExceptionFlags {
    /// No pending floating-point exceptions.
    pub const EMPTY: Self = Self(0);
    /// Invalid-operation exception.
    pub const INVALID: Self = Self(0x01);
    /// Division-by-zero exception.
    pub const DIVIDE_BY_ZERO: Self = Self(0x04);
    /// Overflow exception.
    pub const OVERFLOW: Self = Self(0x08);
    /// Underflow exception.
    pub const UNDERFLOW: Self = Self(0x10);
    /// Inexact-result exception.
    pub const INEXACT: Self = Self(0x20);
    /// All five exception flags represented by this API.
    pub const ALL: Self = Self(EXCEPTION_MASK);

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

    /// Returns the x87/MXCSR-compatible bit representation.
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

/// Linux/x86-64 floating-point rounding mode.
///
/// `raw` is the x87 control-word rounding field.  The matching MXCSR field is
/// three bits higher; [`set_rounding`] changes both units together, while
/// [`Environment`] preserves both captured fields exactly.  An external caller
/// can desynchronize the two registers with inline assembly; in that state
/// [`get_rounding`] intentionally reports x87, the canonical field used by the
/// native C floating-point environment.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoundingMode {
    /// Round to nearest, ties to even.
    Nearest = 0x0000,
    /// Round toward negative infinity.
    Downward = 0x0400,
    /// Round toward positive infinity.
    Upward = 0x0800,
    /// Round toward zero.
    TowardZero = 0x0c00,
}

impl RoundingMode {
    /// Decodes the x87 control-word rounding field.
    ///
    /// x87 reserves exactly two bits for rounding, and all four encodings are
    /// defined.  Masking the field therefore always produces one of these
    /// typed values.
    #[inline]
    pub const fn from_raw(raw: u16) -> Self {
        match raw & X87_ROUNDING_MASK {
            0x0000 => Self::Nearest,
            0x0400 => Self::Downward,
            0x0800 => Self::Upward,
            _ => Self::TowardZero,
        }
    }

    /// Returns the x87 control-word rounding field.
    #[inline]
    pub const fn raw(self) -> u16 {
        self as u16
    }

    #[inline]
    const fn mxcsr_raw(self) -> u32 {
        (self.raw() as u32) << MXCSR_ROUNDING_SHIFT
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

/// A captured Linux/x86-64 floating-point environment.
///
/// This is a thread-local architectural snapshot, not a pointer to a C
/// `fenv_t`.  It captures the x87 control and status words together with
/// MXCSR.  [`Default`] is the x86 `FE_DFL_ENV` state: all exceptions masked,
/// extended x87 precision, round-to-nearest, no pending exceptions, and the
/// architectural default MXCSR.  Its compact Rust layout is intentionally not
/// the padded x86 C `fenv_t` storage layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Environment {
    control_word: u16,
    status_word: u16,
    mxcsr: u32,
}

impl Default for Environment {
    #[inline]
    fn default() -> Self {
        Self {
            control_word: 0x037f,
            status_word: 0,
            mxcsr: 0x1f80,
        }
    }
}

impl Environment {
    /// Reconstructs a captured Linux/x86-64 environment from the x87 and
    /// MXCSR bit patterns stored by the native C `fenv_t` fields.
    ///
    /// `set_environment` restricts MXCSR to the CPU-advertised writable mask
    /// before restoring it, so a raw environment cannot load reserved MXCSR
    /// bits.  As with the AArch64 counterpart, callers should normally obtain
    /// these values through [`get_environment`], not invent control words.
    #[inline]
    pub const fn from_raw(control_word: u16, status_word: u16, mxcsr: u32) -> Self {
        Self {
            control_word,
            status_word,
            mxcsr,
        }
    }

    /// Returns the captured x87 control word.
    #[inline]
    pub const fn control_word(self) -> u16 {
        self.control_word
    }

    /// Returns the captured x87 status word.
    #[inline]
    pub const fn status_word(self) -> u16 {
        self.status_word
    }

    /// Returns the captured MXCSR register.
    #[inline]
    pub const fn mxcsr(self) -> u32 {
        self.mxcsr
    }

    /// Returns the five pending exception flags represented by this API.
    #[inline]
    pub const fn exceptions(self) -> ExceptionFlags {
        ExceptionFlags::from_bits_truncate(self.status_word as u32 | self.mxcsr)
    }

    /// Returns the rounding mode from the captured x87 control word.
    #[inline]
    pub const fn rounding(self) -> RoundingMode {
        RoundingMode::from_raw(self.control_word)
    }
}

/// The legacy 512-byte FXSAVE image used to edit x87 status without changing
/// the x87 register stack or the XMM registers.
///
/// FXSAVE/FXRSTOR require a 16-byte-aligned operand.  The fields used here are
/// common to the architecturally required FXSAVE format: x87 control at byte
/// 0, x87 status at byte 2, MXCSR at byte 24, and the MXCSR writable mask at
/// byte 28.  Other bytes are captured and restored unchanged.
#[repr(C, align(16))]
struct FxSaveArea {
    bytes: [u8; 512],
}

impl FxSaveArea {
    #[inline]
    fn zeroed() -> Self {
        Self { bytes: [0; 512] }
    }

    #[inline]
    fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.bytes[offset], self.bytes[offset + 1]])
    }

    #[inline]
    fn write_u16(&mut self, offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        self.bytes[offset] = bytes[0];
        self.bytes[offset + 1] = bytes[1];
    }

    #[inline]
    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.bytes[offset],
            self.bytes[offset + 1],
            self.bytes[offset + 2],
            self.bytes[offset + 3],
        ])
    }

    #[inline]
    fn write_u32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        self.bytes[offset] = bytes[0];
        self.bytes[offset + 1] = bytes[1];
        self.bytes[offset + 2] = bytes[2];
        self.bytes[offset + 3] = bytes[3];
    }

    #[inline]
    fn mxcsr_mask(&self) -> u32 {
        // Intel specifies a zero MXCSR_MASK as "use the architectural
        // default".  The fallback prevents a caller-created Environment from
        // restoring unsupported reserved MXCSR bits on such processors.
        match self.read_u32(MXCSR_MASK_OFFSET) {
            0 => DEFAULT_MXCSR_MASK,
            mask => mask,
        }
    }
}

#[inline]
fn capture_state() -> FxSaveArea {
    let mut state = FxSaveArea::zeroed();
    // SAFETY: The Linux/x86-64 target contract assumes the architectural
    // FXSAVE/FXRSTOR facilities required by the SysV x86-64 floating-point
    // ABI. `FxSaveArea` is exactly 512 bytes and 16-byte aligned as the
    // instruction requires. This snapshots only the calling thread's x87,
    // XMM, and MXCSR state into the local object.
    unsafe {
        asm!(
            "fxsave64 [{state}]",
            state = in(reg) &mut state,
            options(nostack, preserves_flags),
        );
    }
    state
}

#[inline]
fn restore_state(state: &FxSaveArea) {
    // SAFETY: `state` originated from `capture_state`, retains the complete
    // FXSAVE image, and has 16-byte alignment.  The caller changes only the
    // documented control/status/MXCSR fields.  MXCSR is masked to the CPU's
    // advertised writable bits before this instruction executes.
    unsafe {
        asm!(
            "fxrstor64 [{state}]",
            state = in(reg) state,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
fn environment_from_state(state: &FxSaveArea) -> Environment {
    Environment {
        control_word: state.read_u16(X87_CONTROL_WORD_OFFSET),
        status_word: state.read_u16(X87_STATUS_WORD_OFFSET),
        mxcsr: state.read_u32(MXCSR_OFFSET),
    }
}

#[inline]
fn apply_environment(state: &mut FxSaveArea, environment: Environment) {
    state.write_u16(X87_CONTROL_WORD_OFFSET, environment.control_word);
    state.write_u16(X87_STATUS_WORD_OFFSET, environment.status_word);
    let mxcsr = environment.mxcsr & state.mxcsr_mask();
    state.write_u32(MXCSR_OFFSET, mxcsr);
}

/// Captures the calling thread's x87 control/status words and MXCSR.
#[inline]
pub fn get_environment() -> Environment {
    environment_from_state(&capture_state())
}

/// Restores a previously captured floating-point environment.
///
/// The full FXSAVE image is first captured so x87 data registers and XMM
/// registers are restored exactly as they were at this call boundary; only the
/// environment fields in `environment` are changed.  Unsupported MXCSR bits
/// are discarded using the CPU-provided mask.
#[inline]
pub fn set_environment(environment: Environment) {
    let mut state = capture_state();
    apply_environment(&mut state, environment);
    restore_state(&state);
}

/// Returns the calling thread's current x87 rounding mode.
///
/// [`set_rounding`] synchronizes x87 and MXCSR.  If foreign inline assembly
/// has made them differ, this returns the x87 field while SSE arithmetic still
/// follows MXCSR until a subsequent `set_rounding` or `set_environment` call.
#[inline]
pub fn get_rounding() -> RoundingMode {
    get_environment().rounding()
}

/// Sets the calling thread's rounding mode in both x87 and MXCSR while
/// preserving all other environment bits.
#[inline]
pub fn set_rounding(rounding: RoundingMode) {
    let mut state = capture_state();
    let control_word = state.read_u16(X87_CONTROL_WORD_OFFSET);
    let mxcsr = state.read_u32(MXCSR_OFFSET);
    state.write_u16(
        X87_CONTROL_WORD_OFFSET,
        (control_word & !X87_ROUNDING_MASK) | rounding.raw(),
    );
    state.write_u32(
        MXCSR_OFFSET,
        (mxcsr & !MXCSR_ROUNDING_MASK) | rounding.mxcsr_raw(),
    );
    restore_state(&state);
}

/// Clears selected pending exception flags in both x87 and MXCSR.
///
/// x86's denormal-operand flag is not represented by [`ExceptionFlags`] and
/// is deliberately preserved.
#[inline]
pub fn clear_exceptions(flags: ExceptionFlags) {
    if flags.is_empty() {
        return;
    }

    let mut state = capture_state();
    let status_word = state.read_u16(X87_STATUS_WORD_OFFSET) & !(flags.bits() as u16);
    let mxcsr = state.read_u32(MXCSR_OFFSET) & !flags.bits();
    state.write_u16(X87_STATUS_WORD_OFFSET, status_word);
    state.write_u32(MXCSR_OFFSET, mxcsr);
    restore_state(&state);
}

/// Raises selected pending exception flags in both x87 and MXCSR.
///
/// This updates status state directly, matching the existing core fenv API;
/// it does not execute floating-point operations merely to manufacture an
/// exception.  x86's denormal-operand flag remains unchanged.
#[inline]
pub fn raise_exceptions(flags: ExceptionFlags) {
    if flags.is_empty() {
        return;
    }

    let mut state = capture_state();
    let status_word = state.read_u16(X87_STATUS_WORD_OFFSET) | flags.bits() as u16;
    let mxcsr = state.read_u32(MXCSR_OFFSET) | flags.bits();
    state.write_u16(X87_STATUS_WORD_OFFSET, status_word);
    state.write_u32(MXCSR_OFFSET, mxcsr);
    restore_state(&state);
}

/// Tests selected pending exception flags across x87 and MXCSR.
#[inline]
pub fn test_exceptions(flags: ExceptionFlags) -> ExceptionFlags {
    get_environment().exceptions() & flags
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

#[cfg(test)]
mod tests {
    use super::{
        clear_exceptions, get_environment, get_rounding, hold_exceptions, raise_exceptions,
        set_environment, set_rounding, test_exceptions, update_environment, Environment,
        ExceptionFlags, RoundingMode, MXCSR_ROUNDING_MASK, X87_ROUNDING_MASK,
    };

    struct Restore(Environment);

    impl Drop for Restore {
        fn drop(&mut self) {
            set_environment(self.0);
        }
    }

    #[test]
    fn default_environment_has_the_x86_architectural_rounding_state() {
        let environment = Environment::default();

        assert_eq!(environment.rounding(), RoundingMode::Nearest);
        assert_eq!(environment.exceptions(), ExceptionFlags::EMPTY);
        assert_eq!(environment.control_word(), 0x037f);
        assert_eq!(environment.status_word(), 0);
        assert_eq!(environment.mxcsr(), 0x1f80);
    }

    #[test]
    fn setting_rounding_synchronizes_x87_and_mxcsr() {
        let _restore = Restore(get_environment());
        set_environment(Environment::default());

        for rounding in [
            RoundingMode::Nearest,
            RoundingMode::Downward,
            RoundingMode::Upward,
            RoundingMode::TowardZero,
        ] {
            set_rounding(rounding);
            let environment = get_environment();

            assert_eq!(get_rounding(), rounding);
            assert_eq!(environment.rounding(), rounding);
            assert_eq!(
                environment.control_word() & X87_ROUNDING_MASK,
                rounding.raw(),
            );
            assert_eq!(
                environment.mxcsr() & MXCSR_ROUNDING_MASK,
                (rounding.raw() as u32) << 3,
            );
        }
    }

    #[test]
    fn exception_operations_update_both_x87_and_mxcsr() {
        let _restore = Restore(get_environment());
        set_environment(Environment::default());

        let raised = ExceptionFlags::INVALID | ExceptionFlags::INEXACT;
        raise_exceptions(raised);

        let environment = get_environment();
        assert_eq!(test_exceptions(ExceptionFlags::ALL), raised);
        assert_eq!(environment.status_word() as u32 & raised.bits(), raised.bits());
        assert_eq!(environment.mxcsr() & raised.bits(), raised.bits());

        clear_exceptions(ExceptionFlags::INVALID);
        assert_eq!(test_exceptions(ExceptionFlags::ALL), ExceptionFlags::INEXACT);
    }

    #[test]
    fn update_environment_merges_pending_flags_after_restoring_both_units() {
        let _restore = Restore(get_environment());
        set_environment(Environment::default());

        raise_exceptions(ExceptionFlags::INVALID);
        let held = hold_exceptions();
        assert_eq!(test_exceptions(ExceptionFlags::ALL), ExceptionFlags::EMPTY);

        raise_exceptions(ExceptionFlags::OVERFLOW);
        update_environment(held);
        assert_eq!(
            test_exceptions(ExceptionFlags::ALL),
            ExceptionFlags::INVALID | ExceptionFlags::OVERFLOW,
        );
    }
}
