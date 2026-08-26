//! Typed floating-point environment operations for the staged Linux targets.
//!
//! These wrappers preserve the native Rust contract: they update the calling
//! thread's architecture-specific floating-point environment directly through
//! `crabc-core`, without calling C fenv functions or translating C
//! sentinel/`errno` results.

pub use crabc_core::fenv::{Environment, ExceptionFlags, RoundingMode};

/// Captures the calling thread's floating-point environment.
#[inline]
pub fn get_environment() -> Environment {
    crabc_core::fenv::get_environment()
}

/// Restores a previously captured floating-point environment.
#[inline]
pub fn set_environment(environment: Environment) {
    crabc_core::fenv::set_environment(environment)
}

/// Returns the calling thread's current rounding mode.
#[inline]
pub fn get_rounding() -> RoundingMode {
    crabc_core::fenv::get_rounding()
}

/// Sets the calling thread's rounding mode.
#[inline]
pub fn set_rounding(rounding: RoundingMode) {
    crabc_core::fenv::set_rounding(rounding)
}

/// Restores the calling thread's captured floating-point environment on drop.
///
/// The guard owns an architecture-specific floating-point snapshot; it does
/// not borrow a C `fenv_t` or modify process-global state. Rust code in the
/// guarded region is still subject to ordinary compiler floating-point
/// transformations, so this guard is appropriate for preserving a foreign or
/// explicitly controlled hardware environment, not for promising
/// dynamic-rounding arithmetic from arbitrary optimized Rust expressions.
#[must_use = "dropping the guard restores the previous floating-point environment"]
pub struct EnvironmentGuard {
    saved: Environment,
}

impl EnvironmentGuard {
    /// Captures the current environment and installs `rounding` until dropped.
    #[inline]
    pub fn with_rounding(rounding: RoundingMode) -> Self {
        let saved = get_environment();
        set_rounding(rounding);
        Self { saved }
    }

    /// Returns the captured environment that this guard will restore.
    #[inline]
    pub const fn saved(&self) -> Environment {
        self.saved
    }
}

impl Drop for EnvironmentGuard {
    #[inline]
    fn drop(&mut self) {
        set_environment(self.saved);
    }
}

/// Clears selected pending exception flags.
#[inline]
pub fn clear_exceptions(flags: ExceptionFlags) {
    crabc_core::fenv::clear_exceptions(flags)
}

/// Raises selected pending exception flags.
#[inline]
pub fn raise_exceptions(flags: ExceptionFlags) {
    crabc_core::fenv::raise_exceptions(flags)
}

/// Tests selected pending exception flags.
#[inline]
pub fn test_exceptions(flags: ExceptionFlags) -> ExceptionFlags {
    crabc_core::fenv::test_exceptions(flags)
}

/// Captures the environment and clears all pending exception flags.
#[inline]
pub fn hold_exceptions() -> Environment {
    crabc_core::fenv::hold_exceptions()
}

/// Restores an environment and re-raises exceptions pending before restore.
#[inline]
pub fn update_environment(environment: Environment) {
    crabc_core::fenv::update_environment(environment)
}
