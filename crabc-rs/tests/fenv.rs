use crabc_rs::fenv::{self, Environment, EnvironmentGuard, ExceptionFlags, RoundingMode};

struct Restore(Environment);

impl Drop for Restore {
    fn drop(&mut self) {
        fenv::set_environment(self.0);
    }
}

#[test]
fn captures_rounding_and_exception_state_without_c_abi_translation() {
    let restore = Restore(fenv::get_environment());

    fenv::set_environment(Environment::default());
    assert_eq!(fenv::get_rounding(), RoundingMode::Nearest);
    assert_eq!(fenv::test_exceptions(ExceptionFlags::ALL), ExceptionFlags::EMPTY);

    fenv::set_rounding(RoundingMode::TowardZero);
    assert_eq!(fenv::get_rounding(), RoundingMode::TowardZero);

    let raised = ExceptionFlags::INVALID | ExceptionFlags::INEXACT;
    fenv::raise_exceptions(raised);
    assert_eq!(fenv::test_exceptions(ExceptionFlags::ALL), raised);
    fenv::clear_exceptions(ExceptionFlags::INVALID);
    assert_eq!(fenv::test_exceptions(ExceptionFlags::ALL), ExceptionFlags::INEXACT);

    drop(restore);
}

#[test]
fn hold_and_update_preserve_pending_exception_flags() {
    let restore = Restore(fenv::get_environment());

    fenv::set_environment(Environment::default());
    fenv::raise_exceptions(ExceptionFlags::INVALID | ExceptionFlags::INEXACT);
    let held = fenv::hold_exceptions();
    assert_eq!(held.exceptions(), ExceptionFlags::INVALID | ExceptionFlags::INEXACT);
    assert_eq!(fenv::test_exceptions(ExceptionFlags::ALL), ExceptionFlags::EMPTY);

    fenv::raise_exceptions(ExceptionFlags::OVERFLOW);
    fenv::update_environment(held);
    assert_eq!(
        fenv::test_exceptions(ExceptionFlags::ALL),
        ExceptionFlags::INVALID | ExceptionFlags::OVERFLOW | ExceptionFlags::INEXACT,
    );

    drop(restore);
}

#[test]
fn guard_restores_the_saved_environment() {
    let restore = Restore(fenv::get_environment());

    fenv::set_environment(Environment::default());
    fenv::set_rounding(RoundingMode::Upward);
    let guard = EnvironmentGuard::with_rounding(RoundingMode::Downward);
    assert_eq!(guard.saved().rounding(), RoundingMode::Upward);
    assert_eq!(fenv::get_rounding(), RoundingMode::Downward);
    drop(guard);
    assert_eq!(fenv::get_rounding(), RoundingMode::Upward);

    drop(restore);
}
