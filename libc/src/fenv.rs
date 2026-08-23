

use super::c_int;

pub type fexcept_t = u32;



#[repr(C)]
pub struct fenv_t {
    __fpcr: u32,
    __fpsr: u32,
}




const FE_DFL_ENV: *const fenv_t = -1isize as *const fenv_t;




mod feconst {
    use super::c_int;
    pub const FE_INVALID: c_int = 1;
    pub const FE_DIVBYZERO: c_int = 2;
    pub const FE_OVERFLOW: c_int = 4;
    pub const FE_UNDERFLOW: c_int = 8;
    pub const FE_INEXACT: c_int = 16;
    pub const FE_ALL_EXCEPT: c_int = 31;

    pub const FE_TONEAREST: c_int = 0;
    pub const FE_DOWNWARD: c_int = 0x800000;
    pub const FE_UPWARD: c_int = 0x400000;
    pub const FE_TOWARDZERO: c_int = 0xc00000;
}



use feconst::{
    FE_ALL_EXCEPT, FE_DOWNWARD, FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD,
};
pub(super) use feconst::{FE_INEXACT, FE_INVALID, FE_OVERFLOW, FE_UNDERFLOW};

// aarch64 implementation using FPCR/FPSR
mod aarch64_imp {
    use super::{
        c_int, fenv_t, FE_DFL_ENV, FE_DOWNWARD, FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD,
    };
    use crabc_core::fenv::{self, ExceptionFlags, RoundingMode};

    #[inline]
    fn exception_flags(excepts: c_int) -> ExceptionFlags {
        ExceptionFlags::from_bits_truncate(excepts as u32)
    }

    #[inline]
    fn rounding_mode(rounding: c_int) -> Option<RoundingMode> {
        match rounding {
            FE_TONEAREST => Some(RoundingMode::Nearest),
            FE_DOWNWARD => Some(RoundingMode::Downward),
            FE_UPWARD => Some(RoundingMode::Upward),
            FE_TOWARDZERO => Some(RoundingMode::TowardZero),
            _ => None,
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn feclearexcept(excepts: c_int) -> c_int {
        fenv::clear_exceptions(exception_flags(excepts));
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn feraiseexcept(excepts: c_int) -> c_int {
        fenv::raise_exceptions(exception_flags(excepts));
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn fetestexcept(excepts: c_int) -> c_int {
        fenv::test_exceptions(exception_flags(excepts)).bits() as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn fegetround() -> c_int {
        fenv::get_rounding().raw() as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn fesetround(r: c_int) -> c_int {
        match rounding_mode(r) {
            Some(rounding) => {
                fenv::set_rounding(rounding);
                0
            }
            None => -1,
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn fegetenv(envp: *mut fenv_t) -> c_int {
        let environment = fenv::get_environment();
        (*envp).__fpcr = environment.fpcr();
        (*envp).__fpsr = environment.fpsr();
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn fesetenv(envp: *const fenv_t) -> c_int {
        let environment = if envp == FE_DFL_ENV {
            fenv::Environment::default()
        } else {
            fenv::Environment::from_raw((*envp).__fpcr, (*envp).__fpsr)
        };
        fenv::set_environment(environment);
        0
    }
}

pub(super) use aarch64_imp::{
    feclearexcept, fegetenv, fegetround, feraiseexcept, fesetenv, fetestexcept,
};

#[no_mangle]
pub unsafe extern "C" fn fegetexceptflag(fp: *mut fexcept_t, mask: c_int) -> c_int {
    *fp = fetestexcept(mask) as fexcept_t;
    0
}

#[no_mangle]
pub unsafe extern "C" fn fesetexceptflag(fp: *const fexcept_t, mask: c_int) -> c_int {
    let flags = *fp as c_int;
    feclearexcept((!flags) & mask);
    feraiseexcept(flags & mask);
    0
}

#[no_mangle]
pub unsafe extern "C" fn feholdexcept(envp: *mut fenv_t) -> c_int {
    fegetenv(envp);
    feclearexcept(FE_ALL_EXCEPT);
    0
}

#[no_mangle]
pub unsafe extern "C" fn feupdateenv(envp: *const fenv_t) -> c_int {
    let ex = fetestexcept(FE_ALL_EXCEPT);
    fesetenv(envp);
    feraiseexcept(ex);
    0
}

// C99 FLT_ROUNDS: 0=towardzero, 1=nearest, 2=upward, 3=downward
#[no_mangle]
pub extern "C" fn __flt_rounds() -> c_int {
    match unsafe { fegetround() } {
        FE_TOWARDZERO => 0,
        FE_TONEAREST => 1,
        FE_UPWARD => 2,
        FE_DOWNWARD => 3,
        _ => -1,
    }
}
