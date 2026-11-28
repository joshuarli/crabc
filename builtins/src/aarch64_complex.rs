use super::{ComplexDouble, ComplexQuad};

#[repr(C)]
pub struct ComplexFloat {
    pub real: f32,
    pub imaginary: f32,
}

unsafe extern "C" {
    fn __rust_mulsc3(a: f32, b: f32, c: f32, d: f32) -> ComplexFloat;
    fn __rust_divsc3(a: f32, b: f32, c: f32, d: f32) -> ComplexFloat;
    fn __rust_divdc3(a: f64, b: f64, c: f64, d: f64) -> ComplexDouble;
}

// compiler_builtins defines the binary128 operation with the Rust ABI, unlike
// its C-ABI binary32 and binary64 operations; on AArch64 the Rust ABI returns
// the 32-byte complex value indirectly, the C ABI in q0 and q1.
unsafe extern "Rust" {
    fn __rust_divtc3(a: f128, b: f128, c: f128, d: f128) -> core::num::Complex<f128>;
}

#[unsafe(no_mangle)]
pub extern "C" fn __mulsc3(a: f32, b: f32, c: f32, d: f32) -> ComplexFloat {
    // SAFETY: The compiler-builtins operation accepts all floating-point inputs.
    unsafe { __rust_mulsc3(a, b, c, d) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __divsc3(a: f32, b: f32, c: f32, d: f32) -> ComplexFloat {
    // SAFETY: The compiler-builtins operation accepts all floating-point inputs.
    unsafe { __rust_divsc3(a, b, c, d) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __divdc3(a: f64, b: f64, c: f64, d: f64) -> ComplexDouble {
    // SAFETY: The compiler-builtins operation accepts all floating-point inputs.
    unsafe { __rust_divdc3(a, b, c, d) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __divtc3(a: f128, b: f128, c: f128, d: f128) -> ComplexQuad {
    // SAFETY: The compiler-builtins operation accepts all floating-point inputs.
    let quotient = unsafe { __rust_divtc3(a, b, c, d) };
    ComplexQuad { real: quotient.re, imaginary: quotient.im }
}
