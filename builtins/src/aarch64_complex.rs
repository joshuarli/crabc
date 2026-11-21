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
    fn __rust_divtc3(a: f128, b: f128, c: f128, d: f128) -> ComplexQuad;
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
    unsafe { __rust_divtc3(a, b, c, d) }
}
