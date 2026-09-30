#![no_std]
#![no_builtins]
#![allow(improper_ctypes_definitions)]
extern crate binary32_source_oracle;
use binary32_source_oracle::float::conv;

#[unsafe(no_mangle)]
pub extern "C" fn reference_fixsfti(value: f32) -> i128 { conv::__fixsfti(value) }
#[unsafe(no_mangle)]
pub extern "C" fn reference_fixunssfti(value: f32) -> u128 { conv::__fixunssfti(value) }
#[unsafe(no_mangle)]
pub extern "C" fn reference_floattisf(value: i128) -> f32 { conv::__floattisf(value) }
#[unsafe(no_mangle)]
pub extern "C" fn reference_floatuntisf(value: u128) -> f32 { conv::__floatuntisf(value) }
