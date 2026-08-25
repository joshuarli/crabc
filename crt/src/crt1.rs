#![no_std]
#![feature(naked_functions)]

//! Conventional non-PIE application entry object.

mod normal_entry;
mod array_boundaries;
mod startup;

pub use startup::__crabc_start;
