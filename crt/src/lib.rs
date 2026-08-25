#![no_std]

//! Source owner for crabc's application CRT objects.
//!
//! The production objects are deliberately built directly from the adjacent
//! crate roots by `../build.py`: Cargo libraries are archives, while the C
//! linker contract requires five independently ordered ELF relocatable
//! objects. This target exists only to keep that source and builder ownership
//! visible in the workspace; it is not a reusable runtime library.
