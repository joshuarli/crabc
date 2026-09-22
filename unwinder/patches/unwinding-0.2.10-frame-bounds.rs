// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from unwinding 0.2.10, src/unwinder/frame.rs.
//
// The selected fde-phdr-dl finder resolves a present indirect CIE personality
// or FDE LSDA pointer only while dl_iterate_phdr supplies a readable PT_LOAD
// for its full native-word cell. A non-null personality target must be in an
// executable PT_LOAD; a nonzero LSDA target must be in a readable PT_LOAD.
// A present cell or target that cannot be resolved is malformed unwind
// metadata, not absent metadata. The caller still owns the enclosing loader
// mapping-lifetime obligation and the resulting target's ordinary ABI.
use core::convert::TryFrom;
use core::mem;
use core::ops::Range;
use core::slice;
use gimli::{
    BaseAddresses, CfaRule, Pointer, Register, RegisterRule, UnwindContext,
    UnwindExpression, UnwindTableRow,
};
#[cfg(feature = "dwarf-expr")]
use gimli::{Evaluation, EvaluationResult, Location, Value};
use libc::{dl_iterate_phdr, dl_phdr_info, PF_R, PF_X, PT_LOAD};

#[cfg(target_pointer_width = "32")]
use libc::Elf32_Phdr as Elf_Phdr;
#[cfg(target_pointer_width = "64")]
use libc::Elf64_Phdr as Elf_Phdr;

use super::arch::*;
use super::find_fde::{self, FDEFinder, FDESearchResult};
use crate::abi::PersonalityRoutine;
use crate::arch::*;
use crate::util::*;

// The selected x86 context stores integer registers 0..=16, MXCSR and FCW.
// Validate metadata IDs before Index/IndexMut, whose upstream catch-all panics.
fn validate_register(register: Register) -> Result<(), gimli::Error> {
    match register {
        Register(0..=16) | gimli::X86_64::MXCSR | gimli::X86_64::FCW => Ok(()),
        _ => Err(gimli::Error::UnsupportedRegister(register.0 as u64)),
    }
}

// Bound the interpreter independently of its existing fixed stack storage.
// 4096 operations admits compiler CFI arithmetic with ample headroom while
// ensuring a backward DW_OP_skip cannot hold an unwind phase indefinitely.
// Exhaustion is gimli::Error::TooManyIterations, propagated as a phase error.
const MAX_EXPRESSION_OPERATIONS: u32 = 4096;

struct StoreOnStack;

// gimli's MSRV doesn't allow const generics, so we need to pick a supported array size.
const fn next_value(x: usize) -> usize {
    let supported = [0, 1, 2, 3, 4, 8, 16, 32, 64, 128];
    let mut i = 0;
    while i < supported.len() {
        if supported[i] >= x {
            return supported[i];
        }
        i += 1;
    }
    192
}

impl<O: gimli::ReaderOffset> gimli::UnwindContextStorage<O> for StoreOnStack {
    type Rules = [(Register, RegisterRule<O>); next_value(MAX_REG_RULES)];
    type Stack = [UnwindTableRow<O, Self>; 2];
}

#[cfg(feature = "dwarf-expr")]
impl<R: gimli::Reader> gimli::EvaluationStorage<R> for StoreOnStack {
    type Stack = [Value; 64];
    type ExpressionStack = [(R, R); 0];
    type Result = [gimli::Piece<R>; 1];
}

fn phdr_range(base: usize, phdr: &Elf_Phdr) -> Option<Range<usize>> {
    let start = base.checked_add(usize::try_from(phdr.p_vaddr).ok()?)?;
    let end = start.checked_add(usize::try_from(phdr.p_memsz).ok()?)?;
    Some(start..end)
}

fn contains_range(container: &Range<usize>, candidate: &Range<usize>) -> bool {
    container.start <= candidate.start && candidate.end <= container.end
}

struct IndirectPointerRead {
    range: Range<usize>,
    value: Option<usize>,
}

unsafe fn load_contains(
    info: *mut dl_phdr_info,
    range: &Range<usize>,
    required_flags: u32,
) -> bool {
    unsafe {
        if info.is_null() || (*info).dlpi_phdr.is_null() {
            return false;
        }
        let phdrs = slice::from_raw_parts((*info).dlpi_phdr, (*info).dlpi_phnum as usize);
        let base = (*info).dlpi_addr as usize;
        phdrs.iter().any(|phdr| {
            phdr.p_type == PT_LOAD
                && phdr.p_flags & required_flags == required_flags
                && phdr_range(base, phdr).is_some_and(|load| contains_range(&load, range))
        })
    }
}

unsafe extern "C" fn read_indirect_pointer_callback(
    info: *mut dl_phdr_info,
    _size: usize,
    data: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        let data = &mut *(data as *mut IndirectPointerRead);
        if !load_contains(info, &data.range, PF_R) {
            return 0;
        }
        data.value = Some((data.range.start as *const usize).read_unaligned());
        1
    }
}

struct PointerTarget {
    range: Range<usize>,
    required_flags: u32,
    found: bool,
}

unsafe extern "C" fn find_pointer_target_callback(
    info: *mut dl_phdr_info,
    _size: usize,
    data: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        let data = &mut *(data as *mut PointerTarget);
        if !load_contains(info, &data.range, data.required_flags) {
            return 0;
        }
        data.found = true;
        1
    }
}

/// # Safety
///
/// The loader must keep the mapping disclosed by `dl_iterate_phdr` readable
/// through its callback. Program-header containment does not independently
/// establish that mapping-lifetime obligation.
unsafe fn resolve_fde_pointer(pointer: Pointer) -> Result<usize, gimli::Error> {
    match pointer {
        Pointer::Direct(value) => usize::try_from(value).map_err(|_| gimli::Error::AddressOverflow),
        Pointer::Indirect(value) => {
            let start = usize::try_from(value).map_err(|_| gimli::Error::AddressOverflow)?;
            if start == 0 {
                return Err(gimli::Error::OffsetOutOfBounds(value));
            }
            let end = start
                .checked_add(mem::size_of::<usize>())
                .ok_or(gimli::Error::AddressOverflow)?;
            let mut data = IndirectPointerRead {
                range: start..end,
                value: None,
            };
            // The callback checks the complete word and performs the read while
            // its caller-owned loader mapping-lifetime obligation holds.
            unsafe {
                dl_iterate_phdr(
                    Some(read_indirect_pointer_callback),
                    &mut data as *mut IndirectPointerRead as *mut core::ffi::c_void,
                );
            }
            data.value.ok_or(gimli::Error::OffsetOutOfBounds(value))
        }
    }
}

/// # Safety
///
/// The loader must keep the mapping disclosed by `dl_iterate_phdr` live
/// through the callback. Checking the target's one-byte entry range does not
/// establish its later callable or readable lifetime.
unsafe fn validate_pointer_target(
    target: usize,
    required_flags: u32,
) -> Result<(), gimli::Error> {
    if target == 0 {
        return Err(gimli::Error::OffsetOutOfBounds(0));
    }
    let end = target.checked_add(1).ok_or(gimli::Error::AddressOverflow)?;
    let mut data = PointerTarget {
        range: target..end,
        required_flags,
        found: false,
    };
    unsafe {
        dl_iterate_phdr(
            Some(find_pointer_target_callback),
            &mut data as *mut PointerTarget as *mut core::ffi::c_void,
        );
    }
    if data.found {
        Ok(())
    } else {
        Err(gimli::Error::OffsetOutOfBounds(target as u64))
    }
}

/// # Safety
///
/// The caller must keep the validated executable target live through the ABI
/// call. A null function pointer is not a valid `PersonalityRoutine` value.
unsafe fn resolve_personality(pointer: Pointer) -> Result<PersonalityRoutine, gimli::Error> {
    let target = unsafe { resolve_fde_pointer(pointer) }?;
    unsafe { validate_pointer_target(target, PF_X) }?;
    Ok(unsafe { core::mem::transmute(target) })
}

/// # Safety
///
/// The caller must keep a nonzero validated LSDA target readable while the
/// personality consumes it. Zero is the ordinary absent-LSDA value.
unsafe fn resolve_lsda(pointer: Pointer) -> Result<usize, gimli::Error> {
    let target = unsafe { resolve_fde_pointer(pointer) }?;
    if target != 0 {
        unsafe { validate_pointer_target(target, PF_R) }?;
    }
    Ok(target)
}

#[derive(Debug)]
pub struct Frame {
    fde_result: FDESearchResult,
    row: UnwindTableRow<usize, StoreOnStack>,
    personality: Option<PersonalityRoutine>,
    lsda: usize,
}

impl Frame {
    pub fn from_context(ctx: &Context, signal: bool) -> Result<Option<Self>, gimli::Error> {
        let mut ra = ctx[Arch::RA];

        // Reached end of stack
        if ra == 0 {
            return Ok(None);
        }

        // RA points to the *next* instruction, so move it back 1 byte for the call instruction.
        if !signal {
            ra -= 1;
        }

        let fde_result = match find_fde::get_finder().find_fde(ra as _) {
            Some(v) => v,
            None => return Ok(None),
        };
        let mut unwinder = UnwindContext::<_, StoreOnStack>::new_in();
        let row = fde_result
            .fde
            .unwind_info_for_address(
                &fde_result.eh_frame,
                &fde_result.bases,
                &mut unwinder,
                ra as _,
            )?
            .clone();

        // Preserve absent personality and zero-LSDA values. A present null
        // personality, or a present cell or target that cannot be resolved,
        // is malformed metadata and must reach the caller's phase-specific
        // `Err` path rather than appearing absent.
        let personality = fde_result
            .fde
            .personality()
            .map(|pointer| unsafe { resolve_personality(pointer) })
            .transpose()?;
        let lsda = fde_result
            .fde
            .lsda()
            .map(|pointer| unsafe { resolve_lsda(pointer) })
            .transpose()?
            .unwrap_or(0);

        Ok(Some(Self { fde_result, row, personality, lsda }))
    }

    #[cfg(feature = "dwarf-expr")]
    fn evaluate_expression(
        &self,
        ctx: &Context,
        expr: UnwindExpression<usize>,
    ) -> Result<usize, gimli::Error> {
        let expr = expr.get(&self.fde_result.eh_frame)?;
        let mut eval =
            Evaluation::<_, StoreOnStack>::new_in(expr.0, self.fde_result.fde.cie().encoding());
        eval.set_max_iterations(MAX_EXPRESSION_OPERATIONS);
        let mut result = eval.evaluate()?;
        loop {
            match result {
                EvaluationResult::Complete => break,
                EvaluationResult::RequiresMemory { address, size, space, base_type } => {
                    if space.is_some() || base_type.0 != 0 {
                        return Err(gimli::Error::UnsupportedEvaluation);
                    }
                    // DW_OP_deref_size reads exactly its encoded width, not a
                    // native word. Address readability remains a caller
                    // obligation until a fault-contained memory owner exists.
                    if !(1..=8).contains(&size) {
                        return Err(gimli::Error::UnsupportedEvaluation);
                    }
                    let mut bytes = [0u8; 8];
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            address as *const u8,
                            bytes.as_mut_ptr(),
                            size as usize,
                        );
                    }
                    result = eval.resume_with_memory(Value::Generic(u64::from_le_bytes(bytes)))?;
                }
                EvaluationResult::RequiresRegister { register, base_type } => {
                    if base_type.0 != 0 {
                        return Err(gimli::Error::UnsupportedEvaluation);
                    }
                    validate_register(register)?;
                    let value = ctx[register];
                    result = eval.resume_with_register(Value::Generic(value as _))?;
                }
                EvaluationResult::RequiresRelocatedAddress(address) => {
                    // ELF relocations have already been applied by the loader.
                    // This operation pushes an address; it does not dereference it.
                    result = eval.resume_with_relocated_address(address)?;
                }
                _ => return Err(gimli::Error::UnsupportedEvaluation),
            }
        }

        Ok(
            match eval
                .as_result()
                .last()
                .ok_or(gimli::Error::PopWithEmptyStack)?
                .location
            {
                Location::Address { address } => address as usize,
                _ => return Err(gimli::Error::UnsupportedEvaluation),
            },
        )
    }

    #[cfg(not(feature = "dwarf-expr"))]
    fn evaluate_expression(
        &self,
        _ctx: &Context,
        _expr: UnwindExpression<usize>,
    ) -> Result<usize, gimli::Error> {
        Err(gimli::Error::UnsupportedEvaluation)
    }

    pub fn adjust_stack_for_args(&self, ctx: &mut Context) {
        let size = self.row.saved_args_size();
        ctx[Arch::SP] = ctx[Arch::SP].wrapping_add(size as usize);
    }

    pub fn unwind(&self, ctx: &Context) -> Result<Context, gimli::Error> {
        let row = &self.row;
        let mut new_ctx = ctx.clone();

        let cfa = match *row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                validate_register(register)?;
                ctx[register].wrapping_add(offset as usize)
            }
            CfaRule::Expression(expr) => self.evaluate_expression(ctx, expr)?,
        };

        new_ctx[Arch::SP] = cfa as _;
        new_ctx[Arch::RA] = 0;

        for (reg, rule) in row.registers() {
            validate_register(*reg)?;
            let value = match *rule {
                // For most registers, `Undefined` indicates the value does not need to
                // be preserved so the value content does not matter. However when RA is
                // `Undefined` it indicates that the unwinding is complete.
                RegisterRule::Undefined => 0,
                RegisterRule::SameValue => ctx[*reg],
                RegisterRule::Offset(offset) => unsafe {
                    *((cfa.wrapping_add(offset as usize)) as *const usize)
                },
                RegisterRule::ValOffset(offset) => cfa.wrapping_add(offset as usize),
                RegisterRule::Register(r) => {
                    validate_register(r)?;
                    ctx[r]
                },
                RegisterRule::Expression(expr) => {
                    let addr = self.evaluate_expression(ctx, expr)?;
                    unsafe { *(addr as *const usize) }
                }
                RegisterRule::ValExpression(expr) => self.evaluate_expression(ctx, expr)?,
                RegisterRule::Architectural => return Err(gimli::Error::UnsupportedEvaluation),
                RegisterRule::Constant(value) => value as usize,
            };
            new_ctx[*reg] = value;
        }

        Ok(new_ctx)
    }

    pub fn bases(&self) -> &BaseAddresses {
        &self.fde_result.bases
    }

    pub fn personality(&self) -> Option<PersonalityRoutine> {
        self.personality
    }

    pub fn lsda(&self) -> usize {
        self.lsda
    }

    pub fn initial_address(&self) -> usize {
        self.fde_result.fde.initial_address() as _
    }

    pub fn is_signal_trampoline(&self) -> bool {
        self.fde_result.fde.is_signal_trampoline()
    }
}
