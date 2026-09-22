// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from unwinding 0.2.10, src/unwinder/frame.rs.
//
// The selected fde-phdr-dl finder resolves an indirect CIE personality or FDE
// LSDA pointer only while dl_iterate_phdr supplies a readable PT_LOAD for its
// full native-word cell. The caller still owns the enclosing loader
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
use libc::{dl_iterate_phdr, dl_phdr_info, PF_R, PT_LOAD};

#[cfg(target_pointer_width = "32")]
use libc::Elf32_Phdr as Elf_Phdr;
#[cfg(target_pointer_width = "64")]
use libc::Elf64_Phdr as Elf_Phdr;

use super::arch::*;
use super::find_fde::{self, FDEFinder, FDESearchResult};
use crate::abi::PersonalityRoutine;
use crate::arch::*;
use crate::util::*;

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

unsafe extern "C" fn read_indirect_pointer_callback(
    info: *mut dl_phdr_info,
    _size: usize,
    data: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        if info.is_null() || (*info).dlpi_phdr.is_null() {
            return 0;
        }
        let data = &mut *(data as *mut IndirectPointerRead);
        let phdrs = slice::from_raw_parts((*info).dlpi_phdr, (*info).dlpi_phnum as usize);
        let base = (*info).dlpi_addr as usize;
        let readable = phdrs.iter().any(|phdr| {
            phdr.p_type == PT_LOAD
                && phdr.p_flags & PF_R != 0
                && phdr_range(base, phdr).is_some_and(|load| contains_range(&load, &data.range))
        });
        if !readable {
            return 0;
        }
        data.value = Some((data.range.start as *const usize).read_unaligned());
        1
    }
}

/// # Safety
///
/// The loader must keep the mapping disclosed by `dl_iterate_phdr` readable
/// through its callback. Program-header containment does not independently
/// establish that mapping-lifetime obligation.
unsafe fn resolve_fde_pointer(pointer: Pointer) -> Option<usize> {
    match pointer {
        Pointer::Direct(value) => usize::try_from(value).ok(),
        Pointer::Indirect(value) => {
            let start = usize::try_from(value).ok()?;
            if start == 0 {
                return None;
            }
            let end = start.checked_add(mem::size_of::<usize>())?;
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
            data.value
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    fde_result: FDESearchResult,
    row: UnwindTableRow<usize, StoreOnStack>,
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

        Ok(Some(Self { fde_result, row }))
    }

    #[cfg(feature = "dwarf-expr")]
    fn evaluate_expression(
        &self,
        ctx: &Context,
        expr: UnwindExpression<usize>,
    ) -> Result<usize, gimli::Error> {
        let expr = expr.get(&self.fde_result.eh_frame).unwrap();
        let mut eval =
            Evaluation::<_, StoreOnStack>::new_in(expr.0, self.fde_result.fde.cie().encoding());
        let mut result = eval.evaluate()?;
        loop {
            match result {
                EvaluationResult::Complete => break,
                EvaluationResult::RequiresMemory { address, .. } => {
                    let value = unsafe { (address as usize as *const usize).read_unaligned() };
                    result = eval.resume_with_memory(Value::Generic(value as _))?;
                }
                EvaluationResult::RequiresRegister { register, .. } => {
                    let value = ctx[register];
                    result = eval.resume_with_register(Value::Generic(value as _))?;
                }
                EvaluationResult::RequiresRelocatedAddress(address) => {
                    let value = unsafe { (address as usize as *const usize).read_unaligned() };
                    result = eval.resume_with_memory(Value::Generic(value as _))?;
                }
                _ => unreachable!(),
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
                _ => unreachable!(),
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
                ctx[register].wrapping_add(offset as usize)
            }
            CfaRule::Expression(expr) => self.evaluate_expression(ctx, expr)?,
        };

        new_ctx[Arch::SP] = cfa as _;
        new_ctx[Arch::RA] = 0;

        for (reg, rule) in row.registers() {
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
                RegisterRule::Register(r) => ctx[r],
                RegisterRule::Expression(expr) => {
                    let addr = self.evaluate_expression(ctx, expr)?;
                    unsafe { *(addr as *const usize) }
                }
                RegisterRule::ValExpression(expr) => self.evaluate_expression(ctx, expr)?,
                RegisterRule::Architectural => unreachable!(),
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
        self.fde_result
            .fde
            .personality()
            .and_then(|pointer| unsafe { resolve_fde_pointer(pointer) })
            .map(|x| unsafe { core::mem::transmute(x) })
    }

    pub fn lsda(&self) -> usize {
        self.fde_result
            .fde
            .lsda()
            .and_then(|pointer| unsafe { resolve_fde_pointer(pointer) })
            .unwrap_or(0)
    }

    pub fn initial_address(&self) -> usize {
        self.fde_result.fde.initial_address() as _
    }

    pub fn is_signal_trampoline(&self) -> bool {
        self.fde_result.fde.is_signal_trampoline()
    }
}
