// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from unwinding 0.2.10, src/unwinder/find_fde/phdr.rs.
//
// The PT_GNU_EH_FRAME input is only readable within its declared p_memsz and
// a containing readable PT_LOAD segment. Its decoded .eh_frame pointer must
// also stay within a readable PT_LOAD, including an indirect pointer cell.
// This overlay intentionally does not establish bounds for later DWARF
// records.
use super::FDESearchResult;
use crate::util::*;

use core::convert::TryFrom;
use core::mem;
use core::ops::Range;
use core::slice;
use gimli::{BaseAddresses, EhFrame, EhFrameHdr, NativeEndian, Pointer, UnwindSection};
use libc::{PF_R, PT_DYNAMIC, PT_GNU_EH_FRAME, PT_LOAD};

#[cfg(target_pointer_width = "32")]
use libc::Elf32_Phdr as Elf_Phdr;
#[cfg(target_pointer_width = "64")]
use libc::Elf64_Phdr as Elf_Phdr;

pub struct PhdrFinder(());

pub fn get_finder() -> &'static PhdrFinder {
    &PhdrFinder(())
}

impl super::FDEFinder for PhdrFinder {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        #[cfg(feature = "fde-phdr-aux")]
        if let Some(v) = search_aux_phdr(pc) {
            return Some(v);
        }
        #[cfg(feature = "fde-phdr-dl")]
        if let Some(v) = search_dl_phdr(pc) {
            return Some(v);
        }
        None
    }
}

#[cfg(feature = "fde-phdr-aux")]
fn search_aux_phdr(pc: usize) -> Option<FDESearchResult> {
    use libc::{AT_PHDR, AT_PHNUM, PT_PHDR, getauxval};

    unsafe {
        let phdr = getauxval(AT_PHDR) as *const Elf_Phdr;
        let phnum = getauxval(AT_PHNUM) as usize;
        let phdrs = slice::from_raw_parts(phdr, phnum);
        // With known address of PHDR, we can calculate the base address in reverse.
        let base = phdrs.as_ptr() as usize
            - usize::try_from(phdrs.iter().find(|x| x.p_type == PT_PHDR)?.p_vaddr).ok()?;
        search_phdr(phdrs, base, pc)
    }
}

#[cfg(feature = "fde-phdr-dl")]
fn search_dl_phdr(pc: usize) -> Option<FDESearchResult> {
    use core::ffi::c_void;
    use libc::{dl_iterate_phdr, dl_phdr_info};

    struct CallbackData {
        pc: usize,
        result: Option<FDESearchResult>,
    }

    unsafe extern "C" fn phdr_callback(
        info: *mut dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> c_int {
        unsafe {
            let data = &mut *(data as *mut CallbackData);
            let phdrs = slice::from_raw_parts((*info).dlpi_phdr, (*info).dlpi_phnum as usize);
            if let Some(v) = search_phdr(phdrs, (*info).dlpi_addr as _, data.pc) {
                data.result = Some(v);
                return 1;
            }
            0
        }
    }

    let mut data = CallbackData { pc, result: None };
    unsafe { dl_iterate_phdr(Some(phdr_callback), &mut data as *mut CallbackData as _) };
    data.result
}

fn phdr_range(base: usize, phdr: &Elf_Phdr) -> Option<Range<usize>> {
    let start = base.checked_add(usize::try_from(phdr.p_vaddr).ok()?)?;
    let end = start.checked_add(usize::try_from(phdr.p_memsz).ok()?)?;
    Some(start..end)
}

fn contains_range(container: &Range<usize>, candidate: &Range<usize>) -> bool {
    container.start <= candidate.start && candidate.end <= container.end
}

fn readable_load_for_range(
    phdrs: &[Elf_Phdr],
    base: usize,
    required: &Range<usize>,
) -> Option<Range<usize>> {
    if required.is_empty() {
        return None;
    }
    phdrs.iter().find_map(|phdr| {
        if phdr.p_type != PT_LOAD || phdr.p_flags & PF_R == 0 {
            return None;
        }
        let load = phdr_range(base, phdr)?;
        contains_range(&load, required).then_some(load)
    })
}

type DynRecord = [usize; 2];

/// # Safety
///
/// `dynamic` must describe bytes that remain mapped and readable while this
/// function reads them. Program-header containment is metadata only; the
/// caller owns the loader mapping-lifetime guarantee.
unsafe fn dynamic_got(
    phdrs: &[Elf_Phdr],
    base: usize,
    dynamic: &Range<usize>,
) -> Option<Option<usize>> {
    const DT_NULL: usize = 0;
    const DT_PLTGOT: usize = 3;

    let record_size = mem::size_of::<DynRecord>();
    if dynamic.is_empty()
        || dynamic.start == 0
        || dynamic.len() % record_size != 0
        || readable_load_for_range(phdrs, base, dynamic).is_none()
    {
        return None;
    }
    let mut cursor = dynamic.start;
    while cursor < dynamic.end {
        let record_end = cursor.checked_add(record_size)?;
        if record_end > dynamic.end {
            return None;
        }
        let record = unsafe { (cursor as *const DynRecord).read_unaligned() };
        if record[0] == DT_NULL {
            return Some(None);
        }
        if record[0] == DT_PLTGOT {
            return Some(Some(record[1]));
        }
        cursor = record_end;
    }
    None
}

/// # Safety
///
/// `header` must describe bytes that remain mapped and readable for the
/// returned slice lifetime. Program-header containment is only metadata; the
/// caller owns the loader mapping-lifetime guarantee.
unsafe fn bounded_eh_frame_header(
    phdrs: &[Elf_Phdr],
    base: usize,
    header: &Range<usize>,
) -> Option<&'static [u8]> {
    if header.is_empty() || header.start == 0 || header.len() > isize::MAX as usize {
        return None;
    }
    if readable_load_for_range(phdrs, base, header).is_none() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(header.start as *const u8, header.len()) })
}

/// # Safety
///
/// The program headers must describe bytes that remain mapped and readable
/// while the returned slice is used. Metadata containment does not establish
/// that loader mapping-lifetime obligation.
unsafe fn bounded_eh_frame(
    phdrs: &[Elf_Phdr],
    base: usize,
    pointer: Pointer,
) -> Option<(usize, &'static [u8])> {
    let start = match pointer {
        Pointer::Direct(value) => usize::try_from(value).ok()?,
        Pointer::Indirect(value) => {
            let address = usize::try_from(value).ok()?;
            if address == 0 {
                return None;
            }
            let pointer_end = address.checked_add(mem::size_of::<usize>())?;
            if readable_load_for_range(phdrs, base, &(address..pointer_end)).is_none() {
                return None;
            }
            unsafe { (address as *const usize).read_unaligned() }
        }
    };
    if start == 0 {
        return None;
    }
    let start_end = start.checked_add(1)?;
    let load = readable_load_for_range(phdrs, base, &(start..start_end))?;
    let length = load.end.checked_sub(start)?;
    if length == 0 || length > isize::MAX as usize {
        return None;
    }
    Some((start, unsafe { slice::from_raw_parts(start as *const u8, length) }))
}

fn search_phdr(phdrs: &[Elf_Phdr], base: usize, pc: usize) -> Option<FDESearchResult> {
    unsafe {
        let mut text = None;
        let mut eh_frame_hdr = None;
        let mut dynamic = None;

        for phdr in phdrs {
            let range = phdr_range(base, phdr)?;
            match phdr.p_type {
                PT_LOAD => {
                    if range.contains(&pc) {
                        text = Some(range);
                    }
                }
                PT_GNU_EH_FRAME => {
                    eh_frame_hdr = Some(range);
                }
                PT_DYNAMIC => {
                    dynamic = Some(range);
                }
                _ => (),
            }
        }

        let text = text?;
        let eh_frame_hdr = eh_frame_hdr?;
        let eh_frame_hdr_bytes = bounded_eh_frame_header(phdrs, base, &eh_frame_hdr)?;

        let mut bases = BaseAddresses::default()
            .set_eh_frame_hdr(eh_frame_hdr.start as _)
            .set_text(text.start as _);

        // Find the GOT section from complete declared PT_DYNAMIC records.
        if let Some(dynamic) = dynamic
            && let Some(got) = dynamic_got(phdrs, base, &dynamic)?
        {
            bases = bases.set_got(got as _);
        }

        // Parse only the declared .eh_frame_hdr bytes.
        let eh_frame_hdr = EhFrameHdr::new(eh_frame_hdr_bytes, NativeEndian)
            .parse(&bases, mem::size_of::<usize>() as _)
            .ok()?;

        let (eh_frame_start, eh_frame_bytes) =
            bounded_eh_frame(phdrs, base, eh_frame_hdr.eh_frame_ptr())?;
        bases = bases.set_eh_frame(eh_frame_start as _);
        let eh_frame = EhFrame::new(eh_frame_bytes, NativeEndian);

        // Use binary search table for address if available.
        if let Some(table) = eh_frame_hdr.table()
            && let Ok(fde) =
                table.fde_for_address(&eh_frame, &bases, pc as _, EhFrame::cie_from_offset)
        {
            return Some(FDESearchResult {
                fde,
                bases,
                eh_frame,
            });
        }

        // Otherwise do the linear search.
        if let Ok(fde) = eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset) {
            return Some(FDESearchResult {
                fde,
                bases,
                eh_frame,
            });
        }

        None
    }
}
