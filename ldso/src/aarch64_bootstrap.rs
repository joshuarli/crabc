//! AArch64 early entry and self-relocation, based on musl 1.2.6
//! `arch/aarch64/crt_arch.h` and `ldso/dlstart.c`.

#[cfg(not(test))]
use core::arch::global_asm;

#[cfg(not(test))]
global_asm!(
    ".text",
    ".global _start",
    ".hidden _start",
    ".type _start,%function",
    "_start:",
    "mov x0, sp",
    "mov x29, xzr",
    "mov x30, xzr",
    "and sp, x0, #-16",
    ".hidden __ehdr_start",
    "adrp x1, __ehdr_start",
    "add x1, x1, :lo12:__ehdr_start",
    ".hidden __crabc_aarch64_bootstrap",
    "b __crabc_aarch64_bootstrap",
    ".size _start, .-_start",
);

#[inline(always)]
unsafe fn word(address: usize) -> usize {
    // SAFETY: The caller has checked that this native word is readable.
    unsafe { (address as *const usize).read_unaligned() }
}

#[inline(always)]
unsafe fn half(address: usize) -> u16 {
    // SAFETY: The caller has checked that this native halfword is readable.
    unsafe { (address as *const u16).read_unaligned() }
}

#[inline(always)]
unsafe fn part(address: usize) -> u32 {
    // SAFETY: The caller has checked that this native word is readable.
    unsafe { (address as *const u32).read_unaligned() }
}

#[inline(always)]
unsafe fn mapped(base: usize, phdr: usize, count: usize, start: usize, end: usize, flag: u32) -> bool {
    if start >= end { return false; }
    let Some(bytes) = count.checked_mul(56) else { return false; };
    let Some(limit) = phdr.checked_add(bytes) else { return false; };
    let mut p = phdr;
    while p < limit {
        // SAFETY: The program-header array is supplied by the kernel-mapped interpreter.
        let (kind, flags, address, size) = unsafe {
            (part(p), part(p + 4), word(p + 16), word(p + 40))
        };
        if kind == 1 && flags & flag != 0 {
            let Some(low) = base.checked_add(address) else { return false; };
            let Some(high) = low.checked_add(size) else { return false; };
            if start >= low && end <= high { return true; }
        }
        p += 56;
    }
    false
}

#[inline(always)]
fn overlap(a: usize, ae: usize, b: usize, be: usize) -> bool {
    a != 0 && b != 0 && a < be && b < ae
}

#[inline(always)]
unsafe fn target(base: usize, phdr: usize, count: usize, offset: usize,
                 rela: usize, rela_end: usize, relr: usize, relr_end: usize) -> Option<usize> {
    if offset & 7 != 0 { return None; }
    let address = base.checked_add(offset)?;
    let end = address.checked_add(8)?;
    if address > isize::MAX as usize { return None; }
    // SAFETY: Header array and candidate range are checked by mapped.
    if !unsafe { mapped(base, phdr, count, address, end, 2) }
        || overlap(address, end, rela, rela_end) || overlap(address, end, relr, relr_end) {
        return None;
    }
    Some(address)
}

#[inline(always)]
unsafe fn relocate(base: usize, phdr: usize, count: usize, dynamic: usize, dynamic_end: usize) -> Option<()> {
    // SAFETY: The program headers came from the kernel-mapped interpreter.
    if !unsafe { mapped(base, phdr, count, dynamic, dynamic_end, 4) } { return None; }
    let (mut rela, mut rela_size, mut rela_ent) = (0usize, 0usize, 0usize);
    let (mut relr, mut relr_size, mut relr_ent) = (0usize, 0usize, 0usize);
    let mut p = dynamic;
    while p.checked_add(16)? <= dynamic_end {
        // SAFETY: Each dynamic entry is within the checked readable segment.
        let (tag, value) = unsafe { (word(p), word(p + 8)) };
        if tag == 0 { break; }
        match tag {
            7 => rela = base.checked_add(value)?,
            8 => rela_size = value,
            9 => rela_ent = value,
            35 => relr_size = value,
            36 => relr = base.checked_add(value)?,
            37 => relr_ent = value,
            _ => (),
        }
        p = p.checked_add(16)?;
    }
    if rela_size == 0 { rela = 0; }
    if relr_size == 0 { relr = 0; }
    if rela_size != 0 && (rela == 0 || rela_ent != 24 || rela_size % 24 != 0) { return None; }
    if relr_size != 0 && (relr == 0 || relr_ent != 8 || relr_size & 7 != 0) { return None; }
    let rela_end = rela.checked_add(rela_size)?;
    let relr_end = relr.checked_add(relr_size)?;
    // SAFETY: Each nonempty relocation table must be in a readable load segment.
    if (rela != 0 && !unsafe { mapped(base, phdr, count, rela, rela_end, 4) })
        || (relr != 0 && !unsafe { mapped(base, phdr, count, relr, relr_end, 4) })
        || overlap(rela, rela_end, relr, relr_end) { return None; }
    p = rela;
    while p < rela_end {
        if unsafe { word(p + 8) } == 1027 {
            let offset = unsafe { word(p) };
            let mut q = p + 24;
            while q < rela_end {
                if unsafe { word(q + 8) == 1027 && word(q) == offset } { return None; }
                q += 24;
            }
        }
        p += 24;
    }
    p = rela;
    while p < rela_end {
        // SAFETY: The complete RELA table was admitted above.
        let (offset, info, addend) = unsafe { (word(p), word(p + 8), word(p + 16)) };
        if info == 1027 {
            // SAFETY: target verifies the writable mapping and metadata exclusion.
            let address = unsafe { target(base, phdr, count, offset, rela, rela_end, relr, relr_end) }?;
            let value = if (addend as isize) < 0 { base.checked_sub((addend as isize).unsigned_abs())? }
                else { base.checked_add(addend)? };
            if value > isize::MAX as usize { return None; }
            // SAFETY: The relocation target was checked writable above.
            unsafe { (address as *mut usize).write(value); }
        }
        p += 24;
    }
    p = relr;
    let (mut next, mut last, mut seen) = (0usize, 0usize, false);
    while p < relr_end {
        // SAFETY: p is within the admitted RELR table.
        let entry = unsafe { word(p) };
        if entry & 1 == 0 {
            if seen && entry <= last { return None; }
            // SAFETY: target verifies writable mapping and metadata exclusion.
            let address = unsafe { target(base, phdr, count, entry, rela, rela_end, relr, relr_end) }?;
            // SAFETY: The relocation target was checked writable above.
            let value = unsafe { word(address) }.checked_add(base)?;
            // SAFETY: The relocation target was checked writable above.
            unsafe { (address as *mut usize).write(value); }
            seen = true;
            last = entry;
            next = entry.checked_add(8)?;
        } else {
            if !seen { return None; }
            let mut bitmap = entry >> 1;
            if bitmap != 0 {
                let span = (usize::BITS as usize - bitmap.leading_zeros() as usize).checked_mul(8)?;
                let start = base.checked_add(next)?;
                let end = start.checked_add(span)?;
                // SAFETY: The candidate bitmap span is checked against the load segments.
                if !unsafe { mapped(base, phdr, count, start, end, 2) }
                    || overlap(start, end, rela, rela_end) || overlap(start, end, relr, relr_end) {
                    return None;
                }
            }
            let mut index = 0usize;
            while bitmap != 0 {
                if bitmap & 1 != 0 {
                    let offset = next.checked_add(index.checked_mul(8)?)?;
                    if offset <= last { return None; }
                    // SAFETY: target verifies writable mapping and metadata exclusion.
                    let address = unsafe { target(base, phdr, count, offset, rela, rela_end, relr, relr_end) }?;
                    // SAFETY: The relocation target was checked writable above.
                    let value = unsafe { word(address) }.checked_add(base)?;
                    // SAFETY: The relocation target was checked writable above.
                    unsafe { (address as *mut usize).write(value); }
                    last = offset;
                }
                bitmap >>= 1;
                index += 1;
            }
            next = next.checked_add(504)?;
        }
        p += 8;
    }
    Some(())
}

#[cfg(not(test))]
#[no_mangle]
unsafe extern "C" fn __crabc_aarch64_bootstrap(sp: usize, base: usize) -> ! {
    // SAFETY: Linux enters with a mapped ELF header and its program headers.
    let result = unsafe {
        let phdr = base.checked_add(word(base + 32));
        let count = half(base + 56) as usize;
        match phdr {
            Some(phdr) => {
                let mut i = 0usize;
                let mut result = None;
                while i < count {
                    let p = phdr + i * 56;
                    if part(p) == 2 {
                        if let Some(start) = base.checked_add(word(p + 16)) {
                            if let Some(end) = start.checked_add(word(p + 40)) {
                                result = relocate(base, phdr, count, start, end);
                            }
                        }
                        break;
                    }
                    i += 1;
                }
                result
            }
            None => None,
        }
    };
    if result.is_some() {
        // SAFETY: The self-relocation transaction has completed successfully.
        unsafe { super::x86_64_initial_graph_run(sp, base) }
    }
    // SAFETY: Linux exit terminates this process after a failed bootstrap.
    unsafe { core::arch::asm!("svc #0", in("x8") 93usize, in("x0") 127usize, options(noreturn)); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct Image([u64; 128]);

    #[test]
    fn duplicate_rela_does_not_write_earlier_target() {
        let mut image = Image([0; 128]);
        let base = image.0.as_mut_ptr() as usize;
        let phdr = base;
        image.0[0] = 1 | (6u64 << 32);
        image.0[5] = 1024;
        image.0[8..16].copy_from_slice(&[7, 256, 8, 72, 9, 24, 0, 0]);
        image.0[32..41].copy_from_slice(&[512, 1027, 1, 520, 1027, 2, 520, 1027, 3]);
        image.0[64] = 99;
        let result = unsafe { relocate(base, phdr, 1, base + 64, base + 128) };
        assert!(result.is_none());
        assert_eq!(image.0[64], 99);
    }
}
