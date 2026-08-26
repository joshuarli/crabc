//! Checked Linux/x86-64 base-relative relocation foundation.
//!
//! This module is deliberately not selected by `crabc-ldso` yet.  It isolates
//! the two relocation encodings which need neither symbol lookup nor loader
//! TLS: symbol-free `R_X86_64_RELATIVE` ELF64 RELA records and packed ELF64
//! RELR records.  A future x86-64 loader must first derive every
//! [`CheckedLoadRange`] from its validated `PT_LOAD` map, then pass the
//! dynamic-table locations as object-relative virtual addresses and
//! caller-owned target scratch storage disjoint from those mappings.
//!
//! The model is intentionally narrower than the AArch64 loader's current
//! relocation dispatcher.  It rejects every symbol-bearing or non-relative
//! RELA entry rather than quietly treating this foundation as an x86 dynamic
//! loader.  It also validates all supplied table and writable target ranges
//! before changing a relocation slot.
//!
//! Musl 1.2.6 source oracle: `ldso/dynlink.c:do_relocs` assigns
//! `base + addend` for `REL_RELATIVE`; `do_relr_relocs` adds the load bias to
//! the direct address or to each selected address in the following bitmap.
//! `arch/x86_64/reloc.h` binds `REL_RELATIVE` to `R_X86_64_RELATIVE` (8).

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("x86_64_relocation is a Linux/x86-64 little-endian loader foundation");

use core::ptr;

/// ELF64 `R_X86_64_RELATIVE`.
pub(crate) const R_X86_64_RELATIVE: u32 = 8;

const ELF64_RELA_SIZE: u64 = 24;
const ELF64_RELR_SIZE: u64 = 8;
const ELF64_RELR_BITS: u64 = 63;
const WORD_SIZE: u64 = 8;

/// One checked, live `PT_LOAD`-derived address range.
///
/// `start` is the runtime address after the caller has applied the object's
/// load bias.  `writable` must mirror the segment's `PF_W` permission; a
/// relocation table may be read from either kind of range, while relocation
/// destinations must be in a writable range.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckedLoadRange {
    start: u64,
    byte_len: u64,
    writable: bool,
}

impl CheckedLoadRange {
    /// Records one caller-validated live mapping for relocation checks.
    ///
    /// This constructor validates only the local integer range.  Callers must
    /// still provide a complete, non-overlapping set of load mappings to
    /// [`apply_relative_relocations`].
    pub(crate) fn from_checked_mapping(
        start: *mut u8,
        byte_len: usize,
        writable: bool,
    ) -> Result<Self, RelocationError> {
        if start.is_null() || byte_len == 0 {
            return Err(RelocationError::InvalidLoadRange);
        }
        let start = start as usize as u64;
        let byte_len = byte_len as u64;
        let _ = checked_end(start, byte_len)?;
        Ok(Self {
            start,
            byte_len,
            writable,
        })
    }

    fn end(self) -> Result<u64, RelocationError> {
        checked_end(self.start, self.byte_len)
    }
}

/// One ELF64 `DT_RELA` table, expressed in object-relative virtual addresses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelaTable {
    /// Value from `DT_RELA` before the loader applies its load bias.
    pub(crate) virtual_address: u64,
    /// Value from `DT_RELASZ`.
    pub(crate) byte_len: u64,
    /// Value from `DT_RELAENT`; ELF64 requires twenty-four bytes.
    pub(crate) entry_size: u64,
}

/// One ELF64 `DT_RELR` table, expressed in object-relative virtual addresses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelrTable {
    /// Value from `DT_RELR` before the loader applies its load bias.
    pub(crate) virtual_address: u64,
    /// Value from `DT_RELRSZ`.
    pub(crate) byte_len: u64,
    /// Value from `DT_RELRENT`; ELF64 requires eight bytes.
    pub(crate) entry_size: u64,
}

/// One non-empty relocation table after its ELF shape and runtime range have
/// been checked.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct CheckedRelocationTable {
    address: u64,
    byte_len: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct CheckedRelaTable {
    source: RelaTable,
    range: CheckedRelocationTable,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct CheckedRelrTable {
    source: RelrTable,
    range: CheckedRelocationTable,
}

/// A malformed, unsupported, or out-of-range base-relative relocation input.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum RelocationError {
    /// A mapping was null, empty, or otherwise unusable as a checked range.
    InvalidLoadRange,
    /// Integer address arithmetic would wrap.
    AddressOverflow,
    /// Two caller-supplied ranges overlap, making their permission contract ambiguous.
    OverlappingLoadRanges { first: usize, second: usize },
    /// A RELA table is not an integral sequence of ELF64 RELA records.
    MalformedRelaTable { byte_len: u64 },
    /// A RELA table does not use ELF64's twenty-four-byte record size.
    MalformedRelaEntrySize { entry_size: u64 },
    /// A RELR table does not use ELF64's eight-byte record size.
    MalformedRelrEntrySize { entry_size: u64 },
    /// A RELR table is not an integral sequence of ELF64 RELR words.
    MalformedRelrTable { byte_len: u64 },
    /// A relocation table lies outside one supplied load range.
    TableOutsideLoadRanges,
    /// The non-empty RELA and RELR dynamic tables alias one another.
    OverlappingRelocationTables,
    /// A non-empty relocation table does not begin on an ELF64 word boundary.
    UnalignedRelocationTable { virtual_address: u64 },
    /// A RELA target offset or RELR direct address is not naturally aligned.
    UnalignedRelocationTarget { virtual_address: u64 },
    /// A relocation target is not wholly inside one writable load range.
    TargetOutsideWritableLoadRanges { virtual_address: u64 },
    /// A relocation target would change RELA or RELR bytes after preflight.
    RelocationTargetOverlapsTable { virtual_address: u64 },
    /// More than one RELA or RELR record names the same destination word.
    DuplicateRelocationTarget { virtual_address: u64 },
    /// The caller did not provide one independent scratch word per target.
    InsufficientTargetScratch {
        required_words: u64,
        provided_words: usize,
    },
    /// The caller-supplied scratch storage aliases an object relocation mapping.
    TargetScratchOverlapsLoadRange,
    /// This foundation accepts only symbol-free `R_X86_64_RELATIVE` RELA records.
    UnsupportedRela {
        entry: usize,
        relocation_type: u32,
        symbol_index: u32,
    },
    /// A packed RELR bitmap appeared before its required direct-address word.
    RelrBitmapWithoutAddress { entry: usize },
}

/// Applies only checked x86-64 base-relative relocation records.
///
/// `load_bias` is the runtime address corresponding to object virtual address
/// zero.  Table and relocation target addresses are the un-biased ELF dynamic
/// values.  The function first validates all table shapes, contents, target
/// ranges, and arithmetic, then applies ELF RELA before RELR, matching musl
/// 1.2.6's ordinary-object order. `target_scratch` supplies one `u64` for
/// each validated target. It is used only for an in-place sort that rejects
/// duplicate destinations before any relocation word changes; it must not
/// alias the object's checked load mappings.
///
/// # Safety
///
/// Every `CheckedLoadRange` must describe a live mapping for the whole call,
/// and together the ranges must cover the actual object `PT_LOAD` bytes used
/// by the supplied tables and targets.  The caller must retain exclusive
/// access to every writable relocation word and must not change table bytes,
/// mappings, or permissions concurrently.  `writable` must be derived from
/// the validated ELF load segment, not inferred from a transient mapping
/// permission. `target_scratch` must be live and exclusively borrowed for the
/// whole call. The function checks that it does not overlap a supplied object
/// mapping before reading a table. Those facts cannot be expressed by raw
/// runtime addresses.
pub(crate) unsafe fn apply_relative_relocations(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    rela: Option<RelaTable>,
    relr: Option<RelrTable>,
    target_scratch: &mut [u64],
) -> Result<(), RelocationError> {
    validate_load_ranges(load_ranges)?;
    validate_target_scratch(load_ranges, target_scratch)?;
    let rela = checked_rela_table(load_bias, load_ranges, rela)?;
    let relr = checked_relr_table(load_bias, load_ranges, relr)?;
    validate_table_separation(rela, relr)?;
    let protected_tables = [
        rela.map(|table| table.range),
        relr.map(|table| table.range),
    ];
    preflight_rela(load_bias, load_ranges, rela, &protected_tables)?;
    preflight_relr(load_bias, load_ranges, relr, &protected_tables)?;
    ensure_unique_relocation_targets(rela, relr, target_scratch)?;

    // SAFETY: the preflight covered every read/write address, rejected all
    // destinations that could mutate either table, and rejected duplicate
    // destination words. The function's safety contract keeps mappings and
    // table contents stable until both application passes complete.
    unsafe {
        apply_rela(load_bias, rela);
        apply_relr(load_bias, relr);
    }
    Ok(())
}

fn validate_table_separation(
    rela: Option<CheckedRelaTable>,
    relr: Option<CheckedRelrTable>,
) -> Result<(), RelocationError> {
    let (Some(rela), Some(relr)) = (rela, relr) else {
        return Ok(());
    };
    if ranges_overlap(
        rela.range.address,
        rela.range.byte_len,
        relr.range.address,
        relr.range.byte_len,
    )? {
        // Even though protected table bytes make aliasing memory-safe, one
        // dynamic-table byte stream cannot simultaneously carry these two
        // incompatible ELF encodings in this checked foundation.
        return Err(RelocationError::OverlappingRelocationTables);
    }
    Ok(())
}

fn validate_load_ranges(load_ranges: &[CheckedLoadRange]) -> Result<(), RelocationError> {
    if load_ranges.is_empty() {
        return Err(RelocationError::InvalidLoadRange);
    }
    for (index, range) in load_ranges.iter().copied().enumerate() {
        if range.start == 0 || range.byte_len == 0 {
            return Err(RelocationError::InvalidLoadRange);
        }
        let end = range.end()?;
        for (other_index, other) in load_ranges[..index].iter().copied().enumerate() {
            let other_end = other.end()?;
            if range.start < other_end && other.start < end {
                return Err(RelocationError::OverlappingLoadRanges {
                    first: other_index,
                    second: index,
                });
            }
        }
    }
    Ok(())
}

fn checked_rela_table(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    table: Option<RelaTable>,
) -> Result<Option<CheckedRelaTable>, RelocationError> {
    let Some(source) = table else {
        return Ok(None);
    };
    if source.entry_size != ELF64_RELA_SIZE {
        return Err(RelocationError::MalformedRelaEntrySize {
            entry_size: source.entry_size,
        });
    }
    if source.byte_len % ELF64_RELA_SIZE != 0 {
        return Err(RelocationError::MalformedRelaTable {
            byte_len: source.byte_len,
        });
    }
    if source.byte_len == 0 {
        return Ok(None);
    }
    let range = checked_table_range(
        load_bias,
        load_ranges,
        source.virtual_address,
        source.byte_len,
    )?;
    Ok(Some(CheckedRelaTable { source, range }))
}

fn checked_relr_table(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    table: Option<RelrTable>,
) -> Result<Option<CheckedRelrTable>, RelocationError> {
    let Some(source) = table else {
        return Ok(None);
    };
    if source.entry_size != ELF64_RELR_SIZE {
        return Err(RelocationError::MalformedRelrEntrySize {
            entry_size: source.entry_size,
        });
    }
    if source.byte_len % ELF64_RELR_SIZE != 0 {
        return Err(RelocationError::MalformedRelrTable {
            byte_len: source.byte_len,
        });
    }
    if source.byte_len == 0 {
        return Ok(None);
    }
    let range = checked_table_range(
        load_bias,
        load_ranges,
        source.virtual_address,
        source.byte_len,
    )?;
    Ok(Some(CheckedRelrTable { source, range }))
}

fn checked_table_range(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    virtual_address: u64,
    byte_len: u64,
) -> Result<CheckedRelocationTable, RelocationError> {
    let address = absolute_address(load_bias, virtual_address)?;
    if virtual_address & (WORD_SIZE - 1) != 0 || address & (WORD_SIZE - 1) != 0 {
        return Err(RelocationError::UnalignedRelocationTable { virtual_address });
    }
    require_table_range(load_ranges, address, byte_len)?;
    Ok(CheckedRelocationTable { address, byte_len })
}

fn preflight_rela(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    rela: Option<CheckedRelaTable>,
    protected_tables: &[Option<CheckedRelocationTable>],
) -> Result<(), RelocationError> {
    let Some(table) = rela else {
        return Ok(());
    };
    let entries = table.source.byte_len / ELF64_RELA_SIZE;
    for entry in 0..entries {
        let address = checked_offset(table.range.address, entry, ELF64_RELA_SIZE)?;
        // SAFETY: the complete table range was checked above.
        let r_offset = unsafe { read_word(address) };
        // SAFETY: the complete table range was checked above.
        let r_info = unsafe { read_word(address + WORD_SIZE) };
        // SAFETY: the complete table range was checked above.
        let r_addend = unsafe { read_signed_word(address + 2 * WORD_SIZE) };
        let relocation_type = r_info as u32;
        let symbol_index = (r_info >> 32) as u32;
        if relocation_type != R_X86_64_RELATIVE || symbol_index != 0 {
            return Err(RelocationError::UnsupportedRela {
                entry: entry as usize,
                relocation_type,
                symbol_index,
            });
        }
        require_writable_word(load_bias, load_ranges, protected_tables, r_offset)?;
        let _ = add_signed(load_bias, r_addend)?;
    }
    Ok(())
}

fn preflight_relr(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    relr: Option<CheckedRelrTable>,
    protected_tables: &[Option<CheckedRelocationTable>],
) -> Result<(), RelocationError> {
    let Some(table) = relr else {
        return Ok(());
    };
    let entries = table.source.byte_len / ELF64_RELR_SIZE;
    let mut next_virtual_address = None;
    for entry in 0..entries {
        let address = checked_offset(table.range.address, entry, ELF64_RELR_SIZE)?;
        // SAFETY: the complete table range was checked above.
        let encoded = unsafe { read_word(address) };
        if encoded & 1 == 0 {
            preflight_relr_word(load_bias, load_ranges, protected_tables, encoded)?;
            next_virtual_address = Some(checked_end(encoded, WORD_SIZE)?);
            continue;
        }

        let start = next_virtual_address.ok_or(RelocationError::RelrBitmapWithoutAddress {
            entry: entry as usize,
        })?;
        let bitmap = encoded >> 1;
        for bit in 0..ELF64_RELR_BITS {
            if bitmap & (1u64 << bit) != 0 {
                let virtual_address = checked_end(start, bit * WORD_SIZE)?;
                preflight_relr_word(
                    load_bias,
                    load_ranges,
                    protected_tables,
                    virtual_address,
                )?;
            }
        }
        next_virtual_address = Some(checked_end(start, ELF64_RELR_BITS * WORD_SIZE)?);
    }
    Ok(())
}

fn preflight_relr_word(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    protected_tables: &[Option<CheckedRelocationTable>],
    virtual_address: u64,
) -> Result<(), RelocationError> {
    let address = require_writable_word(
        load_bias,
        load_ranges,
        protected_tables,
        virtual_address,
    )?;
    // SAFETY: `require_writable_word` checked this whole word.
    let addend = unsafe { read_word(address) };
    let _ = add_unsigned(addend, load_bias)?;
    Ok(())
}

fn ensure_unique_relocation_targets(
    rela: Option<CheckedRelaTable>,
    relr: Option<CheckedRelrTable>,
    target_scratch: &mut [u64],
) -> Result<(), RelocationError> {
    let targets = relocation_target_count(rela, relr)?;
    let required_words = usize::try_from(targets).map_err(|_| RelocationError::AddressOverflow)?;
    if target_scratch.len() < required_words {
        return Err(RelocationError::InsufficientTargetScratch {
            required_words: targets,
            provided_words: target_scratch.len(),
        });
    }
    let target_scratch = &mut target_scratch[..required_words];
    collect_relocation_targets(rela, relr, target_scratch)?;

    // `sort_unstable` sorts the caller-owned slice in place. Collection is
    // linear in the table records and this sort is O(n log n), avoiding the
    // unbounded pairwise table rescans that a loader input must never trigger.
    target_scratch.sort_unstable();
    for pair in target_scratch.windows(2) {
        if pair[0] == pair[1] {
            return Err(RelocationError::DuplicateRelocationTarget {
                virtual_address: pair[0],
            });
        }
    }
    Ok(())
}

fn validate_target_scratch(
    load_ranges: &[CheckedLoadRange],
    target_scratch: &mut [u64],
) -> Result<(), RelocationError> {
    if target_scratch.is_empty() {
        return Ok(());
    }
    let byte_len = target_scratch
        .len()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(RelocationError::AddressOverflow)? as u64;
    let address = target_scratch.as_mut_ptr() as usize as u64;
    let _ = checked_end(address, byte_len)?;
    for range in load_ranges.iter().copied() {
        if ranges_overlap(address, byte_len, range.start, range.byte_len)? {
            return Err(RelocationError::TargetScratchOverlapsLoadRange);
        }
    }
    Ok(())
}

fn collect_relocation_targets(
    rela: Option<CheckedRelaTable>,
    relr: Option<CheckedRelrTable>,
    targets: &mut [u64],
) -> Result<(), RelocationError> {
    let mut cursor = 0;
    if let Some(table) = rela {
        let entries = table.source.byte_len / ELF64_RELA_SIZE;
        for entry in 0..entries {
            let address = checked_offset(table.range.address, entry, ELF64_RELA_SIZE)?;
            // SAFETY: preflight validated this complete stable RELA record.
            let virtual_address = unsafe { read_word(address) };
            push_relocation_target(targets, &mut cursor, virtual_address)?;
        }
    }
    if let Some(table) = relr {
        collect_relr_targets(table, targets, &mut cursor)?;
    }
    if cursor != targets.len() {
        return Err(RelocationError::AddressOverflow);
    }
    Ok(())
}

fn collect_relr_targets(
    table: CheckedRelrTable,
    targets: &mut [u64],
    cursor: &mut usize,
) -> Result<(), RelocationError> {
    let entries = table.source.byte_len / ELF64_RELR_SIZE;
    let mut next_virtual_address = None;
    for entry in 0..entries {
        let address = checked_offset(table.range.address, entry, ELF64_RELR_SIZE)?;
        // SAFETY: preflight validated this complete stable RELR word.
        let encoded = unsafe { read_word(address) };
        if encoded & 1 == 0 {
            push_relocation_target(targets, cursor, encoded)?;
            next_virtual_address = Some(checked_end(encoded, WORD_SIZE)?);
            continue;
        }
        let start = next_virtual_address.ok_or(RelocationError::RelrBitmapWithoutAddress {
            entry: entry as usize,
        })?;
        let bitmap = encoded >> 1;
        for bit in 0..ELF64_RELR_BITS {
            if bitmap & (1u64 << bit) != 0 {
                push_relocation_target(targets, cursor, checked_end(start, bit * WORD_SIZE)?)?;
            }
        }
        next_virtual_address = Some(checked_end(start, ELF64_RELR_BITS * WORD_SIZE)?);
    }
    Ok(())
}

fn push_relocation_target(
    targets: &mut [u64],
    cursor: &mut usize,
    virtual_address: u64,
) -> Result<(), RelocationError> {
    let slot = targets
        .get_mut(*cursor)
        .ok_or(RelocationError::AddressOverflow)?;
    *slot = virtual_address;
    *cursor = cursor.checked_add(1).ok_or(RelocationError::AddressOverflow)?;
    Ok(())
}

fn relocation_target_count(
    rela: Option<CheckedRelaTable>,
    relr: Option<CheckedRelrTable>,
) -> Result<u64, RelocationError> {
    let rela_count = rela.map_or(0, |table| table.source.byte_len / ELF64_RELA_SIZE);
    let relr_count = match relr {
        Some(table) => relr_target_count(table)?,
        None => 0,
    };
    rela_count
        .checked_add(relr_count)
        .ok_or(RelocationError::AddressOverflow)
}

fn relr_target_count(table: CheckedRelrTable) -> Result<u64, RelocationError> {
    let entries = table.source.byte_len / ELF64_RELR_SIZE;
    let mut next_virtual_address = None;
    let mut count = 0u64;
    for entry in 0..entries {
        let address = checked_offset(table.range.address, entry, ELF64_RELR_SIZE)?;
        // SAFETY: preflight validated this complete stable table word.
        let encoded = unsafe { read_word(address) };
        if encoded & 1 == 0 {
            count = count.checked_add(1).ok_or(RelocationError::AddressOverflow)?;
            next_virtual_address = Some(checked_end(encoded, WORD_SIZE)?);
            continue;
        }
        let start = next_virtual_address.ok_or(RelocationError::RelrBitmapWithoutAddress {
            entry: entry as usize,
        })?;
        count = count
            .checked_add((encoded >> 1).count_ones() as u64)
            .ok_or(RelocationError::AddressOverflow)?;
        next_virtual_address = Some(checked_end(start, ELF64_RELR_BITS * WORD_SIZE)?);
    }
    Ok(count)
}

unsafe fn apply_rela(load_bias: u64, rela: Option<CheckedRelaTable>) {
    let Some(table) = rela else {
        return;
    };
    let entries = table.source.byte_len / ELF64_RELA_SIZE;
    for entry in 0..entries {
        let address = table
            .range
            .address
            .wrapping_add(entry.wrapping_mul(ELF64_RELA_SIZE));
        // SAFETY: the preceding preflight accepted this complete entry.
        let r_offset = unsafe { read_word(address) };
        // SAFETY: the preceding preflight accepted this complete entry.
        let r_addend = unsafe { read_signed_word(address + 2 * WORD_SIZE) };
        let target = load_bias.wrapping_add(r_offset);
        let value = wrapping_add_signed(load_bias, r_addend);
        // SAFETY: the preceding preflight accepted this writable target.
        unsafe { write_word(target, value) };
    }
}

unsafe fn apply_relr(load_bias: u64, relr: Option<CheckedRelrTable>) {
    let Some(table) = relr else {
        return;
    };
    let entries = table.source.byte_len / ELF64_RELR_SIZE;
    let mut next_virtual_address = None;
    for entry in 0..entries {
        let address = table
            .range
            .address
            .wrapping_add(entry.wrapping_mul(ELF64_RELR_SIZE));
        // SAFETY: the preceding preflight accepted this complete entry.
        let encoded = unsafe { read_word(address) };
        if encoded & 1 == 0 {
            // SAFETY: the preceding preflight accepted this writable target.
            unsafe { apply_relr_word(load_bias, encoded) };
            next_virtual_address = Some(encoded.wrapping_add(WORD_SIZE));
            continue;
        }

        // Preflight rejects a bitmap without a direct-address cursor.  A
        // caller that violates this function's stable-table safety contract
        // must not turn that broken invariant into a loader panic.
        let Some(start) = next_virtual_address else {
            return;
        };
        let bitmap = encoded >> 1;
        for bit in 0..ELF64_RELR_BITS {
            if bitmap & (1u64 << bit) != 0 {
                // SAFETY: the preceding preflight accepted this writable target.
                unsafe { apply_relr_word(load_bias, start.wrapping_add(bit * WORD_SIZE)) };
            }
        }
        next_virtual_address = Some(start.wrapping_add(ELF64_RELR_BITS * WORD_SIZE));
    }
}

unsafe fn apply_relr_word(load_bias: u64, virtual_address: u64) {
    let target = load_bias.wrapping_add(virtual_address);
    // SAFETY: the preceding preflight accepted this writable target.
    let addend = unsafe { read_word(target) };
    let value = addend.wrapping_add(load_bias);
    // SAFETY: the preceding preflight accepted this writable target.
    unsafe { write_word(target, value) };
}

fn require_table_range(
    load_ranges: &[CheckedLoadRange],
    address: u64,
    byte_len: u64,
) -> Result<(), RelocationError> {
    let _ = checked_end(address, byte_len)?;
    if load_ranges
        .iter()
        .copied()
        .any(|range| range_contains(range, address, byte_len))
    {
        return Ok(());
    }
    Err(RelocationError::TableOutsideLoadRanges)
}

fn require_writable_word(
    load_bias: u64,
    load_ranges: &[CheckedLoadRange],
    protected_tables: &[Option<CheckedRelocationTable>],
    virtual_address: u64,
) -> Result<u64, RelocationError> {
    if virtual_address & (WORD_SIZE - 1) != 0 {
        return Err(RelocationError::UnalignedRelocationTarget { virtual_address });
    }
    let address = absolute_address(load_bias, virtual_address)?;
    if address & (WORD_SIZE - 1) != 0 {
        return Err(RelocationError::UnalignedRelocationTarget { virtual_address });
    }
    if !load_ranges
        .iter()
        .copied()
        .any(|range| range.writable && range_contains(range, address, WORD_SIZE))
    {
        return Err(RelocationError::TargetOutsideWritableLoadRanges { virtual_address });
    }
    for table in protected_tables.iter().flatten() {
        if ranges_overlap(address, WORD_SIZE, table.address, table.byte_len)? {
            return Err(RelocationError::RelocationTargetOverlapsTable { virtual_address });
        }
    }
    Ok(address)
}

fn ranges_overlap(
    first_address: u64,
    first_byte_len: u64,
    second_address: u64,
    second_byte_len: u64,
) -> Result<bool, RelocationError> {
    let first_end = checked_end(first_address, first_byte_len)?;
    let second_end = checked_end(second_address, second_byte_len)?;
    Ok(first_address < second_end && second_address < first_end)
}

fn range_contains(range: CheckedLoadRange, address: u64, byte_len: u64) -> bool {
    let Ok(end) = checked_end(address, byte_len) else {
        return false;
    };
    let Ok(range_end) = range.end() else {
        return false;
    };
    address >= range.start && end <= range_end
}

fn absolute_address(load_bias: u64, virtual_address: u64) -> Result<u64, RelocationError> {
    add_unsigned(load_bias, virtual_address)
}

fn checked_offset(start: u64, index: u64, stride: u64) -> Result<u64, RelocationError> {
    let offset = index.checked_mul(stride).ok_or(RelocationError::AddressOverflow)?;
    checked_end(start, offset)
}

fn checked_end(start: u64, byte_len: u64) -> Result<u64, RelocationError> {
    add_unsigned(start, byte_len)
}

fn add_unsigned(left: u64, right: u64) -> Result<u64, RelocationError> {
    left.checked_add(right).ok_or(RelocationError::AddressOverflow)
}

fn add_signed(left: u64, right: i64) -> Result<u64, RelocationError> {
    if right >= 0 {
        add_unsigned(left, right as u64)
    } else {
        let magnitude = right.unsigned_abs();
        left.checked_sub(magnitude)
            .ok_or(RelocationError::AddressOverflow)
    }
}

fn wrapping_add_signed(left: u64, right: i64) -> u64 {
    if right >= 0 {
        left.wrapping_add(right as u64)
    } else {
        left.wrapping_sub(right.unsigned_abs())
    }
}

unsafe fn read_word(address: u64) -> u64 {
    // SAFETY: callers validate that this exact word is in a live range before
    // reaching this helper. Linux/x86-64 has a 64-bit `usize` address space.
    unsafe { ptr::read_unaligned(address as usize as *const u64) }
}

unsafe fn read_signed_word(address: u64) -> i64 {
    // SAFETY: same validated word contract as `read_word`.
    unsafe { ptr::read_unaligned(address as usize as *const i64) }
}

unsafe fn write_word(address: u64, value: u64) {
    // SAFETY: callers validate that this exact word is writable and retain the
    // exclusive-access guarantee documented on `apply_relative_relocations`.
    unsafe { ptr::write_unaligned(address as usize as *mut u64, value) };
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_BYTES: usize = 1024;

    fn load_range(image: &mut [u8], writable: bool) -> CheckedLoadRange {
        CheckedLoadRange::from_checked_mapping(image.as_mut_ptr(), image.len(), writable)
            .expect("test image must form a checked mapping")
    }

    fn bias(image: &mut [u8]) -> u64 {
        image.as_mut_ptr() as usize as u64
    }

    fn write_u64(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + WORD_SIZE as usize].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i64(image: &mut [u8], offset: usize, value: i64) {
        image[offset..offset + WORD_SIZE as usize].copy_from_slice(&value.to_le_bytes());
    }

    fn read_u64(image: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(image[offset..offset + WORD_SIZE as usize].try_into().unwrap())
    }

    fn write_rela(image: &mut [u8], offset: usize, target: u64, info: u64, addend: i64) {
        write_u64(image, offset, target);
        write_u64(image, offset + 8, info);
        write_i64(image, offset + 16, addend);
    }

    unsafe fn apply_relative_relocations(
        load_bias: u64,
        load_ranges: &[CheckedLoadRange],
        rela: Option<RelaTable>,
        relr: Option<RelrTable>,
    ) -> Result<(), RelocationError> {
        let mut target_scratch = [0u64; IMAGE_BYTES / WORD_SIZE as usize];
        // SAFETY: test callers uphold the same complete-exclusive-mapping
        // contract as the production entry point; this local scratch is a
        // distinct stack allocation.
        unsafe {
            super::apply_relative_relocations(
                load_bias,
                load_ranges,
                rela,
                relr,
                &mut target_scratch,
            )
        }
    }

    #[test]
    fn applies_symbol_free_relative_rela_after_full_preflight() {
        let mut image = [0u8; IMAGE_BYTES];
        write_rela(&mut image, 128, 0, R_X86_64_RELATIVE as u64, 0x180);
        write_rela(&mut image, 152, 8, R_X86_64_RELATIVE as u64, 0x1c0);
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image.
        unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 48,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect("symbol-free x86 RELA entries must apply");

        assert_eq!(read_u64(&image, 0), base + 0x180);
        assert_eq!(read_u64(&image, 8), base + 0x1c0);
    }

    #[test]
    fn applies_direct_and_bitmap_packed_relr_records() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0x10);
        write_u64(&mut image, 8, 0x20);
        write_u64(&mut image, 32, 0x30);
        write_u64(&mut image, 504, 0x40);
        write_u64(&mut image, 128, 0);
        let bitmap = (1u64 << 0) | (1u64 << 3) | (1u64 << 62);
        write_u64(&mut image, 136, (bitmap << 1) | 1);
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image.
        unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 16,
                    entry_size: 8,
                }),
            )
        }
        .expect("direct and bitmap RELR entries must apply");

        assert_eq!(read_u64(&image, 0), base + 0x10);
        assert_eq!(read_u64(&image, 8), base + 0x20);
        assert_eq!(read_u64(&image, 32), base + 0x30);
        assert_eq!(read_u64(&image, 504), base + 0x40);
    }

    #[test]
    fn rejects_a_non_relative_rela_without_mutating_an_earlier_target() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0xfeed_face_dead_beef);
        write_rela(&mut image, 128, 0, R_X86_64_RELATIVE as u64, 0x180);
        write_rela(&mut image, 152, 8, 1, 0x1c0);
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 48,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("a non-relative record is outside this foundation");

        assert_eq!(
            error,
            RelocationError::UnsupportedRela {
                entry: 1,
                relocation_type: 1,
                symbol_index: 0,
            }
        );
        assert_eq!(read_u64(&image, 0), 0xfeed_face_dead_beef);
    }

    #[test]
    fn rejects_malformed_relr_without_mutating_an_earlier_target() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0x1234);
        write_u64(&mut image, 128, 0);
        write_u64(&mut image, 136, 2);
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 16,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("an unaligned direct RELR address must fail preflight");

        assert_eq!(
            error,
            RelocationError::UnalignedRelocationTarget {
                virtual_address: 2
            }
        );
        assert_eq!(read_u64(&image, 0), 0x1234);
    }

    #[test]
    fn rejects_a_bitmap_before_a_direct_relr_address() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 128, 3);
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 8,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("a bitmap has no implicit starting address");

        assert_eq!(error, RelocationError::RelrBitmapWithoutAddress { entry: 0 });
    }

    #[test]
    fn rejects_malformed_relocation_table_shapes_before_reading_them() {
        let mut image = [0u8; IMAGE_BYTES];
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: an invalid DT_RELAENT value is rejected before a raw table
        // word is read.
        let rela_entry_error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 16,
                }),
                None,
            )
        }
        .expect_err("ELF64 RELA entries are exactly twenty-four bytes");
        assert_eq!(
            rela_entry_error,
            RelocationError::MalformedRelaEntrySize { entry_size: 16 }
        );

        // SAFETY: malformed byte counts are rejected before a raw table word
        // is read, so this remains valid even though no table bytes are set.
        let rela_error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 23,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("RELA must contain complete 24-byte ELF64 records");
        assert_eq!(
            rela_error,
            RelocationError::MalformedRelaTable { byte_len: 23 }
        );

        // SAFETY: the invalid DT_RELRENT value is rejected before a raw table
        // word is read.
        let relr_entry_error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 8,
                    entry_size: 16,
                }),
            )
        }
        .expect_err("ELF64 RELR entries are exactly eight bytes");
        assert_eq!(
            relr_entry_error,
            RelocationError::MalformedRelrEntrySize { entry_size: 16 }
        );

        // SAFETY: the malformed byte count is rejected before a raw table
        // word is read.
        let relr_size_error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 9,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("RELR must contain complete eight-byte words");
        assert_eq!(
            relr_size_error,
            RelocationError::MalformedRelrTable { byte_len: 9 }
        );

        // SAFETY: the unaligned table location is rejected before a raw table
        // pointer is derived.
        let unaligned_table = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 129,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("ELF64 relocation tables start on an eight-byte boundary");
        assert_eq!(
            unaligned_table,
            RelocationError::UnalignedRelocationTable {
                virtual_address: 129,
            }
        );
    }

    #[test]
    fn rejects_a_rela_target_that_overlaps_its_table_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_rela(&mut image, 128, 128, R_X86_64_RELATIVE as u64, 0x180);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image. The
        // checked table itself must never become a relocation destination.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("a relocation must not overwrite a later table read");

        assert_eq!(
            error,
            RelocationError::RelocationTargetOverlapsTable {
                virtual_address: 128,
            }
        );
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_a_rela_target_that_overlaps_a_relr_table_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_rela(&mut image, 128, 256, R_X86_64_RELATIVE as u64, 0x180);
        write_u64(&mut image, 256, 0);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image. Both
        // table ranges are protected before either encoding is preflighted.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                Some(RelrTable {
                    virtual_address: 256,
                    byte_len: 8,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("a RELA record must not overwrite a RELR table");

        assert_eq!(
            error,
            RelocationError::RelocationTargetOverlapsTable {
                virtual_address: 256,
            }
        );
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_a_relr_target_that_overlaps_its_table_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 128, 128);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image. The
        // direct RELR address names its own encoded word and must be rejected.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 8,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("a RELR record must not overwrite its table");

        assert_eq!(
            error,
            RelocationError::RelocationTargetOverlapsTable {
                virtual_address: 128,
            }
        );
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_duplicate_relr_destinations_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0xfeed_face_dead_beef);
        write_u64(&mut image, 128, 0);
        write_u64(&mut image, 136, 0);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image. The
        // second direct RELR record names the first one's target.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                None,
                Some(RelrTable {
                    virtual_address: 128,
                    byte_len: 16,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("duplicate targets must not allow a partial relocation pass");

        assert_eq!(
            error,
            RelocationError::DuplicateRelocationTarget { virtual_address: 0 }
        );
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_cross_encoding_duplicate_destinations_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0xfeed_face_dead_beef);
        write_rela(&mut image, 128, 0, R_X86_64_RELATIVE as u64, 0x180);
        write_u64(&mut image, 256, 0);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image. RELA
        // and RELR are validated together before either application pass.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                Some(RelrTable {
                    virtual_address: 256,
                    byte_len: 8,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("cross-encoding duplicate targets must not partially apply");

        assert_eq!(
            error,
            RelocationError::DuplicateRelocationTarget { virtual_address: 0 }
        );
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_insufficient_target_scratch_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0xfeed_face_dead_beef);
        write_rela(&mut image, 128, 0, R_X86_64_RELATIVE as u64, 0x180);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);
        let mut target_scratch = [];

        // SAFETY: `range` describes the complete exclusive test image. The
        // empty scratch cannot record the one validated target.
        let error = unsafe {
            super::apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
                &mut target_scratch,
            )
        }
        .expect_err("duplicate validation needs one scratch word per target");

        assert_eq!(
            error,
            RelocationError::InsufficientTargetScratch {
                required_words: 1,
                provided_words: 0,
            }
        );
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_target_scratch_that_aliases_a_load_mapping_before_mutation() {
        let mut words = [0u64; IMAGE_BYTES / WORD_SIZE as usize];
        let base = words.as_mut_ptr() as usize as u64;
        // SAFETY: the word array supplies exactly `IMAGE_BYTES` writable bytes
        // for setup; this temporary byte slice ends before the scratch borrow.
        unsafe {
            let image = core::slice::from_raw_parts_mut(
                words.as_mut_ptr().cast::<u8>(),
                IMAGE_BYTES,
            );
            write_u64(image, 8, 0xfeed_face_dead_beef);
            write_rela(image, 128, 8, R_X86_64_RELATIVE as u64, 0x180);
        }
        let before = words;
        let range = CheckedLoadRange::from_checked_mapping(
            words.as_mut_ptr().cast::<u8>(),
            IMAGE_BYTES,
            true,
        )
        .expect("word array must form a checked mapping");

        // SAFETY: the raw object range remains live. Its scratch aliases the
        // first mapped word, which the production entry point must reject
        // before any relocation target changes.
        let error = unsafe {
            super::apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
                &mut words[..1],
            )
        }
        .expect_err("scratch must remain outside the object's PT_LOAD mappings");

        assert_eq!(error, RelocationError::TargetScratchOverlapsLoadRange);
        assert_eq!(words, before);
    }

    #[test]
    fn rejects_overlapping_rela_and_relr_tables_before_mutation() {
        let mut image = [0u8; IMAGE_BYTES];
        write_u64(&mut image, 0, 0xfeed_face_dead_beef);
        let before = image;
        let base = bias(&mut image);
        let range = load_range(&mut image, true);

        // SAFETY: `range` describes the complete exclusive test image. The
        // two dynamic-table spans overlap even before their contents matter.
        let error = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                Some(RelrTable {
                    virtual_address: 144,
                    byte_len: 8,
                    entry_size: 8,
                }),
            )
        }
        .expect_err("dynamic relocation tables must not alias");

        assert_eq!(error, RelocationError::OverlappingRelocationTables);
        assert_eq!(image, before);
    }

    #[test]
    fn rejects_read_only_and_out_of_range_targets() {
        let mut image = [0u8; IMAGE_BYTES];
        write_rela(&mut image, 128, 0, R_X86_64_RELATIVE as u64, 0x180);
        let base = bias(&mut image);
        let read_only_range = load_range(&mut image, false);

        // SAFETY: `read_only_range` describes the complete test image; the
        // function must reject it before trying to write its target.
        let read_only = unsafe {
            apply_relative_relocations(
                base,
                &[read_only_range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("RELATIVE cannot target a non-writable load range");
        assert_eq!(
            read_only,
            RelocationError::TargetOutsideWritableLoadRanges { virtual_address: 0 }
        );

        let writable_range = load_range(&mut image, true);
        // SAFETY: `writable_range` describes the complete exclusive test image.
        let outside = unsafe {
            apply_relative_relocations(
                base,
                &[writable_range],
                Some(RelaTable {
                    virtual_address: IMAGE_BYTES as u64,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("the table itself must be fully mapped");
        assert_eq!(outside, RelocationError::TableOutsideLoadRanges);
    }

    #[test]
    fn rejects_table_and_result_address_overflow_before_access() {
        let mut image = [0u8; IMAGE_BYTES];
        let range = load_range(&mut image, true);

        // SAFETY: the requested virtual table address overflows before any raw
        // table pointer is derived.
        let table_overflow = unsafe {
            apply_relative_relocations(
                u64::MAX,
                &[range],
                Some(RelaTable {
                    virtual_address: 1,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("load-bias plus table address must not wrap");
        assert_eq!(table_overflow, RelocationError::AddressOverflow);

        write_rela(
            &mut image,
            128,
            0,
            R_X86_64_RELATIVE as u64,
            i64::MIN,
        );
        let base = bias(&mut image);
        let range = load_range(&mut image, true);
        // SAFETY: `range` describes the complete exclusive test image.
        let result_overflow = unsafe {
            apply_relative_relocations(
                base,
                &[range],
                Some(RelaTable {
                    virtual_address: 128,
                    byte_len: 24,
                    entry_size: 24,
                }),
                None,
            )
        }
        .expect_err("an unrepresentable negative addend must fail preflight");
        assert_eq!(result_overflow, RelocationError::AddressOverflow);
    }

    #[test]
    fn accepts_the_representable_minimum_signed_addend() {
        assert_eq!(add_signed(1u64 << 63, i64::MIN), Ok(0));
        assert_eq!(wrapping_add_signed(1u64 << 63, i64::MIN), 0);
    }

    #[test]
    fn rejects_overlapping_caller_load_ranges() {
        let mut image = [0u8; IMAGE_BYTES];
        let first = load_range(&mut image[..512], true);
        let second = load_range(&mut image[256..], true);
        let base = bias(&mut image);

        // SAFETY: the call rejects the ambiguous range contract before any raw
        // read or write. The overlapping slices are not retained as references.
        let error = unsafe { apply_relative_relocations(base, &[first, second], None, None) }
            .expect_err("overlapping load ranges are ambiguous");
        assert_eq!(
            error,
            RelocationError::OverlappingLoadRanges {
                first: 0,
                second: 1,
            }
        );
    }
}
