//! Relocation transaction and symbol scope for the general initial graph.
//!
//! Provenance: musl 1.2.6, revision 9fa28ece75d8a2191de7c5bb53bed224c5947417,
//! MIT license: ldso/dynlink.c::{load_deps,find_sym2,do_relocs,__dls3} and
//! arch/x86_64/reloc.h. AMD64 ELF RELA uses S+A for 64/GOT/PLT,
//! module-relative S+A for DTPOFF, and S+A minus the retained Variant-II
//! module placement for TPOFF. COPY excludes the executable from lookup and
//! copies the executable symbol's size after libraries are relocated.
//!
//! This owner is general-only. It preflights the complete graph before any
//! write, including variable-sized COPY spans and metadata exclusion. The
//! existing fixed/private relocation paths retain their historical contracts.

use super::*;
use super::x86_64_runtime_memory::LoaderVec;
use super::x86_64_initial_graph_state::{InitialGraphState, ObjectState};

#[cfg(test)]
#[path = "x86_64_general_relocation_tests.rs"]
mod tests;

const R_NONE: u32 = 0;
const R_64: u32 = 1;
const R_COPY: u32 = 5;
const SHN_ABS: u16 = 0xfff1;
// musl dynlink.c:find_sym2 includes GNU unique alongside global and weak in
// OK_BINDS. It treats unique as an eligible definition, not a new scope rule.
pub(super) const STB_GNU_UNIQUE: u8 = 10;

/// A transient breadth-first lookup view of the canonical graph, not a
/// second object store. Mapping and TLS module identities remain unchanged.
struct InitialSymbolScope {
    indices: LoaderVec<usize>,
}

/// A borrowed lookup order over one transaction's metadata snapshot. Runtime
/// views may grow independently of the legacy initial stack-array capacity.
struct SymbolScope<'a> {
    indices: &'a [usize],
    module_count: usize,
    static_tls_count: usize,
    initial: bool,
}

impl InitialSymbolScope {
    fn view(&self) -> SymbolScope<'_> {
        // Every initial module is static TLS; planning already assigned
        // exactly consecutive IDs, so no fixed DTV size bounds them here.
        SymbolScope { indices: &self.indices, module_count: usize::MAX,
            static_tls_count: usize::MAX, initial: true }
    }
    fn from_graph(graph: &InitialGraphState) -> Option<Self> {
        let count = graph.object_count();
        let mut scope = Self { indices: LoaderVec::new() };
        let mut seen = LoaderVec::new();
        seen.reserve(count)?;
        for _ in 0..count { seen.push(false)?; }
        scope.indices.reserve(count)?;
        scope.indices.push(0)?;
        seen[0] = true;
        let mut next = 0;
        while next < scope.indices.len() {
            let index = scope.indices[next];
            if graph.state(index) != Some(ObjectState::Ready) { return None; }
            for &child in graph.edges(index)? {
                if !*seen.get(child)? {
                    seen[child] = true;
                    scope.indices.push(child)?;
                }
            }
            next += 1;
        }
        (scope.indices.len() == count).then_some(scope)
    }
}

#[derive(Clone, Copy)]
struct Definition {
    owner: usize,
    value: u64,
    size: u64,
    kind: u8,
    binding: u8,
    visibility: u8,
    section: u16,
}

enum SymbolLookup { Defined(Definition), UndefinedWeak, MissingStrong }

pub(super) enum RuntimeSymbol { Address(u64), Tls { module: usize, offset: usize } }

/// Read-only dlsym lookup over an explicitly ordered scope. The same symbol
/// eligibility and full-definition extent checks as relocation remain active.
///
/// Each scope member is examined as its own one-object table: dlsym needs no
/// cross-object relocation context, so the caller can pass retained records
/// directly instead of copying a whole-registry snapshot per call. A `None`
/// member (an unavailable record) fails the lookup like a malformed table.
/// # Safety
/// Every record/table is retained and readable under the loader mutation lock.
/// Returned addresses borrow retained maps.
pub(super) unsafe fn find_runtime_symbol<'a>(
    scope: impl IntoIterator<Item = Option<&'a Object>>, name: &[u8],
) -> Option<RuntimeSymbol> {
    for object in scope {
        let objects = core::slice::from_ref(object?);
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let Some(symbol) = (unsafe { lookup_exported(objects, 0, name) })? else {
            continue;
        };
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let Some(symbol) = (|| -> Option<Option<Definition>> {
            for index in 1..objects[0].symcount {
                let symbol = unsafe { definition(objects, 0, index) }?;
                if symbol.section == 0 || !matches!(symbol.binding, 1 | 2 | STB_GNU_UNIQUE)
                    || !matches!(symbol.visibility, 0 | 3) || !matches!(symbol.kind, 0 | 1 | 2 | 6)
                { continue; }
                if unsafe { symbol_name(&objects[0], index) }? == name { return Some(Some(symbol)); }
            }
            Some(None)
        })()? else {
            continue;
        };
        if symbol.section == 0 || !matches!(symbol.binding, 1 | 2 | STB_GNU_UNIQUE)
            || !matches!(symbol.visibility, 0 | 3) || !matches!(symbol.kind, 0 | 1 | 2 | 6)
        { continue; }
        if symbol.kind == 6 {
            let object = &objects[0];
            if object.tls_module_id == 0 || symbol.section >= 0xff00
                || symbol.value.checked_add(symbol.size)? > object.tls_memsz as u64
            { return None; }
            return Some(RuntimeSymbol::Tls { module: object.tls_module_id,
                offset: usize::try_from(symbol.value).ok()? });
        }
        return Some(RuntimeSymbol::Address(unsafe { ordinary_address(objects, symbol) }?));
    }
    None
}

unsafe fn definition(objects: &[Object], owner: usize, index: usize) -> Option<Definition> {
    let object = objects.get(owner)?;
    if index == 0 { return None; }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    let symbol = unsafe { direct_symbol(object, index) }?;
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    let symbol = {
        if index >= object.symcount { return None; }
        unsafe { object.symtab.add(index * 24) }
    };
    Some(unsafe { definition_at(owner, symbol) })
}

/// Decode one already-proven readable 24-byte dynsym record.
unsafe fn definition_at(owner: usize, symbol: *const u8) -> Definition {
    Definition {
        owner,
        value: unsafe { read_u64(symbol.add(8)) },
        size: unsafe { read_u64(symbol.add(16)) },
        kind: unsafe { *symbol.add(4) & 15 },
        binding: unsafe { *symbol.add(4) >> 4 },
        visibility: unsafe { *symbol.add(5) & 3 },
        section: unsafe { read_u16(symbol.add(6)) },
    }
}

/// Whether the NUL-terminated string at `string` (with `available` bytes to
/// the end of a table whose last byte is NUL) equals `name`, stopping at the
/// first difference.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn terminated_name_equals(string: *const u8, available: usize, name: &[u8]) -> bool {
    // Equal means `name` then a NUL; the table's final NUL bounds every
    // string, so `name.len() + 1` in-table bytes decide it in one compare.
    available > name.len()
        && unsafe { core::slice::from_raw_parts(string, name.len()) } == name
        && unsafe { string.add(name.len()).read() } == 0
}

unsafe fn symbol_name(object: &Object, index: usize) -> Option<&[u8]> {
    if index == 0 { return None; }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    let symbol = unsafe { direct_symbol(object, index) }?;
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    let symbol = {
        if index >= object.symcount { return None; }
        unsafe { object.symtab.add(index * 24) }
    };
    let offset = unsafe { read_u32(symbol) } as usize;
    if offset >= object.strsz { return None; }
    let name = unsafe { object.strtab.add(offset) };
    let length = unsafe { bounded_symbol_name_len(name, object.strsz - offset) }?;
    Some(unsafe { core::slice::from_raw_parts(name, length) })
}

/// Find a dynsym name's terminator without reading beyond DT_STRSZ. The
/// ordinary ELF table has many import names, so examine eight bytes at a
/// time; only the final partial word needs a byte loop.
unsafe fn bounded_symbol_name_len(name: *const u8, available: usize) -> Option<usize> {
    let mut used = 0usize;
    while available - used >= 8 {
        let word = unsafe { core::ptr::read_unaligned(name.add(used).cast::<u64>()) };
        let zero = word.wrapping_sub(0x0101_0101_0101_0101)
            & !word & 0x8080_8080_8080_8080;
        if zero != 0 {
            return Some(used + zero.trailing_zeros() as usize / 8);
        }
        used += 8;
    }
    while used < available {
        if unsafe { *name.add(used) } == 0 { return Some(used); }
        used += 1;
    }
    None
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(*byte as u32)
    })
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(*byte as u32);
        let high = hash & 0xf000_0000;
        if high != 0 { hash ^= high >> 24; }
        hash &= !high;
    }
    hash
}

/// Lookup one externally visible definition through the table that musl
/// selects for this object. GNU uses its bloom/bucket/chain proof; SysV uses
/// its bucket chain. Neither route linearly scans a mapped dynsym tail.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn lookup_exported(
    objects: &[Object], owner: usize, name: &[u8],
) -> Option<Option<Definition>> {
    let object = objects.get(owner)?;
    let Some(index) = (unsafe { exported_index(object, name) })? else { return Some(None); };
    Some(Some(unsafe { definition_at(owner, object.symtab.add(index.checked_mul(24)?)) }))
}

/// The dynsym index of `name`'s first externally visible definition in
/// `object`'s hash table, `Some(None)` when it has none, and `None` when the
/// walk meets malformed metadata. Every index is bounded by the table's
/// `symbol_count`, whose dynsym records decode proved readable and
/// file-backed, and every chain walk is bounded, so a malformed table fails
/// this lookup rather than reading out of range or looping.
// Inlined into `lookup_exported`, the dlsym and symbol-resolution hot path.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[inline(always)]
unsafe fn exported_index(object: &Object, name: &[u8]) -> Option<Option<usize>> {
    // With a NUL-terminated string table no name read can fail, so the name is
    // compared bytewise up to its first difference instead of being measured.
    let terminated = object.strsz != 0 && unsafe { object.strtab.add(object.strsz - 1).read() } == 0;
    let candidate_matches = |index: usize| -> Option<bool> {
        let symbol = unsafe { object.symtab.add(index.checked_mul(24)?) };
        if !unsafe { exported_symbol_is_visible(object, index) }? {
            return Some(false);
        }
        if terminated {
            let offset = unsafe { read_u32(symbol) } as usize;
            if offset >= object.strsz { return None; }
            Some(unsafe { terminated_name_equals(object.strtab.add(offset), object.strsz - offset, name) })
        } else {
            Some(unsafe { symbol_name(object, index) }? == name)
        }
    };
    match object.symbol_lookup {
        SymbolLookupTable::Gnu {
            bucket_count, symbol_offset, bloom_count, bloom_shift, bloom,
            buckets, chains, symbol_count,
        } => {
            if bucket_count == 0 || bloom_count == 0 { return None; }
            let hash = gnu_hash(name);
            let bloom_index = ((hash >> 6) as usize) & (bloom_count - 1);
            let word = unsafe { read_u64(bloom.add(bloom_index).cast()) };
            let mask = (1u64 << (hash & 63)) | (1u64 << ((hash >> bloom_shift) & 63));
            if word & mask != mask { return Some(None); }
            let mut index = unsafe { read_u32(buckets.add((hash as usize) % bucket_count).cast()) } as usize;
            if index == 0 { return Some(None); }
            if index < symbol_offset || index >= symbol_count { return None; }
            loop {
                let chain = unsafe { read_u32(chains.add(index.checked_sub(symbol_offset)?).cast()) };
                if (chain | 1) == (hash | 1) && candidate_matches(index)? {
                    return Some(Some(index));
                }
                if chain & 1 != 0 { return Some(None); }
                index = index.checked_add(1)?;
                if index >= symbol_count { return None; }
            }
        }
        SymbolLookupTable::Sysv { bucket_count, buckets, chains, symbol_count } => {
            if bucket_count == 0 || symbol_count == 0 { return Some(None); }
            let mut index = unsafe { read_u32(buckets.add((sysv_hash(name) as usize) % bucket_count).cast()) } as usize;
            for _ in 0..symbol_count {
                if index == 0 { return Some(None); }
                if index >= symbol_count { return None; }
                if candidate_matches(index)? {
                    return Some(Some(index));
                }
                index = unsafe { read_u32(chains.add(index).cast()) } as usize;
            }
            None
        }
    }
}

/// Local and non-preemptible references bind in their own object. Global
/// scope admits exported global/weak definitions, including protected ones
/// for external references. Musl accepts the first weak definition in scope;
/// it does not search on for a later strong definition.
unsafe fn lookup(
    scope: &SymbolScope<'_>, objects: &[Object],
    requestor: usize, index: usize, tls: bool, copy: bool,
) -> Option<Option<Definition>> {
    unsafe { lookup_with_name(scope, objects, requestor, index, tls, copy, None) }
}

/// Reuse a name already checked against the requesting object's string table.
/// Relocation dispatch must inspect private imports before ordinary lookup;
/// carrying that slice avoids decoding the same dynsym name twice.
unsafe fn lookup_with_name(
    scope: &SymbolScope<'_>, objects: &[Object],
    requestor: usize, index: usize, tls: bool, copy: bool,
    requested_name: Option<&[u8]>,
) -> Option<Option<Definition>> {
    match unsafe { lookup_result_with_name(scope, objects, requestor, index, tls, copy, requested_name) }? {
        SymbolLookup::Defined(symbol) => Some(Some(symbol)),
        SymbolLookup::UndefinedWeak => Some(None),
        SymbolLookup::MissingStrong => None,
    }
}

/// Missing strong definitions are distinct from malformed symbol metadata.
/// Only the former may enter musl's deferred PLT/GOT queue.
unsafe fn lookup_result(
    scope: &SymbolScope<'_>, objects: &[Object],
    requestor: usize, index: usize, tls: bool, copy: bool,
) -> Option<SymbolLookup> {
    unsafe { lookup_result_with_name(scope, objects, requestor, index, tls, copy, None) }
}

unsafe fn lookup_result_with_name(
    scope: &SymbolScope<'_>, objects: &[Object],
    requestor: usize, index: usize, tls: bool, copy: bool,
    requested_name: Option<&[u8]>,
) -> Option<SymbolLookup> {
    let requested = unsafe { definition(objects, requestor, index) }?;
    if !matches!(requested.binding, 0 | 1 | 2 | STB_GNU_UNIQUE)
        || (requested.binding == 0 && requested.visibility == 3)
        || (tls && requested.kind != 6)
        || (!tls && !matches!(requested.kind, 0 | 1 | 2))
    { return None; }
    if !copy && (requested.binding == 0 || requested.visibility != 0) {
        return (requested.section != 0).then_some(SymbolLookup::Defined(requested));
    }
    let name = match requested_name {
        Some(name) => name,
        None => unsafe { symbol_name(&objects[requestor], index) }?,
    };
    if name.is_empty() { return None; }
    for &owner in scope.indices {
        if copy && owner == 0 { continue; }
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        if let Some(found) = unsafe { lookup_exported(objects, owner, name) }? {
            if found.section == 0 || !matches!(found.binding, 1 | 2 | STB_GNU_UNIQUE)
                || !matches!(found.visibility, 0 | 3)
                || (tls && found.kind != 6)
                || (!tls && !matches!(found.kind, 0 | 1 | 2))
            { continue; }
            if (requested.kind == 1 && found.kind == 2)
                || (requested.kind == 2 && found.kind == 1)
            { return None; }
            return Some(SymbolLookup::Defined(found));
        }
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        for candidate in 1..objects[owner].symcount {
            let found = unsafe { definition(objects, owner, candidate) }?;
            if found.section == 0 || !matches!(found.binding, 1 | 2 | STB_GNU_UNIQUE)
                || !matches!(found.visibility, 0 | 3)
                || (tls && found.kind != 6)
                || (!tls && !matches!(found.kind, 0 | 1 | 2))
            { continue; }
            if unsafe { symbol_name(&objects[owner], candidate) }? == name {
                if (requested.kind == 1 && found.kind == 2)
                    || (requested.kind == 2 && found.kind == 1)
                { return None; }
                return Some(SymbolLookup::Defined(found));
            }
        }
    }
    // Undefined weak data/function references become null. A defined COPY
    // destination and TLS module references always require an actual owner.
    if !copy && !tls && requested.section == 0 && requested.binding == 2 {
        Some(SymbolLookup::UndefinedWeak)
    } else {
        Some(SymbolLookup::MissingStrong)
    }
}

unsafe fn ordinary_address(objects: &[Object], symbol: Definition) -> Option<u64> {
    if symbol.section == SHN_ABS && matches!(symbol.kind, 0 | 1) {
        return Some(symbol.value);
    }
    if symbol.section == 0 || symbol.section >= 0xff00 { return None; }
    let object = &objects[symbol.owner];
    let length = symbol.size.max(1);
    if !unsafe { virtual_range_in_load(object.phdr, object.phnum, symbol.value, length) }
        || (symbol.kind == 2
            && !unsafe { virtual_range_in_executable_load(object.phdr, object.phnum, symbol.value, length) })
    { return None; }
    runtime_address(object.base, symbol.value)
}

#[cfg(crabc_general_initial_tls_materialization_v1)]
unsafe fn tls_coordinates(
    scope: &SymbolScope<'_>, objects: &[Object], requestor: usize,
    index: usize,
) -> Option<(usize, u64)> {
    let (owner, offset, size) = if index == 0 {
        (requestor, 0, 0)
    } else {
        let symbol = unsafe { lookup(scope, objects, requestor, index, true, false) }??;
        if symbol.section == 0 || symbol.section >= 0xff00 { return None; }
        (symbol.owner, symbol.value, symbol.size)
    };
    let object = &objects[owner];
    if object.tls_module_id == 0 || object.tls_module_id > scope.module_count
        || object.tls_memsz == 0
        || (object.tls_module_id <= scope.static_tls_count && object.tls_offset_below_tp < object.tls_memsz)
        || (object.tls_module_id > scope.static_tls_count && object.tls_offset_below_tp != 0)
        || offset.checked_add(size)? > object.tls_memsz as u64
    { return None; }
    Some((owner, offset))
}

fn is_private_runtime_symbol(name: &[u8]) -> bool {
    #[cfg(crabc_general_initial_tls_materialization_v1)]
    if name == b"__tls_get_addr" { return true; }
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    if name == b"__crabc_x86_64_loader_tls_runtime_v1" { return true; }
    #[cfg(crabc_dynamic_main_thread_runtime_v1)]
    if name == b"__crabc_x86_64_owned_crt_handoff" { return true; }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if name == b"__crabc_x86_64_loader_conventional_startup_v1" { return true; }
    let _ = name;
    false
}

unsafe fn word_value(
    scope: &SymbolScope<'_>, objects: &[Object], owner: usize,
    kind: u32, index: usize, addend: i64,
) -> Option<u64> {
    let object = &objects[owner];
    // One name read serves both private-name selectors below.
    let requested_name = if index != 0 { Some(unsafe { symbol_name(object, index) }?) } else { None };
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if let Some(requested_name) = requested_name {
        if let Some(address) = x86_64_initial_worker_tls::runtime_function(requested_name) {
            let requested = unsafe { definition(objects, owner, index) }?;
            return (matches!(kind, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT)
                && addend == 0 && requested.section == 0 && requested.binding == 1
                && requested.visibility == 0 && matches!(requested.kind, 0 | 2))
                .then_some(address);
        }
    }
    if requested_name.is_some_and(is_private_runtime_symbol) {
        // The loader-to-main RuntimeV1 descriptor is an address capability,
        // not an ordinary private-name lookup. Its resolver below verifies
        // the physical main endpoint; reject a changed relocation form here,
        // before the shared initial-graph evaluator can treat JUMP_SLOT or a
        // nonzero addend as an ordinary word relocation.
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        if requested_name == Some(b"__crabc_x86_64_loader_tls_runtime_v1")
        {
            let requested = unsafe { definition(objects, owner, index) }?;
            if kind != R_X86_64_GLOB_DAT || addend != 0
                || owner != 0 || requested.kind != 0 || requested.binding != 2
                || requested.visibility != 0 || requested.section != 0
            {
                return None;
            }
        }
        if !scope.initial {
            #[cfg(crabc_general_initial_tls_materialization_v1)]
            if requested_name == Some(b"__tls_get_addr") {
                let requested = unsafe { definition(objects, owner, index) }?;
                return (matches!(kind, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT)
                    && addend == 0 && requested.section == 0 && requested.binding == 1
                    && requested.visibility == 0 && matches!(requested.kind, 0 | 2))
                    .then_some(__tls_get_addr as *const () as usize as u64);
            }
            return None;
        }
        // Preserve the existing exact weak/main-only data-wire admission;
        // this path must not turn the private descriptor into global scope.
        return unsafe { relocation_value(kind, object, objects.try_into().ok()?, index, addend) };
    }
    match kind {
        R_X86_64_RELATIVE if index == 0 => add_signed(object.base, addend),
        R_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            let address = if index == 0 { 0 } else {
                match unsafe { lookup_with_name(scope, objects, owner, index, false, false, requested_name) }? {
                    Some(symbol) => unsafe { ordinary_address(objects, symbol) }?,
                    None => 0,
                }
            };
            add_signed(address, addend)
        }
        #[cfg(crabc_general_initial_tls_materialization_v1)]
        R_X86_64_DTPMOD64 | R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 => {
            let (provider, value) = unsafe { tls_coordinates(scope, objects, owner, index) }?;
            let module = &objects[provider];
            if kind == R_X86_64_DTPMOD64 {
                return (addend == 0).then_some(module.tls_module_id as u64);
            }
            let offset = add_signed(value, addend)?;
            if offset > module.tls_memsz as u64 { return None; }
            if kind == R_X86_64_DTPOFF64 { return Some(offset); }
            if module.tls_module_id > scope.static_tls_count { return None; }
            let offset = i64::try_from(offset).ok()?;
            let placement = i64::try_from(module.tls_offset_below_tp).ok()?;
            Some(offset.checked_sub(placement)? as u64)
        }
        _ => None,
    }
}

/// None is invalid relocation; Some(None) is a validated deferred strong
/// PLT/GOT reference. Weak undefined symbols still receive zero immediately.
unsafe fn word_resolution(scope: &SymbolScope<'_>, objects: &[Object], owner: usize,
    kind: u32, index: usize, addend: i64, lazy: bool,
) -> Option<Option<u64>> {
    if lazy && index != 0 && matches!(kind, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT) {
        let name = unsafe { symbol_name(&objects[owner], index) }?;
        let private = is_private_runtime_symbol(name);
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let private = private || x86_64_initial_worker_tls::runtime_function(name).is_some();
        if !private && matches!(unsafe { lookup_result(scope, objects, owner, index, false, false) }?, SymbolLookup::MissingStrong) {
            return Some(None);
        }
    }
    unsafe { word_value(scope, objects, owner, kind, index, addend) }.map(Some)
}

#[derive(Clone, Copy)]
struct CopyRelocation { source: u64, destination: u64, length: u64 }

unsafe fn readable_memory(object: &Object, start: u64, length: u64) -> bool {
    let Some(end) = start.checked_add(length) else { return false; };
    for index in 0..object.phnum {
        let header = unsafe { object.phdr.add(index * 56) };
        if unsafe { read_u32(header) } != PT_LOAD || unsafe { read_u32(header.add(4)) } & PF_R == 0 {
            continue;
        }
        let base = unsafe { read_u64(header.add(16)) };
        let Some(limit) = base.checked_add(unsafe { read_u64(header.add(40)) }) else { return false; };
        if start >= base && end <= limit { return true; }
    }
    false
}

unsafe fn copy_relocation(
    scope: &SymbolScope<'_>, objects: &[Object], owner: usize,
    offset: u64, index: usize, addend: i64,
) -> Option<CopyRelocation> {
    let destination = unsafe { definition(objects, owner, index) }?;
    if owner != 0 || objects[owner].role != ObjectRole::Main || addend != 0
        || destination.kind != 1 || !matches!(destination.binding, 1 | 2)
        || destination.visibility != 0 || destination.section == 0
        || destination.section >= 0xff00 || destination.value != offset
    { return None; }
    let source = unsafe { lookup(scope, objects, owner, index, false, true) }??;
    if source.kind != 1 || source.visibility != 0 || source.section >= 0xff00
        || objects[source.owner].role != ObjectRole::Library
        || !unsafe { readable_memory(&objects[source.owner], source.value, source.size.max(1)) }
        || !unsafe { readable_memory(&objects[source.owner], source.value, destination.size) }
    { return None; }
    let source = runtime_address(objects[source.owner].base, source.value)?;
    let destination_address = runtime_address(objects[owner].base, offset)?;
    if ranges_overlap(source, destination.size, destination_address, destination.size)? { return None; }
    Some(CopyRelocation { source, destination: destination_address, length: destination.size })
}

/// Admit one relocation or loader-publication target: 8-byte aligned when
/// `word`, inside one writable PT_LOAD, with a representable runtime address.
/// Like musl's `do_relocs`, the loader does not audit targets against the
/// object's ELF tables or against each other; this cached containment test is
/// the only per-target work, and it keeps a relocation from writing into a
/// read-only mapping.
unsafe fn admitted_target(
    object: &Object, writable: &mut WritableLoadCache, start: u64, length: u64, word: bool,
) -> Option<()> {
    if (word && start & 7 != 0) || !unsafe { writable.contains(object.phdr, object.phnum, start, length) } {
        return None;
    }
    runtime_address(object.base, start)?;
    Some(())
}

/// [`admitted_target`] for a single target outside a relocation pass.
unsafe fn write_target(object: &Object, start: u64, length: u64, word: bool) -> Option<()> {
    unsafe { admitted_target(object, &mut WritableLoadCache::default(), start, length, word) }
}

unsafe fn preflight_object(scope: &SymbolScope<'_>, objects: &[Object], owner: usize) -> Option<()> {
    unsafe { preflight_object_binding(scope, objects, owner, false) }
}

unsafe fn preflight_object_binding(scope: &SymbolScope<'_>, objects: &[Object], owner: usize, lazy: bool) -> Option<()> {
    unsafe { preflight_object_resolved(scope, objects, owner, lazy, None) }
}

/// Resolve every RELA/JMPREL relocation of `objects[owner]` before any write
/// and reject what musl's `do_relocs` rejects: an unsupported relocation type
/// or a missing strong definition, plus crabc's COPY and private-runtime
/// admission rules. A non-lazy caller keeps each word value, in table order,
/// for [`apply_resolved_word_relocations`]. RELR words need no symbol and are
/// applied directly, as in musl.
unsafe fn preflight_object_resolved(
    scope: &SymbolScope<'_>, objects: &[Object], owner: usize, lazy: bool,
    mut resolved: Option<&mut LoaderVec<u64>>,
) -> Option<()> {
    let object = &objects[owner];
    preflight_relocation_table_layout(object)?;
    let mut writable = WritableLoadCache::default();
    for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
        if bytes == 0 { continue; }
        if table.is_null() || bytes % ELF64_RELA_SIZE != 0 { return None; }
        for index in 0..bytes / ELF64_RELA_SIZE {
            let entry = unsafe { table.add(index * ELF64_RELA_SIZE) };
            let offset = unsafe { read_u64(entry) };
            let info = unsafe { read_u64(entry.add(8)) };
            let kind = info as u32;
            if kind == R_NONE { continue; }
            let symbol = (info >> 32) as usize;
            // Reserved runtime wires are imports only through their exact
            // word-relocation admissions. A COPY relocation would otherwise
            // bypass that gate through generic symbol lookup. R_NONE above
            // remains inert and has no import semantics.
            // Only COPY needs the name here; any other symbolic relocation
            // reads (and fails on) the same name in word_resolution below.
            if kind == R_COPY && symbol != 0
                && is_private_runtime_symbol(unsafe { symbol_name(object, symbol) }?)
            {
                return None;
            }
            let addend = unsafe { read_i64(entry.add(16)) };
            let length = if kind == R_COPY {
                if table != object.rela { return None; }
                unsafe { copy_relocation(scope, objects, owner, offset, symbol, addend) }?.length
            } else {
                let value = unsafe { word_resolution(scope, objects, owner, kind, symbol, addend, lazy) }?;
                // A non-lazy caller keeps each word value for application,
                // which then needs no second symbol lookup.
                if let Some(resolved) = resolved.as_deref_mut() { resolved.push(value?)?; }
                8
            };
            unsafe { admitted_target(object, &mut writable, offset, length, kind != R_COPY) }?;
        }
    }
    Some(())
}

/// [`apply_word_relocations`] with the values preflight already resolved for
/// `object`'s word relocations, in table order.
unsafe fn apply_resolved_word_relocations(object: &Object, values: &[u64]) -> Option<()> {
    let mut values = values.iter();
    for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
        for index in 0..bytes / ELF64_RELA_SIZE {
            let entry = unsafe { table.add(index * ELF64_RELA_SIZE) };
            let kind = unsafe { read_u64(entry.add(8)) } as u32;
            if kind == R_NONE || kind == R_COPY { continue; }
            let value = *values.next()?;
            let address = runtime_address(object.base, unsafe { read_u64(entry) })?;
            unsafe { core::ptr::write_unaligned(address as *mut u64, value); }
        }
    }
    if values.next().is_some() { return None; }
    unsafe { apply_relr_table(object) }
}

unsafe fn apply_word_relocations(scope: &SymbolScope<'_>, objects: &[Object], owner: usize) -> Option<()> {
    let object = &objects[owner];
    for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
        for index in 0..bytes / ELF64_RELA_SIZE {
            let entry = unsafe { table.add(index * ELF64_RELA_SIZE) };
            let info = unsafe { read_u64(entry.add(8)) };
            let kind = info as u32;
            if kind == R_NONE || kind == R_COPY { continue; }
            let value = unsafe { word_value(scope, objects, owner, kind, (info >> 32) as usize, read_i64(entry.add(16))) }?;
            let address = runtime_address(object.base, unsafe { read_u64(entry) })?;
            unsafe { core::ptr::write_unaligned(address as *mut u64, value); }
        }
    }
    unsafe { apply_relr_table(object) }
}

/// Relocate one admitted initial graph before protection, TLS copying, or callbacks.
///
/// # Safety
/// Objects and graph must be the same sealed-discovery transaction. All ELF
/// table ranges were validated by parsing, destinations remain writable, and
/// the caller exclusively owns mappings and metadata until this returns.
pub(super) unsafe fn relocate_initial_graph(graph: &InitialGraphState, objects: &[Object]) -> Option<()> {
    unsafe { relocate_initial_graph_inner(graph, objects, #[cfg(feature = "x86_64-owned-dynamic-runtime")] None) }
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(super) unsafe fn relocate_initial_graph_with_debugger(
    graph: &InitialGraphState, objects: &[Object],
    debugger: &super::x86_64_debugger::PreparedInitialDebugger,
) -> Option<()> {
    unsafe { relocate_initial_graph_inner(graph, objects, Some(debugger)) }
}

unsafe fn relocate_initial_graph_inner(
    graph: &InitialGraphState, objects: &[Object],
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    debugger: Option<&super::x86_64_debugger::PreparedInitialDebugger>,
) -> Option<()> {
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    {
        unsafe { validate_main_crt_mode(objects) }?;
        unsafe { validate_canonical_libc_startup_import(graph, objects) }?;
    }
    let initial_scope = InitialSymbolScope::from_graph(graph)?;
    let scope = initial_scope.view();
    // Every word value preflight resolves, in table order, per owner.
    let mut resolved = LoaderVec::<u64>::new();
    let mut resolved_start = LoaderVec::<usize>::new();
    for owner in 0..scope.indices.len() {
        resolved_start.push(resolved.len())?;
        unsafe { preflight_object_resolved(&scope, objects, owner, false, Some(&mut resolved)) }?;
    }
    resolved_start.push(resolved.len())?;
    // Libraries first, main last, matching musl. All copies form the final
    // phase so their source data includes ordinary symbol/relative fixups.
    // Word values come from preflight; a linker never points a relocation at
    // the symbol, string, or hash tables they were resolved from. The
    // debugger publication follows word relocation, so it overwrites any
    // relocation of its own slots, as musl's publication does.
    for owner in (1..scope.indices.len()).chain(core::iter::once(0)) {
        let values = &resolved[resolved_start[owner]..resolved_start[owner + 1]];
        unsafe { apply_resolved_word_relocations(&objects[owner], values) }?;
    }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if let Some(debugger) = debugger { unsafe { debugger.relocate(); } }
    let main = &objects[0];
    for index in 0..main.relasz / ELF64_RELA_SIZE {
        let entry = unsafe { main.rela.add(index * ELF64_RELA_SIZE) };
        let info = unsafe { read_u64(entry.add(8)) };
        if info as u32 != R_COPY { continue; }
        let copy = unsafe { copy_relocation(&scope, objects, 0, read_u64(entry), (info >> 32) as usize, read_i64(entry.add(16))) }?;
        for index in 0..usize::try_from(copy.length).ok()? {
            unsafe { *(copy.destination as *mut u8).add(index) = *(copy.source as *const u8).add(index) };
        }
    }
    Some(())
}

/// The canonical libc identity grants this one data publication boundary.
/// Name presence alone never grants another DSO a loader-state receiver.
/// Like musl's symbol resolution, the slot is libc's hash-table definition of
/// `_dl_debug_addr`; the loader does not scan every dynsym record for a
/// second definition.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(super) unsafe fn debugger_pointer_slot(object: &Object) -> Option<*mut usize> {
    if object.canonical_libc_identity.is_none() { return None; }
    let index = unsafe { exported_index(object, b"_dl_debug_addr") }??;
    let symbol = unsafe { direct_symbol(object, index) }?;
    let value = unsafe { read_u64(symbol.add(8)) };
    let size = unsafe { read_u64(symbol.add(16)) };
    let section = unsafe { read_u16(symbol.add(6)) };
    if unsafe { *symbol.add(4) } != 0x11
        || unsafe { *symbol.add(5) } != 0 || section == 0 || section >= 0xff00
        || size != 8 || (!object.versym.is_null()
            && unsafe { read_u16(object.versym.add(index.checked_mul(2)?)) } > 1)
    { return None; }
    unsafe { write_target(object, value, 8, true) }?;
    Some(runtime_address(object.base, value)? as *mut usize)
}


/// The owned note and the one private handoff relocation are independent
/// proofs of CRT ownership. A note without the exact relocation (or that
/// relocation without the note) is rejected before any relocation writes.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn validate_main_crt_mode(objects: &[Object]) -> Option<()> {
    let main = objects.first()?;
    let mut handoffs = 0usize;
    for (table, bytes) in [(main.rela, main.relasz), (main.jmprel, main.pltrelsz)] {
        if bytes == 0 { continue; }
        if table.is_null() || bytes % ELF64_RELA_SIZE != 0 { return None; }
        for offset in 0..bytes / ELF64_RELA_SIZE {
            let entry = unsafe { table.add(offset * ELF64_RELA_SIZE) };
            let info = unsafe { read_u64(entry.add(8)) };
            // R_NONE consumes neither destination nor dynsym. In particular,
            // its high info word is not a symbol index and must not be passed
            // to the owned-CRT selector's direct-record validator.
            if info as u32 == R_NONE { continue; }
            let index = (info >> 32) as usize;
            if index == 0 { continue; }
            let symbol = unsafe { direct_symbol(main, index) }?;
            let name_offset = unsafe { read_u32(symbol) } as usize;
            if name_offset >= main.strsz { return None; }
            let name = unsafe { main.strtab.add(name_offset) };
            let length = unsafe { bounded_nul(name, main.strsz - name_offset) }?;
            if length != b"__crabc_x86_64_owned_crt_handoff".len()
                || !unsafe { bytes_eq(name, b"__crabc_x86_64_owned_crt_handoff".as_ptr(), length) }
            {
                continue;
            }
            handoffs = handoffs.checked_add(1)?;
            if info as u32 != R_X86_64_GLOB_DAT || unsafe { read_i64(entry.add(16)) } != 0
                || unsafe { *symbol.add(4) >> 4 } != 2
                || unsafe { *symbol.add(4) & 15 } != 1
                || unsafe { *symbol.add(5) & 3 } != 0
                || unsafe { read_u16(symbol.add(6)) } != 0
            {
                return None;
            }
        }
    }
    match main.main_crt_mode {
        MainCrtMode::Conventional => (handoffs == 0).then_some(()),
        MainCrtMode::Owned => (handoffs == 1).then_some(()),
    }
}

/// The fixed installed libc has exactly one relocation request for the
/// ordinary-startup record. Classification has already marked one retained
/// library by opened-file identity; require that one request before any write
/// so duplicate private slots cannot turn into a second authority.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn validate_canonical_libc_startup_import(
    graph: &InitialGraphState,
    objects: &[Object],
) -> Option<()> {
    let mut canonical = None;
    for index in 0..graph.object_count() {
        if objects.get(index)?.canonical_libc_identity.is_some() {
            if canonical.replace(index).is_some() { return None; }
        }
    }
    // Structural unit fixtures that do not exercise installed-product
    // classification retain their independent relocation coverage. A real
    // product cannot reach this code without the selector's one mark.
    let Some(canonical) = canonical else { return Some(()); };
    let mut imports = 0usize;
    for owner in 0..graph.object_count() {
        let object = objects.get(owner)?;
        for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
            if bytes == 0 { continue; }
            if table.is_null() || bytes % ELF64_RELA_SIZE != 0 { return None; }
            for offset in 0..bytes / ELF64_RELA_SIZE {
                let entry = unsafe { table.add(offset * ELF64_RELA_SIZE) };
                let info = unsafe { read_u64(entry.add(8)) };
                let symbol_index = (info >> 32) as usize;
                if info as u32 == R_NONE || symbol_index == 0 { continue; }
                if unsafe { symbol_name(object, symbol_index) }?
                    != b"__crabc_x86_64_loader_conventional_startup_v1"
                {
                    continue;
                }
                if owner != canonical { return None; }
                let symbol = unsafe { direct_symbol(object, symbol_index) }?;
                let exact = info as u32 == R_X86_64_GLOB_DAT
                    && unsafe { read_i64(entry.add(16)) } == 0
                    && unsafe { *symbol.add(4) >> 4 } == 2
                    && unsafe { *symbol.add(4) & 15 } == 1
                    && unsafe { *symbol.add(5) & 3 } == 0
                    && unsafe { read_u16(symbol.add(6)) } == 0;
                if !exact { return None; }
                imports = imports.checked_add(1)?;
            }
        }
    }
    (imports == 1).then_some(())
}

/// Relocate only this transaction's runtime-new suffix. Existing mappings
/// provide scope but are never rewritten; failure before apply leaves every
/// destination untouched. The caller rolls back only newly mapped objects.
/// # Safety
/// Snapshot records borrow loader-owned readable ELF mappings under the
/// mutation lock. `indices` contains only valid object indices and follows the
/// admitted global-plus-dependency lookup order. New mappings are writable;
/// their module IDs are monotonic, and only initial modules have IE placement.
pub(super) unsafe fn relocate_runtime_objects(
    objects: &[Object], indices: &[usize], first_new: usize, static_tls_count: usize,
) -> Option<()> {
    if first_new == 0 || first_new > objects.len() || indices.iter().any(|index| *index >= objects.len()) { return None; }
    let scope = SymbolScope { indices, module_count: objects.iter().map(|object| object.tls_module_id).max().unwrap_or(0),
        static_tls_count, initial: false };
    for owner in first_new..objects.len() { unsafe { preflight_object(&scope, objects, owner) }?; }
    for owner in first_new..objects.len() {
        unsafe { apply_word_relocations(&scope, objects, owner) }?;
    }
    Some(())
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[path = "x86_64_deferred_relocations.rs"]
pub(super) mod deferred;
