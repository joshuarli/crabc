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
    let length = unsafe { bounded_nul(name, object.strsz - offset) }?;
    Some(unsafe { core::slice::from_raw_parts(name, length) })
}

/// `symbol_name(object, index)? == name` for a string table whose final byte
/// is NUL: the same record and offset checks, then a bounded comparison that
/// stops at the first differing byte instead of measuring the whole name.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn terminated_symbol_name_is(object: &Object, index: usize, name: &[u8]) -> Option<bool> {
    if index == 0 { return None; }
    let symbol = unsafe { direct_symbol(object, index) }?;
    let offset = unsafe { read_u32(symbol) } as usize;
    if offset >= object.strsz { return None; }
    // A terminated table ends every in-range name before its last byte.
    Some(unsafe { terminated_name_equals(object.strtab.add(offset), object.strsz - offset, name) })
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
    // Every candidate below is an index the object's hash table certified at
    // load (decode_gnu_hash/decode_sysv_hash proved each record in
    // [symbol_offset or 0, symbol_count) readable and file-backed), so the
    // record is read without repeating that range proof per lookup. With a
    // NUL-terminated string table no name read can fail, so the name is
    // compared bytewise up to its first difference instead of being measured.
    let terminated = object.strsz != 0 && unsafe { object.strtab.add(object.strsz - 1).read() } == 0;
    let candidate_matches = |index: usize| -> Option<Option<Definition>> {
        let symbol = unsafe { object.symtab.add(index.checked_mul(24)?) };
        let definition = unsafe { definition_at(owner, symbol) };
        if !unsafe { exported_symbol_is_visible(object, index) }? {
            return Some(None);
        }
        let matches = if terminated {
            let offset = unsafe { read_u32(symbol) } as usize;
            if offset >= object.strsz { return None; }
            unsafe { terminated_name_equals(object.strtab.add(offset), object.strsz - offset, name) }
        } else {
            unsafe { symbol_name(object, index) }? == name
        };
        Some(matches.then_some(definition))
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
                if (chain | 1) == (hash | 1) {
                    if let Some(definition) = candidate_matches(index)? {
                        return Some(Some(definition));
                    }
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
                if let Some(definition) = candidate_matches(index)? {
                    return Some(Some(definition));
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
    match unsafe { lookup_result(scope, objects, requestor, index, tls, copy) }? {
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
    let requested = unsafe { definition(objects, requestor, index) }?;
    if !matches!(requested.binding, 0 | 1 | 2 | STB_GNU_UNIQUE)
        || (requested.binding == 0 && requested.visibility == 3)
        || (tls && requested.kind != 6)
        || (!tls && !matches!(requested.kind, 0 | 1 | 2))
    { return None; }
    if !copy && (requested.binding == 0 || requested.visibility != 0) {
        return (requested.section != 0).then_some(SymbolLookup::Defined(requested));
    }
    let name = unsafe { symbol_name(&objects[requestor], index) }?;
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
        if unsafe { symbol_name(object, index) }?
            == b"__crabc_x86_64_loader_tls_runtime_v1"
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
            if unsafe { symbol_name(object, index) }? == b"__tls_get_addr" {
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
                match unsafe { lookup(scope, objects, owner, index, false, false) }? {
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

#[derive(Clone, Copy)]
pub(super) struct WriteSpan { pub(super) start: u64, pub(super) length: u64 }

/// Exclusive preflight scratch, sized from already range-checked ELF tables.
/// It owns only anonymous loader memory: no libc allocator, TLS or callbacks
/// are available at this point. Drop releases it on every validation failure.
struct RelocationScratch { mapping: *mut u8, bytes: usize, spans: usize, relrs: usize }
impl RelocationScratch {
    unsafe fn new(object: &Object) -> Option<Self> {
        let relrs = (object.relrsz / ELF64_RELR_SIZE).checked_mul(63)?;
        let spans = (object.relasz / ELF64_RELA_SIZE)
            .checked_add(object.pltrelsz / ELF64_RELA_SIZE)?.checked_add(relrs)?;
        let bytes = spans.checked_mul(core::mem::size_of::<WriteSpan>())?
            .checked_add(relrs.checked_mul(8)?)?.max(1);
        if bytes > isize::MAX as usize { return None; }
        let mapping = super::x86_64_runtime_memory::allocate(bytes, SCRATCH_ALIGN)?;
        Some(Self { mapping, bytes, spans, relrs })
    }
    unsafe fn slices(&mut self) -> (&mut [WriteSpan], &mut [u64]) {
        // The lengths were checked together before allocation. Loader blocks
        // are zeroed, so every integer field starts at zero; the two regions
        // are disjoint.
        unsafe { (core::slice::from_raw_parts_mut(self.mapping.cast(), self.spans),
            core::slice::from_raw_parts_mut(self.mapping.add(self.spans * core::mem::size_of::<WriteSpan>()).cast(), self.relrs)) }
    }
}
impl Drop for RelocationScratch {
    fn drop(&mut self) {
        unsafe { super::x86_64_runtime_memory::release(self.mapping, self.bytes, SCRATCH_ALIGN); }
    }
}
// Both scratch regions hold u64-aligned records.
const SCRATCH_ALIGN: usize = core::mem::align_of::<u64>();
const _: () = assert!(core::mem::align_of::<WriteSpan>() <= SCRATCH_ALIGN);

/// Reject writes into every ELF table read again during apply, not just the
/// relocation tables. COPY may be byte-aligned and larger than a machine word.
unsafe fn write_span(
    object: &Object, start: u64, length: u64, word: bool, symbol_index: Option<usize>,
) -> Option<WriteSpan> {
    unsafe { checked_write_span(object, start, length, word, symbol_index, ReferencedRecords::Scan) }
}

/// Whether one write-span check also scans every relocation-referenced
/// symbol/VERSYM record. That scan is linear in the relocation count, so a
/// caller that checks every relocation of an object instead defers it to one
/// sorted pass, [`referenced_records_overlap_spans`], over all its spans.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferencedRecords { Scan, Deferred }

unsafe fn checked_write_span(
    object: &Object, start: u64, length: u64, word: bool, symbol_index: Option<usize>,
    referenced: ReferencedRecords,
) -> Option<WriteSpan> {
    if (word && start & 7 != 0)
        || !unsafe { virtual_range_in_writable_load(object.phdr, object.phnum, start, length) }
    { return None; }
    let address = runtime_address(object.base, start)?;
    let tables = [
        (object.rela, object.relasz), (object.jmprel, object.pltrelsz),
        (object.relr, object.relrsz), (object.symtab, object.symcount.checked_mul(24)?),
        (object.strtab, object.strsz), (object.phdr, object.phnum.checked_mul(56)?),
    ];
    for (table, bytes) in tables {
        if bytes != 0 && (table.is_null() || ranges_overlap(address, length, table as u64, bytes as u64)?) {
            return None;
        }
    }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if unsafe { overlaps_relocation_metadata(object, address, length, referenced) }? {
        return None;
    }
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    let _ = (referenced, symbol_index);
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if let Some(index) = symbol_index {
        let symbol = unsafe { direct_symbol(object, index) }?;
        if ranges_overlap(address, length, symbol as u64, 24)? {
            return None;
        }
        if !object.versym.is_null() {
            let version_offset = index.checked_mul(2)?;
            let version = unsafe { object.versym.add(version_offset) };
            if ranges_overlap(address, length, version as u64, 2)? {
                return None;
            }
        }
    }
    Some(WriteSpan { start, length })
}

/// Reject a write into any symbol/hash/version record that a later relocation
/// can consume. `symcount` is an export-iteration extent, not a dynsym
/// extent: GNU-hash imports can name records after an all-zero bucket table,
/// so every relocation-selected record is protected independently as well.
/// This completes preflight before the first write, preventing one relocation
/// from changing another relocation's requested symbol shape.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn overlaps_relocation_metadata(
    object: &Object,
    address: u64,
    length: u64,
    referenced: ReferencedRecords,
) -> Option<bool> {
    let overlaps = |table: *const u8, bytes: usize| -> Option<bool> {
        if bytes == 0 { return Some(false); }
        if table.is_null() { return None; }
        ranges_overlap(address, length, table as u64, u64::try_from(bytes).ok()?)
    };

    if overlaps(object.symtab, object.symcount.checked_mul(24)?)? {
        return Some(true);
    }
    if !object.versym.is_null()
        && overlaps(object.versym, object.symcount.checked_mul(2)?)?
    {
        return Some(true);
    }
    match object.symbol_lookup {
        SymbolLookupTable::Sysv { bucket_count, buckets, symbol_count, .. } => {
            if !(buckets.is_null() && bucket_count == 0 && symbol_count == 0) {
                // Unit fixtures without an export table still exercise
                // direct relocation-indexed symbol admission below.
                let table = (buckets as usize).checked_sub(8)? as *const u8;
                let words = bucket_count.checked_add(symbol_count)?.checked_add(2)?;
                if overlaps(table, words.checked_mul(4)?)? { return Some(true); }
            }
        }
        SymbolLookupTable::Gnu {
            bucket_count, symbol_offset, bloom_count, bloom, symbol_count, ..
        } => {
            let table = (bloom as usize).checked_sub(16)? as *const u8;
            let bytes = 16usize
                .checked_add(bloom_count.checked_mul(8)?)?
                .checked_add(bucket_count.checked_mul(4)?)?
                .checked_add(symbol_count.saturating_sub(symbol_offset).checked_mul(4)?)?;
            if overlaps(table, bytes)? { return Some(true); }
        }
    }

    // Direct dynsym reads deliberately bypass hash iteration. Scan every
    // relocation request now, while relocation tables are still immutable,
    // and protect the exact symbol and VERSYM words each later application
    // may reread. R_NONE is an inert table entry and consumes no symbol.
    if referenced == ReferencedRecords::Deferred { return Some(false); }
    for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
        if bytes == 0 { continue; }
        if table.is_null() || bytes % ELF64_RELA_SIZE != 0 { return None; }
        for offset in 0..bytes / ELF64_RELA_SIZE {
            let entry = unsafe { table.add(offset * ELF64_RELA_SIZE) };
            let info = unsafe { read_u64(entry.add(8)) };
            if info as u32 == R_NONE { continue; }
            let index = (info >> 32) as usize;
            if index == 0 { continue; }
            let symbol = unsafe { direct_symbol(object, index) }?;
            if ranges_overlap(address, length, symbol as u64, 24)? { return Some(true); }
            if !object.versym.is_null() {
                let version = unsafe { object.versym.add(index.checked_mul(2)?) };
                if ranges_overlap(address, length, version as u64, 2)? { return Some(true); }
            }
        }
    }
    Some(false)
}

unsafe fn preflight_object(scope: &SymbolScope<'_>, objects: &[Object], owner: usize) -> Option<()> {
    unsafe { preflight_object_binding(scope, objects, owner, false) }
}

unsafe fn preflight_object_binding(scope: &SymbolScope<'_>, objects: &[Object], owner: usize, lazy: bool) -> Option<()> {
    unsafe { preflight_object_guarded(scope, objects, owner, lazy, None, None) }
}

/// [`preflight_object_binding`], additionally rejecting a write set that
/// `destination_guard` reports as overlapping protected loader slots; it
/// sees the object's final sorted, admitted spans (virtual start, length).
unsafe fn preflight_object_guarded(
    scope: &SymbolScope<'_>, objects: &[Object], owner: usize, lazy: bool,
    destination_guard: Option<&dyn Fn(&Object, &[WriteSpan]) -> Option<bool>>,
    mut resolved: Option<&mut LoaderVec<u64>>,
) -> Option<()> {
    let object = &objects[owner];
    preflight_relocation_table_layout(object)?;
    let mut scratch = unsafe { RelocationScratch::new(object) }?;
    let (spans, relr_targets) = unsafe { scratch.slices() };
    let mut writable = WritableLoadCache::default();
    let mut count = 0;
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
            *spans.get_mut(count)? = unsafe { admitted_span(object, &mut writable, offset, length, kind != R_COPY) }?;
            count += 1;
        }
    }
    // RELR targets need the same containment before their addend is read;
    // their table checks join every other span's below.
    let relr_count = unsafe { decode_relr_table(object, relr_targets, 0, |target| {
        let span = unsafe { admitted_span(object, &mut writable, target, 8, true) }?;
        let address = runtime_address(object.base, span.start)?;
        // Packed RELR uses the preexisting pointer word as its addend; check
        // that arithmetic before any write, as preflight_relr_target does.
        let _ = unsafe { read_u64(address as *const u8) }.checked_add(object.base)?;
        Some(())
    }) }?;
    // Linkers emit each table in ascending offset order, so the RELA spans and
    // the RELR targets are usually two sorted runs: merge them from the back
    // in linear time. Anything else falls back to one sort.
    let total = count.checked_add(relr_count)?;
    if spans.len() < total { return None; }
    let relr = &relr_targets[..relr_count];
    if !spans[..count].is_sorted_by_key(|span| span.start) {
        spans[..count].sort_unstable_by_key(|span| span.start);
    }
    if relr.is_sorted() {
        let (mut left, mut right) = (count, relr_count);
        for slot in (0..total).rev() {
            let take_left = right == 0 || (left != 0 && spans[left - 1].start > relr[right - 1]);
            spans[slot] = if take_left {
                left -= 1;
                spans[left]
            } else {
                right -= 1;
                WriteSpan { start: relr[right], length: 8 }
            };
        }
        count = total;
    } else {
        for &offset in relr {
            spans[count] = WriteSpan { start: offset, length: 8 };
            count += 1;
        }
        spans[..count].sort_unstable_by_key(|span| span.start);
    }
    let mut end = 0;
    for span in &spans[..count] {
        if span.length == 0 { continue; }
        if span.start < end { return None; }
        end = span.start.checked_add(span.length)?;
    }
    if unsafe { forbidden_tables_overlap_spans(object, &spans[..count]) }? { return None; }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if unsafe { referenced_records_overlap_spans(object, &spans[..count]) }? { return None; }
    if let Some(guard) = destination_guard {
        if guard(object, &spans[..count])? { return None; }
    }
    Some(())
}

/// The per-span half of [`checked_write_span`]: word alignment, containment
/// in one writable PT_LOAD, and a representable runtime address. Table
/// overlap is checked once for the whole set by
/// [`forbidden_tables_overlap_spans`], and the span's own symbol/VERSYM
/// record by [`referenced_records_overlap_spans`].
unsafe fn admitted_span(
    object: &Object, writable: &mut WritableLoadCache, start: u64, length: u64, word: bool,
) -> Option<WriteSpan> {
    if (word && start & 7 != 0) || !unsafe { writable.contains(object.phdr, object.phnum, start, length) } {
        return None;
    }
    runtime_address(object.base, start)?;
    Some(WriteSpan { start, length })
}

/// Whether any of `spans` (sorted by start, nonzero spans pairwise disjoint,
/// runtime addresses admitted) overlaps `[record, record + length)` in
/// exactly `ranges_overlap`'s sense, including a zero-length span strictly
/// inside the record; `None` when `record + length` overflows. Binary search
/// finds the candidates instead of scanning every span.
unsafe fn spans_overlap_range(object: &Object, spans: &[WriteSpan], record: u64, length: u64) -> Option<bool> {
    let span_address = |span: &WriteSpan| runtime_address(object.base, span.start);
    // Index of the first span whose runtime start is at or after `address`.
    let first_at_or_after = |address: u64| -> Option<usize> {
        let (mut low, mut high) = (0, spans.len());
        while low < high {
            let middle = low + (high - low) / 2;
            if span_address(&spans[middle])? < address { low = middle + 1; } else { high = middle; }
        }
        Some(low)
    };
    let from_record = first_at_or_after(record)?;
    let after_record = first_at_or_after(record.checked_add(length)?)?;
    // A span starting inside the record overlaps it, except an empty span
    // exactly at the record start.
    for span in &spans[from_record..after_record] {
        if span_address(span)? > record || span.length != 0 { return Some(true); }
    }
    // Of the spans starting before the record, only the last nonempty one
    // can reach into it.
    for span in spans[..from_record].iter().rev() {
        if span.length == 0 { continue; }
        return ranges_overlap(span_address(span)?, span.length, record, length);
    }
    Some(false)
}

/// Whether an admitted write set (sorted, disjoint) reaches a debugger slot,
/// with exactly the outcome of calling `debugger.overlaps` on every span:
/// empty writes never overlap, an overflowing write end rejects, and each
/// slot is found among the sorted spans by binary search.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(super) unsafe fn debugger_slots_overlap_spans(
    debugger: &super::x86_64_debugger::PreparedInitialDebugger, object: &Object, spans: &[WriteSpan],
) -> Option<bool> {
    let mut any_nonempty = false;
    for span in spans {
        runtime_address(object.base, span.start)?.checked_add(span.length)?;
        any_nonempty |= span.length != 0;
    }
    if !any_nonempty { return Some(false); }
    for slot in debugger.slots() {
        slot.checked_add(8)?;
        if unsafe { nonempty_spans_overlap_range(object, spans, slot, 8) }? { return Some(true); }
    }
    Some(false)
}

/// [`spans_overlap_range`] counting only nonempty spans, as
/// [`super::x86_64_debugger::PreparedInitialDebugger::overlaps`] does.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn nonempty_spans_overlap_range(object: &Object, spans: &[WriteSpan], record: u64, length: u64) -> Option<bool> {
    let span_address = |span: &WriteSpan| runtime_address(object.base, span.start);
    let first_at_or_after = |address: u64| -> Option<usize> {
        let (mut low, mut high) = (0, spans.len());
        while low < high {
            let middle = low + (high - low) / 2;
            if span_address(&spans[middle])? < address { low = middle + 1; } else { high = middle; }
        }
        Some(low)
    };
    let from_record = first_at_or_after(record)?;
    let after_record = first_at_or_after(record.checked_add(length)?)?;
    if spans[from_record..after_record].iter().any(|span| span.length != 0) { return Some(true); }
    for span in spans[..from_record].iter().rev() {
        if span.length == 0 { continue; }
        return ranges_overlap(span_address(span)?, span.length, record, length);
    }
    Some(false)
}

/// The per-object half of [`checked_write_span`]'s table checks for one
/// complete, sorted, disjoint write set: every span must avoid each ELF table
/// that relocation or later application rereads (and, with the installed
/// runtime, the symbol/VERSYM/hash metadata of [`overlaps_relocation_metadata`]).
/// Each table is tested once against the sorted spans rather than every span
/// against every table. The outcome equals running those per-span checks on
/// every span: a null table with a nonzero size, an overflowing table or span
/// extent, or any overlap rejects a nonempty set; an empty set is accepted.
unsafe fn forbidden_tables_overlap_spans(object: &Object, spans: &[WriteSpan]) -> Option<bool> {
    if spans.is_empty() { return Some(false); }
    let mut tables: [(*const u8, Option<usize>); 9] = [
        (object.rela, Some(object.relasz)), (object.jmprel, Some(object.pltrelsz)),
        (object.relr, Some(object.relrsz)), (object.symtab, object.symcount.checked_mul(24)),
        (object.strtab, Some(object.strsz)), (object.phdr, object.phnum.checked_mul(56)),
        (core::ptr::null(), Some(0)), (core::ptr::null(), Some(0)), (core::ptr::null(), Some(0)),
    ];
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    {
        // `overlaps_relocation_metadata`'s tables; the symbol table repeats.
        if !object.versym.is_null() { tables[6] = (object.versym, object.symcount.checked_mul(2)); }
        match object.symbol_lookup {
            SymbolLookupTable::Sysv { bucket_count, buckets, symbol_count, .. } => {
                if !(buckets.is_null() && bucket_count == 0 && symbol_count == 0) {
                    let table = (buckets as usize).checked_sub(8)? as *const u8;
                    let words = bucket_count.checked_add(symbol_count)?.checked_add(2)?;
                    tables[7] = (table, words.checked_mul(4));
                }
            }
            SymbolLookupTable::Gnu { bucket_count, symbol_offset, bloom_count, bloom, symbol_count, .. } => {
                let table = (bloom as usize).checked_sub(16)? as *const u8;
                let bytes = 16usize
                    .checked_add(bloom_count.checked_mul(8)?)?
                    .checked_add(bucket_count.checked_mul(4)?)?
                    .checked_add(symbol_count.saturating_sub(symbol_offset).checked_mul(4)?)?;
                tables[7] = (table, Some(bytes));
            }
        }
    }
    let mut any_table = false;
    for (table, bytes) in tables {
        let bytes = bytes?;
        if bytes == 0 { continue; }
        if table.is_null() { return None; }
        any_table = true;
        if unsafe { spans_overlap_range(object, spans, table as u64, u64::try_from(bytes).ok()?) }? {
            return Some(true);
        }
    }
    // Any table check would have rejected a span whose runtime extent overflows.
    if any_table {
        for span in spans {
            runtime_address(object.base, span.start)?.checked_add(span.length)?;
        }
    }
    Some(false)
}

/// The deferred half of [`overlaps_relocation_metadata`] for one object's
/// complete write set: does any span overlap a symbol or VERSYM record that a
/// relocation names? `spans` is sorted by start and its nonzero spans are
/// pairwise disjoint, so each record is tested by binary search instead of
/// rescanning every relocation per span (quadratic in the relocation count).
/// Overlap has exactly `ranges_overlap`'s meaning, including a zero-length
/// span strictly inside a record.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn referenced_records_overlap_spans(object: &Object, spans: &[WriteSpan]) -> Option<bool> {
    let overlaps = |record: u64, length: u64| unsafe { spans_overlap_range(object, spans, record, length) };
    for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
        if bytes == 0 { continue; }
        if table.is_null() || bytes % ELF64_RELA_SIZE != 0 { return None; }
        for offset in 0..bytes / ELF64_RELA_SIZE {
            let entry = unsafe { table.add(offset * ELF64_RELA_SIZE) };
            let info = unsafe { read_u64(entry.add(8)) };
            if info as u32 == R_NONE { continue; }
            let index = (info >> 32) as usize;
            if index == 0 { continue; }
            let symbol = unsafe { direct_symbol(object, index) }?;
            if overlaps(symbol as u64, 24)? { return Some(true); }
            if !object.versym.is_null() {
                let version = unsafe { object.versym.add(index.checked_mul(2)?) };
                if overlaps(version as u64, 2)? { return Some(true); }
            }
        }
    }
    Some(false)
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
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        if let Some(debugger) = debugger {
            // The loader's two initial publication slots must not overlap any
            // admitted RELA/RELR write (a crafted COPY cannot overwrite
            // DT_DEBUG). They are checked against the same admitted write set
            // preflight just built, instead of re-deriving it.
            let guard = |object: &Object, spans: &[WriteSpan]| unsafe { debugger_slots_overlap_spans(debugger, object, spans) };
            resolved_start.push(resolved.len())?;
            unsafe { preflight_object_guarded(&scope, objects, owner, false, Some(&guard), Some(&mut resolved)) }?;
            continue;
        }
        resolved_start.push(resolved.len())?;
        unsafe { preflight_object_guarded(&scope, objects, owner, false, None, Some(&mut resolved)) }?;
    }
    resolved_start.push(resolved.len())?;
    // Libraries first, main last, matching musl. All copies form the final
    // phase so their source data includes ordinary symbol/relative fixups.
    // Word values come from preflight: they depend only on immutable,
    // write-protected tables and load bases, which no admitted write reaches.
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
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(super) unsafe fn debugger_pointer_slot(object: &Object) -> Option<*mut usize> {
    if object.canonical_libc_identity.is_none() { return None; }
    let mut result = None;
    // With a NUL-terminated string table no name read can fail, so a byte
    // comparison bounded by the table decides equality without measuring
    // every name; otherwise keep the measuring read and its failure.
    let terminated = unsafe { object.strtab.add(object.strsz.checked_sub(1)?).read() } == 0;
    for index in 1..object.symcount {
        let matches = if terminated {
            unsafe { terminated_symbol_name_is(object, index, b"_dl_debug_addr") }?
        } else {
            unsafe { symbol_name(object, index) }? == b"_dl_debug_addr"
        };
        if !matches { continue; }
        let symbol = unsafe { direct_symbol(object, index) }?;
        let value = unsafe { read_u64(symbol.add(8)) };
        let size = unsafe { read_u64(symbol.add(16)) };
        let section = unsafe { read_u16(symbol.add(6)) };
        if result.is_some() || unsafe { *symbol.add(4) } != 0x11
            || unsafe { *symbol.add(5) } != 0 || section == 0 || section >= 0xff00
            || size != 8 || (!object.versym.is_null()
                && unsafe { read_u16(object.versym.add(index.checked_mul(2)?)) } > 1)
        { return None; }
        // Reuse the relocation writer's range and immutable-table checks.
        unsafe { write_span(object, value, 8, true, Some(index)) }?;
        result = Some(runtime_address(object.base, value)? as *mut usize);
    }
    result
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
