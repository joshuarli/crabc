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
use super::x86_64_initial_graph_state::{InitialGraphState, ObjectState};

#[cfg(test)]
#[path = "x86_64_general_relocation_tests.rs"]
mod tests;

const R_NONE: u32 = 0;
const R_64: u32 = 1;
const R_COPY: u32 = 5;
const SHN_ABS: u16 = 0xfff1;

/// A transient breadth-first lookup view of the canonical graph, not a
/// second object store. Mapping and TLS module identities remain unchanged.
struct InitialSymbolScope {
    indices: [usize; MAX_OBJECTS],
    count: usize,
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
        SymbolScope { indices: &self.indices[..self.count], module_count: TLS_DTV_WORDS - 1,
            static_tls_count: TLS_DTV_WORDS - 1, initial: true }
    }
    fn from_graph(graph: &InitialGraphState) -> Option<Self> {
        let mut scope = Self { indices: [0; MAX_OBJECTS], count: 1 };
        let mut next = 0;
        while next < scope.count {
            let index = scope.indices[next];
            if graph.state(index) != Some(ObjectState::Ready) { return None; }
            for &child in graph.edges(index)? {
                if !scope.indices[..scope.count].contains(&child) {
                    *scope.indices.get_mut(scope.count)? = child;
                    scope.count += 1;
                }
            }
            next += 1;
        }
        (scope.count == graph.object_count()).then_some(scope)
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

unsafe fn definition(objects: &[Object], owner: usize, index: usize) -> Option<Definition> {
    let object = objects.get(owner)?;
    if index == 0 || index >= object.symcount { return None; }
    let symbol = unsafe { object.symtab.add(index * 24) };
    Some(Definition {
        owner,
        value: unsafe { read_u64(symbol.add(8)) },
        size: unsafe { read_u64(symbol.add(16)) },
        kind: unsafe { *symbol.add(4) & 15 },
        binding: unsafe { *symbol.add(4) >> 4 },
        visibility: unsafe { *symbol.add(5) & 3 },
        section: unsafe { read_u16(symbol.add(6)) },
    })
}

unsafe fn symbol_name(object: &Object, index: usize) -> Option<&[u8]> {
    if index == 0 || index >= object.symcount { return None; }
    let offset = unsafe { read_u32(object.symtab.add(index * 24)) } as usize;
    if offset >= object.strsz { return None; }
    let name = unsafe { object.strtab.add(offset) };
    let length = unsafe { bounded_nul(name, object.strsz - offset) }?;
    Some(unsafe { core::slice::from_raw_parts(name, length) })
}

/// Local and non-preemptible references bind in their own object. Global
/// scope admits exported global/weak definitions, including protected ones
/// for external references. Musl accepts the first weak definition in scope;
/// it does not search on for a later strong definition.
unsafe fn lookup(
    scope: &SymbolScope<'_>, objects: &[Object],
    requestor: usize, index: usize, tls: bool, copy: bool,
) -> Option<Option<Definition>> {
    let requested = unsafe { definition(objects, requestor, index) }?;
    if !matches!(requested.binding, 0 | 1 | 2)
        || (requested.binding == 0 && requested.visibility == 3)
        || (tls && requested.kind != 6)
        || (!tls && !matches!(requested.kind, 0 | 1 | 2))
    { return None; }
    if !copy && (requested.binding == 0 || requested.visibility != 0) {
        return (requested.section != 0).then_some(Some(requested));
    }
    let name = unsafe { symbol_name(&objects[requestor], index) }?;
    if name.is_empty() { return None; }
    for &owner in scope.indices {
        if copy && owner == 0 { continue; }
        for candidate in 1..objects[owner].symcount {
            let found = unsafe { definition(objects, owner, candidate) }?;
            if found.section == 0 || !matches!(found.binding, 1 | 2)
                || !matches!(found.visibility, 0 | 3)
                || (tls && found.kind != 6)
                || (!tls && !matches!(found.kind, 0 | 1 | 2))
            { continue; }
            if unsafe { symbol_name(&objects[owner], candidate) }? == name {
                if (requested.kind == 1 && found.kind == 2)
                    || (requested.kind == 2 && found.kind == 1)
                { return None; }
                return Some(Some(found));
            }
        }
    }
    // Undefined weak data/function references become null. A defined COPY
    // destination and TLS module references always require an actual owner.
    if !copy && !tls && requested.section == 0 && requested.binding == 2 {
        Some(None)
    } else {
        None
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
    let _ = name;
    false
}

unsafe fn word_value(
    scope: &SymbolScope<'_>, objects: &[Object], owner: usize,
    kind: u32, index: usize, addend: i64,
) -> Option<u64> {
    let object = &objects[owner];
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if index != 0 {
        if let Some(address) = x86_64_initial_worker_tls::runtime_function(unsafe { symbol_name(object, index) }?) {
            let requested = unsafe { definition(objects, owner, index) }?;
            return (matches!(kind, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT)
                && addend == 0 && requested.section == 0 && requested.binding == 1
                && requested.visibility == 0 && matches!(requested.kind, 0 | 2))
                .then_some(address);
        }
    }
    if index != 0 && is_private_runtime_symbol(unsafe { symbol_name(object, index) }?) {
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
    if owner != 0 || objects[owner].mapped || addend != 0
        || destination.kind != 1 || !matches!(destination.binding, 1 | 2)
        || destination.visibility != 0 || destination.section == 0
        || destination.section >= 0xff00 || destination.value != offset
    { return None; }
    let source = unsafe { lookup(scope, objects, owner, index, false, true) }??;
    if source.kind != 1 || source.visibility != 0 || source.section >= 0xff00
        || !objects[source.owner].mapped
        || !unsafe { readable_memory(&objects[source.owner], source.value, source.size.max(1)) }
        || !unsafe { readable_memory(&objects[source.owner], source.value, destination.size) }
    { return None; }
    let source = runtime_address(objects[source.owner].base, source.value)?;
    let destination_address = runtime_address(objects[owner].base, offset)?;
    if ranges_overlap(source, destination.size, destination_address, destination.size)? { return None; }
    Some(CopyRelocation { source, destination: destination_address, length: destination.size })
}

#[derive(Clone, Copy)]
struct WriteSpan { start: u64, length: u64 }

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
        let address = unsafe { syscall6(SYS_MMAP, 0, bytes as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if is_linux_error(address) { return None; }
        Some(Self { mapping: address as *mut u8, bytes, spans, relrs })
    }
    unsafe fn slices(&mut self) -> (&mut [WriteSpan], &mut [u64]) {
        // The lengths were checked together before mapping. Anonymous pages
        // initialize every integer field to zero; the two regions are disjoint.
        unsafe { (core::slice::from_raw_parts_mut(self.mapping.cast(), self.spans),
            core::slice::from_raw_parts_mut(self.mapping.add(self.spans * core::mem::size_of::<WriteSpan>()).cast(), self.relrs)) }
    }
}
impl Drop for RelocationScratch {
    fn drop(&mut self) { unsafe { syscall2(SYS_MUNMAP, self.mapping as i64, self.bytes as i64); } }
}

/// Reject writes into every ELF table read again during apply, not just the
/// relocation tables. COPY may be byte-aligned and larger than a machine word.
unsafe fn write_span(object: &Object, start: u64, length: u64, word: bool) -> Option<WriteSpan> {
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
    Some(WriteSpan { start, length })
}

unsafe fn preflight_object(scope: &SymbolScope<'_>, objects: &[Object], owner: usize) -> Option<()> {
    let object = &objects[owner];
    preflight_relocation_table_layout(object)?;
    let mut scratch = unsafe { RelocationScratch::new(object) }?;
    let (spans, relr_targets) = unsafe { scratch.slices() };
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
            let addend = unsafe { read_i64(entry.add(16)) };
            let length = if kind == R_COPY {
                if table != object.rela { return None; }
                unsafe { copy_relocation(scope, objects, owner, offset, symbol, addend) }?.length
            } else {
                unsafe { word_value(scope, objects, owner, kind, symbol, addend) }?;
                8
            };
            *spans.get_mut(count)? = unsafe { write_span(object, offset, length, kind != R_COPY) }?;
            count += 1;
        }
    }
    let relr_count = unsafe { preflight_relr_table(object, relr_targets, 0) }?;
    for &offset in &relr_targets[..relr_count] {
        *spans.get_mut(count)? = unsafe { write_span(object, offset, 8, true) }?;
        count += 1;
    }
    spans[..count].sort_unstable_by_key(|span| span.start);
    let mut end = 0;
    for span in &spans[..count] {
        if span.length == 0 { continue; }
        if span.start < end { return None; }
        end = span.start.checked_add(span.length)?;
    }
    Some(())
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
pub(super) unsafe fn relocate_initial_graph(graph: &InitialGraphState, objects: &[Object; MAX_OBJECTS]) -> Option<()> {
    let initial_scope = InitialSymbolScope::from_graph(graph)?;
    let scope = initial_scope.view();
    for owner in 0..scope.indices.len() {
        unsafe { preflight_object(&scope, objects, owner) }?;
    }
    // Libraries first, main last, matching musl. All copies form the final
    // phase so their source data includes ordinary symbol/relative fixups.
    for owner in (1..scope.indices.len()).chain(core::iter::once(0)) {
        unsafe { apply_word_relocations(&scope, objects, owner) }?;
    }
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
