// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source map: pinned mimalloc v3.5.0 `src/arena.c:1930-2163`.
// The renderer observes source bitmap words and short page geometry images,
// then releases every projection before delivering each raw output fragment.

use core::ffi::CStr;
use core::fmt::{self, Write};
use core::ptr::{NonNull, addr_of};
use crate::arena::ArenaRegistry;
use crate::bitmap::{BFIELD_BITS, BCHUNK_FIELDS, BinnedBitmapLayout, BinnedBitmapView, BitmapLayout, BitmapView, ChunkBin};
use crate::config::{ARENA_SLICE_SIZE, BCHUNK_BITS, MIB, PAGE_META_ALIGNED_COUNT};
use crate::diagnostic_output::{OutputOwner, SourceFormattedMessage};
use crate::types::{Arena, MemoryId, Page, Theap, THREAD_ID_ABANDONED_MAPPED};

pub(crate) struct PagePrintSnapshot {
    pub(crate) start: *mut u8,
    pub(crate) used: usize,
    pub(crate) block_size: usize,
    pub(crate) reserved: usize,
    pub(crate) slice_pcommitted: usize,
    pub(crate) memory: MemoryId,
    pub(crate) theap: *mut Theap,
    pub(crate) thread_id: usize,
}

struct Line { bytes: [u8; 992], len: usize }
impl Line {
    fn new() -> Self { Self { bytes: [0; 992], len: 0 } }
    fn byte(&mut self, byte: u8) { let _ = self.write_str(core::str::from_utf8(&[byte]).unwrap()); }
    fn color(&mut self, color: usize) { let _ = write!(self, "\x1B[{color}m"); }
    unsafe fn emit(&self, output: &OutputOwner) {
        // SAFETY: the stack line is NUL-terminated and contains only source
        // ASCII/control bytes. Caller retains the registered callback pair.
        let text = unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..self.len + 1]) };
        unsafe { output.raw_message(SourceFormattedMessage::from_source_formatted(text)) };
    }
}
impl Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let count = text.len().min(990 - self.len);
        self.bytes[self.len..self.len + count].copy_from_slice(&text.as_bytes()[..count]);
        self.len += count;
        Ok(())
    }
}

struct ArenaPrintSnapshot {
    pointer: NonNull<Arena>, start: *mut u8, count: usize, info: usize,
    parent: *mut Arena, pinned: bool, exclusive: bool, numa: i32,
    free: *mut u8, committed: *mut u8, purge: *mut u8,
}
impl ArenaPrintSnapshot {
    unsafe fn copy(pointer: NonNull<Arena>) -> Self {
        let raw = pointer.as_ptr();
        // SAFETY: registry Acquire publication retains these immutable
        // subobjects. No borrow of a concurrently owned arena is constructed.
        unsafe { Self {
            pointer, start: addr_of!((*raw).start).read(), count: addr_of!((*raw).slice_count).read(),
            info: addr_of!((*raw).info_slices).read(), parent: addr_of!((*raw).parent).read(),
            pinned: addr_of!((*raw).memid).read().is_pinned,
            exclusive: addr_of!((*raw).is_exclusive).read(), numa: addr_of!((*raw).numa_node).read(),
            free: addr_of!((*raw).slices_free).read(), committed: addr_of!((*raw).slices_committed).read(),
            purge: addr_of!((*raw).slices_purge).read(),
        } }
    }
}

/// The caller retains arenas and map registration, excludes ordinary page
/// mutations during copying, and serializes callback registration/delivery.
pub(crate) unsafe fn print(registry: &ArenaRegistry) {
    let Some(output) = crate::process_init::process_output_owner() else { return };
    if registry.count() == 0 {
        // Empty source groups need no arena binding, PageMap, or page owner.
        let mut footer = Line::new();
        let _ = footer.write_str("total pages in arenas: 0\n");
        unsafe { footer.emit(output) };
        return;
    }
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return };
    // SAFETY: the admitted subprocess operation retains this identity and its
    // initialized sequence; metadata-Theap comparison only observes an atomic.
    let subprocess = unsafe { &*registry.subprocess() };
    let Some(sequence) = subprocess.arena_print_sequence() else { return };
    let mut total = 0;
    for index in 0..registry.count() {
        let Some(pointer) = registry.arena_print_pointer(index) else { continue };
        // SAFETY: the caller retains this published arena for the traversal.
        let arena = unsafe { ArenaPrintSnapshot::copy(pointer) };
        let Some(free_layout) = BinnedBitmapLayout::for_bit_count(arena.count) else { continue };
        let Some(bitmap_layout) = BitmapLayout::for_bit_count(arena.count) else { continue };
        // SAFETY: published bitmap images remain live and are accessed only
        // through their atomics; their immutable layouts were initialized first.
        let Some(free) = (unsafe { BinnedBitmapView::attach(arena.free, free_layout.byte_size(), free_layout) }) else { continue };
        let Some(committed) = (unsafe { BitmapView::attach(arena.committed, bitmap_layout.byte_size(), bitmap_layout) }) else { continue };
        let Some(purge) = (unsafe { BitmapView::attach(arena.purge, bitmap_layout.byte_size(), bitmap_layout) }) else { continue };
        let address = arena.pointer.as_ptr().addr();
        let digits = if address <= u32::MAX as usize { 8 } else if address >> 16 <= u32::MAX as usize { 12 } else { 16 };
        let mut header = Line::new();
        let _ = write!(header, "{}arena {index} at 0x{address:0digits$X}: {} slices ({} MiB){}{}, subproc: {sequence}, numa: {}\n",
            if arena.parent.is_null() { "" } else { "(sub)" }, arena.count, arena.count * ARENA_SLICE_SIZE / MIB,
            if arena.pinned { ", pinned" } else { "" }, if arena.exclusive { ", exclusive" } else { "" }, arena.numa);
        unsafe { header.emit(output) };
        let mut header = Line::new();
        let _ = header.write_str("\x1B[37mchunks (p:page, f:full, s:single, m:meta-data, i:arena-info, P,F,S,M:not abandoned, ~:free-purgable, _:free-committed, .:free-reserved)\n       (chunk bin: S:small, M : medium, L : large, X : other) (use/commit: \x1B[31m0 - 25%\x1B[33m - 50%\x1B[36m - 75%\x1B[32m - 100%\x1B[0m)\n");
        unsafe { header.emit(output) };
        let used_slices = free.highest_clear_relaxed().map_or(arena.info, |bit| bit + 1);
        let mut bit_count = 0;
        let mut page_remaining: isize = 0;
        let mut page_color = 37;
        let mut arena_total = 0;
        let mut chunk = 0;
        while chunk < free.chunk_count() && bit_count < arena.count {
            if bit_count > used_slices && chunk + 2 < free.chunk_count() {
                bit_count += (free.chunk_count() - 1 - chunk) * BCHUNK_BITS;
                let mut skip = Line::new(); let _ = skip.write_str("  |\n");
                unsafe { skip.emit(output) };
                chunk = free.chunk_count() - 1;
            }
            let mut row = Line::new();
            if chunk < 10 { let _ = write!(row, "{chunk}  "); }
            else if chunk < 100 { let _ = write!(row, "{chunk} "); }
            else if chunk < 1000 { let _ = write!(row, "{chunk}"); }
            row.byte(match free.chunk_bin(chunk) { Some(ChunkBin::Small) => b'S', Some(ChunkBin::Medium) => b'M', Some(ChunkBin::Large) => b'L', Some(ChunkBin::Huge) => b'H', Some(ChunkBin::Other) => b'X', _ => b' ' });
            row.byte(b' ');
            for field in 0..BCHUNK_FIELDS {
                if field > 0 && field % 2 == 0 {
                    let mut fragment = Line::new(); let _ = write!(fragment, "  {}\n\x1B[37m", core::str::from_utf8(&row.bytes[..row.len]).unwrap());
                    unsafe { fragment.emit(output) };
                    row = Line::new(); let _ = row.write_str("     ");
                }
                if bit_count >= arena.count {
                    for _ in 0..BFIELD_BITS { row.byte(b'o'); }
                } else {
                    let mut previous_color = 37;
                    for bit in 0..BFIELD_BITS {
                        let slice = bit_count + bit;
                        let start = arena.start.wrapping_add(slice * ARENA_SLICE_SIZE);
                        // SAFETY: caller excludes registration changes for
                        // this lookup and ordinary page mutation during copying.
                        let page = unsafe { binding.page_map().lookup_registered_page(start) }.ok().flatten();
                        let image = page.map(|page| unsafe { Page::arena_print_snapshot_at(page) });
                        let image = image.filter(|image| image.start.addr() & !(ARENA_SLICE_SIZE - 1) == start.addr());
                        let new_page = image.is_some();
                        let mut symbol = b'?';
                        if let Some(image) = image {
                            arena_total += 1;
                            symbol = if NonNull::new(image.theap).is_some_and(|theap| subprocess.matches_published_detached_metadata_theap(theap)) { b'm' }
                                else if image.reserved == 1 { b's' } else if image.used == image.reserved { b'f' } else { b'p' };
                            if image.thread_id > THREAD_ID_ABANDONED_MAPPED { symbol = symbol.to_ascii_uppercase(); }
                            let committed_bytes = if image.slice_pcommitted == 0 { image.reserved * image.block_size }
                                else {
                                    // A successful retained page lookup proves
                                    // the map/configuration are live; empty or
                                    // failed maps require no page-size query.
                                    let Ok(config) = binding.page_map().memory_config() else { return };
                                    image.slice_pcommitted * config.page_size().bytes() - (image.start.addr() - start.addr())
                                };
                            let usage = image.used.wrapping_mul(image.block_size).wrapping_mul(100) / committed_bytes;
                            page_color = if usage < 25 { 31 } else if usage < 50 { 33 } else if usage < 75 { 36 } else { 32 };
                            page_remaining = image.memory.arena_memory().map_or(0, |memory| memory.slice_count as isize);
                        } else if page_remaining > 0 { symbol = b'-'; }
                        else if slice < arena.info || (bit_count % PAGE_META_ALIGNED_COUNT == 0 && bit <= crate::arena::page_metadata_slice_count().unwrap_or(0)) {
                            symbol = b'i'; page_color = 37;
                        } else if free.is_set_range(slice, 1) == Some(true) {
                            if purge.is_set_range(slice, 1) == Some(true) { symbol = b'~'; page_color = 33; }
                            else if committed.is_set_range(slice, 1) == Some(true) { symbol = b'_'; page_color = 37; }
                            else { symbol = b'.'; page_color = 37; }
                        }
                        if !new_page && bit == BFIELD_BITS - 1 && page_remaining > 1 { symbol = b'>'; }
                        if page_color != previous_color { row.color(page_color); previous_color = page_color; }
                        row.byte(symbol);
                        page_remaining -= 1;
                    }
                    row.color(37);
                    row.byte(b' ');
                }
                bit_count += BFIELD_BITS;
            }
            let mut fragment = Line::new(); let _ = write!(fragment, "  {}\n\x1B[37m", core::str::from_utf8(&row.bytes[..row.len]).unwrap());
            unsafe { fragment.emit(output) };
            chunk += 1;
        }
        let mut footer = Line::new(); let _ = write!(footer, "\x1B[0m  total pages: {arena_total}\n");
        unsafe { footer.emit(output) };
        total += arena_total;
    }
    let mut footer = Line::new(); let _ = write!(footer, "total pages in arenas: {total}\n");
    unsafe { footer.emit(output) };
}
