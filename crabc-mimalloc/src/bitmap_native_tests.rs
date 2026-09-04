//! Scalar bitmap component qualification against fixed mimalloc 3.5.0.
//! Storage belongs to each test, including threaded tests; no global arena,
//! page or allocator registry participates. Each binned image has a fresh
//! address-stable subprocess statistics owner.

extern crate std;

use super::*;
use core::mem::MaybeUninit;

#[repr(align(64))]
struct Storage([MaybeUninit<u8>; 34_000]);

impl Storage {
    fn new() -> Self { Self([MaybeUninit::uninit(); 34_000]) }

    fn bitmap(&mut self, bits: usize) -> BitmapView<'_> {
        unsafe {
            BitmapView::initialize(self.0.as_mut_ptr().cast(), self.0.len(),
                BitmapLayout::for_bit_count(bits).unwrap(), false).unwrap()
        }
    }

    fn binned(&mut self, bits: usize) -> BinnedBitmapView<'_> {
        unsafe {
            BinnedBitmapView::initialize(crate::subproc::MainSubprocess::test_static_owner().as_ptr(), self.0.as_mut_ptr().cast(),
                self.0.len(), BinnedBitmapLayout::for_bit_count(bits).unwrap(), false).unwrap()
        }
    }
}

struct Transcript(usize);
impl Transcript {
    fn value(&mut self, value: usize) {
        std::println!("m2.bitmap.native.{}={}", self.0, value);
        self.0 += 1;
    }
    fn bitmap(&mut self, bitmap: &BitmapView<'_>, first: usize, last: usize) {
        self.value(bitmap.popcount_relaxed());
        self.value(bitmap.highest_set_relaxed().unwrap_or(usize::MAX));
        self.value(bitmap.is_all_clear() as usize);
        for field in 0..BCHUNK_FIELDS { self.value(word_load_relaxed(bitmap.chunkmap().field(field))); }
        for field in first / BFIELD_BITS..=last / BFIELD_BITS {
            self.value(word_load_relaxed(bitmap.chunk(field / BCHUNK_FIELDS).field(field % BCHUNK_FIELDS)));
        }
    }
    fn binned(&mut self, bitmap: &BinnedBitmapView<'_>) {
        let stats = unsafe { &*bitmap.subprocess() }.bitmap_statistics();
        for bin in &stats.chunk_bins {
            self.value(crate::atomic::i64_load_relaxed(&bin.total) as usize);
            self.value(crate::atomic::i64_load_relaxed(&bin.peak) as usize);
            self.value(crate::atomic::i64_load_relaxed(&bin.current) as usize);
        }
        self.value(bitmap.max_accessed_chunk());
        self.value(bitmap.highest_clear_relaxed().unwrap_or(usize::MAX));
        for field in 0..BCHUNK_FIELDS { self.value(word_load_relaxed(bitmap.chunkmap().field(field))); }
        for chunk in 0..bitmap.chunk_count() {
            self.value(bitmap.chunk_bin(chunk).unwrap().index());
            for field in 0..BCHUNK_FIELDS { self.value(word_load_relaxed(bitmap.chunk(chunk).field(field))); }
        }
    }
}

const LENGTHS: [usize; 16] = [1, 2, 7, 8, 9, 31, 63, 64, 65, 127, 255, 511, 512, 513, 777, 1025];

#[test]
fn binned_images_require_live_isolated_statistics_owners() {
    let mut storage = Storage::new();
    let layout = BinnedBitmapLayout::for_bit_count(512).unwrap();
    let pointer = storage.0.as_mut_ptr().cast::<u8>();
    assert!(unsafe { BinnedBitmapView::initialize(core::ptr::null_mut(), pointer,
        storage.0.len(), layout, false) }.is_none());
    {
        let bitmap = storage.binned(512);
        bitmap.set_range(0, 512).unwrap();
        assert_eq!(bitmap.try_find_and_claim(0, 1), Some(0));
        let stats = unsafe { &*bitmap.subprocess() }.bitmap_statistics();
        assert_eq!(crate::atomic::i64_load_relaxed(&stats.chunk_bins[0].current), 1);
        let mut other_storage = Storage::new();
        let other = other_storage.binned(512);
        let other_stats = unsafe { &*other.subprocess() }.bitmap_statistics();
        assert_eq!(crate::atomic::i64_load_relaxed(&other_stats.chunk_bins[0].current), 0);
    }
    // A quiesced malformed header must not publish a view whose otherwise
    // safe bin mutation could dereference a missing statistics owner.
    unsafe { (*pointer.cast::<BinnedBitmapPrefix>()).subprocess = core::ptr::null_mut() };
    assert!(unsafe { BinnedBitmapView::attach(pointer, storage.0.len(), layout) }.is_none());
}

#[test]
fn emit_native_bitmap_component_trace() {
    // This ordered, exhaustive boundary matrix is mirrored by the C fixture.
    // Values include every touched atomic word, not only successful return codes.
    let mut out = Transcript(0);
    out.value(crate::config::STAT_LEVEL);
    out.value(BFIELD_BITS);
    out.value(BCHUNK_BITS);
    let mut storage = Storage::new();
    for bits in [512, 1024, 1536, 33280] {
        let max = BitmapLayout::for_bit_count(bits).unwrap().max_bits();
        for index in [0, 1, 7, 8, 31, 62, 63, 64, 65, 127, 255, 448, 510, 511, 512, 513, max - 64, max - 1] {
            for len in LENGTHS {
                if index + len > max { continue; }
                let bitmap = storage.bitmap(bits);
                out.value(bits); out.value(index); out.value(len);
                let first = bitmap.set_range(index, len).unwrap();
                out.value(first.all_transitioned() as usize); out.value(first.already_set());
                let second = bitmap.set_range(index, len).unwrap();
                out.value(second.all_transitioned() as usize); out.value(second.already_set());
                out.value(bitmap.popcount_range(index, len).unwrap());
                out.value(bitmap.is_set_range(index, len).unwrap() as usize);
                out.value(bitmap.clear_range(index + len / 2, 1).unwrap() as usize);
                out.value(bitmap.clear_range(index + len / 2, 1).unwrap() as usize);
                out.bitmap(&bitmap, index, index + len - 1);
                out.value(bitmap.clear_range(index, len).unwrap() as usize);
                out.bitmap(&bitmap, index, index + len - 1);
            }
        }
    }

    // Read-only, clearing-run, and aligned clearing visitors, including callback
    // stop/restore after an intervening publication in the exchanged field.
    for alignment in [usize::MAX, 0, 1, 2, 3, 7, 8, 63, 64, 65, 513] {
        for stop in [0, 1, 3, 17] {
            let bitmap = storage.bitmap(33280);
            for chunk in [0, 1, 63, 64] {
                bitmap.set_range(chunk * BCHUNK_BITS, 64).unwrap();
                bitmap.clear_range(chunk * BCHUNK_BITS + 4, 1).unwrap();
                bitmap.set_range(chunk * BCHUNK_BITS + 67, 11).unwrap();
                bitmap.set_range(chunk * BCHUNK_BITS + 510, 2).unwrap();
            }
            out.value(alignment); out.value(stop);
            let mut count = 0;
            let mut callback = |index, len| {
                out.value(index); out.value(len);
                count += 1;
                // A concurrent setter's publication must survive restoration.
                if count == 1 { bitmap.set_range(4, 1).unwrap(); }
                stop == 0 || count < stop
            };
            let completed = if alignment == usize::MAX { bitmap.visit_set_bits(&mut callback) }
                else { bitmap.visit_set_ranges_clear_aligned(alignment, &mut callback) };
            out.value(completed as usize); out.value(count);
            out.bitmap(&bitmap, 0, bitmap.max_bits() - 1);
        }
    }

    // Binned claims cover every specialized width, both levels of the chunk
    // map, all thread cycle boundaries, partial returns, and bin reset on free.
    for chunks in [3, 65] {
        for sequence in [0, 1, 7, 63, 64, 0x1_0000_0001] {
            for len in LENGTHS {
                let bitmap = storage.binned(chunks * BCHUNK_BITS);
                out.value(chunks); out.value(sequence); out.value(len);
                out.value(bitmap.set_range(0, bitmap.max_bits()).unwrap() as usize);
                let mut claims = std::vec::Vec::new();
                for _ in 0..12 {
                    let claim = bitmap.try_find_and_claim(sequence, len);
                    out.value(claim.unwrap_or(usize::MAX));
                    if let Some(index) = claim { claims.push(index); }
                }
                for index in claims.into_iter().step_by(3) {
                    out.value(bitmap.set_range(index, len).unwrap() as usize);
                }
                out.binned(&bitmap);
            }
        }
    }

    // The complete source callback outcome matrix: refusal with restore,
    // refusal without restore, and successful claim (which must remain clear).
    for disposition in 0..3 {
        let bitmap = storage.bitmap(33280);
        for chunk in [0, 1, 63, 64] { bitmap.set_range(chunk * BCHUNK_BITS + 7, 1).unwrap(); }
        out.value(disposition);
        let result = bitmap.try_find_and_claim_abandoned(5, |index| {
            out.value(index);
            match disposition { 0 => AbandonedBitmapClaim::KeepSet,
                1 => AbandonedBitmapClaim::Discarded, _ => AbandonedBitmapClaim::Claimed }
        });
        out.value(result.unwrap_or(usize::MAX));
        out.bitmap(&bitmap, 0, bitmap.max_bits() - 1);
    }
    let bitmap = storage.bitmap(512);
    let subprocess = crate::subproc::MainSubprocess::new();
    let counter = &subprocess.bitmap_statistics().pages_unabandon_busy_wait;
    bitmap.set_range(7, 1).unwrap();
    assert_eq!(bitmap.clear_once_set(&subprocess, 7), Some(()));
    out.value(crate::atomic::i64_load_relaxed(counter) as usize);
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| bitmap.clear_once_set(&subprocess, 7));
        while crate::atomic::i64_load_relaxed(counter) == 0 { std::thread::yield_now(); }
        bitmap.set_range(7, 1).unwrap();
        assert_eq!(waiter.join().unwrap(), Some(()));
    });
    out.value(crate::atomic::i64_load_relaxed(counter) as usize);
    assert_eq!(crate::atomic::i64_load_relaxed(counter), 1);
    out.bitmap(&bitmap, 0, bitmap.max_bits() - 1);
}

#[test]
fn rejected_candidate_can_remain_clear_without_ending_the_chunk_search() {
    // bitmap.c:1358 permits claim=false/keep_set=false. The next candidate is
    // in another chunk because the source offers only one bit per chunk visit.
    let mut storage = Storage::new();
    let bitmap = storage.bitmap(3 * BCHUNK_BITS);
    bitmap.set_range(7, 1).unwrap();
    bitmap.set_range(BCHUNK_BITS + 9, 1).unwrap();
    let mut offered = std::vec::Vec::new();
    assert_eq!(bitmap.try_find_and_claim_abandoned(0, |index| {
        offered.push(index);
        if index == 7 { AbandonedBitmapClaim::Discarded }
        else { AbandonedBitmapClaim::Claimed }
    }), Some(BCHUNK_BITS + 9));
    assert_eq!(offered, [7, BCHUNK_BITS + 9]);
    assert_eq!(bitmap.popcount_relaxed(), 0);
    // Neither successful nor discarded callback eagerly repairs the map.
    assert_eq!(word_load_relaxed(bitmap.chunkmap().field(0)), 3);
}

#[test]
fn conditional_chunk_claims_restore_every_failed_range_and_preserve_neighbors() {
    for index in 0..BCHUNK_BITS {
        for len in 1..=BCHUNK_BITS - index {
            for hole in [None, Some(index), Some(index + len / 2), Some(index + len - 1)] {
                let chunk = Chunk::all_set();
                if let Some(hole) = hole { chunk.clear_run(hole, 1).unwrap(); }
                let result = chunk.try_claim_at(index, len).unwrap();
                assert_eq!(result.is_claimed(), hole.is_none(), "index={index}, len={len}, hole={hole:?}");
                for field in 0..BCHUNK_FIELDS {
                    let mut expected = usize::MAX;
                    if let Some(hole) = hole {
                        if hole / BFIELD_BITS == field { expected &= !(1 << (hole % BFIELD_BITS)); }
                    } else {
                        for bit in 0..BFIELD_BITS {
                            let position = field * BFIELD_BITS + bit;
                            if (index..index + len).contains(&position) { expected &= !(1 << bit); }
                        }
                    }
                    assert_eq!(word_load_relaxed(chunk.field(field)), expected);
                }
            }
        }
    }
}

#[test]
fn concurrent_binned_claims_and_returns_conserve_every_bit_and_reset_bins() {
    use std::sync::Mutex;
    let mut storage = Storage::new();
    let bitmap = storage.binned(65 * BCHUNK_BITS);
    bitmap.set_range(0, bitmap.max_bits()).unwrap();
    let claims = Mutex::new(std::vec::Vec::new());
    std::thread::scope(|scope| {
        for (sequence, len) in [1, 8, 63, 65].into_iter().enumerate() {
            let bitmap = &bitmap;
            let claims = &claims;
            scope.spawn(move || {
                while let Some(index) = bitmap.try_find_and_claim(sequence, len) {
                    assert_eq!(bitmap.is_clear_range(index, len), Some(true));
                    claims.lock().unwrap().push((index, len));
                }
            });
        }
    });
    let claims = claims.into_inner().unwrap();
    let mut occupied = std::vec![false; bitmap.max_bits()];
    for &(index, len) in &claims {
        for bit in &mut occupied[index..index + len] {
            assert!(!*bit, "overlapping concurrent bitmap ownership");
            *bit = true;
        }
    }
    for (index, claimed) in occupied.into_iter().enumerate() {
        assert_eq!(bitmap.is_clear_range(index, 1), Some(claimed));
    }
    std::thread::scope(|scope| {
        for partition in 0..4 {
            let bitmap = &bitmap;
            let claims = &claims;
            scope.spawn(move || {
                for &(index, len) in claims.iter().skip(partition).step_by(4) {
                    assert_eq!(bitmap.set_range(index, len), Some(true));
                }
            });
        }
    });
    assert_eq!(bitmap.is_set_range(0, bitmap.max_bits()), Some(true));
    for chunk in 0..bitmap.chunk_count() { assert_eq!(bitmap.chunk_bin(chunk), Some(ChunkBin::None)); }
    let stats = unsafe { &*bitmap.subprocess() }.bitmap_statistics();
    for bin in &stats.chunk_bins {
        assert_eq!(crate::atomic::i64_load_relaxed(&bin.current), 0);
        let peak = crate::atomic::i64_load_relaxed(&bin.peak);
        let total = crate::atomic::i64_load_relaxed(&bin.total);
        assert!(peak >= 0 && peak <= total);
    }
}

#[test]
fn stopped_range_visitor_retains_a_concurrent_setter_publication() {
    use std::sync::Barrier;
    for alignment in [1, 3, 8] {
        let mut storage = Storage::new();
        let bitmap = storage.bitmap(512);
        bitmap.set_range(0, 24).unwrap();
        bitmap.set_range(40, 3).unwrap();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                // The visitor already exchanged the whole source field to 0.
                bitmap.set_range(31, 1).unwrap();
                barrier.wait();
            });
            assert!(!bitmap.visit_set_ranges_clear_aligned(alignment, |_, _| {
                barrier.wait(); barrier.wait(); false
            }));
        });
        assert_eq!(bitmap.is_set_range(31, 1), Some(true));
        assert_eq!(bitmap.is_set_range(40, 3), Some(true));
        let visited = if alignment == 1 { 24 } else { alignment };
        assert_eq!(bitmap.is_clear_range(0, visited), Some(true));
        assert_eq!(bitmap.popcount_relaxed(), 28 - visited);
    }
}
