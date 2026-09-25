use super::*;
use super::super::x86_64_initial_graph_state::ObjectIdentity;

struct Image(*mut u8);
impl Image {
    fn new() -> Self {
        let mapping = unsafe { syscall6(SYS_MMAP, 0, PAGE as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        assert!(!is_linux_error(mapping));
        let image = Self(mapping as *mut u8);
        image.word(0, PT_LOAD as u64 | ((PF_R | PF_W) as u64) << 32);
        image.word(32, PAGE as u64);
        image.word(40, PAGE as u64);
        image.word(56, PT_DYNAMIC as u64);
        image.word(72, 0x400);
        image.word(88, 32);
        image.word(96, 32);
        image.word(0x400, DT_DEBUG);
        image.word(0x218, 1 | (0x11u64 << 32) | (1u64 << 48));
        image.word(0x220, 0x500);
        image.word(0x228, 8);
        unsafe { core::ptr::copy_nonoverlapping(b"\0_dl_debug_addr\0".as_ptr(), image.0.add(0x300), 16); }
        image
    }
    fn word(&self, offset: usize, value: u64) { unsafe { self.0.add(offset).cast::<u64>().write(value); } }
    fn object(&self, libc: bool) -> Object {
        Object { base: self.0 as u64, phdr: self.0, phnum: 2,
            dynamic: unsafe { self.0.add(0x400) },
            symtab: unsafe { self.0.add(0x200) }, symcount: 2,
            strtab: unsafe { self.0.add(0x300) }, strsz: 16,
            role: if libc { ObjectRole::Library } else { ObjectRole::Main },
            canonical_libc_identity: libc.then_some(ObjectIdentity { device: 1, inode: 2 }),
            ..EMPTY_OBJECT }
    }
}
impl Drop for Image {
    fn drop(&mut self) { unsafe { syscall2(SYS_MUNMAP, self.0 as i64, PAGE as i64); } }
}

#[test]
fn debugger_publication_preserves_one_pointer_and_rejects_wrong_receiver_metadata() {
    let main = Image::new();
    let libc = Image::new();
    let objects = [main.object(false), libc.object(true)];
    let prepared = unsafe { PreparedInitialDebugger::prepare(&objects) }.unwrap();
    unsafe { prepared.relocate(); }
    assert_eq!(unsafe { read_u64(libc.0.add(0x500)) }, address() as u64);
    assert_eq!(unsafe { read_u64(main.0.add(0x408)) }, address() as u64);
    assert!(prepared.overlaps(libc.0 as u64 + 0x4ff, 2).unwrap());
    assert!(!prepared.overlaps(libc.0 as u64 + 0x4f8, 8).unwrap());
    for (offset, replacement) in [(0x218, 1 | (0x21u64 << 32) | (1u64 << 48)),
        (0x218, 1 | (0x11u64 << 32) | (2u64 << 40) | (1u64 << 48)),
        (0x218, 1 | (0x11u64 << 32)), (0x220, 0x501), (0x220, 0x218), (0x228, 40)] {
        let saved = unsafe { read_u64(libc.0.add(offset)) };
        libc.word(offset, replacement);
        assert!(unsafe { PreparedInitialDebugger::prepare(&objects) }.is_none(), "offset {offset:#x}");
        libc.word(offset, saved);
    }
    let mut missing = objects;
    missing[1].canonical_libc_identity = None;
    assert!(unsafe { PreparedInitialDebugger::prepare(&missing) }.is_none());
    let mut ambiguous = objects;
    ambiguous[0].canonical_libc_identity = ambiguous[1].canonical_libc_identity;
    assert!(unsafe { PreparedInitialDebugger::prepare(&ambiguous) }.is_none());
}

#[test]
fn debugger_dynamic_tag_may_be_absent_but_must_be_unique_and_writable() {
    let main = Image::new();
    let libc = Image::new();
    let objects = [main.object(false), libc.object(true)];
    main.word(0x400, 0);
    assert!(unsafe { PreparedInitialDebugger::prepare(&objects) }.is_some());
    main.word(0x400, DT_DEBUG);
    main.word(96, 48);
    main.word(0x410, DT_DEBUG);
    assert!(unsafe { PreparedInitialDebugger::prepare(&objects) }.is_none());
    main.word(0x410, 0);
    main.word(0, PT_LOAD as u64 | (PF_R as u64) << 32);
    assert!(unsafe { PreparedInitialDebugger::prepare(&objects) }.is_none());
}

#[test]
fn debugger_add_guard_restores_consistent_on_every_transaction_exit() {
    let guard = RuntimeGuard::acquire();
    let operation = || -> Result<(), ()> {
        let _notification = AddNotification::begin(&guard);
        assert_eq!(unsafe { (*RENDEZVOUS.0.get()).state }, RT_ADD);
        Err(())
    };
    assert!(operation().is_err());
    assert_eq!(unsafe { (*RENDEZVOUS.0.get()).state }, RT_CONSISTENT);
    {
        let _notification = AddNotification::begin(&guard);
        assert_eq!(unsafe { (*RENDEZVOUS.0.get()).state }, RT_ADD);
    }
    assert_eq!(unsafe { (*RENDEZVOUS.0.get()).state }, RT_CONSISTENT);
}

// Relocation preflight checks the debugger slots against the admitted write
// set it builds: a RELATIVE write into either published slot rejects the
// whole graph before any write, and one beside the slot does not.
#[test]
fn relocation_into_a_debugger_slot_rejects_the_graph_before_any_write() {
    use super::super::x86_64_initial_graph_state::{InitialGraphState, ObjectAdmission};
    let graph = || {
        let mut graph = InitialGraphState::new(ObjectIdentity { device: 1, inode: 0 });
        assert!(matches!(graph.admit_mapped(ObjectIdentity { device: 1, inode: 1 }), Ok(ObjectAdmission::New { .. })));
        graph.attach_needed(0, 1).unwrap();
        graph.finish_discovery(1).unwrap();
        graph.finish_discovery(0).unwrap();
        graph
    };
    for (image_index, slot, target, rejected) in [(1usize, 0x500u64, 0x500u64, true), (1, 0x500, 0x508, false),
        (0, 0x408, 0x408, true), (0, 0x408, 0x410, false)] {
        let main = Image::new();
        let libc = Image::new();
        let images = [&main, &libc];
        // One RELATIVE record at 0x600 writing `target` in the chosen image.
        images[image_index].word(0x600, target);
        images[image_index].word(0x608, R_X86_64_RELATIVE as u64);
        images[image_index].word(0x610, 0x40);
        let objects = [main.object(false), libc.object(true)];
        let debugger = unsafe { PreparedInitialDebugger::prepare(&objects) }.unwrap();
        let mut relocated = objects;
        relocated[image_index].rela = unsafe { images[image_index].0.add(0x600) };
        relocated[image_index].relasz = 24;
        // The unit graph has no canonical-libc startup import to validate.
        relocated[1].canonical_libc_identity = None;
        let before = unsafe { read_u64(images[image_index].0.add(target as usize)) };
        let result = unsafe {
            super::super::x86_64_general_relocation::relocate_initial_graph_with_debugger(&graph(), &relocated, &debugger)
        };
        assert_eq!(result.is_none(), rejected, "slot {slot:#x} target {target:#x}");
        if rejected {
            assert_eq!(unsafe { read_u64(images[image_index].0.add(target as usize)) }, before);
        }
    }
}

// The batched slot check agrees with `overlaps` on every span over generated
// sorted disjoint write sets around both published slots.
#[test]
fn batched_debugger_slot_check_matches_the_per_span_scan() {
    extern crate std;
    use super::super::x86_64_general_relocation::{debugger_slots_overlap_spans, WriteSpan};
    let main = Image::new();
    let libc = Image::new();
    let objects = [main.object(false), libc.object(true)];
    let debugger = unsafe { PreparedInitialDebugger::prepare(&objects) }.unwrap();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |bound: u64| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed % bound };
    let (mut hits, mut misses) = (0, 0);
    for object in &objects {
        for _ in 0..4000 {
            let mut spans = std::vec::Vec::new();
            let mut cursor = 0x3c0 + next(0x60);
            for _ in 0..(1 + next(6)) {
                let length = [0u64, 1, 8, 16, 24][next(5) as usize];
                spans.push(WriteSpan { start: cursor, length });
                cursor += length.max(1) + next(0x20);
            }
            // Both are rejections unless they report no overlap.
            let old = (|| -> Option<bool> {
                for span in &spans {
                    if debugger.overlaps(object.base + span.start, span.length)? { return Some(true); }
                }
                Some(false)
            })() != Some(false);
            let new = unsafe { debugger_slots_overlap_spans(&debugger, object, &spans) } != Some(false);
            assert_eq!(new, old);
            if old { hits += 1; } else { misses += 1; }
        }
    }
    assert!(hits > 500 && misses > 500, "{hits}/{misses}");
}
