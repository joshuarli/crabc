extern crate std;
use super::*;
use core::ops::{Deref, DerefMut};
use super::super::x86_64_initial_graph_state::{ObjectAdmission, ObjectIdentity};

// Relocation tests build small fixed graphs in local arrays.
const TEST_OBJECTS: usize = 32;
const IMAGE_BYTES: usize = 0x2000;
const IMAGE_SYMTAB: usize = 0x200;
const IMAGE_STRTAB: usize = 0x300;
const IMAGE_HASH: usize = 0x380;
const IMAGE_RELA: usize = 0x400;
const IMAGE_DATA: usize = 0x1000;
const IMAGE_METADATA_BYTES: usize = 0x800;
const IMAGE_DATA_BYTES: usize = 512;

// The structural relocation tests mutate words and records after borrowing
// `Object`s. Keep those convenient views, but point every view into one
// declared PT_LOAD rather than putting dynsym, strings and RELA records in
// unrelated Rust allocations. That is the same physical-address invariant
// production direct indexed-symbol validation requires.
pub(super) struct ImageData(*mut [u64; 64]);
impl Deref for ImageData {
    type Target = [u64; 64];
    fn deref(&self) -> &Self::Target { unsafe { &*self.0 } }
}
impl DerefMut for ImageData {
    fn deref_mut(&mut self) -> &mut Self::Target { unsafe { &mut *self.0 } }
}

struct ImageSymbols(*mut [[u64; 3]; 5]);
impl Deref for ImageSymbols {
    type Target = [[u64; 3]; 5];
    fn deref(&self) -> &Self::Target { unsafe { &*self.0 } }
}
impl DerefMut for ImageSymbols {
    fn deref_mut(&mut self) -> &mut Self::Target { unsafe { &mut *self.0 } }
}

struct ImageRelocations(*mut [[u64; 3]; 4]);
impl Deref for ImageRelocations {
    type Target = [[u64; 3]; 4];
    fn deref(&self) -> &Self::Target { unsafe { &*self.0 } }
}
impl DerefMut for ImageRelocations {
    fn deref_mut(&mut self) -> &mut Self::Target { unsafe { &mut *self.0 } }
}

pub(super) struct Image {
    // One owned anonymous mapping backs all raw ELF views. It is an explicit
    // interior-mutability boundary: the typed views below never originate
    // from a shared whole-image reference, and Drop retires this exact map.
    // Its isolated data page also lets the deferred-RELRO test protect a
    // genuine page without involving allocator storage.
    storage: *mut u8,
    pub(super) data: ImageData,
    // This legacy one-header view is only used by the malformed-PHDR case.
    // `object()` below always points at the real header in `storage`.
    phdr: [u64; 7],
    symbols: ImageSymbols,
    relocations: ImageRelocations,
    count: usize,
}
impl Image {
    pub(super) fn new() -> Self {
        let storage = unsafe { syscall6(SYS_MMAP, 0, IMAGE_BYTES as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        assert!(!is_linux_error(storage));
        let base = storage as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, IMAGE_BYTES) };
        let mut image = Self {
            data: ImageData(unsafe { base.add(IMAGE_DATA).cast() }),
            phdr: [1 | (7 << 32), 0, 0x1000, 0, 512, 512, 4096],
            symbols: ImageSymbols(unsafe { base.add(IMAGE_SYMTAB).cast() }),
            relocations: ImageRelocations(unsafe { base.add(IMAGE_RELA).cast() }),
            storage: base, count: 0,
        };
        // The metadata and destination live in distinct declared loads, as
        // in an ELF image: parser-consumed bytes are file-backed/readable,
        // while 512 destination bytes remain the bounded writable range.
        // Tests do not execute either mapping; PF_X preserves ordinary
        // callable-address validation.
        image.put_u32(0, PT_LOAD);
        image.put_u32(4, PF_R | PF_X);
        image.put_u64(16, 0);
        image.put_u64(32, IMAGE_METADATA_BYTES as u64);
        image.put_u64(40, IMAGE_METADATA_BYTES as u64);
        image.put_u64(48, 4096);
        image.put_u32(56, PT_LOAD);
        image.put_u32(60, PF_R | PF_W | PF_X);
        image.put_u64(56 + 16, IMAGE_DATA as u64);
        image.put_u64(56 + 32, IMAGE_DATA_BYTES as u64);
        image.put_u64(56 + 40, IMAGE_DATA_BYTES as u64);
        image.put_u64(56 + 48, 4096);
        unsafe { core::ptr::copy_nonoverlapping(b"\0value\0".as_ptr(), base.add(IMAGE_STRTAB), 7) };
        // One valid SysV bucket exposes index one for the fixture's `value`
        // name. Direct relocation-indexed accesses remain independently
        // checked, just as a GNU all-zero export table can retain imports.
        image.put_u32(IMAGE_HASH, 1);
        image.put_u32(IMAGE_HASH + 4, 5);
        image.put_u32(IMAGE_HASH + 8, 1);
        image
    }
    fn put_u32(&mut self, offset: usize, value: u32) {
        unsafe { core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), self.storage.cast::<u8>().add(offset), 4) };
    }
    fn put_u64(&mut self, offset: usize, value: u64) {
        unsafe { core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), self.storage.cast::<u8>().add(offset), 8) };
    }
    pub(super) fn symbol(&mut self, index: usize, kind: u8, binding: u8, visibility: u8, section: u16, value: u64, size: u64) {
        self.symbols[index] = [
            1 | ((kind as u64 | (binding as u64) << 4) << 32)
                | ((visibility as u64) << 40) | ((section as u64) << 48), value, size,
        ];
    }
    pub(super) fn rela(&mut self, offset: u64, kind: u32, symbol: usize, addend: i64) {
        self.relocations[self.count] = [offset, kind as u64 | ((symbol as u64) << 32), addend as u64];
        self.count += 1;
    }
    pub(super) fn object(&self, mapped: bool) -> Object {
        Object {
            base: self.storage as u64,
            phdr: self.storage.cast(), phnum: 2,
            symtab: unsafe { self.storage.add(IMAGE_SYMTAB) }, symcount: self.symbols.len(),
            #[cfg(feature = "x86_64-owned-dynamic-runtime")]
            symbol_lookup: SymbolLookupTable::Sysv {
                bucket_count: 1,
                buckets: unsafe { self.storage.add(IMAGE_HASH + 8).cast() },
                chains: unsafe { self.storage.add(IMAGE_HASH + 12).cast() },
                symbol_count: self.symbols.len(),
            },
            strtab: unsafe { self.storage.add(IMAGE_STRTAB) }, strsz: 7,
            rela: unsafe { self.storage.add(IMAGE_RELA) }, relasz: self.count * 24,
            role: if mapped { ObjectRole::Library } else { ObjectRole::Main }, ..EMPTY_OBJECT
        }
    }
}
impl Drop for Image {
    fn drop(&mut self) {
        unsafe { syscall2(SYS_MUNMAP, self.storage as i64, IMAGE_BYTES as i64); }
    }
}

// Private-wire cases need a compact one-load image. Like `Image`, this owns
// an explicit mapping; its raw ELF pointers are never derived from a shared
// byte-array borrow. The larger `Image` models separated metadata/data loads
// and RELRO, while this one keeps exact byte/range wire cases small.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
struct MappedImage {
    storage: *mut u8,
    count: usize,
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
impl MappedImage {
    const SYMTAB: usize = 0x100;
    const STRTAB: usize = 0x180;
    const RELA: usize = 0x200;
    const DESTINATION: usize = 0x300;
    const BYTES: usize = 1024;

    fn new() -> Self {
        let storage = unsafe { syscall6(SYS_MMAP, 0, PAGE as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        assert!(!is_linux_error(storage));
        let mut image = Self { storage: storage as *mut u8, count: 0 };
        unsafe { core::ptr::write_bytes(image.storage, 0, PAGE as usize) };
        // One RWX PT_LOAD covers the synthetic ELF records and relocation
        // target. The test never executes it; PF_X permits the graph's
        // ordinary code-range validation to remain faithful to production.
        image.put_u32(0, PT_LOAD);
        image.put_u32(4, PF_R | PF_W | PF_X);
        image.put_u64(16, 0);
        image.put_u64(32, Self::BYTES as u64);
        image.put_u64(40, Self::BYTES as u64);
        image.put_u64(48, 4096);
        image
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        assert!(offset.checked_add(4).is_some_and(|end| end <= Self::BYTES));
        unsafe { core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), self.storage.add(offset), 4) };
    }

    fn put_u64(&mut self, offset: usize, value: u64) {
        assert!(offset.checked_add(8).is_some_and(|end| end <= Self::BYTES));
        unsafe { core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), self.storage.add(offset), 8) };
    }

    fn put_bytes(&mut self, offset: usize, bytes: &[u8]) {
        assert!(offset.checked_add(bytes.len()).is_some_and(|end| end <= Self::BYTES));
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.storage.add(offset), bytes.len()) };
    }

    fn put_byte(&mut self, offset: usize, value: u8) {
        assert!(offset < Self::BYTES);
        unsafe { self.storage.add(offset).write(value) };
    }

    fn symbol(&mut self, index: usize, name: &[u8], kind: u8, binding: u8, visibility: u8, section: u16) {
        let name_offset = 1usize;
        self.put_bytes(Self::STRTAB + name_offset, name);
        self.put_byte(Self::STRTAB + name_offset + name.len(), 0);
        let offset = Self::SYMTAB.checked_add(index.checked_mul(24).expect("symbol offset"))
            .expect("symbol offset");
        assert!(offset.checked_add(24).is_some_and(|end| end <= Self::BYTES));
        self.put_u32(offset, name_offset as u32);
        self.put_byte(offset + 4, kind | binding << 4);
        self.put_byte(offset + 5, visibility);
        self.put_bytes(offset + 6, &section.to_le_bytes());
    }

    fn rela(&mut self, kind: u32, symbol: usize, addend: i64) {
        self.rela_at(Self::DESTINATION, kind, symbol, addend);
    }

    fn rela_at(&mut self, destination: usize, kind: u32, symbol: usize, addend: i64) {
        let offset = Self::RELA.checked_add(self.count.checked_mul(ELF64_RELA_SIZE).expect("RELA offset"))
            .expect("RELA offset");
        assert!(offset.checked_add(ELF64_RELA_SIZE).is_some_and(|end| end <= Self::BYTES));
        self.put_u64(offset, destination as u64);
        self.put_u64(offset + 8, kind as u64 | (symbol as u64) << 32);
        self.put_u64(offset + 16, addend as u64);
        self.count += 1;
    }

    fn exact_owned_crt_note(&mut self) {
        const NOTE: usize = 0x80;
        self.put_u32(56, PT_NOTE);
        self.put_u64(56 + 16, NOTE as u64);
        self.put_u64(56 + 32, 24);
        self.put_u32(NOTE, OWNED_CRT_NOTE_NAME.len() as u32);
        self.put_u32(NOTE + 4, 4);
        self.put_u32(NOTE + 8, OWNED_CRT_NOTE_TYPE);
        self.put_bytes(NOTE + 12, OWNED_CRT_NOTE_NAME);
        self.put_u32(NOTE + 20, OWNED_CRT_NOTE_REVISION);
    }

    fn object(&self, mapped: bool) -> Object {
        Object {
            base: self.storage as u64,
            phdr: self.storage,
            phnum: 2,
            symtab: unsafe { self.storage.add(Self::SYMTAB) },
            strtab: unsafe { self.storage.add(Self::STRTAB) },
            strsz: 128,
            rela: unsafe { self.storage.add(Self::RELA) },
            relasz: self.count * ELF64_RELA_SIZE,
            role: if mapped { ObjectRole::Library } else { ObjectRole::Main },
            ..EMPTY_OBJECT
        }
    }

    fn destination(&self) -> u64 {
        unsafe { read_u64(self.storage.add(Self::DESTINATION)) }
    }

    fn set_destination(&mut self, value: u64) {
        self.put_u64(Self::DESTINATION, value);
    }

    fn word_at(&self, offset: usize) -> u64 {
        assert!(offset.checked_add(8).is_some_and(|end| end <= Self::BYTES));
        unsafe { read_u64(self.storage.add(offset)) }
    }

    fn base(&self) -> u64 {
        self.storage as u64
    }
}
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
impl Drop for MappedImage {
    fn drop(&mut self) {
        unsafe { syscall2(SYS_MUNMAP, self.storage as i64, PAGE as i64); }
    }
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[test]
fn owned_crt_note_and_private_handoff_must_agree_before_relocation() {
    let mut owned = MappedImage::new();
    owned.exact_owned_crt_note();
    owned.symbol(1, b"__crabc_x86_64_owned_crt_handoff", 1, 2, 0, 0);
    owned.rela(R_X86_64_GLOB_DAT, 1, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = owned.object(false);
    objects[0].main_crt_mode = unsafe {
        owned_crt_note_mode(objects[0].phdr, objects[0].phnum, objects[0].base)
    }.expect("exact CRABC note");
    assert_eq!(objects[0].main_crt_mode, MainCrtMode::Owned);
    assert!(unsafe { validate_main_crt_mode(&objects) }.is_some());

    // A conventional entry never gains owned lifecycle merely because an
    // arbitrary main imports the private handoff name.
    let mut import_only = MappedImage::new();
    import_only.symbol(1, b"__crabc_x86_64_owned_crt_handoff", 1, 2, 0, 0);
    import_only.rela(R_X86_64_GLOB_DAT, 1, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = import_only.object(false);
    objects[0].main_crt_mode = unsafe {
        owned_crt_note_mode(objects[0].phdr, objects[0].phnum, objects[0].base)
    }.expect("absent marker is conventional");
    assert_eq!(objects[0].main_crt_mode, MainCrtMode::Conventional);
    assert!(unsafe { validate_main_crt_mode(&objects) }.is_none());

    // Conversely a retained owned marker cannot fall back if its exact
    // private relocation is missing or if its relocation form drifts.
    let mut note_only = MappedImage::new();
    note_only.exact_owned_crt_note();
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = note_only.object(false);
    objects[0].main_crt_mode = MainCrtMode::Owned;
    assert!(unsafe { validate_main_crt_mode(&objects) }.is_none());

    let mut wrong_form = MappedImage::new();
    wrong_form.exact_owned_crt_note();
    wrong_form.symbol(1, b"__crabc_x86_64_owned_crt_handoff", 1, 1, 0, 0);
    wrong_form.rela(R_X86_64_GLOB_DAT, 1, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = wrong_form.object(false);
    objects[0].main_crt_mode = MainCrtMode::Owned;
    assert!(unsafe { validate_main_crt_mode(&objects) }.is_none());
}

// The installed owned main has one weak, default-visible, undefined NOTYPE
// GLOB_DAT request with a zero addend.  The descriptor address is private
// loader state, so accepting a superficially similar data relocation would
// make that address ambient symbol-resolution policy.  Keep these synthetic
// table records at the relocation transaction boundary; the installed-CRT
// receipt separately proves the corresponding supplied-product mutations.
#[cfg(all(
    feature = "x86_64-owned-dynamic-runtime",
    crabc_general_loader_libc_tls_runtime_v1
))]
#[test]
fn general_runtime_v1_descriptor_request_is_one_exact_main_data_wire() {
    const DESCRIPTOR: &[u8] = b"__crabc_x86_64_loader_tls_runtime_v1";

    let relocate = |symbol_type, binding, visibility, kind, addend, mapped| {
        let mut requestor = MappedImage::new();
        requestor.set_destination(0xfeed);
        requestor.symbol(1, DESCRIPTOR, symbol_type, binding, visibility, 0);
        requestor.rela(kind, 1, addend);
        let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
        objects[0] = requestor.object(mapped);
        objects[0].symcount = 2;
        let graph = graph(1);
        let result = unsafe { relocate_initial_graph(&graph, &objects) };
        (requestor, result)
    };

    let (accepted, result) = relocate(0, 2, 0, R_X86_64_GLOB_DAT, 0, false);
    assert!(result.is_some());
    assert_eq!(accepted.destination(), x86_64_general_initial_tls_state::loader_tls_runtime_v1_record_address());

    for (label, symbol_type, binding, visibility, kind, addend, mapped) in [
        ("symbol type", 1, 2, 0, R_X86_64_GLOB_DAT, 0, false),
        ("binding", 0, 1, 0, R_X86_64_GLOB_DAT, 0, false),
        ("visibility", 0, 2, 2, R_X86_64_GLOB_DAT, 0, false),
        ("relocation kind", 0, 2, 0, R_X86_64_JUMP_SLOT, 0, false),
        ("addend", 0, 2, 0, R_X86_64_GLOB_DAT, 1, false),
        ("DSO endpoint", 0, 2, 0, R_X86_64_GLOB_DAT, 0, true),
    ] {
        let (rejected, result) = relocate(symbol_type, binding, visibility, kind, addend, mapped);
        assert!(result.is_none(), "descriptor {label} was admitted");
        assert_eq!(rejected.destination(), 0xfeed, "descriptor {label} wrote before rejection");
    }
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[test]
fn conventional_startup_import_requires_canonical_libc_and_keeps_owned_mode_null() {
    const STARTUP: &[u8] = b"__crabc_x86_64_loader_conventional_startup_v1";
    let conventional_main = || {
        let mut main = MappedImage::new();
        main.rela(R_X86_64_RELATIVE, 0, 0);
        main
    };
    let imported_libc = || {
        let mut libc = MappedImage::new();
        libc.set_destination(0xfeed);
        libc.symbol(1, STARTUP, 1, 2, 0, 0);
        libc.rela(R_X86_64_GLOB_DAT, 1, 0);
        libc
    };

    let main = conventional_main();
    let libc = imported_libc();
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false);
    objects[1] = libc.object(true);
    objects[1].canonical_libc_identity = Some(ObjectIdentity { device: 7, inode: 9 });
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_some());
    assert_eq!(libc.destination(), x86_64_conventional_startup_v1::address());

    // The installed libc retains one exact request. A second otherwise valid
    // slot is rejected before either relocation write, rather than becoming a
    // second private receiver.
    let main = conventional_main();
    let mut duplicate = imported_libc();
    duplicate.rela_at(MappedImage::DESTINATION + 8, R_X86_64_GLOB_DAT, 1, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false);
    objects[1] = duplicate.object(true);
    objects[1].canonical_libc_identity = Some(ObjectIdentity { device: 7, inode: 9 });
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
    assert_eq!(duplicate.destination(), 0xfeed);
    assert_eq!(duplicate.word_at(MappedImage::DESTINATION + 8), 0);

    // A matching name in an unclassified DSO cannot turn importer possession
    // into private startup authority.
    let main = conventional_main();
    let libc = imported_libc();
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false);
    objects[1] = libc.object(true);
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
    assert_eq!(libc.destination(), 0xfeed);

    // The shared libc appears in an owned product too. Its exact weak import
    // remains a null slot; only the note-plus-handoff path owns lifecycle.
    let mut owned_main = MappedImage::new();
    owned_main.exact_owned_crt_note();
    owned_main.symbol(1, b"__crabc_x86_64_owned_crt_handoff", 1, 2, 0, 0);
    owned_main.rela(R_X86_64_GLOB_DAT, 1, 0);
    let libc = imported_libc();
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = owned_main.object(false);
    objects[0].main_crt_mode = unsafe {
        owned_crt_note_mode(objects[0].phdr, objects[0].phnum, objects[0].base)
    }.unwrap();
    objects[1] = libc.object(true);
    objects[1].canonical_libc_identity = Some(ObjectIdentity { device: 7, inode: 9 });
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_some());
    assert_eq!(libc.destination(), 0);

    let main = conventional_main();
    let mut wrong_form = imported_libc();
    wrong_form.symbol(1, STARTUP, 1, 1, 0, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false);
    objects[1] = wrong_form.object(true);
    objects[1].canonical_libc_identity = Some(ObjectIdentity { device: 7, inode: 9 });
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
    assert_eq!(wrong_form.destination(), 0xfeed);
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[test]
fn relocation_cannot_mutate_a_later_private_import_record_before_admission() {
    const STARTUP: &[u8] = b"__crabc_x86_64_loader_conventional_startup_v1";
    let mut main = MappedImage::new();
    main.rela(R_X86_64_RELATIVE, 0, 0);
    let mut libc = MappedImage::new();
    libc.set_destination(0xfeed);
    libc.symbol(1, STARTUP, 1, 2, 0, 0);
    // The first relocation targets symbol 1's metadata. The second uses that
    // same record for the exact private import. Preflight must reject before
    // either destination changes, including with an empty GNU export table.
    libc.rela_at(MappedImage::SYMTAB + 24, R_64, 0, 0);
    libc.rela(R_X86_64_GLOB_DAT, 1, 0);
    let symbol_before = libc.word_at(MappedImage::SYMTAB + 24);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false);
    objects[1] = libc.object(true);
    objects[1].canonical_libc_identity = Some(ObjectIdentity { device: 7, inode: 9 });
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
    assert_eq!(libc.word_at(MappedImage::SYMTAB + 24), symbol_before);
    assert_eq!(libc.destination(), 0xfeed);
}

fn graph(count: usize) -> InitialGraphState {
    let mut graph = InitialGraphState::new(ObjectIdentity { device: 1, inode: 0 });
    for index in 1..count {
        assert!(matches!(graph.admit_mapped(ObjectIdentity { device: 1, inode: index as u64 }), Ok(ObjectAdmission::New { .. })));
        graph.attach_needed(0, index).unwrap();
        graph.finish_discovery(index).unwrap();
    }
    graph.finish_discovery(0).unwrap();
    graph
}

#[test]
fn general_relocation_scratch_tracks_elf_size_and_rejects_late_overlap_before_writes() {
    let count = 1025;
    let mut data = self::std::vec![0xfeedu64; count];
    let mut relocations: self::std::vec::Vec<[u64; 3]> = (0..count)
        .map(|index| [0x1000 + index as u64 * 8, R_X86_64_RELATIVE as u64, 0x1000])
        .collect();
    let phdr = [1u64 | (7 << 32), 0, 0x1000, 0, count as u64 * 8, count as u64 * 8, 4096];
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = Object { base: data.as_ptr() as u64 - 0x1000,
        phdr: phdr.as_ptr().cast(), phnum: 1,
        rela: relocations.as_ptr().cast(), relasz: relocations.len() * 24, ..EMPTY_OBJECT };
    assert!(unsafe { relocate_initial_graph(&graph(1), &objects) }.is_some());
    assert!(data.iter().all(|word| *word == data.as_ptr() as u64));
    data.fill(0xfeed);
    relocations[count - 1][0] = 0x1000;
    assert!(unsafe { relocate_initial_graph(&graph(1), &objects) }.is_none());
    assert!(data.iter().all(|word| *word == 0xfeed));
}

#[test]
fn general_relr_scratch_exceeds_legacy_table_and_target_limits_without_weakening_overlap_checks() {
    let count = 600;
    let mut data = self::std::vec![0u64; count];
    let mut relr: self::std::vec::Vec<u64> = (0..count).map(|index| 0x1000 + index as u64 * 8).collect();
    let phdr = [1u64 | (7 << 32), 0, 0x1000, 0, count as u64 * 8, count as u64 * 8, 4096];
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = Object { base: data.as_ptr() as u64 - 0x1000,
        phdr: phdr.as_ptr().cast(), phnum: 1,
        relr: relr.as_ptr().cast(), relrsz: relr.len() * 8, ..EMPTY_OBJECT };
    assert!(unsafe { relocate_initial_graph(&graph(1), &objects) }.is_some());
    assert!(data.iter().all(|word| *word == objects[0].base));
    data.fill(0);
    relr[count - 1] = 0x1000;
    assert!(unsafe { relocate_initial_graph(&graph(1), &objects) }.is_none());
    assert!(data.iter().all(|word| *word == 0));
    let oversized = Object { relrsz: usize::MAX, ..EMPTY_OBJECT };
    assert!(unsafe { RelocationScratch::new(&oversized) }.is_none());
}

#[test]
fn runtime_relocation_scope_grows_past_initial_capacity_and_never_rewrites_retained_objects() {
    let mut images: self::std::vec::Vec<Image> = (0..40).map(|_| Image::new()).collect();
    for (index, image) in images.iter_mut().enumerate() {
        image.data[0] = 0xfeed;
        image.rela(0x1000, if index < 32 { 65535 } else { R_X86_64_RELATIVE }, 0, 0x1000);
    }
    let objects: self::std::vec::Vec<Object> = images.iter().enumerate().map(|(index, image)| image.object(index != 0)).collect();
    let order: self::std::vec::Vec<usize> = (0..objects.len()).collect();
    assert!(unsafe { relocate_runtime_objects(&objects, &order, 32, 0) }.is_some());
    for (index, image) in images.iter().enumerate() {
        assert_eq!(image.data[0], if index < 32 { 0xfeed } else { image.data.as_ptr() as u64 });
    }
}

#[test]
#[cfg(crabc_general_initial_tls_materialization_v1)]
fn runtime_new_tls_supports_gd_but_rejects_ie_before_any_new_object_write() {
    let mut main = Image::new();
    let mut first = Image::new();
    let mut provider = Image::new();
    main.data[0] = 0xfeed;
    first.data[0] = 0xbeef;
    provider.data[0] = 0xcafe;
    first.rela(0x1000, R_X86_64_RELATIVE, 0, 0x1000);
    provider.rela(0x1000, R_X86_64_TPOFF64, 0, 0);
    let mut objects = [main.object(false), first.object(true), provider.object(true)];
    objects[0].tls_module_id = 1;
    objects[0].tls_memsz = 16;
    objects[0].tls_offset_below_tp = 16;
    objects[2].tls_module_id = 2;
    objects[2].tls_memsz = 32;
    assert!(unsafe { relocate_runtime_objects(&objects, &[0, 1, 2], 1, 1) }.is_none());
    assert_eq!(main.data[0], 0xfeed);
    assert_eq!(first.data[0], 0xbeef);
    assert_eq!(provider.data[0], 0xcafe);
    provider.relocations[0][1] = R_X86_64_DTPMOD64 as u64;
    assert!(unsafe { relocate_runtime_objects(&objects, &[0, 1, 2], 1, 1) }.is_some());
    assert_eq!(provider.data[0], 2);
    assert_eq!(main.data[0], 0xfeed);
    provider.relocations[0][1] = R_X86_64_DTPOFF64 as u64;
    provider.relocations[0][2] = 31;
    assert!(unsafe { relocate_runtime_objects(&objects, &[0, 1, 2], 2, 1) }.is_some());
    assert_eq!(provider.data[0], 31);
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[test]
fn installed_runtime_function_imports_validate_shape_before_any_graph_write() {
    for name in [
        b"\0__crabc_x86_64_initial_tls_allocate\0".as_slice(),
        b"\0__crabc_x86_64_initial_tls_release\0".as_slice(),
        b"\0__crabc_x86_64_resolve_initial_tls\0".as_slice(),
        b"\0__crabc_x86_64_reset_current_tls_v1\0".as_slice(),
        b"\0__crabc_x86_64_runtime_open\0".as_slice(),
        b"\0__crabc_x86_64_runtime_symbol\0".as_slice(),
        b"\0__crabc_x86_64_runtime_close\0".as_slice(),
        b"\0__crabc_x86_64_runtime_address\0".as_slice(),
        b"\0__crabc_x86_64_runtime_information\0".as_slice(),
        b"\0__crabc_x86_64_runtime_iterate\0".as_slice(),
    ] {
        for (relocation, kind, binding, visibility, section, addend, admitted) in [
            (R_X86_64_GLOB_DAT, 2, 1, 0, 0, 0, true),
            (R_X86_64_JUMP_SLOT, 0, 1, 0, 0, 0, true),
            (R_X86_64_GLOB_DAT, 2, 2, 0, 0, 0, false),
            (R_X86_64_GLOB_DAT, 1, 1, 0, 0, 0, false),
            (R_X86_64_GLOB_DAT, 2, 1, 3, 0, 0, false),
            (R_X86_64_GLOB_DAT, 2, 1, 0, 1, 0, false),
            (R_64, 2, 1, 0, 0, 0, false),
            (R_X86_64_GLOB_DAT, 2, 1, 0, 0, 1, false),
        ] {
            let mut main = MappedImage::new();
            let mut library = MappedImage::new();
            main.set_destination(0xfeed);
            library.set_destination(0xbeef);
            main.rela(R_X86_64_RELATIVE, 0, 0);
            library.symbol(1, &name[1..name.len() - 1], kind, binding, visibility, section);
            library.rela(relocation, 1, addend);
            let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
            objects[0] = main.object(false);
            objects[1] = library.object(true);
            assert_eq!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_some(), admitted);
            if admitted {
                assert_eq!(main.destination(), main.base());
                assert_eq!(library.destination(), x86_64_initial_worker_tls::runtime_function(&name[1..name.len()-1]).unwrap());
            } else {
                assert_eq!(main.destination(), 0xfeed);
                assert_eq!(library.destination(), 0xbeef);
            }
        }
    }
}

#[test]
fn copy_runs_after_provider_fixups_and_preserves_main_interposition_addresses() {
    let mut main = Image::new();
    let mut provider = Image::new();
    main.symbol(1, 1, 1, 0, 1, 0x1000, 16);
    provider.symbol(1, 1, 1, 0, 1, 0x1000, 16);
    main.rela(0x1000, R_COPY, 1, 0);
    provider.rela(0x1000, R_64, 1, 0);
    provider.data[1] = 0xface;
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false);
    objects[1] = provider.object(true);
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_some());
    assert_eq!(main.data[0], main.data.as_ptr() as u64);
    assert_eq!(provider.data[0], main.data.as_ptr() as u64);
    assert_eq!(main.data[1], 0xface);
}

#[test]
fn copy_uses_executable_size_with_byte_alignment_and_readable_extent_not_provider_size() {
    for length in [1, 7, 16, 24] {
        let mut main = Image::new();
        let mut provider = Image::new();
        main.data.fill(0xa5a5_a5a5_a5a5_a5a5);
        provider.data.fill(0x1234_5678_9abc_def0);
        main.symbol(1, 1, 1, 0, 1, 0x1003, length);
        provider.symbol(1, 1, 1, 0, 1, 0x1000, 16);
        main.rela(0x1003, R_COPY, 1, 0);
        let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
        objects[0] = main.object(false); objects[1] = provider.object(true);
        assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_some());
        let actual = unsafe { core::slice::from_raw_parts(main.data.as_ptr().cast::<u8>(), 512) };
        let source = unsafe { core::slice::from_raw_parts(provider.data.as_ptr().cast::<u8>(), 512) };
        assert_eq!(&actual[3..3 + length as usize], &source[..length as usize]);
        assert_eq!(actual[2], 0xa5); assert_eq!(actual[3 + length as usize], 0xa5);
    }
}

#[test]
fn malformed_copy_ranges_scope_and_metadata_fail_before_any_graph_write() {
    for case in 0..13 {
        let mut main = Image::new(); let mut provider = Image::new();
        main.data.fill(0xaaaa); provider.data.fill(0xbbbb);
        main.symbol(1, 1, 1, 0, 1, 0x1000, 24);
        provider.symbol(1, 1, 1, 0, 1, 0x1000, 24);
        main.rela(0x1000, R_COPY, 1, 0);
        provider.rela(0x1080, R_X86_64_RELATIVE, 0, 0x1000);
        match case {
            0 => main.symbols[1][1] += 8,
            1 => main.symbols[1][2] = 513,
            2 => provider.symbols[1][1] = 0x11f8,
            3 => provider.symbols[1][2] = 513,
            4 => provider.symbol(1, 1, 1, 2, 1, 0x1000, 24),
            5 => provider.symbol(1, 1, 1, 3, 1, 0x1000, 24),
            6 => provider.symbol(1, 1, 0, 0, 1, 0x1000, 24),
            7 => provider.symbol(1, 6, 1, 0, 1, 0x1000, 24),
            8 => main.relocations[0][2] = 1,
            9 => main.rela(0x1010, R_X86_64_RELATIVE, 0, 0x1000),
            10 => main.symbol(1, 1, 1, 3, 1, 0x1000, 24),
            11 | 12 => {},
            _ => unreachable!(),
        }
        let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
        objects[0] = main.object(false); objects[1] = provider.object(true);
        if case == 11 { objects[0].role = ObjectRole::Library; }
        if case == 12 { objects[0].phdr = main.data.as_ptr().cast(); main.data[..7].copy_from_slice(&main.phdr); }
        let before_main = *main.data; let before_provider = *provider.data;
        assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none(), "case {case}");
        assert_eq!(*main.data, before_main, "case {case}");
        assert_eq!(*provider.data, before_provider, "case {case}");
    }
}

#[test]
fn invalid_later_object_relocation_cannot_commit_earlier_main_or_dependency_writes() {
    let mut main = Image::new(); let mut provider = Image::new();
    main.data[0] = 0xaaaa; provider.data[0] = 0xbbbb;
    main.rela(0x1000, R_X86_64_RELATIVE, 0, 0x1010);
    provider.rela(0x1000, R_X86_64_RELATIVE, 0, 0x1010);
    provider.rela(0x1010, 0xffff, 0, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false); objects[1] = provider.object(true);
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
    assert_eq!(main.data[0], 0xaaaa); assert_eq!(provider.data[0], 0xbbbb);
}

#[test]
fn none_relocation_has_no_destination_or_symbol_access() {
    let mut main = Image::new();
    main.data[0] = 0xaaaa;
    main.rela(u64::MAX, R_NONE, u32::MAX as usize, i64::MIN);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS]; objects[0] = main.object(false);
    assert!(unsafe { relocate_initial_graph(&graph(1), &objects) }.is_some());
    assert_eq!(main.data[0], 0xaaaa);
}

#[test]
fn ordinary_symbol_type_and_full_definition_extent_are_checked_before_write() {
    let mut main = Image::new(); let mut provider = Image::new();
    main.data[0] = 0xaaaa;
    main.symbol(1, 1, 1, 0, 0, 0, 8);
    main.rela(0x1000, R_64, 1, 0);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false); objects[1] = provider.object(true);
    for (kind, address, size) in [(2, 0x1000, 8), (1, 0x11f8, 16), (1, 0x1000, u64::MAX)] {
        provider.symbol(1, kind, 1, 0, 1, address, size);
        assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
        assert_eq!(main.data[0], 0xaaaa);
    }
}

#[test]
fn symbol_scope_is_breadth_first_and_first_weak_definition_wins() {
    let mut graph = InitialGraphState::new(ObjectIdentity { device: 1, inode: 0 });
    for index in 1..4 {
        graph.admit_mapped(ObjectIdentity { device: 1, inode: index }).unwrap();
        graph.finish_discovery(index as usize).unwrap();
    }
    graph.attach_needed(0, 1).unwrap(); graph.attach_needed(1, 2).unwrap();
    graph.attach_needed(0, 3).unwrap(); graph.finish_discovery(0).unwrap();
    let initial_scope = InitialSymbolScope::from_graph(&graph).unwrap();
    let scope = initial_scope.view();
    assert_eq!(scope.indices, &[0, 1, 3, 2]);
    let mut main = Image::new(); let mut left = Image::new();
    let mut shared = Image::new(); let mut right = Image::new();
    main.symbol(1, 1, 1, 0, 0, 0, 8);
    shared.symbol(1, 1, 1, 0, 1, 0x1000, 8);
    right.symbol(1, 1, 1, 0, 1, 0x1000, 8);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false); objects[1] = left.object(true);
    objects[2] = shared.object(true); objects[3] = right.object(true);
    assert_eq!(unsafe { lookup(&scope, &objects, 0, 1, false, false) }.unwrap().unwrap().owner, 3);
    left.symbol(1, 1, 2, 0, 1, 0x1000, 8);
    assert_eq!(unsafe { lookup(&scope, &objects, 0, 1, false, false) }.unwrap().unwrap().owner, 1);
}

#[test]
fn local_protected_hidden_and_undefined_weak_references_keep_distinct_scopes() {
    let mut main = Image::new(); let mut provider = Image::new();
    main.symbol(1, 1, 1, 0, 1, 0x1000, 8);
    let initial_scope = InitialSymbolScope::from_graph(&graph(2)).unwrap();
    let scope = initial_scope.view();
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false); objects[1] = provider.object(true);
    for (binding, visibility) in [(0, 0), (1, 2), (1, 3)] {
        provider.symbol(1, 1, binding, visibility, 1, 0x1000, 8);
        assert_eq!(unsafe { lookup(&scope, &objects, 1, 1, false, false) }.unwrap().unwrap().owner, 1);
    }
    provider.symbol(1, 1, 1, 0, 1, 0x1000, 8);
    assert_eq!(unsafe { lookup(&scope, &objects, 1, 1, false, false) }.unwrap().unwrap().owner, 0);
    main.symbol(1, 1, 2, 0, 0, 0, 8);
    provider.symbol(1, 1, 1, 2, 1, 0x1000, 8);
    assert!(unsafe { lookup(&scope, &objects, 0, 1, false, false) }.unwrap().is_none());
    assert_eq!(unsafe { word_value(&scope, &objects, 0, R_64, 1, 7) }, Some(7));
}

#[cfg(crabc_general_initial_tls_materialization_v1)]
#[test]
fn initial_exec_and_dynamic_offsets_share_retained_module_coordinates_and_checked_addends() {
    let mut main = Image::new(); let mut provider = Image::new();
    main.symbol(1, 6, 1, 0, 0, 0, 8);
    provider.symbol(1, 6, 1, 0, 1, 8, 8);
    let mut objects = [EMPTY_OBJECT; TEST_OBJECTS];
    objects[0] = main.object(false); objects[1] = provider.object(true);
    objects[1].tls_module_id = 2; objects[1].tls_memsz = 64;
    objects[1].tls_offset_below_tp = 8192; objects[1].tls_align = 4096;
    let initial_scope = InitialSymbolScope::from_graph(&graph(2)).unwrap();
    let scope = initial_scope.view();
    for addend in [-8, 0, 4, 56] {
        let offset = 8 + addend;
        assert_eq!(unsafe { word_value(&scope, &objects, 0, R_X86_64_DTPOFF64, 1, addend) }, Some(offset as u64));
        assert_eq!(unsafe { word_value(&scope, &objects, 0, R_X86_64_TPOFF64, 1, addend) }, Some((offset - 8192) as u64));
    }
    assert_eq!(unsafe { word_value(&scope, &objects, 0, R_X86_64_DTPMOD64, 1, 0) }, Some(2));
    assert_eq!(unsafe { word_value(&scope, &objects, 1, R_X86_64_TPOFF64, 0, 8) }, Some((-8184i64) as u64));
    for addend in [-9, 57, i64::MAX, i64::MIN] {
        assert!(unsafe { word_value(&scope, &objects, 0, R_X86_64_TPOFF64, 1, addend) }.is_none());
    }
    provider.symbol(1, 6, 1, 0, 1, 60, 8);
    assert!(unsafe { word_value(&scope, &objects, 0, R_X86_64_TPOFF64, 1, 0) }.is_none());
    provider.symbol(1, 6, 1, 0, 1, 8, 8);
    objects[1].tls_offset_below_tp = 32;
    assert!(unsafe { word_value(&scope, &objects, 0, R_X86_64_TPOFF64, 1, 0) }.is_none());
    objects[1].tls_offset_below_tp = 8192; objects[1].tls_module_id = 0;
    assert!(unsafe { word_value(&scope, &objects, 0, R_X86_64_TPOFF64, 1, 0) }.is_none());
}

// The batched referenced-record check must agree exactly with the per-span
// scan it replaces in preflight, including empty spans strictly inside a
// record, spans reaching in from below, and records at a span boundary.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[test]
fn batched_referenced_record_check_matches_the_per_span_scan() {
    let mut image = MappedImage::new();
    for index in [1, 3] { image.symbol(index, b"s", 1, 1, 0, 1); }
    image.rela(R_64, 1, 0);
    image.rela(R_64, 3, 0);
    let object = image.object(true);
    let records: std::vec::Vec<(u64, u64)> = [1u64, 3].iter()
        .map(|index| (object.symtab as u64 + 24 * index, 24)).collect();
    let brute = |spans: &[WriteSpan]| spans.iter().any(|span| records.iter().any(|&(record, length)|
        ranges_overlap(object.base + span.start, span.length, record, length).unwrap()));
    let symtab = MappedImage::SYMTAB as u64;
    let mut candidates = std::vec::Vec::new();
    for start in (symtab..symtab + 5 * 24).step_by(4) {
        for length in [0u64, 1, 4, 8, 23, 24, 40] { candidates.push(WriteSpan { start, length }); }
    }
    for first in &candidates {
        let single = [*first];
        assert_eq!(unsafe { referenced_records_overlap_spans(&object, &single) }, Some(brute(&single)),
            "span {:#x}+{}", first.start, first.length);
        // Pair it with a later disjoint span, as sorted preflight spans are.
        for second in candidates.iter().filter(|second| second.start >= first.start + first.length.max(1)) {
            let pair = [*first, *second];
            assert_eq!(unsafe { referenced_records_overlap_spans(&object, &pair) }, Some(brute(&pair)),
                "spans {:#x}+{} {:#x}+{}", first.start, first.length, second.start, second.length);
        }
    }
}

// The batched preflight (per-span containment plus one sorted pass per table)
// must accept exactly the write sets the per-span `checked_write_span` scan
// accepts, over generated sorted disjoint span sets and object layouts that
// place, omit, null or overflow the relocation, symbol, string, program
// header, VERSYM and hash tables.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[test]
fn batched_write_set_checks_match_the_per_span_scan() {
    let mut image = MappedImage::new();
    for index in [1, 2, 3] { image.symbol(index, b"s", 1, 1, 0, 1); }
    image.rela(R_64, 1, 0);
    image.rela(R_64, 3, 0);
    let base = image.object(true);
    let at = |offset: usize| unsafe { base.base as *const u8 }.wrapping_add(offset);
    let mut layouts = std::vec::Vec::new();
    layouts.push(base);
    let mut versioned = base;
    versioned.versym = at(0x2c0);
    versioned.symcount = 4;
    layouts.push(versioned);
    let mut hashed = versioned;
    hashed.symbol_lookup = SymbolLookupTable::Sysv {
        bucket_count: 2, buckets: at(0x2e8).cast(), chains: at(0x2f0).cast(), symbol_count: 4,
    };
    layouts.push(hashed);
    let mut relr = base;
    relr.relr = at(0x3c0);
    relr.relrsz = 16;
    relr.jmprel = at(0x3a0);
    relr.pltrelsz = 0;
    layouts.push(relr);
    let mut null_table = base;
    null_table.relr = core::ptr::null();
    null_table.relrsz = 8;
    layouts.push(null_table);
    let mut overflowing = base;
    overflowing.symcount = usize::MAX / 8;
    layouts.push(overflowing);
    let mut empty = base;
    empty.symtab = core::ptr::null();
    empty.symcount = 0;
    empty.strsz = 0;
    empty.rela = core::ptr::null();
    empty.relasz = 0;
    empty.phnum = 0;
    layouts.push(empty);

    let old = |object: &Object, spans: &[(WriteSpan, bool)]| -> bool {
        spans.iter().all(|(span, word)| unsafe {
            checked_write_span(object, span.start, span.length, *word, None, ReferencedRecords::Deferred)
        }.is_some())
            && unsafe { referenced_records_overlap_spans(object, &spans.iter().map(|item| item.0).collect::<std::vec::Vec<_>>()) }
                == Some(false)
    };
    let new = |object: &Object, spans: &[(WriteSpan, bool)]| -> bool {
        let mut writable = WritableLoadCache::default();
        spans.iter().all(|(span, word)| unsafe { admitted_span(object, &mut writable, span.start, span.length, *word) }.is_some())
            && {
                let set: std::vec::Vec<_> = spans.iter().map(|item| item.0).collect();
                let tables = unsafe { forbidden_tables_overlap_spans(object, &set) };
                let records = unsafe { referenced_records_overlap_spans(object, &set) };
                tables == Some(false) && records == Some(false)
            }
    };
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = |bound: u64| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed % bound };
    let mut accepted = 0;
    let mut rejected = 0;
    for object in &layouts {
        for _ in 0..4000 {
            let mut spans = std::vec::Vec::new();
            let mut cursor = next(0x80);
            for _ in 0..(1 + next(5)) {
                let length = [0u64, 1, 8, 8, 16, 24, 40][next(7) as usize];
                let word = length == 8 && next(4) != 0;
                if cursor + length > MappedImage::BYTES as u64 + 16 { break; }
                spans.push((WriteSpan { start: cursor, length }, word));
                cursor += length.max(1) + next(0x60);
            }
            let (old, new) = (old(object, &spans), new(object, &spans));
            assert_eq!(new, old, "spans {:?}", spans.iter().map(|(span, word)| (span.start, span.length, *word)).collect::<std::vec::Vec<_>>());
            if old { accepted += 1; } else { rejected += 1; }
        }
    }
    assert!(accepted > 500 && rejected > 500, "sweep must exercise both outcomes: {accepted}/{rejected}");
}
