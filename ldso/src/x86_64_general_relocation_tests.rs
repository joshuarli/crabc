extern crate std;
use super::*;
use self::std::boxed::Box;
use super::super::x86_64_initial_graph_state::{ObjectAdmission, ObjectIdentity};

pub(super) struct Image {
    pub(super) data: Box<[u64; 64]>,
    phdr: [u64; 7],
    symbols: [[u64; 3]; 5],
    relocations: [[u64; 3]; 4],
    count: usize,
}
impl Image {
    pub(super) fn new() -> Self {
        Self {
            data: Box::new([0; 64]),
            phdr: [1 | (7 << 32), 0, 0x1000, 0, 512, 512, 4096],
            symbols: [[0; 3]; 5], relocations: [[0; 3]; 4], count: 0,
        }
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
            base: self.data.as_ptr() as u64 - 0x1000,
            phdr: self.phdr.as_ptr().cast(), phnum: 1,
            symtab: self.symbols.as_ptr().cast(), symcount: self.symbols.len(),
            strtab: b"\0value\0".as_ptr(), strsz: 7,
            rela: self.relocations.as_ptr().cast(), relasz: self.count * 24,
            mapped, ..EMPTY_OBJECT
        }
    }
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
            let mut main = Image::new();
            let mut library = Image::new();
            main.data[0] = 0xfeed;
            library.data[0] = 0xbeef;
            main.rela(0x1000, R_X86_64_RELATIVE, 0, 0x1000);
            library.symbol(1, kind, binding, visibility, section, 0, 0);
            library.rela(0x1000, relocation, 1, addend);
            let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
            objects[0] = main.object(false);
            objects[1] = library.object(true);
            objects[1].strtab = name.as_ptr();
            objects[1].strsz = name.len();
            assert_eq!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_some(), admitted);
            if admitted {
                assert_eq!(main.data[0], main.data.as_ptr() as u64);
                assert_eq!(library.data[0], x86_64_initial_worker_tls::runtime_function(&name[1..name.len()-1]).unwrap());
            } else {
                assert_eq!(main.data[0], 0xfeed);
                assert_eq!(library.data[0], 0xbeef);
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
        let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
        let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
        objects[0] = main.object(false); objects[1] = provider.object(true);
        if case == 11 { objects[0].mapped = true; }
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
    objects[0] = main.object(false); objects[1] = provider.object(true);
    assert!(unsafe { relocate_initial_graph(&graph(2), &objects) }.is_none());
    assert_eq!(main.data[0], 0xaaaa); assert_eq!(provider.data[0], 0xbbbb);
}

#[test]
fn none_relocation_has_no_destination_or_symbol_access() {
    let mut main = Image::new();
    main.data[0] = 0xaaaa;
    main.rela(u64::MAX, R_NONE, u32::MAX as usize, i64::MIN);
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS]; objects[0] = main.object(false);
    assert!(unsafe { relocate_initial_graph(&graph(1), &objects) }.is_some());
    assert_eq!(main.data[0], 0xaaaa);
}

#[test]
fn ordinary_symbol_type_and_full_definition_extent_are_checked_before_write() {
    let mut main = Image::new(); let mut provider = Image::new();
    main.data[0] = 0xaaaa;
    main.symbol(1, 1, 1, 0, 0, 0, 8);
    main.rela(0x1000, R_64, 1, 0);
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
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
