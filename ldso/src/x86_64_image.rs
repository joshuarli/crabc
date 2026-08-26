//! Checked ELF64 image metadata for the future Linux/x86-64 loader.
//!
//! This source-only foundation validates the file-facing part of the loader
//! boundary: an ELF64 little-endian x86-64 image, its `PT_LOAD` map, its
//! `PT_DYNAMIC` range, and the shape and mapped ranges of its RELA/RELR
//! metadata.  It deliberately does not map bytes, apply relocations, resolve
//! symbols, or select `crabc-ldso` for x86-64.  The resulting load ranges and
//! relocation descriptors are intended to feed `x86_64_relocation.rs` only
//! after the runtime mapper has established the corresponding live mappings.

#![allow(dead_code)]

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("x86_64_image is a Linux/x86-64 little-endian loader foundation");

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const DYNAMIC_ENTRY_SIZE: usize = 16;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_LOAD_SEGMENTS: usize = 32;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_PHDR: u32 = 6;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_RELR: i64 = 36;
const DT_RELRSZ: i64 = 35;
const DT_RELRENT: i64 = 37;

const ELF64_RELA_SIZE: u64 = 24;
const ELF64_RELR_SIZE: u64 = 8;

const EMPTY_LOAD_SEGMENT: LoadSegment = LoadSegment {
    virtual_address: 0,
    memory_size: 0,
    file_offset: 0,
    file_size: 0,
    flags: 0,
    alignment: 0,
};

/// A validated `PT_LOAD` descriptor in the file's x86-64 virtual address
/// space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoadSegment {
    pub(crate) virtual_address: u64,
    pub(crate) memory_size: u64,
    pub(crate) file_offset: u64,
    pub(crate) file_size: u64,
    pub(crate) flags: u32,
    pub(crate) alignment: u64,
}

/// A dynamic relocation table descriptor, still expressed in object-relative
/// virtual addresses.  The runtime must apply its load bias before derefencing
/// either table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelocationTable {
    pub(crate) virtual_address: u64,
    pub(crate) byte_len: u64,
    pub(crate) entry_size: u64,
}

/// Dynamic metadata extracted from one validated `PT_DYNAMIC` segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DynamicInfo {
    pub(crate) virtual_address: u64,
    pub(crate) byte_len: u64,
    pub(crate) rela: Option<RelocationTable>,
    pub(crate) relr: Option<RelocationTable>,
}

/// The checked file-facing image shape needed by the x86-64 relocation
/// foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImageLayout {
    pub(crate) entry: u64,
    pub(crate) program_header_virtual_address: Option<u64>,
    loads: [LoadSegment; MAX_LOAD_SEGMENTS],
    load_count: usize,
    pub(crate) dynamic: Option<DynamicInfo>,
    pub(crate) relro: Option<(u64, u64)>,
}

impl ImageLayout {
    pub(crate) fn load_segments(&self) -> &[LoadSegment] {
        &self.loads[..self.load_count]
    }
}

/// A malformed or unsupported x86-64 ELF image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImageError {
    Truncated { needed: usize, available: usize },
    BadMagic,
    UnsupportedClassOrEncoding,
    UnsupportedVersion,
    MalformedElfHeader,
    UnsupportedType { elf_type: u16 },
    WrongMachine { machine: u16 },
    MalformedProgramHeaderTable,
    TooManyProgramHeaders { count: usize },
    NoLoadSegments,
    TooManyLoadSegments,
    LoadFileRangeOutsideImage,
    LoadFileLargerThanMemory,
    LoadAddressOverflow,
    InvalidLoadAlignment,
    OverlappingLoadSegments,
    DuplicateProgramHeader { kind: u32 },
    DynamicRangeOutsideLoad,
    DynamicRangeMalformed,
    DynamicMissingTerminator,
    DuplicateDynamicTag { tag: i64 },
    RelocationMetadataIncomplete { table: &'static str },
    RelocationEntrySize { table: &'static str, entry_size: u64 },
    RelocationSize { table: &'static str, byte_len: u64 },
    RelocationOutsideLoad { table: &'static str },
    RelocationAddressOverflow { table: &'static str },
}

/// Parse and validate a complete little-endian ELF64 x86-64 image.
///
/// The returned addresses are object-relative.  No pointer into `bytes` is
/// retained, so callers may discard the file buffer after copying the image
/// into validated runtime mappings.  This function intentionally accepts both
/// `ET_EXEC` and `ET_DYN`; the caller chooses the load bias according to the
/// executable's type and startup policy.
pub(crate) fn parse_image(bytes: &[u8]) -> Result<ImageLayout, ImageError> {
    require_range(bytes, 0, ELF_HEADER_SIZE)?;
    if bytes[..4] != *b"\x7fELF" {
        return Err(ImageError::BadMagic);
    }
    if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
        return Err(ImageError::UnsupportedClassOrEncoding);
    }
    if bytes[6] != EV_CURRENT {
        return Err(ImageError::UnsupportedVersion);
    }
    if read_u32(bytes, 20) != u32::from(EV_CURRENT) {
        return Err(ImageError::UnsupportedVersion);
    }
    if read_u16(bytes, 52) as usize != ELF_HEADER_SIZE {
        return Err(ImageError::MalformedElfHeader);
    }

    let elf_type = read_u16(bytes, 16);
    if elf_type != ET_EXEC && elf_type != ET_DYN {
        return Err(ImageError::UnsupportedType { elf_type });
    }
    let machine = read_u16(bytes, 18);
    if machine != EM_X86_64 {
        return Err(ImageError::WrongMachine { machine });
    }

    let entry = read_u64(bytes, 24);
    let program_header_offset = read_u64(bytes, 32);
    let program_header_entry_size = read_u16(bytes, 54);
    let program_header_count = read_u16(bytes, 56) as usize;
    if program_header_entry_size as usize != PROGRAM_HEADER_SIZE {
        return Err(ImageError::MalformedProgramHeaderTable);
    }
    if program_header_count == 0 || program_header_count > MAX_PROGRAM_HEADERS {
        return Err(ImageError::TooManyProgramHeaders {
            count: program_header_count,
        });
    }
    let table_size = program_header_count
        .checked_mul(PROGRAM_HEADER_SIZE)
        .ok_or(ImageError::MalformedProgramHeaderTable)?;
    let table_offset = usize::try_from(program_header_offset)
        .map_err(|_| ImageError::MalformedProgramHeaderTable)?;
    require_range(bytes, table_offset, table_size)
        .map_err(|_| ImageError::MalformedProgramHeaderTable)?;

    let mut layout = ImageLayout {
        entry,
        program_header_virtual_address: None,
        loads: [EMPTY_LOAD_SEGMENT; MAX_LOAD_SEGMENTS],
        load_count: 0,
        dynamic: None,
        relro: None,
    };
    let mut dynamic_file_range = None;
    let mut dynamic_virtual_address = None;
    let mut dynamic_memory_size = None;

    for index in 0..program_header_count {
        let offset = table_offset + index * PROGRAM_HEADER_SIZE;
        let kind = read_u32(bytes, offset);
        let flags = read_u32(bytes, offset + 4);
        let file_offset = read_u64(bytes, offset + 8);
        let virtual_address = read_u64(bytes, offset + 16);
        let file_size = read_u64(bytes, offset + 32);
        let memory_size = read_u64(bytes, offset + 40);
        let alignment = read_u64(bytes, offset + 48);

        match kind {
            PT_LOAD => {
                if file_size > memory_size {
                    return Err(ImageError::LoadFileLargerThanMemory);
                }
                let file_offset_usize = usize::try_from(file_offset)
                    .map_err(|_| ImageError::LoadFileRangeOutsideImage)?;
                let file_size_usize = usize::try_from(file_size)
                    .map_err(|_| ImageError::LoadFileRangeOutsideImage)?;
                require_range(bytes, file_offset_usize, file_size_usize)
                    .map_err(|_| ImageError::LoadFileRangeOutsideImage)?;
                let _ = virtual_address
                    .checked_add(memory_size)
                    .ok_or(ImageError::LoadAddressOverflow)?;
                if alignment > 1
                    && (!alignment.is_power_of_two()
                        || file_offset % alignment != virtual_address % alignment)
                {
                    return Err(ImageError::InvalidLoadAlignment);
                }
                if layout.load_count == MAX_LOAD_SEGMENTS {
                    return Err(ImageError::TooManyLoadSegments);
                }
                let candidate = LoadSegment {
                    virtual_address,
                    memory_size,
                    file_offset,
                    file_size,
                    flags,
                    alignment,
                };
                for prior in layout.load_segments() {
                    if ranges_overlap(
                        prior.virtual_address,
                        prior.memory_size,
                        candidate.virtual_address,
                        candidate.memory_size,
                    ) {
                        return Err(ImageError::OverlappingLoadSegments);
                    }
                }
                layout.loads[layout.load_count] = candidate;
                layout.load_count += 1;
            }
            PT_DYNAMIC => {
                if dynamic_file_range.is_some() {
                    return Err(ImageError::DuplicateProgramHeader { kind });
                }
                let file_offset_usize = usize::try_from(file_offset)
                    .map_err(|_| ImageError::DynamicRangeMalformed)?;
                let file_size_usize = usize::try_from(file_size)
                    .map_err(|_| ImageError::DynamicRangeMalformed)?;
                require_range(bytes, file_offset_usize, file_size_usize)
                    .map_err(|_| ImageError::DynamicRangeMalformed)?;
                if file_size < DYNAMIC_ENTRY_SIZE as u64
                    || file_size % DYNAMIC_ENTRY_SIZE as u64 != 0
                    || memory_size < file_size
                {
                    return Err(ImageError::DynamicRangeMalformed);
                }
                let _ = virtual_address
                    .checked_add(memory_size)
                    .ok_or(ImageError::LoadAddressOverflow)?;
                dynamic_file_range = Some((file_offset_usize, file_size_usize));
                dynamic_virtual_address = Some(virtual_address);
                dynamic_memory_size = Some(memory_size);
            }
            PT_PHDR => {
                if layout.program_header_virtual_address.is_some() {
                    return Err(ImageError::DuplicateProgramHeader { kind });
                }
                layout.program_header_virtual_address = Some(virtual_address);
            }
            PT_GNU_RELRO => {
                if layout.relro.is_some() {
                    return Err(ImageError::DuplicateProgramHeader { kind });
                }
                let _ = virtual_address
                    .checked_add(memory_size)
                    .ok_or(ImageError::LoadAddressOverflow)?;
                layout.relro = Some((virtual_address, memory_size));
            }
            _ => {}
        }
    }

    if layout.load_count == 0 {
        return Err(ImageError::NoLoadSegments);
    }
    if let Some((address, size)) = dynamic_virtual_address.zip(dynamic_memory_size) {
        if !contains_range(layout.load_segments(), address, size) {
            return Err(ImageError::DynamicRangeOutsideLoad);
        }
    }
    if let Some(address) = layout.program_header_virtual_address {
        let size = (program_header_count * PROGRAM_HEADER_SIZE) as u64;
        if !contains_range(layout.load_segments(), address, size) {
            return Err(ImageError::DynamicRangeOutsideLoad);
        }
    }
    if let Some((address, size)) = layout.relro {
        if !contains_range(layout.load_segments(), address, size) {
            return Err(ImageError::DynamicRangeOutsideLoad);
        }
    }

    let Some((dynamic_offset, dynamic_size)) = dynamic_file_range else {
        return Ok(layout);
    };
    let dynamic_address = dynamic_virtual_address.ok_or(ImageError::DynamicRangeMalformed)?;
    let dynamic = parse_dynamic(
        bytes,
        dynamic_offset,
        dynamic_size,
        dynamic_address,
        layout.load_segments(),
    )?;
    layout.dynamic = Some(dynamic);
    Ok(layout)
}

fn parse_dynamic(
    bytes: &[u8],
    offset: usize,
    size: usize,
    virtual_address: u64,
    loads: &[LoadSegment],
) -> Result<DynamicInfo, ImageError> {
    let mut rela_address = None;
    let mut rela_size = None;
    let mut rela_entry_size = None;
    let mut relr_address = None;
    let mut relr_size = None;
    let mut relr_entry_size = None;
    let mut terminated = false;

    for index in 0..(size / DYNAMIC_ENTRY_SIZE) {
        let entry = offset + index * DYNAMIC_ENTRY_SIZE;
        let tag = read_i64(bytes, entry);
        let value = read_u64(bytes, entry + 8);
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        let destination = match tag {
            DT_RELA => &mut rela_address,
            DT_RELASZ => &mut rela_size,
            DT_RELAENT => &mut rela_entry_size,
            DT_RELR => &mut relr_address,
            DT_RELRSZ => &mut relr_size,
            DT_RELRENT => &mut relr_entry_size,
            _ => continue,
        };
        if destination.is_some() {
            return Err(ImageError::DuplicateDynamicTag { tag });
        }
        *destination = Some(value);
    }
    if !terminated {
        return Err(ImageError::DynamicMissingTerminator);
    }

    let rela = relocation_table(
        "RELA",
        rela_address,
        rela_size,
        rela_entry_size,
        ELF64_RELA_SIZE,
        loads,
    )?;
    let relr = relocation_table(
        "RELR",
        relr_address,
        relr_size,
        relr_entry_size,
        ELF64_RELR_SIZE,
        loads,
    )?;
    Ok(DynamicInfo {
        virtual_address,
        byte_len: size as u64,
        rela,
        relr,
    })
}

fn relocation_table(
    name: &'static str,
    address: Option<u64>,
    size: Option<u64>,
    entry_size: Option<u64>,
    expected_entry_size: u64,
    loads: &[LoadSegment],
) -> Result<Option<RelocationTable>, ImageError> {
    if address.is_none() && size.is_none() && entry_size.is_none() {
        return Ok(None);
    }
    let (Some(address), Some(byte_len), Some(entry_size)) = (address, size, entry_size) else {
        return Err(ImageError::RelocationMetadataIncomplete { table: name });
    };
    if entry_size != expected_entry_size {
        return Err(ImageError::RelocationEntrySize { table: name, entry_size });
    }
    if byte_len % entry_size != 0 {
        return Err(ImageError::RelocationSize { table: name, byte_len });
    }
    let _ = address
        .checked_add(byte_len)
        .ok_or(ImageError::RelocationAddressOverflow { table: name })?;
    if byte_len != 0 && !contains_range(loads, address, byte_len) {
        return Err(ImageError::RelocationOutsideLoad { table: name });
    }
    Ok(Some(RelocationTable {
        virtual_address: address,
        byte_len,
        entry_size,
    }))
}

fn contains_range(loads: &[LoadSegment], address: u64, size: u64) -> bool {
    loads.iter().any(|load| {
        let Some(end) = address.checked_add(size) else {
            return false;
        };
        let Some(load_end) = load.virtual_address.checked_add(load.memory_size) else {
            return false;
        };
        address >= load.virtual_address && end <= load_end
    })
}

fn ranges_overlap(first: u64, first_size: u64, second: u64, second_size: u64) -> bool {
    let Some(first_end) = first.checked_add(first_size) else {
        return true;
    };
    let Some(second_end) = second.checked_add(second_size) else {
        return true;
    };
    first < second_end && second < first_end
}

fn require_range(bytes: &[u8], offset: usize, size: usize) -> Result<(), ImageError> {
    let end = offset.checked_add(size).ok_or(ImageError::Truncated {
        needed: usize::MAX,
        available: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(ImageError::Truncated {
            needed: end,
            available: bytes.len(),
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_SIZE: usize = 0x500;
    const PHOFF: usize = 0x40;
    const LOAD0: usize = PHOFF;
    const DYNAMIC: usize = PHOFF + PROGRAM_HEADER_SIZE;
    const RELA: usize = 0x300;

    fn image() -> Vec<u8> {
        let mut bytes = vec![0u8; IMAGE_SIZE];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        put_u16(&mut bytes, 16, ET_DYN);
        put_u16(&mut bytes, 18, EM_X86_64);
        put_u32(&mut bytes, 20, u32::from(EV_CURRENT));
        put_u64(&mut bytes, 24, 0x180);
        put_u64(&mut bytes, 32, PHOFF as u64);
        put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
        put_u16(&mut bytes, 54, PROGRAM_HEADER_SIZE as u16);
        put_u16(&mut bytes, 56, 2);
        put_phdr(
            &mut bytes,
            LOAD0,
            PT_LOAD,
            0,
            0,
            0,
            IMAGE_SIZE as u64,
            IMAGE_SIZE as u64,
            0x1000,
        );
        put_phdr(
            &mut bytes,
            DYNAMIC,
            PT_DYNAMIC,
            0,
            0x200,
            0x200,
            0x80,
            0x80,
            8,
        );
        put_dynamic(&mut bytes, 0, DT_RELA, RELA as u64);
        put_dynamic(&mut bytes, 1, DT_RELASZ, 24);
        put_dynamic(&mut bytes, 2, DT_RELAENT, 24);
        put_dynamic(&mut bytes, 3, DT_NULL, 0);
        bytes
    }

    fn put_phdr(
        bytes: &mut [u8],
        offset: usize,
        kind: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        put_u32(bytes, offset, kind);
        put_u32(bytes, offset + 4, flags);
        put_u64(bytes, offset + 8, file_offset);
        put_u64(bytes, offset + 16, virtual_address);
        put_u64(bytes, offset + 32, file_size);
        put_u64(bytes, offset + 40, memory_size);
        put_u64(bytes, offset + 48, alignment);
    }

    fn put_dynamic(bytes: &mut [u8], index: usize, tag: i64, value: u64) {
        let offset = 0x200 + index * DYNAMIC_ENTRY_SIZE;
        bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
        put_u64(bytes, offset + 8, value);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_x86_dynamic_image_and_relocation_metadata() {
        let bytes = image();
        let parsed = parse_image(&bytes).expect("well-formed x86 image");
        assert_eq!(parsed.entry, 0x180);
        assert_eq!(parsed.load_segments().len(), 1);
        assert_eq!(parsed.load_segments()[0].memory_size, IMAGE_SIZE as u64);
        let dynamic = parsed.dynamic.expect("dynamic segment");
        assert_eq!(dynamic.virtual_address, 0x200);
        assert_eq!(
            dynamic.rela,
            Some(RelocationTable {
                virtual_address: RELA as u64,
                byte_len: 24,
                entry_size: 24,
            })
        );
        assert_eq!(dynamic.relr, None);
    }

    #[test]
    fn parses_relr_metadata_alongside_rela() {
        let mut bytes = image();
        put_dynamic(&mut bytes, 3, DT_RELR, 0x320);
        put_dynamic(&mut bytes, 4, DT_RELRSZ, 8);
        put_dynamic(&mut bytes, 5, DT_RELRENT, 8);
        put_dynamic(&mut bytes, 6, DT_NULL, 0);

        let parsed = parse_image(&bytes).expect("well-formed RELR metadata");
        assert_eq!(
            parsed.dynamic.expect("dynamic segment").relr,
            Some(RelocationTable {
                virtual_address: 0x320,
                byte_len: 8,
                entry_size: 8,
            })
        );
    }

    #[test]
    fn rejects_non_x86_class_and_machine_before_program_headers() {
        let mut bytes = image();
        bytes[4] = 1;
        assert_eq!(parse_image(&bytes), Err(ImageError::UnsupportedClassOrEncoding));
        let mut bytes = image();
        put_u16(&mut bytes, 18, 183);
        assert_eq!(parse_image(&bytes), Err(ImageError::WrongMachine { machine: 183 }));
    }

    #[test]
    fn rejects_mismatched_elf_header_versions_and_size() {
        let mut bytes = image();
        put_u32(&mut bytes, 20, 0);
        assert_eq!(parse_image(&bytes), Err(ImageError::UnsupportedVersion));

        let mut bytes = image();
        put_u16(&mut bytes, 52, 0);
        assert_eq!(parse_image(&bytes), Err(ImageError::MalformedElfHeader));
    }

    #[test]
    fn rejects_truncated_program_headers() {
        let mut bytes = image();
        put_u64(&mut bytes, 32, (IMAGE_SIZE - 4) as u64);
        assert_eq!(
            parse_image(&bytes),
            Err(ImageError::MalformedProgramHeaderTable)
        );
    }

    #[test]
    fn rejects_overlapping_load_segments() {
        let mut bytes = image();
        put_u16(&mut bytes, 56, 3);
        let second = PHOFF + 2 * PROGRAM_HEADER_SIZE;
        put_phdr(
            &mut bytes,
            second,
            PT_LOAD,
            4,
            0x100,
            0x100,
            0x10,
            0x100,
            0x1000,
        );
        assert_eq!(parse_image(&bytes), Err(ImageError::OverlappingLoadSegments));
    }

    #[test]
    fn rejects_dynamic_segment_outside_load() {
        let mut bytes = image();
        put_phdr(&mut bytes, DYNAMIC, PT_DYNAMIC, 0, 0x200, 0x800, 0x80, 0x80, 8);
        assert_eq!(parse_image(&bytes), Err(ImageError::DynamicRangeOutsideLoad));
    }

    #[test]
    fn rejects_program_header_and_relro_ranges_outside_load() {
        let mut bytes = image();
        put_u16(&mut bytes, 56, 3);
        let third = PHOFF + 2 * PROGRAM_HEADER_SIZE;
        put_phdr(&mut bytes, third, PT_PHDR, 0, 0, IMAGE_SIZE as u64, 0, 0, 8);
        assert_eq!(parse_image(&bytes), Err(ImageError::DynamicRangeOutsideLoad));

        let mut bytes = image();
        put_u16(&mut bytes, 56, 3);
        let third = PHOFF + 2 * PROGRAM_HEADER_SIZE;
        put_phdr(
            &mut bytes,
            third,
            PT_GNU_RELRO,
            0,
            0,
            IMAGE_SIZE as u64,
            0,
            1,
            8,
        );
        assert_eq!(parse_image(&bytes), Err(ImageError::DynamicRangeOutsideLoad));
    }

    #[test]
    fn rejects_unterminated_dynamic_table() {
        let mut bytes = image();
        for index in 3..(0x80 / DYNAMIC_ENTRY_SIZE) {
            put_dynamic(&mut bytes, index, 0x100 + index as i64, 0);
        }
        assert_eq!(parse_image(&bytes), Err(ImageError::DynamicMissingTerminator));
    }

    #[test]
    fn rejects_duplicate_dynamic_tags() {
        let mut bytes = image();
        put_dynamic(&mut bytes, 3, DT_RELAENT, 24);
        assert_eq!(parse_image(&bytes), Err(ImageError::DuplicateDynamicTag { tag: DT_RELAENT }));
    }

    #[test]
    fn rejects_incomplete_and_malformed_rela_metadata() {
        let mut bytes = image();
        put_dynamic(&mut bytes, 1, DT_NULL, 0);
        assert_eq!(
            parse_image(&bytes),
            Err(ImageError::RelocationMetadataIncomplete { table: "RELA" })
        );

        let mut bytes = image();
        put_dynamic(&mut bytes, 2, DT_RELAENT, 8);
        assert_eq!(
            parse_image(&bytes),
            Err(ImageError::RelocationEntrySize {
                table: "RELA",
                entry_size: 8,
            })
        );

        let mut bytes = image();
        put_dynamic(&mut bytes, 1, DT_RELASZ, 25);
        assert_eq!(
            parse_image(&bytes),
            Err(ImageError::RelocationSize {
                table: "RELA",
                byte_len: 25,
            })
        );
    }

    #[test]
    fn accepts_static_image_without_dynamic_segment() {
        let mut bytes = image();
        put_u16(&mut bytes, 56, 1);
        let parsed = parse_image(&bytes).expect("static image has valid load map");
        assert_eq!(parsed.dynamic, None);
    }
}
