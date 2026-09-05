//! musl 1.2.6 `ldso/dynlink.c::__dls3` (MIT), revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: direct command entry.
//! The source mapping and retained bounds live in direct-interpreter.md.
//! Argument strings and the compacted stack remain in the kernel stack mapping.
use super::*;

static mut LIST: bool = false;

unsafe fn usage() -> ! {
    let message = b"Usage: ld-crabc-x86_64.so.1 [--list] [--library-path PATH] [--preload LIST] [--argv0 STRING] [--] PROGRAM [ARGS]\n";
    unsafe { command_error(message) }
}

unsafe fn command_error(message: &[u8]) -> ! {
    unsafe { syscall3(1, 2, message.as_ptr() as i64, message.len() as i64); syscall1(60, 1); }
    loop {}
}

unsafe fn argument(pointer: usize) -> &'static [u8] {
    let pointer = pointer as *const u8;
    let length = unsafe { bounded_nul(pointer, 4096) }.unwrap_or_else(|| unsafe { usage() });
    unsafe { core::slice::from_raw_parts(pointer, length) }
}

/// Returns an admitted executable and its compacted initial stack. The main
/// mapping belongs to the normal initial transaction after this returns.
///
/// # Safety
/// `sp` must identify the writable Linux initial stack. `ldso_base` must be
/// this already self-relocated interpreter. Call once, before TLS or callbacks.
pub(super) unsafe fn prepare(sp: usize, ldso_base: usize) -> (Object, usize) {
    unsafe {
        let argc = *(sp as *const usize);
        if argc == 0 { usage(); }
        let argv = (sp + 8) as *mut usize;
        let loader_name = argument(*argv);
        x86_64_library_search::command_interpreter(loader_name.as_ptr());
        LIST = loader_name.ends_with(b"ldd");
        let mut index = 1;
        let mut replacement = None;
        while index < argc {
            let value = argument(*argv.add(index));
            if !value.starts_with(b"--") { break; }
            index += 1;
            if value == b"--" { break; }
            if value == b"--list" { LIST = true; continue; }
            let split = value.iter().position(|byte| *byte == b'=');
            let key = split.map_or(value, |offset| &value[..offset]);
            if !matches!(key, b"--library-path" | b"--preload" | b"--argv0") { usage(); }
            let option = if let Some(offset) = split {
                value.as_ptr().add(offset + 1) as usize
            } else {
                if index == argc { usage(); }
                let pointer = *argv.add(index);
                index += 1;
                pointer
            };
            match key {
                b"--library-path" => x86_64_library_search::command_path(option as *const u8),
                b"--preload" => x86_64_library_search::command_preload(option as *const u8),
                _ => replacement = Some(option),
            }
        }
        if index == argc { usage(); }
        let program_pointer = *argv.add(index);
        let program = argument(program_pointer);
        if program.len() >= MAX_PATH { command_error(b"executable pathname exceeds loader capacity\n"); }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, program_pointer as i64, 0x80000, 0);
        if fd < 0 { command_error(b"cannot open executable\n"); }
        let mapped = map_elf_for_role(fd, false, true, ObjectRole::Main);
        syscall1(SYS_CLOSE, fd);
        let mut main = mapped.unwrap_or_else(|| command_error(b"not a valid dynamic executable\n"));
        main.search_name[..program.len()].copy_from_slice(program);
        if LIST {
            for index in 0..main.phnum {
                let phdr = main.phdr.add(index * 56);
                if read_u32(phdr) != 3 { continue; }
                let address = read_u64(phdr.add(16));
                let size = read_u64(phdr.add(32));
                if size == 0 || size > 4096
                    || !virtual_range_in_readable_file_load(main.phdr, main.phnum, address, size) {
                    usage();
                }
                let pointer = (main.base + address) as *const u8;
                if bounded_nul(pointer, size as usize).is_none() { usage(); }
                x86_64_library_search::command_interpreter(pointer);
                break;
            }
        }
        // Removing only leading argv pointers leaves envp, auxv, AT_RANDOM,
        // and every backing string at its original process-lifetime address.
        let compacted = sp + index * 8;
        *(compacted as *mut usize) = argc - index;
        if let Some(value) = replacement { *argv.add(index) = value; }
        let mut aux = argv.add(argc + 1);
        while *aux != 0 { aux = aux.add(1); }
        aux = aux.add(1);
        while *aux != 0 {
            match *aux {
                3 => *aux.add(1) = main.phdr as usize,
                4 => *aux.add(1) = 56,
                5 => *aux.add(1) = main.phnum,
                7 => *aux.add(1) = ldso_base,
                9 => *aux.add(1) = main.entry as usize,
                31 => *aux.add(1) = program_pointer,
                _ => {}
            }
            aux = aux.add(2);
        }
        (main, compacted)
    }
}

unsafe fn write(bytes: &[u8]) {
    unsafe { syscall3(1, 1, bytes.as_ptr() as i64, bytes.len() as i64); }
}

unsafe fn address_line(address: u64) {
    let mut digits = [b'0'; 16];
    let mut value = address;
    for byte in digits.iter_mut().rev() {
        *byte = b"0123456789abcdef"[(value & 15) as usize];
        value >>= 4;
    }
    let start = digits.iter().position(|byte| *byte != b'0').unwrap_or(15);
    unsafe { write(b" (0x"); write(&digits[start..]); write(b")\n"); }
}

pub(super) unsafe fn list_and_exit(objects: &[Object], ldso_base: usize) {
    if !unsafe { LIST } { return; }
    unsafe {
        write(b"\t"); write(x86_64_library_search::interpreter_name());
        address_line(ldso_base as u64);
        for object in objects.iter().skip(1) {
            let name = argument(object.search_name.as_ptr() as usize);
            let requested = if object.initial_load_name_is_short {
                name.iter().rposition(|byte| *byte == b'/').map_or(name, |index| &name[index + 1..])
            } else { name };
            write(b"\t"); write(requested); write(b" => "); write(name);
            address_line(object.base);
        }
        syscall1(60, 0);
    }
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pie_admission_cannot_replace_an_existing_mapping() {
        unsafe {
            let span = syscall6(SYS_MMAP, 0, PAGE as i64, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert!(!is_linux_error(span));
            let lease = MappingLease { address: span, byte_len: PAGE };
            *(span as *mut u64) = 0x71ab_cdef_8934_5026;
            let fd = syscall2(319, b"direct-entry-collision\0".as_ptr() as i64, 0);
            assert!(fd >= 0);
            let mut elf = [0u8; 128];
            elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
            elf[16..18].copy_from_slice(&2u16.to_le_bytes());
            elf[18..20].copy_from_slice(&62u16.to_le_bytes());
            elf[24..32].copy_from_slice(&(span as u64).to_le_bytes());
            elf[32..40].copy_from_slice(&64u64.to_le_bytes());
            elf[54..56].copy_from_slice(&56u16.to_le_bytes());
            elf[56..58].copy_from_slice(&1u16.to_le_bytes());
            elf[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
            elf[68..72].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
            elf[80..88].copy_from_slice(&(span as u64).to_le_bytes());
            elf[96..104].copy_from_slice(&128u64.to_le_bytes());
            elf[104..112].copy_from_slice(&PAGE.to_le_bytes());
            assert_eq!(syscall3(1, fd, elf.as_ptr() as i64, elf.len() as i64), elf.len() as i64);
            let mapped = map_elf_for_role(fd, false, true, ObjectRole::Main);
            syscall1(SYS_CLOSE, fd);
            assert!(mapped.is_none());
            assert_eq!(*(span as *const u64), 0x71ab_cdef_8934_5026);
            drop(lease);
        }
    }
}
