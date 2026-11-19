//! TLS_ABOVE_TP layout from musl 1.2.6 ldso/dynlink.c and src/env/__init_tls.c.

use super::*;

const RECORD_SIZE: usize = 32;

pub(super) unsafe fn initial_tls_block_layout(objects: &[Object], ownership_prefix: usize) -> Option<InitialTlsBlockLayout> {
    let mut end = 16usize;
    let mut align = 16usize;
    let mut count = 0usize;
    for object in objects {
        if object.tls_memsz == 0 { continue; }
        if object.tls_offset_below_tp < end || !object.tls_align.is_power_of_two()
            || object.tls_filesz > object.tls_memsz
            || (object.tls_filesz != 0 && object.tls_image.is_null())
            || (object.tls_offset_below_tp & (object.tls_align - 1))
                != (object.tls_image as usize & (object.tls_align - 1)) { return None; }
        end = object.tls_offset_below_tp.checked_add(object.tls_memsz)?;
        align = align.max(object.tls_align);
        count = count.checked_add(1)?;
        if object.tls_module_id != count { return None; }
    }
    if count == 0 { return None; }
    let words = count.checked_add(1)?;
    let tables = words.checked_mul(core::mem::size_of::<usize>())?.checked_mul(2)?;
    let size = ownership_prefix.checked_add(RECORD_SIZE)?.checked_add(align - 1)?
        .checked_add(end)?.checked_add(7)?.checked_add(tables)?;
    Some(InitialTlsBlockLayout { total_tls_size: end, tp_alignment: align, module_count: count,
        dtv_words: words, mapping_size: align_up_usize(size, PAGE as usize)? })
}

pub(super) unsafe fn materialize_tls_in_layout(objects: &[Object], ownership_prefix: usize,
    layout: *const InitialTlsBlockLayout, builtin: Option<(*mut u8, usize)>) -> Option<InstalledInitialTls> {
    // SAFETY: The caller provides the validated immutable layout.
    let layout = unsafe { *layout };
    let builtin = builtin.filter(|&(_, bytes)| layout.mapping_size <= bytes);
    // SAFETY: mmap arguments request private writable anonymous storage.
    let mapping = match builtin {
        Some((pointer, _)) => pointer as i64,
        None => unsafe { syscall6(SYS_MMAP, 0, layout.mapping_size as i64, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) },
    };
    if is_linux_error(mapping) { return None; }
    let block = mapping as usize;
    let coordinates = (|| {
        let end = block.checked_add(layout.mapping_size)?;
        let tp = align_up_usize(block.checked_add(ownership_prefix)?.checked_add(RECORD_SIZE)?, layout.tp_alignment)?;
        let dtv = align_up_usize(tp.checked_add(layout.total_tls_size)?, 8)?;
        let table_bytes = layout.dtv_words.checked_mul(8)?;
        let sizes = dtv.checked_add(table_bytes)?;
        if sizes.checked_add(table_bytes)? > end { return None; }
        Some((tp, dtv, sizes))
    })();
    let Some((tp, dtv, sizes)) = coordinates else {
        if builtin.is_none() {
            // SAFETY: This mapping was just allocated and has not been published.
            unsafe { syscall2(SYS_MUNMAP, mapping, layout.mapping_size as i64); }
        }
        return None;
    };
    // SAFETY: The checked layout reserves the record, gap, tables and images;
    // the fresh block is private until the caller publishes its thread pointer.
    unsafe {
        core::ptr::write_bytes((tp - RECORD_SIZE) as *mut u8, 0, RECORD_SIZE);
        ((tp - 8) as *mut usize).write(dtv);
        (tp as *mut usize).write(sizes);
        core::ptr::write_bytes(dtv as *mut usize, 0, layout.dtv_words * 2);
        (dtv as *mut usize).write(layout.module_count);
        for object in objects {
            if object.tls_memsz == 0 { continue; }
            if object.tls_module_id == 0 || object.tls_module_id >= layout.dtv_words {
                if builtin.is_none() { syscall2(SYS_MUNMAP, mapping, layout.mapping_size as i64); }
                return None;
            }
            let destination = (tp + object.tls_offset_below_tp) as *mut u8;
            if object.tls_filesz != 0 { core::ptr::copy_nonoverlapping(object.tls_image, destination, object.tls_filesz); }
            core::ptr::write_bytes(destination.add(object.tls_filesz), 0, object.tls_memsz - object.tls_filesz);
            (dtv as *mut usize).add(object.tls_module_id).write(destination as usize);
            (sizes as *mut usize).add(object.tls_module_id).write(object.tls_memsz);
        }
    }
    Some(InstalledInitialTls { mapping: mapping as *mut u8, mapping_byte_len: layout.mapping_size,
        thread_pointer: tp as *mut u8, dtv: dtv as *mut usize, dtv_words: layout.dtv_words,
        module_count: layout.module_count })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4096))]
    struct Storage([u8; 4096]);

    #[test]
    fn materialization_rejects_module_outside_dtv() {
        let image = [1u8];
        let object = Object { tls_image: image.as_ptr(), tls_filesz: 1, tls_memsz: 1,
            tls_align: 1, tls_module_id: 1, tls_offset_below_tp: 16, ..EMPTY_OBJECT };
        let mut storage = Storage([0; 4096]);
        let layout = unsafe { initial_tls_block_layout(&[object], 0) }.unwrap();
        let invalid = Object { tls_module_id: layout.dtv_words, ..object };
        assert!(unsafe { materialize_tls_in_layout(&[invalid], 0, &layout,
            Some((storage.0.as_mut_ptr(), storage.0.len()))) }.is_none());
    }

    #[test]
    fn initial_record_and_image_follow_aarch64_variant_i() {
        let image = [31u8, 41, 59];
        let placement = 16 + ((image.as_ptr() as usize).wrapping_sub(16) & 7);
        let object = Object { tls_image: image.as_ptr(), tls_filesz: image.len(), tls_memsz: 8,
            tls_align: 8, tls_module_id: 1, tls_offset_below_tp: placement, ..EMPTY_OBJECT };
        let mut storage = Storage([0xa5; 4096]);
        // SAFETY: The image and placement remain live for the entire test.
        let layout = unsafe { initial_tls_block_layout(&[object], 0) }.unwrap();
        // SAFETY: Storage is private, page aligned, and at least layout.mapping_size bytes.
        let block = unsafe { materialize_tls_in_layout(&[object], 0, &layout,
            Some((storage.0.as_mut_ptr(), storage.0.len()))) }.unwrap();
        let tp = block.thread_pointer;
        // SAFETY: The materialized block contains the checked record and module image.
        unsafe {
            assert_eq!(*tp.sub(8).cast::<usize>(), block.dtv as usize);
            assert_eq!(*tp.sub(16).cast::<usize>(), 0);
            assert_eq!(*tp.sub(24).cast::<usize>(), 0);
            assert_eq!(*block.dtv, 1);
            let module = *block.dtv.add(1) as *const u8;
            assert_eq!(module as usize, tp as usize + placement);
            assert_eq!(core::slice::from_raw_parts(module, 8), &[31, 41, 59, 0, 0, 0, 0, 0]);
        }
    }
}
