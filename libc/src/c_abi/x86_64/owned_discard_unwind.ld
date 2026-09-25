/*
 * Shared libc.so and ld-crabc link input: discard .eh_frame.
 *
 * The runtime is panic=abort Rust plus the fixed C allocator, so no frame
 * in either image can be unwound through by design; pinned musl builds its
 * libc.so/loader with -fno-unwind-tables -fno-asynchronous-unwind-tables for
 * the same reason. Rust still emits the tables (the precompiled core/alloc
 * debug info makes LLVM keep CFI for every function), and they sat in the
 * first read-only segment that every process maps: about 100 KiB of
 * .eh_frame/.eh_frame_hdr in libc.so and 10 KiB in the loader. Without them
 * the linker emits no PT_GNU_EH_FRAME, so unwinders stop at a runtime frame
 * as they do at a musl one.
 */
SECTIONS { /DISCARD/ : { *(.eh_frame) } }
INSERT AFTER .text;
