# Owned VM mechanisms

The installed native x86 owned products provide C `mremap`, `brk`, `sbrk`, and
`remap_file_pages` through
`libc/src/c_abi/x86_64/owned_vm_mechanisms.rs`. The source-specific port maps
those entries to pinned musl 1.2.6 `src/mman/mremap.c`, `src/linux/brk.c`,
`src/linux/sbrk.c`, and `src/linux/remap_file_pages.c`, respectively, under the
musl MIT license recorded in `COPYRIGHT`.

`mremap` retains musl's pre-syscall `PTRDIFF_MAX` rejection and its C variadic
contract: a fifth destination pointer is read only for `MREMAP_FIXED`; a
four-argument nonfixed call supplies a null fifth syscall word. Its public ELF
name is a weak same-address alias of hidden `__mremap`, matching musl's source
body and allowing an application to interpose only the public name. Linux 5.10
owns all mapping topology and error details, including `MREMAP_MAYMOVE` and
`MREMAP_DONTUNMAP`. `brk` and nonzero `sbrk` intentionally return musl's
`ENOMEM` result instead of changing the application break, while `sbrk(0)`
returns Linux's raw current-break value. `remap_file_pages` is a direct legacy
Linux syscall boundary and does not emulate a rejected request. The latter
three public names remain their source's strong default-visible entries.

The owned product reuses `pthread_vmlock` for every musl `__vm_wait` call that
can replace or retire a mapping: `mremap(MREMAP_FIXED)`, `mmap(MAP_FIXED)`, and
`munmap`. Its worker retirement path waits for `CLONE_CHILD_CLEARTID`, removes
the registry entry, and drains selected signal and cancellation leases before
private mappings are reclaimed. The vmlock protects selected process-shared
barrier and robust-mutex transitions that temporarily retain a caller-owned
public-object pointer. It does not synchronize application mappings, aliases,
or application access: callers still own those lifetimes and concurrent use.

Run `./scripts/dev-x86_64.sh owned-vm-mechanisms` for the focused matrix. The
runner compiles one installed-header workload object, then executes the same
object with pinned musl, owned static, static-PIE, dynamic PIE, and dynamic
non-PIE products; dynamic applications use both kernel and direct-interpreter
entry. It checks resize and fixed remaps, the shared zero-size remap alias,
content, preserved read protection, old-range retirement, local `ENOMEM`, and
raw legacy-remap errno translation. The `vm-mechanisms` dynamic qualification
case repeats the dynamic workload for both clean products and extraction.
It also compares the pinned-musl and owned static archive/final executable ELF
bindings: hidden `__mremap` and weak default `mremap` share one address, while
`brk`, `sbrk`, and `remap_file_pages` remain strong default entries. The shared
provider exports only the weak public alias, and both dynamic application modes
retain default-visible PLT imports for all four names.

This is private product evidence. It neither selects a general VM manager or
allocator policy nor completes the C ABI, memory, pthread, sysroot, or x86
support contracts.
