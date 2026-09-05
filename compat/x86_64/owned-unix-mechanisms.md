# Owned Linux/filesystem/terminal mechanisms

The installed native x86 owned products provide C
`get_current_dir_name`, `mount`, `umount`, `umount2`, `tcdrain`, `vhangup`,
`vmsplice`, and `isastream` through
`libc/src/c_abi/x86_64/owned_unix_mechanisms.rs`. This is a source-preserving
port of pinned musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under the musl MIT license
recorded in `COPYRIGHT`.

| Pinned musl source | Installed C entries |
| --- | --- |
| `src/misc/get_current_dir_name.c` | `get_current_dir_name` |
| `src/linux/mount.c` | `mount`, `umount`, `umount2` |
| `src/termios/tcdrain.c` | `tcdrain` |
| `src/linux/vhangup.c` | `vhangup` |
| `src/linux/vmsplice.c` | `vmsplice` |
| `src/legacy/isastream.c` | `isastream` |

`get_current_dir_name` retains musl's `PWD` device/inode validation and its
`PATH_MAX` stack-buffer fallback before `strdup`; a valid logical `PWD` remains
allocator-owned after return, while physical fallback preserves the selected
`getcwd` error source. `mount`, `umount`, `umount2`, `vhangup`, and `vmsplice`
are direct Linux 5.10 syscall translations. `tcdrain` alone retains musl's
`syscall_cp(SYS_ioctl, fd, TCSBRK, 1)` cancellation-point boundary. Linux has
no STREAMS subsystem, so `isastream` follows musl's `F_GETFD` validation:
a valid descriptor returns zero without changing `errno`; an invalid
descriptor returns `-1` with `EBADF`.

Run `./scripts/dev-x86_64.sh owned-unix-mechanisms` for the focused
same-object matrix. It compiles one installed-header workload object, links it
with pinned musl and owned static/static-PIE products, then runs owned dynamic
PIE and non-PIE programs by both kernel and direct interpreter entry. Archive,
final executable, and shared-provider symbol tables must contain one strong
global/default definition of each entry. The workload checks logical and
physical current-directory spelling, terminal drain and deferred cancellation,
pipe transfers in both directions, and STREAMS results. The public unsafe
`vmsplice` boundary documents writable read-side buffers, retained source
pages, and permanent gift-page restrictions from the Linux
[`vmsplice(2)` contract](https://man7.org/linux/man-pages/man2/vmsplice.2.html).

No privileged request reaches the host: the workload forks a child which first
installs a local seccomp filter returning `EPERM` for `mount`, `umount2`, and
`vhangup`, then compares raw and installed error translation. The runner opens
a private pseudo-terminal before `chroot` and passes it only as an inherited
descriptor for the terminal cases. Its supplied dynamic product and all
evidence paths must be physical paths under checkout `.work`.

This is private product evidence. It does not select mount namespace policy,
filesystem ownership, STREAMS emulation, terminal/session management, a
general Unix runtime, POSIX-family completion, or public x86 support.
