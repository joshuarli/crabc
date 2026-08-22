# crabc-ldso

A `no_std` Rust dynamic linker (`ldso`) for crabc's focused Linux AArch64
musl-compatible runtime profile. It produces `libldso.so`, which can be used
as `--dynamic-linker` for selected unmodified musl-linked executables.

## Compatibility profile

The supported target is Linux AArch64 on Linux kernel versions 5.10 and
newer. This is a focused modern-runtime loader, not a general loader for
other architectures or a promise of complete historical musl or glibc
behavior.

## Usage

Build with:
```bash
cargo build -p crabc-ldso
```

Output is in `target/debug/libldso.so`.

Run a supported AArch64 musl-linked binary:
```bash
LD_LIBRARY_PATH=target/debug ./target/debug/loader my_binary
```

Or directly:
```bash
./my_binary  # if ldso is set as PT_INTERP
```

## Features

- Self-relocating `_start` entry point
- Loads `DT_NEEDED` dependencies
- Handles AArch64 TLS (Thread-Local Storage) with TLS_ABOVE_TP
- Processes the supported AArch64 ELF relocation types
- TLSDESC resolver for aarch64

Startup vectors are copied without fixed argv/envp/auxv limits, and failed
dependency closures roll back their DSO mappings.  In secure execution
(`AT_SECURE`), `LD_LIBRARY_PATH` and `LD_PRELOAD` are ignored and removed from
the environment handed to the program.  Bare
`DT_NEEDED` names are searched through configured and system library paths;
the current working directory is never an implicit search directory.

Runtime `dlopen`, `dlsym`, and `dlclose` operations use a recursive loader lock
and keep `dlerror()` state separate for each thread. Error storage is allocated
per thread; if that allocation fails, the defined result is no pending error
(`dlerror()` returns null) rather than another thread's message.

Consumers that reclaim a TLS block belonging to another thread should use
`__rc_tls_block_size_for(fs_base)` and `__rc_tls_base_offset_for(fs_base)`;
the parameterless compatibility helpers describe the calling thread/process
default only.

## License

MIT OR Apache-2.0
