# Native x86 `tgkill` C ABI extension

`libc/src/c_abi/x86_64/thread_signal.rs` preserves the frozen crabc GNU/BSD C
spelling `int tgkill(int, int, int)` on native Linux/x86-64.  It is an explicit
crabc extension, not a musl public `tgkill` ABI: pinned musl 1.2.6 has no
public symbol with that name.  The frozen source origin is
`3e100d45c5a0798c2d3862d5e2eef584c610ccf9:libc/src/c_abi.rs::tgkill`, whose
paired frozen `include/signal.h` declaration uses the same GNU/BSD signature.

The native provider forwards all three caller-selected `int` words to Linux
x86-64 `SYS_tgkill=234`, then uses the selected C ABI `c_status` translator.
It does not replace `tgid` with the caller's process id, and it is distinct
from the Rust facade's same-process `signal::kill_thread` boundary.  A call has
no pointer lifetime or initialization arguments. Callers must retain the
lifetime and authority for an operation they request; ordinary invalid ids,
nonmember tasks, invalid signals, and permission failures are Linux-defined
`-1`/`errno` results rather than Rust-side preconditions.

`include/signal.h` declares the extension only in its native x86 GNU/BSD
section. The retained AArch64 branch is unchanged. `thread_signal.rs` is a
normal direct native static C ABI leaf, alongside `signal_execution.rs`; it
does not claim pthread coordination, signal disposition management, target
lifecycle, musl API equivalence, a loader contract, or public x86 support.

The header proof also compiles two C++17 witnesses through the installed
`signal.h`. With `_GNU_SOURCE`, the address has the exact three-`int` C
function type and the retained object refers to unmangled `tgkill`. A truly
strict C++17 compile explicitly undefines `_GNU_SOURCE`, `_BSD_SOURCE`,
`_DEFAULT_SOURCE`, and `_ALL_SOURCE`; taking that address must fail with
`undeclared identifier 'tgkill'`. This distinguishes the ordinary GNU request
from Clang's ambient GNU feature macro without adding a tgkill-specific
`__STRICT_ANSI__` exception.

## Focused evidence

The native dispatcher forwards one validated installed static product and
one validated installed dynamic product to `run_native_thread_signal_abi.sh`:

```sh
./scripts/dev-x86_64.sh native-thread-signal-abi \
  --static-sysroot .work/x86_64/native-thread-signal-products/static/products/primary \
  .work/x86_64/native-thread-signal-products/dynamic
```

The dispatcher selects the pinned native Docker image and checkout-local
`TMPDIR`; the retained command logs identify the exact image,
source commit, source files, installed products, headers, objects, link
commands, raw ELF tables, and process transcripts.

The runner compiles **one installed-header object** from
`native_thread_signal_abi_probe.c`. It reuses that exact object for all links:

- pinned musl static and shared links add only
  `native_thread_signal_oracle_adapter.c`, whose `syscall(SYS_tgkill, ...)`
  supplies the frozen crabc spelling solely to observe Linux errno behavior;
- candidate static ET_EXEC and static-PIE links use the installed static
  product; and
- candidate dynamic PIE and non-PIE links run through both kernel and direct
  loader entry using the installed dynamic product.

The workload targets a fixture-owned child process, so its parent can prove a
caller-selected child `tgid`, valid self and child signal-zero requests,
contained `SIGUSR1` delivery, `ESRCH` for a missing task id, and `EINVAL` for
signal 65 and nonpositive group/task ids. Every successful tgkill call begins
with stale `ERANGE` and must leave it untouched. The child blocks `SIGUSR1`
before readiness, proves the parent's later request is pending, then unblocks
and restores its inherited mask before checking the handler. It never signals
an unrelated process. Candidate transcripts must match the adapter-backed
pinned-musl/Linux observation.

`native_thread_signal_abi_symbols.py` independently replays the retained
`readelf` tables. It requires one `FUNC GLOBAL DEFAULT` candidate definition in
the static archive, shared `.dynsym`, and full shared `.symtab`; it separately
requires that musl's archive and shared tables retain no public `tgkill`
definition. Each candidate row must retain the exact unversioned raw spelling
`tgkill`, a null ELF version, and false version-defaultness; a versioned spelling
such as `tgkill@@CRABC_1` is a different ABI identity and fails replay. The
runner also retains the candidate disassembly and requires the
`SYS_TGKILL=234` immediate plus `syscall` instruction.

This is private component evidence. It does not complete
`process.thread-kill`, a C signal family, ABI differential, qualification,
promotion, or public support. The default static export roster includes
`tgkill`, while the supplied owned-static archive also selects runtime feature
providers. The runner checks that every default provider remains present,
requires exactly one strong `tgkill` definition, and records the raw feature
surplus separately. Complete profile-specific archive selection and the
canonical static-surface ratchet remain independent requirements. The
isolated real-archive regression in `tests/test_native_thread_signal_abi_roster.py`
keeps this comparison valid after the provider enters the default roster.
