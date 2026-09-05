# Owned POSIX environment lifecycle

The installed native x86-64 products provide the selected
`process.environment-mutation` entries `setenv`, `unsetenv`, and `clearenv`
through the allocator-backed owner in
`libc/src/c_abi/x86_64/environment_runtime.rs`. `getenv`, `putenv`, and the
one-object `__environ`/`environ`/`_environ`/`___environ` aliases are the
necessary lookup, caller-storage, and public-global machinery for that
selected mutation contract. They do not extend the frozen capability to
`process.globals`.

The implementation is a source-preserving translation of pinned musl 1.2.6
release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT
license in `COPYRIGHT`. The source map is
`src/env/__environ.c`, `src/env/getenv.c`, `src/env/setenv.c`,
`src/env/putenv.c`, `src/env/unsetenv.c`, and `src/env/clearenv.c`. The mapping retains musl's one public pointer object with weak
aliases; first-match borrowed lookup; copied, tracked `setenv` strings;
caller-owned `putenv` strings; in-place replacement and duplicate removal in
a directly assigned vector; and `oldenv` allocation only for append. The
tracked-string registry is the source's `__env_rm_add` rule: a replacement or
removal frees only a successful `setenv` allocation. `clearenv` publishes a
null environment before walking the former vector to reclaim tracked strings.

`./scripts/dev-x86_64.sh owned-environment-lifecycle` compiles one
installed-header C object with the installed dynamic driver, links that exact
object to pinned musl and the installed static/static-PIE and dynamic
PIE/non-PIE products, and compares the oracle stream with each candidate
stream. Dynamic applications run in a disposable chroot through normal kernel
`PT_INTERP` resolution and direct
`/lib/ld-crabc-x86_64.so.1` entry. The runner accepts a supplied dynamic
product for the three-product qualification path. It checks strong static and
global-default shared providers, installed-header provenance, and the object
digest before running the matrix. Each static link requests its sealed receipt;
the common `compat/x86_64/owned_posix_product_evidence.py` validator binds the
static, static-PIE, PIE, and non-PIE output, receipt, one workload object, and
physical product. Its returned identities are retained with the raw
status/stdout/stderr transcripts. The runner also proves that a forged retained
identity is rejected by a fresh shared-validator result; receipt and product
tampering are covered by that validator's focused tests.

The runner accepts `[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`.
With no arguments it builds both disposable products. A positional dynamic
product preserves the existing dynamic-only replay and does not build or run a
static product. `--static-sysroot` selects a physical checkout `.work` static
product for the static/static-PIE pair. The supplied paths must be nonempty;
the static path cannot be parsed as an option. Each is canonicalized to a
physical target beneath the checkout `.work` tree before the shared validator
checks that target. If static is the only argument, the runner still builds its
disposable dynamic product for the installed-driver object and dynamic portion.
Giving both product paths reuses both sealed products and does not invoke either
producer. This is a bounded primary/reproduction/extracted-static replay seam,
not a family receipt or a claim that any family closure gate has passed.

The workload serializes every environment access. It checks copied replacement,
all-match removal, clear, no-overwrite, and the direct-vector/borrowed-value
boundaries. A disposable child installs a narrow seccomp filter that returns `ENOMEM` for
future `brk` and `mmap` growth before requesting a large replacement. This
makes allocation failure deterministic without adding a production failure
hook. Fork observes an inherited snapshot; exec
and `posix_spawn` publish the requested child environment and leave the
parent's published vector unchanged. The child uses only data valid through
the stated fork boundary, and the parent waits before later mutation.

This component does not make environment mutation async-signal-safe, repair a
lock in a fork child, make an unsynchronized direct `environ` write or
borrowed `getenv` pointer valid, or promise behavior for concurrent mutation.
It does not prove the separate multi-threaded environment/signal/FILE/syslog
`global-state-composition` workload, complete `libc.posix-runtime`, or promote
native x86-64 support.
