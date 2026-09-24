# Shared static crabc-libc builder for private native x86 C fixtures.
#
# Source this file, then call
#
#   build_source_runtime_libc OUTPUT [--features LIST] [--release]
#       [--relocation-model static|pic] [-- LIBC_RUSTC_ARGS...]
#
# A plain `cargo rustc -p crabc-libc` archive bundles the toolchain's prebuilt
# `core`, which is compiled for unwinding and references
# `rust_eh_personality`. The C runtime deliberately leaves that personality to
# Rust std, so a freestanding C link of such an archive fails. This builds the
# archive through `native_static_source_runtime_closure.py` instead: `core`,
# `alloc`, and `compiler_builtins` are source-built with immediate-abort
# panics, and the staticlib's runtime members are audited against them. Only
# the libc rustc invocation receives LIBC_RUSTC_ARGS; the panic, unwind-table,
# relocation, code-model, and TLS settings belong to the whole graph.
#
# OUTPUT receives the archive and OUTPUT.source-runtime.json its closure
# receipt. The private Cargo graph lives under the checkout's
# `.work/x86_64/tmp` and is removed on success; a failure retains it and names
# it on stderr.
_source_runtime_libc_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

build_source_runtime_libc() {
    local output="$1"
    shift
    local root="$_source_runtime_libc_root"
    local private archive
    mkdir -p "$root/.work/x86_64/tmp"
    private="$(mktemp -d "$root/.work/x86_64/tmp/source-runtime-libc.XXXXXX")"
    if ! archive="$(python3 "$root/compat/x86_64/native_static_source_runtime_closure.py" build \
        --work "tmp/${private##*/}/graph" --print-archive "$@")"; then
        printf 'source-runtime libc build failed; evidence retained: %s\n' "$private" >&2
        return 1
    fi
    mkdir -p "$(dirname "$output")"
    cp -- "$archive" "$output"
    cp -- "$private/graph/receipt.json" "$output.source-runtime.json"
    rm -rf -- "$private"
}
