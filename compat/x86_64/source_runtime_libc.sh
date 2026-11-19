# Shared static crabc-libc builder for private native x86 C fixtures.
#
# Source this file, then call
#
#   build_source_runtime_libc OUTPUT [--retain-work PATH] [--features LIST] [--release]
#       [--relocation-model static|pic] [-- LIBC_RUSTC_ARGS...]
#
# PATH must be a new child of `.work/x86_64`. The helper builds there directly
# and leaves the graph in place after copying its archive and receipt.
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
    local work_name
    work_name="$(python3 -B "$root/compat/x86_64/native_arch.py" | sed -n "s/^work_name=//p")"
    local retained_work=""
    if [ "${1:-}" = "--retain-work" ]; then
        [ "$#" -ge 2 ] && [ -n "$2" ] || { printf 'build_source_runtime_libc: --retain-work requires a path\n' >&2; return 2; }
        retained_work="$2"
        shift 2
        case "$retained_work" in
            /*) ;;
            *) retained_work="$root/.work/$work_name/$retained_work" ;;
        esac
    fi
    local private archive
    mkdir -p "$root/.work/$work_name/tmp"
    if [ -n "$retained_work" ]; then
        if ! archive="$(python3 "$root/compat/x86_64/native_static_source_runtime_closure.py" build \
            --work "$retained_work" --print-archive "$@")"; then
            printf 'source-runtime libc build failed; evidence retained: %s\n' "$retained_work" >&2
            return 1
        fi
        mkdir -p "$(dirname "$output")"
        cp -- "$archive" "$output"
        cp -- "$retained_work/receipt.json" "$output.source-runtime.json"
        return 0
    fi
    private="$(mktemp -d "$root/.work/$work_name/tmp/source-runtime-libc.XXXXXX")"
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

source_runtime_expected_static_surface() {
    local contract="$1" output="$2" arch="$3"
    {
        grep -Ev '^(#|$)' "$contract" | awk -v arch="$arch" 'arch != "aarch64" || ($0 != "arch_prctl" && $0 != "ioperm" && $0 != "iopl")'
        if [ "$arch" = aarch64 ]; then
            printf '%s\n' __sigsetjmp_tail crabc_x86_float_parse_shlim
        fi
    } | LC_ALL=C sort -u >"$output"
}

# Exact source-runtime C export and binding inventories shared by math proofs.
collect_math_global_surface() {
	local archive_path="$1" output_path="$2" members_path="$3"
	local -a members
	mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
	[ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
	mkdir "$members_path"
	(
		cd "$members_path"
		ar x "$archive_path" "${members[@]}"
		nm -g --defined-only --format=posix "${members[@]}"
	) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
		sort -u >"$output_path"
}

collect_math_global_bindings() {
	local archive_path="$1" output_path="$2" members_path="$3"
	local -a members
	mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
	[ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
	mkdir "$members_path"
	(
		cd "$members_path"
		ar x "$archive_path" "${members[@]}"
		nm -g --defined-only --format=posix "${members[@]}"
	) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1, $2 }' |
		sort -u >"$output_path"
}


record_math_argv() {
	local path="$1"
	shift
	python3 -B - "$path" "$@" <<'PY'
import json
from pathlib import Path
import sys

Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]) + "\n", encoding="utf-8")
PY
}

run_math_recorded() {
	local stdout_path="$1" stderr_path="$2" status_path="$3" label="$4" status=0
	shift 4
	"$@" >"$stdout_path" 2>"$stderr_path" || status=$?
	printf '%s\n' "$status" >"$status_path"
	[ "$status" -eq 0 ] || fail "$label exited with ${status}"
}

