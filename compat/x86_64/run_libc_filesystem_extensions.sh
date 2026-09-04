#!/usr/bin/env bash
# Native Linux/x86-64 selected-private filesystem.extensions aggregate.
#
# This is one capability-selection gate, not a new generic C filesystem
# runtime. It composes the independently evidenced default mktemp leaf,
# opt-in GNU file handles, and allocator-backed legacy temporary names. The
# frozen default archive remains unchanged. The combined archive establishes
# only the exact five frozen C spellings; it does not make their pathname or
# file-handle semantics safe, reserve a temporary pathname, or promote the
# still-planned libc.posix-runtime family.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly -a FILESYSTEM_EXTENSIONS_SYMBOLS=(
    mktemp
    name_to_handle_at
    open_by_handle_at
    tempnam
    tmpnam
)
readonly -a FILE_HANDLE_ADDITIONS=(name_to_handle_at open_by_handle_at)

fail() {
    printf 'ERROR: x86 libc filesystem.extensions aggregate: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

collect_global_surface() {
    local archive_path="$1" output_path="$2" members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ &&
        $1 != "crabc_x86_64_signal_restorer" &&
        $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm rustup sort uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done

# Each component supplies its own project-header, pinned-musl, archive, and
# runtime boundary. The aggregate adds only exact cross-feature composition.
bash "$ROOT_DIR/compat/x86_64/run_libc_mktemp.sh"
bash "$ROOT_DIR/compat/x86_64/run_libc_file_handles.sh"
bash "$ROOT_DIR/compat/x86_64/run_libc_temporary_names.sh"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-filesystem-extensions.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
default_target="$work_dir/default-target"
temporary_names_target="$work_dir/temporary-names-target"
combined_target="$work_dir/combined-target"
default_archive="$default_target/x86_64-unknown-linux-musl/debug/libc.a"
temporary_names_archive="$temporary_names_target/x86_64-unknown-linux-musl/debug/libc.a"
combined_archive="$combined_target/x86_64-unknown-linux-musl/debug/libc.a"
default_surface="$work_dir/default-surface"
temporary_names_surface="$work_dir/temporary-names-surface"
combined_surface="$work_dir/combined-surface"
expected_default="$work_dir/expected-default"
observed_additions="$work_dir/observed-additions"
expected_additions="$work_dir/expected-additions"
combined_symbols="$work_dir/combined-symbols"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$default_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$temporary_names_target" cargo rustc --locked -p crabc-libc --lib \
    --features x86-temporary-names --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$combined_target" cargo rustc --locked -p crabc-libc --lib \
    --features x86-temporary-names,x86-file-handles \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
for archive in "$default_archive" "$temporary_names_archive" "$combined_archive"; do
    [ -f "$archive" ] || fail "cargo did not emit one aggregate archive"
done

collect_global_surface "$default_archive" "$default_surface" "$work_dir/default-members"
collect_global_surface "$temporary_names_archive" "$temporary_names_surface" \
    "$work_dir/temporary-names-members"
collect_global_surface "$combined_archive" "$combined_surface" "$work_dir/combined-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_default"
if ! cmp -s "$expected_default" "$default_surface"; then
    diff -u "$expected_default" "$default_surface" >&2 || true
    fail "default selected-static C ABI export surface drifted"
fi

# The temporary-name feature deliberately carries its allocator/strdup
# closure. Once it is selected, composing file handles may add only its two
# frozen authority spellings—no hidden C ABI surface.
comm -13 "$temporary_names_surface" "$combined_surface" >"$observed_additions"
printf '%s\n' "${FILE_HANDLE_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "combined filesystem.extensions archive added more than file handles"
fi

nm -A --defined-only "$combined_archive" >"$combined_symbols"
for symbol in "${FILESYSTEM_EXTENSIONS_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$combined_symbols" ||
        fail "combined archive does not own frozen filesystem.extensions symbol $symbol"
done

printf 'x86 selected-private filesystem.extensions aggregate: PASS\n'
