#!/usr/bin/env bash
# Native Linux/x86-64 selected-private filesystem.directory aggregate.
#
# This is an accounting aggregate, not a new general C ABI surface. It reruns
# the three independently closed components that collectively cover the frozen
# seven-symbol directory roster, then proves a combined feature archive adds
# only ftw/nftw over the established scandir composition. The default archive
# remains exactly frozen and the family stays planned/private.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly -a DIRECTORY_SYMBOLS=(alphasort ftw nftw readdir_r scandir telldir versionsort)
readonly -a TRAVERSAL_ADDITIONS=(ftw nftw)

fail() {
    printf 'ERROR: x86 libc filesystem.directory aggregate: %s\n' "$*" >&2
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
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm rustup sort uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done

# These component gates supply the ordinary musl differential, frozen CHDIR
# profile, header ABI, directory-stream, and allocation-client evidence.
bash "$ROOT_DIR/compat/x86_64/run_libc_directory_streams.sh"
bash "$ROOT_DIR/compat/x86_64/run_libc_scandir.sh"
bash "$ROOT_DIR/compat/x86_64/run_libc_filesystem_traversal.sh"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-filesystem-directory.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
default_target="$work_dir/default-target"
scandir_target="$work_dir/scandir-target"
combined_target="$work_dir/combined-target"
default_archive="$default_target/x86_64-unknown-linux-musl/debug/libc.a"
scandir_archive="$scandir_target/x86_64-unknown-linux-musl/debug/libc.a"
combined_archive="$combined_target/x86_64-unknown-linux-musl/debug/libc.a"
default_surface="$work_dir/default-surface"
scandir_surface="$work_dir/scandir-surface"
combined_surface="$work_dir/combined-surface"
expected_default="$work_dir/expected-default"
observed_additions="$work_dir/observed-additions"
expected_additions="$work_dir/expected-additions"
combined_symbols="$work_dir/combined-symbols"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$default_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$scandir_target" cargo rustc --locked -p crabc-libc --lib \
    --features x86-scandir --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$combined_target" cargo rustc --locked -p crabc-libc --lib \
    --features x86-scandir,x86-filesystem-traversal \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
for archive in "$default_archive" "$scandir_archive" "$combined_archive"; do
    [ -f "$archive" ] || fail "cargo did not emit one aggregate archive"
done

collect_global_surface "$default_archive" "$default_surface" "$work_dir/default-members"
collect_global_surface "$scandir_archive" "$scandir_surface" "$work_dir/scandir-members"
collect_global_surface "$combined_archive" "$combined_surface" "$work_dir/combined-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_default"
if ! cmp -s "$expected_default" "$default_surface"; then
    diff -u "$expected_default" "$default_surface" >&2 || true
    fail "default selected-static C ABI export surface drifted"
fi
comm -13 "$scandir_surface" "$combined_surface" >"$observed_additions"
printf '%s\n' "${TRAVERSAL_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "combined directory feature added more than ftw/nftw"
fi

nm -A --defined-only "$combined_archive" >"$combined_symbols"
for symbol in "${DIRECTORY_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$combined_symbols" ||
        fail "combined archive does not own frozen filesystem.directory symbol $symbol"
done
printf 'x86 selected-private filesystem.directory aggregate: PASS\n'
