#!/usr/bin/env bash
# Native Linux/x86-64 permanent-stream formatted-I/O evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly EXECUTION_TIMEOUT=20s

[ "$(uname -s)" = Linux ] || { echo "requires native Linux" >&2; exit 1; }
case "$(uname -m)" in x86_64|amd64) ;; *) echo "requires native x86-64" >&2; exit 1 ;; esac
[ -x "$ORACLE_CC" ] || { echo "missing pinned musl oracle compiler" >&2; exit 1; }
for tool in ar awk basename cargo cat cmp comm diff grep mkdir mktemp nm readelf sort timeout; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-stdio-permanent-format-scan.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
default_target_dir="$work_dir/default-cargo-target"
fixture=compat/x86_64/libc_stdio_permanent_format_scan_wave_probe.c
start=compat/x86_64/libc_stdio_permanent_format_scan_wave_start.S

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" \
    -fno-builtin -fno-stack-protector "$ROOT_DIR/$fixture" -o "$work_dir/reference"
timeout "$EXECUTION_TIMEOUT" "$work_dir/reference"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$default_target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-stdio-permanent-format-scan \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
default_archive="$default_target_dir/x86_64-unknown-linux-musl/debug/libc.a"
archive_symbols="$work_dir/archive-symbols"
default_archive_symbols="$work_dir/default-archive-symbols"
nm -A --defined-only "$archive" >"$archive_symbols" 2>/dev/null || true
nm -A --defined-only "$default_archive" >"$default_archive_symbols" 2>/dev/null || true

collect_c_abi_surface() {
    local input_archive="$1" output_path="$2"
    local member_dir="$work_dir/members-$(basename "$output_path")"
    local -a members
    mkdir "$member_dir"
    mapfile -t members < <(ar t "$input_archive" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || { echo "archive has no crabc-libc object members" >&2; exit 1; }
    (
        cd "$member_dir"
        ar x "$input_archive" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

collect_c_abi_surface "$archive" "$work_dir/feature-names"
collect_c_abi_surface "$default_archive" "$work_dir/default-names"
for symbol in printf vprintf fprintf vfprintf scanf vscanf fscanf vfscanf; do
    if grep -Fxq "$symbol" "$work_dir/default-names"; then
        echo "default archive unexpectedly exports $symbol" >&2
        exit 1
    fi
done
grep -Ev '^(#|$)' compat/x86_64/static_c_abi_exports.txt | LC_ALL=C sort -u >"$work_dir/expected-default-names"
if ! cmp -s "$work_dir/default-names" "$work_dir/expected-default-names"; then
    echo "default archive export surface drifted" >&2
    diff -u "$work_dir/expected-default-names" "$work_dir/default-names" >&2 || true
    exit 1
fi
comm -23 "$work_dir/feature-names" "$work_dir/default-names" >"$work_dir/feature-delta"
comm -13 "$work_dir/feature-names" "$work_dir/default-names" >"$work_dir/feature-removals"
cat >"$work_dir/expected-delta" <<'EOF'
fprintf
fscanf
printf
scanf
vfprintf
vfscanf
vprintf
vscanf
EOF
if ! cmp -s "$work_dir/feature-delta" "$work_dir/expected-delta" || [ -s "$work_dir/feature-removals" ]; then
    echo "opt-in archive symbol delta is not exactly the eight permanent formatted-I/O entries" >&2
    diff -u "$work_dir/expected-delta" "$work_dir/feature-delta" >&2 || true
    exit 1
fi
for symbol in printf vprintf fprintf vfprintf scanf vscanf fscanf vfscanf; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_STDIO_PERMANENT_FORMAT_SCAN_WAVE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$ROOT_DIR/$fixture" "$ROOT_DIR/$start" "$archive" -o "$work_dir/candidate"
readelf --symbols --wide "$work_dir/candidate" >"$work_dir/candidate-symbols"
if awk '$7 == "UND" && NF >= 8 { print }' "$work_dir/candidate-symbols" | grep -q .; then
    echo "candidate has unresolved symbols" >&2
    exit 1
fi
if readelf --dynamic --wide "$work_dir/candidate" | grep -Eq 'NEEDED|INTERP'; then
    echo "candidate unexpectedly selected dynamic runtime" >&2
    exit 1
fi
timeout "$EXECUTION_TIMEOUT" "$work_dir/candidate"
printf 'x86 static crabc-libc permanent formatted I/O: PASS\n'
