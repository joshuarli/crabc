#!/usr/bin/env bash
# Native Linux/x86-64 musl signal.c legacy-alias evidence.
#
# The same GNU project-header C body runs through pinned musl 1.2.6 and a
# `-nostdlib -static` candidate. The feature archive may add exactly weak
# bsd_signal and __sysv_signal aliases to the frozen default surface, both at
# signal's address. This ABI-only leaf is not a general signal runtime,
# pthread policy, CRT, loader, sysroot, or public x86 support claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-signal-legacy-aliases
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly STATIC_C_ABI_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs"
readonly EXPECTED_ADDITIONS=(__sysv_signal bsd_signal)

fail() {
    printf 'ERROR: x86 static libc signal legacy aliases: %s\n' "$*" >&2
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

collect_global_bindings() {
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
        LC_ALL=C sort -u >"$output_path"
}

assert_signal_aliases() {
    local symbols_path="$1" label="$2"
    local signal_value alias_value alias

    signal_value="$(awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "signal" { print $2; exit }' "$symbols_path")"
    [ -n "$signal_value" ] || fail "$label lacks strong default signal"
    for alias in bsd_signal __sysv_signal; do
        alias_value="$(awk -v symbol="$alias" '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { print $2; exit }' "$symbols_path")"
        [ -n "$alias_value" ] || fail "$label lacks weak default $alias"
        [ "$alias_value" = "$signal_value" ] ||
            fail "$label does not retain same-address signal/$alias alias"
    done
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm objdump readelf rustup sort uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_ROOT" ] || fail "missing selected static C ABI root"
# The general Rust forwarding wrappers are outside this selected-static root;
# selecting this feature must continue to use only the musl-shaped .set
# aliases emitted with signal_control.rs.
if grep -Fq "system_utils_exports" "$STATIC_C_ABI_ROOT"; then
    fail "selected static C ABI root imports system-utils forwarding aliases"
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_signal_legacy_aliases_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-signal-legacy-aliases.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
base_target="$work_dir/base-target"
feature_target="$work_dir/feature-target"
base_archive="$base_target/x86_64-unknown-linux-musl/debug/libc.a"
archive="$feature_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-signal-legacy-aliases-reference"
candidate="$work_dir/crabc-static-signal-legacy-aliases-candidate"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_members="$work_dir/musl-members"
musl_symbols="$work_dir/musl-signal-symbols"
header_trace="$work_dir/header-trace"
base_surface="$work_dir/base-surface"
feature_surface="$work_dir/feature-surface"
expected_surface="$work_dir/expected-surface"
expected_feature_surface="$work_dir/expected-feature-surface"
observed_additions="$work_dir/observed-additions"
expected_additions="$work_dir/expected-additions"
base_bindings="$work_dir/base-bindings"
feature_bindings="$work_dir/feature-bindings"
feature_baseline_bindings="$work_dir/feature-baseline-bindings"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
mkdir "$musl_members"
(
    cd "$musl_members"
    ar x "$musl_archive" signal.lo
    readelf --symbols --wide signal.lo
) >"$musl_symbols"
assert_signal_aliases "$musl_symbols" "pinned-musl signal.lo"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_signal_legacy_aliases_probe.c >/dev/null 2>"$header_trace"
for header in errno.h signal.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -fno-builtin \
    -fno-stack-protector compat/x86_64/libc_signal_legacy_aliases_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl legacy signal-alias fixture failed"

# The default archive remains the frozen selected-static surface. The private
# feature can add only the two musl signal.c aliases, with no binding change to
# existing names.
CARGO_TARGET_DIR="$base_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$base_archive" ] || fail "cargo did not emit the unfeatured x86 archive"
collect_global_surface "$base_archive" "$base_surface" "$work_dir/base-members"
collect_global_bindings "$base_archive" "$base_bindings" "$work_dir/base-binding-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_surface"
if ! cmp -s "$expected_surface" "$base_surface"; then
    diff -u "$expected_surface" "$base_surface" >&2 || true
    fail "unfeatured selected-static C ABI export surface drifted"
fi
for alias in "${EXPECTED_ADDITIONS[@]}"; do
    if grep -Fxq "$alias" "$base_surface"; then
        fail "unfeatured archive unexpectedly exposes opt-in $alias"
    fi
done

CARGO_TARGET_DIR="$feature_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the opt-in x86 archive"
collect_global_surface "$archive" "$feature_surface" "$work_dir/feature-members"
collect_global_bindings "$archive" "$feature_bindings" "$work_dir/feature-binding-members"
comm -13 "$base_surface" "$feature_surface" >"$observed_additions"
printf '%s\n' "${EXPECTED_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "opt-in signal legacy aliases changed more than their exact public closure"
fi
LC_ALL=C sort -u "$base_surface" "$expected_additions" >"$expected_feature_surface"
if ! cmp -s "$expected_feature_surface" "$feature_surface"; then
    diff -u "$expected_feature_surface" "$feature_surface" >&2 || true
    fail "opt-in signal legacy aliases did not preserve the frozen export surface"
fi
awk 'NR == FNR { baseline[$1] = 1; next } $1 in baseline { print }' \
    "$base_bindings" "$feature_bindings" >"$feature_baseline_bindings"
if ! cmp -s "$base_bindings" "$feature_baseline_bindings"; then
    diff -u "$base_bindings" "$feature_baseline_bindings" >&2 || true
    fail "opt-in signal legacy aliases changed a frozen baseline export binding"
fi

readelf --symbols --wide "$archive" >"$archive_symbols"
# The static root does not import the general `system_utils_exports.rs`
# forwarding wrappers. These same-address checks therefore ratchet the actual
# signal.c alias graph rather than a second legacy implementation.
assert_signal_aliases "$archive_symbols" "opt-in crabc archive"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "opt-in archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_SIGNAL_LEGACY_ALIASES_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_signal_legacy_aliases_probe.c \
    compat/x86_64/libc_signal_legacy_aliases_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
assert_signal_aliases "$candidate_symbols" "freestanding candidate"
for symbol in _start __errno_location signal bsd_signal __sysv_signal \
    crabc_x86_64_signal_legacy_aliases_probe crabc_x86_64_signal_restorer; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks required signal-alias closure symbol $symbol"
done
for unselected in raise kill killpg tgkill pthread_kill pthread_sigmask \
    sigsuspend sigtimedwait sigwaitinfo sigwait sigqueue signalfd sigaltstack \
    malloc free calloc realloc crabc_core mimalloc sha_crypt; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate unexpectedly pulls $unselected"
    fi
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected errno initial TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an ambient runtime fallback"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"

"$candidate" || fail "freestanding legacy signal-alias candidate failed"
printf 'x86 static crabc-libc signal legacy aliases: PASS\n'
