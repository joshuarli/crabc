#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc spawn-attribute signal fields.
#
# This runs one project-header fixture through pinned musl and a candidate made
# from exactly the five emitted provider sections. It proves only direct record
# field validation/copying and a closed ET_EXEC link; it does not select spawn,
# file actions, or signal delivery.
set -euo pipefail
export LC_ALL=C
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/posix_spawnattr_signal_fields.rs"
readonly -a SYMBOLS=(posix_spawnattr_setflags posix_spawnattr_setsigmask posix_spawnattr_getsigmask posix_spawnattr_setsigdefault posix_spawnattr_getsigdefault)
fail() { printf 'ERROR: x86 static libc posix_spawnattr signal fields: %s\n' "$*" >&2; exit 1; }
require_native_linux_x86_64() { [ "$(uname -s)" = Linux ] || fail "requires native Linux"; case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }
archive_member_for_symbol() { nm -A --defined-only "$1" | awk -v symbol="$2" '$NF == symbol { member=$1; sub(/^.*\.a:/, "", member); sub(/:.*$/, "", member); print member }' | sort -u; }
assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3" members_path="$work_dir/selected-c-abi-members"; local -a members
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$'); [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"; mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; nm -g --defined-only --format=posix "${members[@]}" ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' | sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    cmp -s "$expected_path" "$symbols_path" || { diff -u "$expected_path" "$symbols_path" >&2 || true; fail "selected static C ABI export surface drifted"; }
}
require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objcopy objdump readelf rustup sed sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"; [ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"; [ -f "$SOURCE" ] || fail "missing signal-field provider"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_posix_spawnattr_signal_fields_header_abi.sh" >/dev/null
for row in $'posix_spawnattr_setflags\tposix_spawnattr_setflags.lo\tT\tGLOBAL\t0\t20' $'posix_spawnattr_setsigmask\tposix_spawnattr_setsigmask.lo\tT\tGLOBAL\t0\t38' $'posix_spawnattr_getsigmask\tposix_spawnattr_getsigmask.lo\tT\tGLOBAL\t0\t38' $'posix_spawnattr_setsigdefault\tposix_spawnattr_setsigdefault.lo\tT\tGLOBAL\t0\t38' $'posix_spawnattr_getsigdefault\tposix_spawnattr_getsigdefault.lo\tT\tGLOBAL\t0\t38'; do grep -Fqx "$row" "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost $row"; done
for marker in 'posix_spawnattr_setflags.c::posix_spawnattr_setflags' 'posix_spawnattr_setsigmask.c::posix_spawnattr_setsigmask' 'posix_spawnattr_getsigmask.c::posix_spawnattr_getsigmask' 'posix_spawnattr_setsigdefault.c::posix_spawnattr_setsigdefault' 'posix_spawnattr_getsigdefault.c::posix_spawnattr_getsigdefault' 'EINVAL: c_int = 22'; do grep -Fq "$marker" "$SOURCE" || fail "source lacks $marker"; done
if grep -Eq 'raw_syscall::|errno::|static_tls::|crabc_core|crabc_mimalloc|fork\(|execve' "$SOURCE"; then fail "provider widened beyond record fields"; fi
work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-spawnattr-signal-fields.XXXXXX)"; trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"; selected_archive="$work_dir/libcrabc-posix-spawnattr-signal-fields.a"; reference="$work_dir/musl-reference"; candidate="$work_dir/crabc-static-candidate"; archive_symbols="$work_dir/archive-symbols"; selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"; candidate_symbols="$work_dir/candidate-symbols"; candidate_headers="$work_dir/candidate-program-headers"; candidate_sections="$work_dir/candidate-sections"; candidate_dynamic="$work_dir/candidate-dynamic"; candidate_relocations="$work_dir/candidate-relocations"; candidate_disassembly="$work_dir/candidate-disassembly"; link_map="$work_dir/candidate.map"; header_trace="$work_dir/header-trace"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_posix_spawnattr_signal_fields_probe.c >/dev/null 2>"$header_trace"
for header in spawn.h features.h bits/alltypes.h errno.h; do grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture did not use project $header"; done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" compat/x86_64/libc_posix_spawnattr_signal_fields_probe.c -o "$reference"; "$reference" || fail "pinned-musl signal-field fixture failed"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"; nm -A --defined-only "$archive" >"$archive_symbols"; assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
declare -a owners=()
for symbol in "${SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" || fail "archive does not define $symbol"
    mapfile -t member < <(archive_member_for_symbol "$archive" "$symbol"); [ "${#member[@]}" -eq 1 ] || fail "$symbol must have exactly one crate object owner"; owners+=("${member[0]}")
done
[ "$(printf '%s\n' "${owners[@]}" | sort -u | wc -l)" -eq 1 ] || fail "five signal-field exports must share one bounded provider object"
mkdir "$work_dir/owner"; ( cd "$work_dir/owner"; ar x "$archive" "${owners[0]}"; for symbol in "${SYMBOLS[@]}"; do objcopy --only-section=".text.${symbol}" --keep-symbol="$symbol" "${owners[0]}" "${symbol}.o"; ar rcs "$selected_archive" "${symbol}.o"; done )
for symbol in "${SYMBOLS[@]}"; do
    object="$work_dir/owner/${symbol}.o"; mapfile -t exports < <(nm -g --defined-only --format=posix "$object" | awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u); [ "${exports[*]}" = "$symbol" ] || fail "$symbol object export surface drifted"
    if nm --undefined-only --format=posix "$object" | awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | grep -q .; then fail "$symbol object unexpectedly depends on another symbol"; fi
    objdump -d "$object" >"$work_dir/${symbol}-disassembly"; if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$work_dir/${symbol}-disassembly"; then fail "$symbol object unexpectedly performs a call or syscall"; fi
done
"$ORACLE_CC" -std=c11 -DCRABC_POSIX_SPAWNATTR_SIGNAL_FIELDS_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections -Wl,-Map,"$link_map" compat/x86_64/libc_posix_spawnattr_signal_fields_probe.c compat/x86_64/libc_posix_spawnattr_signal_fields_start.S "$selected_archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"; readelf --program-headers --wide "$candidate" >"$candidate_headers"; readelf --sections --wide "$candidate" >"$candidate_sections"; readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true; readelf --relocs --wide "$candidate" >"$candidate_relocations"; objdump -d "$candidate" >"$candidate_disassembly"
for symbol in "${SYMBOLS[@]}"; do awk -v symbol="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 } END { exit(found ? 0 : 1) }' "$candidate_symbols" || fail "candidate lacks global $symbol"; done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then fail "candidate retains an unresolved symbol"; fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$candidate_headers" "$candidate_dynamic"; then fail "candidate selects a dynamic dependency"; fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' "$candidate_headers" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then fail "candidate unexpectedly retains errno or TLS"; fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections" || grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' "$link_map" "$candidate_headers" "$candidate_dynamic"; then fail "candidate selected an ambient runtime"; fi
for unselected in posix_spawn posix_spawnp posix_spawnattr_destroy posix_spawnattr_init posix_spawnattr_getflags posix_spawnattr_setpgroup posix_spawnattr_getpgroup posix_spawnattr_setschedparam posix_spawnattr_getschedparam posix_spawnattr_setschedpolicy posix_spawnattr_getschedpolicy posix_spawn_file_actions_init posix_spawn_file_actions_destroy posix_spawn_file_actions_addopen posix_spawn_file_actions_addclose posix_spawn_file_actions_adddup2 fork vfork clone execve wait4; do if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then fail "candidate accidentally selects $unselected"; fi; done
if grep -Eq 'crabc_core|mimalloc|sha_crypt|memset|memcpy|memmove|bzero' "$candidate_symbols" "$candidate_disassembly"; then fail "candidate selects an unowned allocator, runtime, or memory utility"; fi
"$candidate" || fail "freestanding signal-field fixture failed"
printf 'x86 static libc posix_spawnattr signal fields: PASS\n'
