#!/usr/bin/env bash
# Native Linux/x86-64 selected static stateful byte-string provider evidence.
#
# One project-header C fixture first runs through pinned musl 1.2.6, then
# through a true one-member -nostdlib static candidate. The member exports only
# dirname, strcasestr, and strtok_r and closes every musl helper locally.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "$BASH_SOURCE")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() { printf 'ERROR: x86 static libc stateful byte strings: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }
archive_member_for_symbol() { nm -A --defined-only "$1" | awk -v symbol="$2" '$NF == symbol { member = $1; sub(/^.*\.a:/, "", member); sub(/:.*$/, "", member); print member }' | sort -u; }

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3" members_path="$work_dir/selected-c-abi-members"
    local -a members
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' | sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then diff -u "$expected_path" "$symbols_path" >&2 || true; fail "selected static C ABI export surface drifted"; fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_stateful_byte_strings_header_abi.sh" >/dev/null
grep -Fqx $'dirname\tdirname.lo\tT\tGLOBAL\t0\t98' "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost dirname ownership"
grep -Fqx $'strcasestr\tstrcasestr.lo\tT\tGLOBAL\t0\t5c' "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost strcasestr ownership"
grep -Fqx $'strtok_r\tstrtok_r.lo\tT\tGLOBAL\t0\t80' "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost strtok_r ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stateful-byte-strings.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-stateful-byte-strings.a"
reference="$work_dir/musl-stateful-byte-strings-reference"
candidate="$work_dir/crabc-static-stateful-byte-strings"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/stateful-byte-strings-undefined"
object_relocations="$work_dir/stateful-byte-strings-relocations"
object_disassembly="$work_dir/stateful-byte-strings-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
link_map="$work_dir/candidate.map"

case "$musl_archive" in /*) ;; *) fail "pinned musl compiler did not report an absolute libc.a path" ;; esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
for source_member in dirname.lo strcasestr.lo strtok_r.lo; do
    ar p "$musl_archive" "$source_member" >"$work_dir/$source_member"
done
readelf --symbols --wide "$work_dir/dirname.lo" | grep -Eq '[[:space:]]dirname$' || fail "pinned musl dirname source member drifted"
readelf --symbols --wide "$work_dir/strcasestr.lo" | grep -Eq '[[:space:]]strcasestr$' || fail "pinned musl strcasestr source member drifted"
readelf --symbols --wide "$work_dir/strtok_r.lo" | grep -Eq '[[:space:]]strtok_r$' || fail "pinned musl strtok_r source member drifted"
nm --undefined-only --format=posix "$work_dir/dirname.lo" | awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$work_dir/dirname-undefined"
cmp -s <(printf '%s\n' strlen) "$work_dir/dirname-undefined" || fail "dirname musl helper boundary drifted"
nm --undefined-only --format=posix "$work_dir/strcasestr.lo" | awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$work_dir/strcasestr-undefined"
cmp -s <(printf '%s\n' strlen strncasecmp) "$work_dir/strcasestr-undefined" || fail "strcasestr musl helper boundary drifted"
nm --undefined-only --format=posix "$work_dir/strtok_r.lo" | awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$work_dir/strtok-r-undefined"
cmp -s <(printf '%s\n' strcspn strspn) "$work_dir/strtok-r-undefined" || fail "strtok_r musl helper boundary drifted"

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" -E -H "$ROOT_DIR/compat/x86_64/libc_stateful_byte_strings_probe.c" >/dev/null 2>"$header_trace"
for header in libgen.h string.h features.h bits/alltypes.h errno.h; do grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture did not use project <$header>"; done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/libc_stateful_byte_strings_probe.c" -o "$reference"
"$reference" || fail "pinned-musl stateful byte-string fixture failed"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in dirname strcasestr strtok_r; do grep -Eq "[[:space:]][TW][[:space:]]$symbol$" "$archive_symbols" || fail "archive does not define $symbol"; done
owner="$(archive_member_for_symbol "$archive" dirname)"
[ -n "$owner" ] && [ "$(printf '%s\n' "$owner" | wc -l)" -eq 1 ] || fail "dirname must have exactly one crate object owner"
for symbol in strcasestr strtok_r; do [ "$(archive_member_for_symbol "$archive" "$symbol")" = "$owner" ] || fail "$symbol must share dirname's one-object owner"; done
mkdir "$work_dir/owner"
( cd "$work_dir/owner"; ar x "$archive" "$owner"; ar crs "$selected_archive" "$owner" )
object="$work_dir/owner/$owner"
exports="$(nm -g --defined-only --format=posix "$object" | awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u)"
[ "$exports" = "$(printf '%s\n' dirname strcasestr strtok_r)" ] || fail "stateful byte-string object export surface drifted"
if nm -S --defined-only --format=posix "$object" | awk '$2 ~ /^[BD]$/ { print }' | grep -q .; then fail "object unexpectedly retains mutable static storage"; fi
nm --undefined-only --format=posix "$object" | awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
[ ! -s "$object_undefined" ] || { cat "$object_undefined" >&2; fail "object unexpectedly depends on another symbol"; }
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$object_disassembly"; then fail "object unexpectedly performs a call or syscall"; fi

"$ORACLE_CC" -std=c11 -DCRABC_STATEFUL_BYTE_STRINGS_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,-Map,"$link_map" "$ROOT_DIR/compat/x86_64/libc_stateful_byte_strings_probe.c" "$ROOT_DIR/compat/x86_64/libc_stateful_byte_strings_start.S" "$selected_archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in dirname strcasestr strtok_r; do awk -v symbol="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 } END { exit(found ? 0 : 1) }' "$candidate_symbols" || fail "candidate lacks global $symbol"; done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then fail "candidate retains an unresolved symbol"; fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$candidate_headers" "$candidate_dynamic"; then fail "candidate selects a dynamic dependency"; fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers"; then fail "candidate unexpectedly selects TLS"; fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' "$object_relocations" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then fail "candidate unexpectedly retains errno or TLS"; fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then fail "candidate retains a PLT"; fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' "$link_map" "$candidate_headers" "$candidate_dynamic"; then fail "candidate selected an ambient libc runtime"; fi
for unselected in basename __xpg_basename strtok strsep strcasecmp strncasecmp strlen strspn strcspn malloc calloc realloc free memcpy memmove memset; do if grep -Eq "[[:space:]]$unselected$" "$candidate_symbols"; then fail "candidate accidentally selects $unselected"; fi; done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then fail "candidate selects an unowned runtime dependency"; fi
"$candidate" || fail "freestanding stateful byte-string fixture failed"
printf 'x86 static libc stateful byte strings: PASS\n'
