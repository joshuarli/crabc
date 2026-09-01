#!/usr/bin/env bash
# Native Linux/x86-64 bounded SHA-crypt C ABI evidence.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 static libc crypt: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"
    nm -A --defined-only "$archive_path" | awk -v symbol="$symbol" '$NF == symbol { member = $1; sub(/^.*\.a:/, "", member); sub(/:.*$/, "", member); print member }' | sort -u
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo grep mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_crypt_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-crypt.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/pinned-musl-crypt-reference"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
candidate="$work_dir/crabc-crypt-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
combined_feature_log="$work_dir/combined-feature.log"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_crypt_probe.c >/dev/null 2>"$header_trace"
for header in crypt.h string.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" compat/x86_64/libc_crypt_probe.c -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" || fail "pinned-musl explicit-round crypt reference failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib --features x86-crypt --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the opt-in x86 libc archive"

readelf --symbols --wide "$archive" >"$archive_symbols"
mapfile -t crypt_members < <(archive_member_for_symbol "$archive" crypt)
mapfile -t crypt_exports < <(archive_member_for_symbol "$archive" crypt)
mapfile -t crypt_r_exports < <(archive_member_for_symbol "$archive" crypt_r)
[ "${#crypt_members[@]}" -eq 1 ] || fail "crypt must have exactly one crate object owner"
[ "${#crypt_exports[@]}" -eq 1 ] && [ "${#crypt_r_exports[@]}" -eq 1 ] || fail "crypt entries must each have exactly one crate object owner"
[ "${crypt_members[0]}" = "${crypt_exports[0]}" ] && [ "${crypt_members[0]}" = "${crypt_r_exports[0]}" ] || fail "crypt entries must share one object owner"

selected_member_dir="$work_dir/crypt-member"
mkdir "$selected_member_dir"
(cd "$selected_member_dir" && ar x "$archive" "${crypt_members[0]}")
selected_member="$selected_member_dir/${crypt_members[0]}"
mapfile -t owner_exports < <(nm -g --defined-only --format=posix "$selected_member" | awk '$2 ~ /^[TW]$/ && $1 !~ /^_R/ { print $1 }' | sort -u)
expected_owner_exports=(__crypt_blowfish __crypt_md5 __crypt_r __crypt_sha256 __crypt_sha512 crypt crypt_r)
if [ "${owner_exports[*]}" != "${expected_owner_exports[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_owner_exports[*]}" "${owner_exports[*]}" >&2
    fail "crypt object export surface drifted"
fi
if nm -g --defined-only --format=posix "$selected_member" | awk '$1 ~ /^__crabc_x86_crypt/ { found = 1 } END { exit(found ? 0 : 1) }'; then
    fail "crypt object retains a test-only export"
fi
awk '$4 == "FUNC" && $5 == "WEAK" && $8 == "crypt_r" { found = 1 } END { exit(found ? 0 : 1) }' "$archive_symbols" || fail "crypt_r lost its weak C ABI binding"
for symbol in crypt __crypt_r __crypt_sha256 __crypt_sha512 __crypt_md5 __crypt_blowfish; do
    awk -v symbol="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 } END { exit(found ? 0 : 1) }' "$archive_symbols" || fail "$symbol is not a strong global function"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_X86_CRYPT_CANDIDATE -DCRABC_CRYPT_TRACE -I"$ROOT_DIR/include" -static -fno-pie -no-pie -fno-builtin -fno-stack-protector -Wl,--allow-multiple-definition -Wl,-Map,"$link_map" compat/x86_64/libc_crypt_probe.c "$selected_member" "$musl_archive" "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in crypt crypt_r __crypt_r __crypt_sha256 __crypt_sha512 __crypt_md5 __crypt_blowfish; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || fail "candidate lacks $symbol"
done
if grep -Eq '[[:space:]]__crabc_x86_crypt' "$candidate_symbols"; then
    fail "candidate retains a test-only crypt export"
fi
for symbol in crypt __crypt_r __crypt_sha256 __crypt_sha512 __crypt_md5 __crypt_blowfish; do
    awk -v symbol="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $8 == symbol { found = 1 } END { exit(found ? 0 : 1) }' "$candidate_symbols" || fail "candidate lost the global-default $symbol binding"
done
awk '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $8 == "crypt_r" { found = 1 } END { exit(found ? 0 : 1) }' "$candidate_symbols" || fail "candidate lost the weak-default crypt_r binding"
grep -Fq "$selected_member" "$link_map" || fail "candidate did not link the selected crabc crypt object directly"
if grep -Eq 'libc\.a\((crypt|crypt_r|crypt_sha256|crypt_sha512|crypt_md5|crypt_blowfish|crypt_des)\.lo\)' "$link_map"; then
    fail "candidate selected a pinned-musl crypt implementation"
fi
# The selected object comes first, then pinned musl, and the full crabc archive
# comes last only for RustCrypto closure. These pinned-musl members therefore
# own the fixture's support calls and the allocator bridge before crabc's
# archive can satisfy either class of symbol.
for member in strcmp.lo strlen.lo write.lo lite_malloc.lo aligned_alloc.lo free.lo; do
    grep -Fq "libc.a($member)" "$link_map" || fail "candidate did not select pinned-musl $member"
done
if grep -Eqi 'mimalloc|mi_(malloc|free)|allocator_mimalloc' "$link_map"; then
    fail "candidate selected an allocator provider outside the pinned-musl boundary"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' "$candidate_headers" "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi

set +e
env -i LC_ALL=C TZ=UTC "$candidate"
candidate_status=$?
set -e
[ "$candidate_status" -eq 0 ] || fail "crabc SHA-crypt candidate failed with status $candidate_status"

if CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib --features x86-crypt,x86-allocator-runtime --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort >"$combined_feature_log" 2>&1; then
    fail "x86-crypt unexpectedly composes with x86-allocator-runtime"
fi
grep -Fq 'x86-crypt cannot compose with x86-allocator-runtime' "$combined_feature_log" || fail "combined crypt/allocator feature rejection drifted"

printf 'x86 static libc bounded SHA-crypt: PASS\n'
