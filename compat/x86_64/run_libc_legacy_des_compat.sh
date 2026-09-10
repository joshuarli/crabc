#!/usr/bin/env bash
# Native Linux/x86-64 direct proof for the narrow inert-DES compatibility ABI.
#
# This checks the exact archive feature delta and one freestanding candidate.
# The two link spellings are intentionally inert: this is not a DES oracle,
# cipher implementation, cryptographic service, aggregate legacy runtime, or
# public x86 support claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly FEATURE=x86-legacy-des-compat
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly STATIC_C_ABI_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/legacy_des_compat.rs"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_legacy_des_compat_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_legacy_des_compat_start.S"
readonly -a FEATURE_EXPORTS=(encrypt setkey)

fail() {
    printf 'ERROR: x86 static libc inert-DES compatibility: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

checkout_local_tmpdir() {
    local physical_work_dir physical_tmpdir

    [ -n "${TMPDIR:-}" ] || fail "requires a checkout-local TMPDIR"
    physical_work_dir="$(readlink -f "$ROOT_DIR/.work")" \
        || fail "checkout .work directory must exist"
    [ "$physical_work_dir" = "$ROOT_DIR/.work" ] \
        || fail "checkout .work directory must be physical"
    physical_tmpdir="$(readlink -f "$TMPDIR")" \
        || fail "TMPDIR must be a physical checkout .work directory"
    [ "$physical_tmpdir" = "$TMPDIR" ] \
        || fail "TMPDIR must be a physical checkout .work directory"
    case "$physical_tmpdir" in
        "$physical_work_dir"/*) ;;
        *) fail "TMPDIR must be a physical checkout .work directory" ;;
    esac
    printf '%s\n' "$physical_tmpdir"
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

archive_member_for_symbol() {
    local archive_path="$1" symbol="$2"
    nm -A -g --defined-only "$archive_path" | awk -v symbol="$symbol" '
        $NF == symbol {
            member = $1
            sub(/^.*\.a:/, "", member)
            sub(/:.*$/, "", member)
            print member
        }
    ' | LC_ALL=C sort -u
}

assert_provider_counts() {
    local symbol="$1" default_count="$2" narrow_count="$3" composite_count="$4"
    local expected_default="$5" expected_narrow="$6" expected_composite="$7"

    if [ "$default_count" -ne "$expected_default" ] ||
        [ "$narrow_count" -ne "$expected_narrow" ] ||
        [ "$composite_count" -ne "$expected_composite" ]; then
        fail "${symbol} providers default/narrow/composite were ${default_count}/${narrow_count}/${composite_count}; expected ${expected_default}/${expected_narrow}/${expected_composite}"
    fi
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
for tool in ar awk cargo chmod cmp comm diff env grep mapfile mkdir mktemp nm objdump readelf readlink rustup sort uname; do
    require_tool "$tool"
done
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing frozen selected-static export contract"
[ -f "$STATIC_C_ABI_ROOT" ] || fail "missing selected-static C ABI root"
[ -f "$SOURCE" ] || fail "missing inert-DES target-local owner"
[ -f "$PROBE" ] && [ -f "$START" ] || fail "missing freestanding proof source"
grep -Fq 'x86-legacy-des-compat' "$ROOT_DIR/libc/Cargo.toml" ||
    fail "manifest does not define narrow inert-DES feature"
grep -Fq '#[cfg(feature = "x86-legacy-des-compat")]' "$STATIC_C_ABI_ROOT" ||
    fail "inert-DES owner is not directly feature-gated"
grep -Fq 'mod legacy_des_compat;' "$STATIC_C_ABI_ROOT" ||
    fail "selected-static root does not compose inert-DES owner"
for phrase in 'src/legacy/encrypt.c::setkey' 'src/legacy/encrypt.c::encrypt' \
    'inert-DES' 'does not alter errno' 'no-hand-rolled-cryptography'; do
    grep -Fq "$phrase" "$SOURCE" || fail "inert-DES source contract omits $phrase"
done

work_tmpdir="$(checkout_local_tmpdir)"
work_dir="$(mktemp -d "$work_tmpdir/crabc-x86-64-libc-legacy-des-compat.XXXXXX")"
chmod g+rwx "$work_dir"
# Passing runs leave no disposable build state. A failure retains its full
# archive, final ELF, disassembly, and source/binding receipts for review.
cleanup_work_dir() {
    local status=$?

    trap - EXIT
    if [ "$status" -eq 0 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 static libc inert-DES retained failure evidence: %s\n' "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup_work_dir EXIT
baseline_target="$work_dir/cargo-baseline"
feature_target="$work_dir/cargo-feature"
both_target="$work_dir/cargo-both"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
feature_archive="$feature_target/x86_64-unknown-linux-musl/debug/libc.a"
both_archive="$both_target/x86_64-unknown-linux-musl/debug/libc.a"
baseline_surface="$work_dir/baseline-surface"
feature_surface="$work_dir/feature-surface"
both_surface="$work_dir/both-surface"
baseline_bindings="$work_dir/baseline-bindings"
feature_bindings="$work_dir/feature-bindings"
both_bindings="$work_dir/both-bindings"
expected_surface="$work_dir/expected-surface"
expected_feature_bindings="$work_dir/expected-feature-bindings"
expected_both_bindings="$work_dir/expected-both-bindings"
feature_additions="$work_dir/feature-additions"
both_additions="$work_dir/both-additions"
feature_addition_bindings="$work_dir/feature-addition-bindings"
both_addition_bindings="$work_dir/both-addition-bindings"
archive_symbols="$work_dir/archive-symbols"
encrypt_definition_dir="$work_dir/encrypt-definition"
setkey_definition_dir="$work_dir/setkey-definition"
encrypt_definition="$encrypt_definition_dir/encrypt-definition.o"
setkey_definition="$setkey_definition_dir/setkey-definition.o"
encrypt_definition_disassembly="$work_dir/encrypt-definition-disassembly"
setkey_definition_disassembly="$work_dir/setkey-definition-disassembly"
candidate="$work_dir/crabc-static-legacy-des-compat"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$feature_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$both_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE x86-legacy-misc" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
for archive in "$baseline_archive" "$feature_archive" "$both_archive"; do
    [ -f "$archive" ] || fail "cargo did not emit expected static archive"
done
collect_global_surface "$baseline_archive" "$baseline_surface" "$work_dir/baseline-members"
collect_global_surface "$feature_archive" "$feature_surface" "$work_dir/feature-members"
collect_global_surface "$both_archive" "$both_surface" "$work_dir/both-members"
collect_global_bindings "$baseline_archive" "$baseline_bindings" "$work_dir/baseline-binding-members"
collect_global_bindings "$feature_archive" "$feature_bindings" "$work_dir/feature-binding-members"
collect_global_bindings "$both_archive" "$both_bindings" "$work_dir/both-binding-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_surface"
if ! cmp -s "$expected_surface" "$baseline_surface"; then
    diff -u "$expected_surface" "$baseline_surface" >&2 || true
    fail "default archive selected-static C ABI export surface drifted"
fi
for symbol in "${FEATURE_EXPORTS[@]}" fmtmsg; do
    if grep -Fxq "$symbol" "$baseline_surface"; then
        fail "default archive unexpectedly exposes opt-in $symbol"
    fi
done
comm -13 "$baseline_surface" "$feature_surface" >"$feature_additions"
printf '%s T\n' "${FEATURE_EXPORTS[@]}" | LC_ALL=C sort -u >"$feature_addition_bindings"
if ! cmp -s <(printf '%s\n' "${FEATURE_EXPORTS[@]}" | LC_ALL=C sort) "$feature_additions"; then
    diff -u <(printf '%s\n' "${FEATURE_EXPORTS[@]}" | LC_ALL=C sort) "$feature_additions" >&2 || true
    fail "narrow feature widened the archive beyond encrypt/setkey"
fi
LC_ALL=C sort -u "$baseline_bindings" "$feature_addition_bindings" >"$expected_feature_bindings"
if ! cmp -s "$expected_feature_bindings" "$feature_bindings"; then
    diff -u "$expected_feature_bindings" "$feature_bindings" >&2 || true
    fail "narrow feature changed the full global binding surface"
fi
comm -23 "$baseline_surface" "$feature_surface" | grep -q . &&
    fail "narrow feature removes a frozen default export"
comm -13 "$feature_surface" "$both_surface" >"$both_additions"
printf 'fmtmsg T\n' >"$both_addition_bindings"
if ! cmp -s <(printf 'fmtmsg\n') "$both_additions"; then
    diff -u <(printf 'fmtmsg\n') "$both_additions" >&2 || true
    fail "both-feature closure must add only fmtmsg beyond inert-DES"
fi
LC_ALL=C sort -u "$baseline_bindings" "$feature_addition_bindings" "$both_addition_bindings" >"$expected_both_bindings"
if ! cmp -s "$expected_both_bindings" "$both_bindings"; then
    diff -u "$expected_both_bindings" "$both_bindings" >&2 || true
    fail "both-feature closure changed the full global binding surface"
fi

readelf --symbols --wide "$feature_archive" >"$archive_symbols"
for symbol in "${FEATURE_EXPORTS[@]}"; do
    grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]].*[[:space:]]${symbol}$" "$archive_symbols" ||
        fail "narrow archive lacks global default $symbol"
done
mapfile -t baseline_encrypt_members < <(archive_member_for_symbol "$baseline_archive" encrypt)
mapfile -t baseline_setkey_members < <(archive_member_for_symbol "$baseline_archive" setkey)
mapfile -t baseline_fmtmsg_members < <(archive_member_for_symbol "$baseline_archive" fmtmsg)
mapfile -t encrypt_members < <(archive_member_for_symbol "$feature_archive" encrypt)
mapfile -t setkey_members < <(archive_member_for_symbol "$feature_archive" setkey)
mapfile -t narrow_fmtmsg_members < <(archive_member_for_symbol "$feature_archive" fmtmsg)
mapfile -t both_encrypt_members < <(archive_member_for_symbol "$both_archive" encrypt)
mapfile -t both_setkey_members < <(archive_member_for_symbol "$both_archive" setkey)
mapfile -t both_fmtmsg_members < <(archive_member_for_symbol "$both_archive" fmtmsg)
assert_provider_counts encrypt "${#baseline_encrypt_members[@]}" "${#encrypt_members[@]}" \
    "${#both_encrypt_members[@]}" 0 1 1
assert_provider_counts setkey "${#baseline_setkey_members[@]}" "${#setkey_members[@]}" \
    "${#both_setkey_members[@]}" 0 1 1
assert_provider_counts fmtmsg "${#baseline_fmtmsg_members[@]}" "${#narrow_fmtmsg_members[@]}" \
    "${#both_fmtmsg_members[@]}" 0 0 1
mkdir "$encrypt_definition_dir" "$setkey_definition_dir"
ar p "$feature_archive" "${encrypt_members[0]}" >"$encrypt_definition"
ar p "$feature_archive" "${setkey_members[0]}" >"$setkey_definition"
objdump -d --disassemble=encrypt "$encrypt_definition" >"$encrypt_definition_disassembly"
objdump -d --disassemble=setkey "$setkey_definition" >"$setkey_definition_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' \
    "$encrypt_definition_disassembly" "$setkey_definition_disassembly"; then
    fail "inert DES compatibility functions select a local cipher or runtime edge"
fi

/usr/local/bin/crabc-x86_64-musl-gcc -std=c11 -D_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_LEGACY_DES_COMPAT_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-Map,"$link_map" "$PROBE" "$START" "$feature_archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Fq "${encrypt_members[0]}" "$link_map" ||
    fail "candidate link map did not take the encrypt defining archive member"
grep -Fq "${setkey_members[0]}" "$link_map" ||
    fail "candidate link map did not take the setkey defining archive member"
for symbol in _start __errno_location __crabc_x86_static_tls_bootstrap \
    crabc_x86_legacy_des_compat_probe "${FEATURE_EXPORTS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks required inert-DES closure symbol $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks direct initial TLS for errno"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned runtime"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|glibc|ld-linux|libc\.so\.6|crabc_core|mimalloc|sha_crypt)' \
    "$candidate_headers" "$candidate_dynamic" "$candidate_symbols" "$candidate_disassembly" "$link_map"; then
    fail "candidate selects an ambient runtime or cipher dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"
env -i LC_ALL=C "$candidate" || fail "freestanding inert-DES candidate failed"

printf 'x86 static crabc-libc inert-DES compatibility: PASS\n'
