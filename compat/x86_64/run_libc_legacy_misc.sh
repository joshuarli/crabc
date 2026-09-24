#!/usr/bin/env bash
# Native Linux/x86-64 frozen legacy.misc aggregate evidence.
#
# This dedicated opt-in archive adds only fmtmsg/encrypt/setkey to the frozen
# default selected-static export surface.  It composes the already verified
# processor/page and issetugid prerequisites, then proves the full eight-name
# aggregate's C/C++ declarations, source-owner definition checks, static link map and ELF
# closure.  Pinned musl 1.2.6 is the fmtmsg/header source oracle.  The DES
# behavior is deliberately different: the candidate retains the project-wide
# inert ABI contract rather than implementing a local cipher.
#
# This is not a full legacy runtime, cryptographic service, allocator, dynamic
# libc, CRT/sysroot product, public support claim, capability completion, or
# family promotion.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-legacy-misc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly STATIC_C_ABI_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs"
readonly LEGACY_MISC_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/legacy_misc.rs"
readonly LEGACY_DES_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/legacy_des_compat.rs"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly -a FEATURE_EXPORTS=(encrypt fmtmsg setkey)
readonly -a NARROW_EXPORTS=(encrypt setkey)
readonly -a COMPOSITE_EXPORTS=(fmtmsg)
readonly -a ALL_SYMBOLS=(
    fmtmsg encrypt setkey get_avphys_pages get_nprocs get_nprocs_conf
    get_phys_pages issetugid
)

fail() {
    printf 'ERROR: x86 static libc frozen legacy.misc: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
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

require_native_linux_x86_64
for tool in ar awk cargo chmod cmp comm diff env grep mapfile mkdir mktemp nm objdump \
    python3 readelf readlink rustup sed sort uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing frozen selected-static export contract"
[ -f "$STATIC_C_ABI_ROOT" ] || fail "missing selected static C ABI root"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_legacy_misc_header_abi.sh" >/dev/null
# These closed existing artifacts remain prerequisites; invoking them here
# prevents this aggregate from reclassifying their retained observations.
bash "$ROOT_DIR/compat/x86_64/run_libc_system_information.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_libc_issetugid.sh" >/dev/null

[ -f "$LEGACY_MISC_ROOT" ] || fail "missing target-local legacy.misc fmtmsg owner"
[ -f "$LEGACY_DES_ROOT" ] || fail "missing shared target-local inert DES owner"
grep -Fq '#[cfg(all(feature = "x86-legacy-misc", not(crabc_x86_owned_runtime)))]' "$STATIC_C_ABI_ROOT" ||
    fail "legacy.misc is not opt-in at the selected-static root"
grep -Fq 'mod legacy_misc;' "$STATIC_C_ABI_ROOT" ||
    fail "selected-static root does not compose the opt-in legacy.misc owner"
grep -Fq '#[cfg(feature = "x86-legacy-des-compat")]' \
    "$STATIC_C_ABI_ROOT" || fail "inert DES owner is not selected by its narrow feature"
grep -Fq 'mod legacy_des_compat;' "$STATIC_C_ABI_ROOT" ||
    fail "selected-static root does not compose the shared inert DES owner"
for phrase in \
    'src/misc/fmtmsg.c::fmtmsg' \
    'MSGVERB' \
    'retry-on-short-write'; do
    grep -Fq "$phrase" "$LEGACY_MISC_ROOT" ||
        fail "target-local legacy.misc fmtmsg provenance/contract omits $phrase"
done
for phrase in \
    'src/legacy/encrypt.c::setkey' \
    'src/legacy/encrypt.c::encrypt' \
    'x86-owned-static-runtime' \
    'x86-legacy-misc' \
    'inert-DES' \
    'does not alter errno' \
    'no-hand-rolled-cryptography'; do
    grep -Fq "$phrase" "$LEGACY_DES_ROOT" ||
        fail "shared inert DES provenance/contract omits $phrase"
done

work_tmpdir="$(checkout_local_tmpdir)"
work_dir="$(mktemp -d "$work_tmpdir/crabc-x86-64-libc-legacy-misc.XXXXXX")"
chmod g+rwx "$work_dir"
# Passing runs leave no disposable build state. A failure retains its full
# archive, final ELF, disassembly, and source/binding receipts for review.
cleanup_work_dir() {
    local status=$?

    trap - EXIT
    if [ "$status" -eq 0 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 static libc legacy.misc retained failure evidence: %s\n' "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup_work_dir EXIT
base_target="$work_dir/base-target"
narrow_target="$work_dir/narrow-target"
base_archive="$base_target/x86_64-unknown-linux-musl/debug/libc.a"
narrow_archive="$narrow_target/x86_64-unknown-linux-musl/debug/libc.a"
source_runtime_helper="$ROOT_DIR/compat/x86_64/native_static_source_runtime_closure.py"
source_runtime_work="${work_dir#"$ROOT_DIR/.work/x86_64/"}/source-runtime"
[ "$source_runtime_work" != "$work_dir/source-runtime" ] ||
    fail "source-runtime work directory escaped the checkout"
source_runtime_receipt="$work_dir/source-runtime/receipt.json"
reference="$work_dir/musl-legacy-misc-reference"
candidate="$work_dir/crabc-static-legacy-misc-candidate"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_fmtmsg="$work_dir/musl-fmtmsg.o"
musl_encrypt="$work_dir/musl-encrypt.o"
header_trace="$work_dir/header-trace"
base_surface="$work_dir/base-surface"
narrow_surface="$work_dir/narrow-surface"
feature_surface="$work_dir/feature-surface"
expected_surface="$work_dir/expected-surface"
expected_narrow_surface="$work_dir/expected-narrow-surface"
expected_feature_surface="$work_dir/expected-feature-surface"
observed_narrow_additions="$work_dir/observed-narrow-additions"
observed_additions="$work_dir/observed-additions"
expected_narrow_additions="$work_dir/expected-narrow-additions"
expected_additions="$work_dir/expected-additions"
base_bindings="$work_dir/base-bindings"
narrow_bindings="$work_dir/narrow-bindings"
feature_bindings="$work_dir/feature-bindings"
expected_narrow_bindings="$work_dir/expected-narrow-bindings"
expected_feature_bindings="$work_dir/expected-feature-bindings"
narrow_addition_bindings="$work_dir/narrow-addition-bindings"
feature_addition_bindings="$work_dir/feature-addition-bindings"
archive_symbols="$work_dir/archive-symbols"
encrypt_definition_dir="$work_dir/encrypt-definition"
setkey_definition_dir="$work_dir/setkey-definition"
encrypt_definition="$encrypt_definition_dir/encrypt-definition.o"
setkey_definition="$setkey_definition_dir/setkey-definition.o"
encrypt_definition_disassembly="$work_dir/encrypt-definition-disassembly"
setkey_definition_disassembly="$work_dir/setkey-definition-disassembly"
archive_relocations="$work_dir/archive-relocations"
link_map="$work_dir/candidate.map"
link_trace="$work_dir/candidate.trace"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
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
ar p "$musl_archive" fmtmsg.lo >"$musl_fmtmsg"
ar p "$musl_archive" encrypt.lo >"$musl_encrypt"
readelf --symbols --wide "$musl_fmtmsg" | grep -Eq '[[:space:]]fmtmsg$' ||
    fail "pinned musl fmtmsg.lo lacks fmtmsg"
for symbol in encrypt setkey; do
    readelf --symbols --wide "$musl_encrypt" | grep -Eq "[[:space:]]${symbol}$" ||
        fail "pinned musl encrypt.lo lacks ${symbol}"
done
grep -Eq '^fmtmsg[[:space:]]+fmtmsg\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost fmtmsg ownership"
for symbol in encrypt setkey; do
    grep -Eq "^${symbol}[[:space:]]+encrypt\\.lo[[:space:]]+T[[:space:]]+GLOBAL" \
        "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost ${symbol} ownership"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_legacy_misc_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h fmtmsg.h stdlib.h sys/sysinfo.h unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -D_XOPEN_SOURCE=700 -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_legacy_misc_probe.c -o "$reference"
env -i LC_ALL=C "$reference" || fail "pinned-musl legacy.misc fixture failed"

# The default, narrow inert-DES, and composite archives have exact C global
# symbol/binding maps. The narrow map is the frozen default plus encrypt and
# setkey; the composite map is that narrow map plus fmtmsg.
build_source_runtime_libc "$base_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$base_archive" ] || fail "cargo did not emit the unfeatured x86 archive"
collect_global_surface "$base_archive" "$base_surface" "$work_dir/base-members"
collect_global_bindings "$base_archive" "$base_bindings" "$work_dir/base-binding-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_surface"
if ! cmp -s "$expected_surface" "$base_surface"; then
    diff -u "$expected_surface" "$base_surface" >&2 || true
    fail "unfeatured selected-static C ABI export surface drifted"
fi
for symbol in "${FEATURE_EXPORTS[@]}"; do
    if grep -Fxq "$symbol" "$base_surface"; then
        fail "unfeatured archive unexpectedly exposes opt-in ${symbol}"
    fi
done

build_source_runtime_libc "$narrow_target/x86_64-unknown-linux-musl/debug/libc.a" \
    --features x86-legacy-des-compat
[ -f "$narrow_archive" ] || fail "cargo did not emit the narrow inert-DES archive"
collect_global_surface "$narrow_archive" "$narrow_surface" "$work_dir/narrow-members"
collect_global_bindings "$narrow_archive" "$narrow_bindings" "$work_dir/narrow-binding-members"
comm -13 "$base_surface" "$narrow_surface" >"$observed_narrow_additions"
printf '%s\n' "${NARROW_EXPORTS[@]}" | LC_ALL=C sort -u >"$expected_narrow_additions"
if ! cmp -s "$expected_narrow_additions" "$observed_narrow_additions"; then
    diff -u "$expected_narrow_additions" "$observed_narrow_additions" >&2 || true
    fail "narrow inert-DES changed more than encrypt/setkey"
fi
LC_ALL=C sort -u "$base_surface" "$expected_narrow_additions" >"$expected_narrow_surface"
if ! cmp -s "$expected_narrow_surface" "$narrow_surface"; then
    diff -u "$expected_narrow_surface" "$narrow_surface" >&2 || true
    fail "narrow inert-DES did not preserve the frozen export surface"
fi
printf '%s T\n' "${NARROW_EXPORTS[@]}" | LC_ALL=C sort -u >"$narrow_addition_bindings"
LC_ALL=C sort -u "$base_bindings" "$narrow_addition_bindings" >"$expected_narrow_bindings"
if ! cmp -s "$expected_narrow_bindings" "$narrow_bindings"; then
    diff -u "$expected_narrow_bindings" "$narrow_bindings" >&2 || true
    fail "narrow inert-DES changed the full global binding surface"
fi

archive="$(python3 "$source_runtime_helper" build \
    --work "$source_runtime_work" --features "$FEATURE" --print-archive)"
[ -f "$archive" ] || fail "cargo did not emit the opt-in x86 archive"
[ -f "$source_runtime_receipt" ] || fail "source-built libc lacks runtime closure receipt"
collect_global_surface "$archive" "$feature_surface" "$work_dir/feature-members"
collect_global_bindings "$archive" "$feature_bindings" "$work_dir/feature-binding-members"
comm -13 "$narrow_surface" "$feature_surface" >"$observed_additions"
printf '%s\n' "${COMPOSITE_EXPORTS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "composite legacy.misc changed more than fmtmsg beyond narrow inert-DES"
fi
LC_ALL=C sort -u "$narrow_surface" "$expected_additions" >"$expected_feature_surface"
if ! cmp -s "$expected_feature_surface" "$feature_surface"; then
    diff -u "$expected_feature_surface" "$feature_surface" >&2 || true
    fail "composite legacy.misc did not preserve the narrow export surface"
fi
printf '%s T\n' "${COMPOSITE_EXPORTS[@]}" | LC_ALL=C sort -u >"$feature_addition_bindings"
LC_ALL=C sort -u "$expected_narrow_bindings" "$feature_addition_bindings" >"$expected_feature_bindings"
if ! cmp -s "$expected_feature_bindings" "$feature_bindings"; then
    diff -u "$expected_feature_bindings" "$feature_bindings" >&2 || true
    fail "composite legacy.misc changed the full global binding surface"
fi

readelf --symbols --wide "$archive" >"$archive_symbols"
for symbol in "${ALL_SYMBOLS[@]}"; do
    awk -v symbol="$symbol" '
        $4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$archive_symbols" || fail "opt-in archive lacks global-default ${symbol}"
done
mapfile -t base_encrypt_members < <(archive_member_for_symbol "$base_archive" encrypt)
mapfile -t base_setkey_members < <(archive_member_for_symbol "$base_archive" setkey)
mapfile -t base_fmtmsg_members < <(archive_member_for_symbol "$base_archive" fmtmsg)
mapfile -t narrow_encrypt_members < <(archive_member_for_symbol "$narrow_archive" encrypt)
mapfile -t narrow_setkey_members < <(archive_member_for_symbol "$narrow_archive" setkey)
mapfile -t narrow_fmtmsg_members < <(archive_member_for_symbol "$narrow_archive" fmtmsg)
mapfile -t fmtmsg_members < <(archive_member_for_symbol "$archive" fmtmsg)
mapfile -t encrypt_members < <(archive_member_for_symbol "$archive" encrypt)
mapfile -t setkey_members < <(archive_member_for_symbol "$archive" setkey)
assert_provider_counts encrypt "${#base_encrypt_members[@]}" "${#narrow_encrypt_members[@]}" \
    "${#encrypt_members[@]}" 0 1 1
assert_provider_counts setkey "${#base_setkey_members[@]}" "${#narrow_setkey_members[@]}" \
    "${#setkey_members[@]}" 0 1 1
assert_provider_counts fmtmsg "${#base_fmtmsg_members[@]}" "${#narrow_fmtmsg_members[@]}" \
    "${#fmtmsg_members[@]}" 0 0 1
mkdir "$encrypt_definition_dir" "$setkey_definition_dir"
ar p "$archive" "${encrypt_members[0]}" >"$encrypt_definition"
ar p "$archive" "${setkey_members[0]}" >"$setkey_definition"
objdump -d --disassemble=encrypt "$encrypt_definition" >"$encrypt_definition_disassembly"
objdump -d --disassemble=setkey "$setkey_definition" >"$setkey_definition_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' \
    "$encrypt_definition_disassembly" "$setkey_definition_disassembly"; then
    fail "inert DES compatibility functions select a local cipher or runtime edge"
fi
readelf --relocs --wide "$archive" >"$archive_relocations"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "opt-in legacy.misc archive selects dynamic TLS or an unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_LEGACY_MISC_CANDIDATE \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections -Wl,-Map,"$link_map" \
    -Wl,--trace-symbol=rust_eh_personality \
    compat/x86_64/libc_legacy_misc_probe.c \
    compat/x86_64/libc_legacy_misc_start.S "$archive" -o "$candidate" \
    2>"$link_trace"
python3 "$source_runtime_helper" audit-final-link \
    --receipt "$source_runtime_receipt" --candidate "$candidate" \
    --link-map "$link_map" --trace "$link_trace" --label legacy-misc

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Fq "${fmtmsg_members[0]}" "$link_map" ||
    fail "candidate link map did not take the fmtmsg defining archive member"
grep -Fq "${encrypt_members[0]}" "$link_map" ||
    fail "candidate link map did not take the encrypt defining archive member"
grep -Fq "${setkey_members[0]}" "$link_map" ||
    fail "candidate link map did not take the setkey defining archive member"
if grep -Eq 'libc\.a\((fmtmsg|encrypt)\.lo\)' "$link_map"; then
    fail "candidate selected a pinned-musl fmtmsg or DES implementation"
fi
for symbol in _start __errno_location __crabc_x86_static_tls_bootstrap \
    __libc_start_main "${ALL_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks required legacy.misc closure symbol ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks selected initial TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|glibc|ld-linux|libc\.so\.6|crabc_core|mimalloc|sha_crypt)' \
    "$candidate_headers" "$candidate_dynamic" "$candidate_symbols" \
    "$candidate_disassembly" "$link_map"; then
    fail "candidate selects an ambient runtime or unowned dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"

env -i LC_ALL=C "$candidate" || fail "freestanding legacy.misc candidate failed"

printf 'x86 static crabc-libc frozen legacy.misc aggregate: PASS\n'
