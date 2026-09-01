#!/usr/bin/env bash
# Native Linux/x86-64 frozen legacy.misc aggregate evidence.
#
# This dedicated opt-in archive adds only fmtmsg/encrypt/setkey to the frozen
# default selected-static export surface.  It composes the already verified
# processor/page and issetugid prerequisites, then proves the full eight-name
# aggregate's C/C++ declarations, archive ownership, static link map and ELF
# closure.  Pinned musl 1.2.6 is the fmtmsg/header source oracle.  The DES
# behavior is deliberately different: the candidate retains the project-wide
# inert ABI contract rather than implementing a local cipher.
#
# This is not a full legacy runtime, cryptographic service, allocator, dynamic
# libc, CRT/sysroot product, public support claim, capability completion, or
# family promotion.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-legacy-misc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly STATIC_C_ABI_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs"
readonly LEGACY_MISC_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/legacy_misc.rs"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly -a FEATURE_EXPORTS=(encrypt fmtmsg setkey)
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
    nm -A --defined-only "$archive_path" | awk -v symbol="$symbol" '
        $NF == symbol {
            member = $1
            sub(/^.*\.a:/, "", member)
            sub(/:.*$/, "", member)
            print member
        }
    ' | LC_ALL=C sort -u
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff env grep mapfile mkdir mktemp nm objdump \
    readelf rustup sed sort uname; do
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

[ -f "$LEGACY_MISC_ROOT" ] || fail "missing target-local legacy.misc owner"
grep -Fq '#[cfg(feature = "x86-legacy-misc")]' "$STATIC_C_ABI_ROOT" ||
    fail "legacy.misc is not opt-in at the selected-static root"
grep -Fq 'mod legacy_misc;' "$STATIC_C_ABI_ROOT" ||
    fail "selected-static root does not compose the opt-in legacy.misc owner"
for phrase in \
    'src/legacy/fmtmsg.c::fmtmsg' \
    'src/legacy/encrypt.c::setkey' \
    'src/legacy/encrypt.c::encrypt' \
    'inert' \
    'DES' \
    'intentional divergence'; do
    grep -Fq "$phrase" "$LEGACY_MISC_ROOT" ||
        fail "target-local legacy.misc provenance/contract omits $phrase"
done

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-legacy-misc.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
base_target="$work_dir/base-target"
feature_target="$work_dir/feature-target"
base_archive="$base_target/x86_64-unknown-linux-musl/debug/libc.a"
archive="$feature_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-legacy-misc-reference"
candidate="$work_dir/crabc-static-legacy-misc-candidate"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_fmtmsg="$work_dir/musl-fmtmsg.o"
musl_encrypt="$work_dir/musl-encrypt.o"
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
owner_member_names="$work_dir/owner-member-names"
owner_dir="$work_dir/owner"
owner_symbols="$work_dir/owner-symbols"
owner_setkey_disassembly="$work_dir/owner-setkey-disassembly"
owner_encrypt_disassembly="$work_dir/owner-encrypt-disassembly"
archive_relocations="$work_dir/archive-relocations"
link_map="$work_dir/candidate.map"
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

# The unfeatured archive must remain precisely the frozen selected-static
# surface.  The feature archive may add exactly this module's three public
# spellings, with no mutation to an existing binding.
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
for symbol in "${FEATURE_EXPORTS[@]}"; do
    if grep -Fxq "$symbol" "$base_surface"; then
        fail "unfeatured archive unexpectedly exposes opt-in ${symbol}"
    fi
done

CARGO_TARGET_DIR="$feature_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the opt-in x86 archive"
collect_global_surface "$archive" "$feature_surface" "$work_dir/feature-members"
collect_global_bindings "$archive" "$feature_bindings" "$work_dir/feature-binding-members"
comm -13 "$base_surface" "$feature_surface" >"$observed_additions"
printf '%s\n' "${FEATURE_EXPORTS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "opt-in legacy.misc changed more than its exact public closure"
fi
LC_ALL=C sort -u "$base_surface" "$expected_additions" >"$expected_feature_surface"
if ! cmp -s "$expected_feature_surface" "$feature_surface"; then
    diff -u "$expected_feature_surface" "$feature_surface" >&2 || true
    fail "opt-in legacy.misc did not preserve the frozen export surface"
fi
awk 'NR == FNR { baseline[$1] = 1; next } $1 in baseline { print }' \
    "$base_bindings" "$feature_bindings" >"$feature_baseline_bindings"
if ! cmp -s "$base_bindings" "$feature_baseline_bindings"; then
    diff -u "$base_bindings" "$feature_baseline_bindings" >&2 || true
    fail "opt-in legacy.misc changed a frozen baseline export binding"
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
mapfile -t fmtmsg_members < <(archive_member_for_symbol "$archive" fmtmsg)
mapfile -t encrypt_members < <(archive_member_for_symbol "$archive" encrypt)
mapfile -t setkey_members < <(archive_member_for_symbol "$archive" setkey)
[ "${#fmtmsg_members[@]}" -eq 1 ] || fail "fmtmsg must have one target-local archive owner"
[ "${#encrypt_members[@]}" -eq 1 ] || fail "encrypt must have one target-local archive owner"
[ "${#setkey_members[@]}" -eq 1 ] || fail "setkey must have one target-local archive owner"
[ "${fmtmsg_members[0]}" = "${encrypt_members[0]}" ] &&
    [ "${fmtmsg_members[0]}" = "${setkey_members[0]}" ] ||
    fail "legacy.misc additions must share their one target-local archive owner"
printf '%s\n' "${fmtmsg_members[0]}" >"$owner_member_names"
mkdir "$owner_dir"
(
    cd "$owner_dir"
    ar x "$archive" "${fmtmsg_members[0]}"
)
owner_member="$owner_dir/${fmtmsg_members[0]}"
nm -g --defined-only --format=posix "$owner_member" >"$owner_symbols"
mapfile -t owner_exports < <(
    awk '$2 ~ /^[TW]$/ && $1 !~ /^_R/ { print $1 }' "$owner_symbols" | LC_ALL=C sort -u
)
if [ "${owner_exports[*]}" != "encrypt fmtmsg setkey" ]; then
    printf 'expected: %s\nactual:   %s\n' 'encrypt fmtmsg setkey' \
        "${owner_exports[*]}" >&2
    fail "legacy.misc owner export surface drifted"
fi
objdump -d --disassemble=setkey "$owner_member" >"$owner_setkey_disassembly"
objdump -d --disassemble=encrypt "$owner_member" >"$owner_encrypt_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' \
    "$owner_setkey_disassembly" "$owner_encrypt_disassembly"; then
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
    compat/x86_64/libc_legacy_misc_probe.c \
    compat/x86_64/libc_legacy_misc_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Fq "${fmtmsg_members[0]}" "$link_map" ||
    fail "candidate link map did not take the target-local legacy.misc owner"
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
