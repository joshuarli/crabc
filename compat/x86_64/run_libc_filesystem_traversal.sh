#!/usr/bin/env bash
# Native Linux/x86-64 opt-in crabc-libc ftw/nftw evidence.
#
# The same project-header fixture runs the pinned-musl ordinary traversal
# reference, then an allocation-free -nostdlib crabc candidate. FTW_CHDIR is
# intentionally candidate-only frozen FTW_CHDIR profile evidence because musl
# 1.2.6 ignores that flag. This artifact owns no scandir, allocator, cancellation,
# general filesystem policy, libc.so, CRT, loader, sysroot, family completion,
# promotion, or public x86 support claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-filesystem-traversal
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s
readonly -a EXPECTED_ADDITIONS=(ftw nftw)

fail() {
    printf 'ERROR: x86 libc filesystem traversal: %s\n' "$*" >&2
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

archive_member_for_symbol() {
    local archive_path="$1" symbol="$2"
    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' | sort -u
}

assert_fixture_tls_capacity() {
    local filesz memsz alignment
    read -r filesz memsz alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( filesz == 0 )) || fail "fixture TLS cannot initialize nonzero PT_TLS data"
    (( memsz > 0 && memsz <= 4096 )) || fail "fixture TLS scratch is too small"
    (( alignment > 0 && alignment <= 64 && 64 % alignment == 0 )) ||
        fail "fixture TLS alignment is incompatible"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm objdump readelf rustup sort timeout uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_ftw_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-filesystem-traversal.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
base_target="$work_dir/base-target"
feature_target="$work_dir/feature-target"
base_archive="$base_target/x86_64-unknown-linux-musl/debug/libc.a"
archive="$feature_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-filesystem-traversal-reference"
candidate="$work_dir/crabc-static-filesystem-traversal-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
base_surface="$work_dir/base-surface"
feature_surface="$work_dir/feature-surface"
expected_surface="$work_dir/expected-surface"
expected_feature_surface="$work_dir/expected-feature-surface"
observed_additions="$work_dir/observed-additions"
expected_additions="$work_dir/expected-additions"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
traversal_object="$work_dir/traversal-owner.o"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

mkdir "$reference_work" "$candidate_work"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_filesystem_traversal_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h ftw.h stddef.h stdint.h sys/stat.h sys/syscall.h \
    sys/types.h unistd.h bits/alltypes.h bits/fcntl.h bits/stat.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_filesystem_traversal_probe.c \
    -o "$reference"
if (cd "$reference_work" && timeout "$EXECUTION_TIMEOUT" "$reference"); then
    :
else
    reference_status=$?
    fail "pinned-musl ordinary traversal reference exited $reference_status"
fi

CARGO_TARGET_DIR="$base_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$base_archive" ] || fail "cargo did not emit unfeatured x86 archive"
collect_global_surface "$base_archive" "$base_surface" "$work_dir/base-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_surface"
if ! cmp -s "$expected_surface" "$base_surface"; then
    diff -u "$expected_surface" "$base_surface" >&2 || true
    fail "unfeatured selected-static C ABI export surface drifted"
fi
for symbol in "${EXPECTED_ADDITIONS[@]}"; do
    if grep -Fxq "$symbol" "$base_surface"; then
        fail "unfeatured archive unexpectedly exposes opt-in $symbol"
    fi
done

CARGO_TARGET_DIR="$feature_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit opt-in x86 archive"
collect_global_surface "$archive" "$feature_surface" "$work_dir/feature-members"
comm -13 "$base_surface" "$feature_surface" >"$observed_additions"
printf '%s\n' "${EXPECTED_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "opt-in traversal changed more than its exact public closure"
fi
LC_ALL=C sort -u "$base_surface" "$expected_additions" >"$expected_feature_surface"
if ! cmp -s "$expected_feature_surface" "$feature_surface"; then
    diff -u "$expected_feature_surface" "$feature_surface" >&2 || true
    fail "opt-in traversal did not preserve frozen export surface"
fi

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
for symbol in ftw nftw; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "feature archive does not define $symbol"
    mapfile -t members < <(archive_member_for_symbol "$archive" "$symbol")
    [ "${#members[@]}" -eq 1 ] ||
        fail "$symbol must have exactly one archive member owner"
done
traversal_member="$(archive_member_for_symbol "$archive" nftw)"
if [ "$(archive_member_for_symbol "$archive" ftw)" != "$traversal_member" ]; then
    fail "ftw and nftw must remain colocated in one traversal owner"
fi
ar p "$archive" "$traversal_member" >"$traversal_object"
readelf --relocs --wide "$traversal_object" >"$archive_relocations"
objdump -dr "$traversal_object" >"$archive_disassembly"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|mimalloc|sha_crypt|scandir|malloc|calloc|realloc|free' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "feature archive selects dynamic TLS, an allocator, or scandir"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_TRAVERSAL_CANDIDATE \
    -DCRABC_TRAVERSAL_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static \
    -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector \
    -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections -Wl,-Map,"$link_map" \
    compat/x86_64/libc_filesystem_traversal_probe.c \
    compat/x86_64/libc_filesystem_traversal_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in _start __errno_location __crabc_x86_static_tls_bootstrap ftw nftw \
    opendir closedir chdir getcwd; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks crabc traversal dependency $symbol"
done
for unrelated in scandir malloc calloc realloc free pthread_setcancelstate \
    __tls_get_addr; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "candidate unexpectedly pulls $unrelated"
    fi
done
for musl_member in ftw.lo nftw.lo scandir.lo scandir64.lo opendir.lo \
    fdopendir.lo closedir.lo readdir.lo readdir64.lo readdir_r.lo malloc.lo \
    calloc.lo realloc.lo free.lo pthread_setcancelstate.lo; do
    if grep -Fq "libc.a($musl_member)" "$link_map"; then
        fail "candidate selected pinned-musl fallback object $musl_member"
    fi
done
grep -Fq "$archive($traversal_member)" "$link_map" ||
    fail "candidate did not select the traversal archive member"
if [ "$(grep -Fc "$archive($traversal_member)" "$link_map")" -lt 1 ]; then
    fail "selected archive member set drifted during extraction"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected errno initial TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|mimalloc|sha_crypt|scandir|malloc|calloc|realloc|free' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS, allocator, or ambient traversal fallback"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno is not direct initial TLS"
grep -Fq 'call __crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_filesystem_traversal_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_filesystem_traversal_start.S; then
    fail "fixture start must not install a private FS base"
fi

if (cd "$candidate_work" && timeout "$EXECUTION_TIMEOUT" "$candidate"); then
    :
else
    candidate_status=$?
    fail "crabc filesystem traversal candidate exited $candidate_status"
fi

printf 'x86 static crabc-libc filesystem traversal: PASS\n'
