#!/usr/bin/env bash
# Native Linux/x86-64 private allocator-basic real-runtime evidence.
#
# This runner moves no public support or family state by itself.  It proves the
# nine basic allocation entries through the existing real crabc CRT, startup,
# Initial TLS, pthread, bounded joined-worker fork/atfork, and ordinary-exit
# composition.  `malloc_usable_size` is present only to observe live basic
# allocations; its strong owner and selected-private capability remain the
# separate allocator-observability slice.
#
# The bundled mimalloc v3.3.2 backend retains an exact eleven-object pinned
# musl support tail. That tail is deliberately non-product: deterministic backend allocation failure remains intentionally unproved.
# This does not
# claim full allocator lifecycle, allocator-family completion, a static
# sysroot, product closure, promotion, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIBC=/opt/musl-1.2.6/lib/libc.a
readonly EXIT_MARKER=ALLOCATOR_BASIC_RUNTIME_V1_ATEXIT

fail() {
    printf 'ERROR: x86 libc allocator-basic-runtime-v1: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" 2>/dev/null |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        sort -u
}

assert_elf_function_binding() {
    local symbols_path="$1"
    local symbol="$2"
    local binding="$3"
    local owner="$4"

    awk -v symbol="$symbol" -v binding="$binding" '
        $4 == "FUNC" && $5 == binding && $6 == "DEFAULT" && $NF == symbol {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$symbols_path" \
        || fail "$owner must export ${symbol} as ${binding}/DEFAULT/FUNC"
}

assert_crabc_backend_support_owner() {
    local archive_path="$1"
    local map_path="$2"
    local symbol="$3"
    local -a owners

    mapfile -t owners < <(archive_member_for_symbol "$archive_path" "$symbol")
    [ "${#owners[@]}" -eq 1 ] \
        || fail "crabc archive must have exactly one ${symbol} owner"

    case "$symbol" in
        fputs)
            grep -F "$archive_path(" "$map_path" |
                grep -F "(.text.fputs)" >/dev/null \
                || fail "candidate does not link fputs from crabc archive"
            ;;
        sleep)
            grep -F "$archive_path(" "$map_path" |
                grep -F "(.text.sleep)" >/dev/null \
                || fail "candidate does not link sleep from crabc archive"
            ;;
        __stack_chk_fail)
            awk -v archive="${archive_path}(" '
                $NF == "__stack_chk_fail" && index(previous, archive) { found = 1 }
                { previous = $0 }
                END { exit(found ? 0 : 1) }
            ' "$map_path" \
                || fail "candidate does not link __stack_chk_fail from crabc archive"
            ;;
        *)
            fail "unsupported crabc backend-support ownership symbol: ${symbol}"
            ;;
    esac
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp cp grep nm objcopy objdump readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$MUSL_LIBC" ] || fail "missing pinned musl static libc"

if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_rustc="$(rustup which rustc)"
    toolchain_root="$(dirname "$(dirname "$toolchain_rustc")")"
    link_editor="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    [ -x "$link_editor" ] || fail "requires the pinned Rust x86-64 linker"
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-allocator-basic-runtime-v1.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
crt_dir="$work_dir/crt"
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/release/libc.a"
reference="$work_dir/pinned-musl-allocator-basic-runtime-v1-reference"
candidate="$work_dir/crabc-allocator-basic-runtime-v1-candidate"
probe_object="$work_dir/probe.o"
header_trace="$work_dir/header-trace"
reference_stdout="$work_dir/reference.stdout"
candidate_stdout="$work_dir/candidate.stdout"
expected_stdout="$work_dir/expected.stdout"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
actual_musl_members="$work_dir/actual-musl-members"
expected_musl_members="$work_dir/expected-musl-members"
backend_musl_libc="$work_dir/pinned-musl-backend-support.a"
musl_patch_dir="$work_dir/musl-program-name-bridge"
patched_musl_symbols="$work_dir/patched-musl-libc-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_allocator_basic_runtime_v1_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h malloc.h pthread.h stdint.h stdlib.h sys/wait.h features.h signal.h \
    unistd.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use project $header"
done
[ "$(grep -Ec '^[[:space:]]*size_t[[:space:]]+malloc_usable_size\(void \*\);' \
    "$ROOT_DIR/include/malloc.h")" = 1 ] \
    || fail "malloc.h must declare exactly one malloc_usable_size entry"
grep -Fq 'include!("allocator_observability_mimalloc.rs");' \
    "$ROOT_DIR/libc/src/c_abi.rs" \
    || fail "AArch64 runtime no longer includes the shared observability leaf"
grep -Fq 'include!("../../allocator_mimalloc.rs");' \
    "$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs" \
    || fail "x86 runtime no longer includes the shared basic allocator wrapper"
grep -Fq 'include!("../../allocator_observability_mimalloc.rs");' \
    "$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs" \
    || fail "x86 runtime no longer includes the shared observability leaf"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_allocator_basic_runtime_v1_probe.c -o "$reference"
printf '%s\n' "$EXIT_MARKER" >"$expected_stdout"
env -i LC_ALL=C TZ=UTC "$reference" >"$reference_stdout" \
    || fail "pinned-musl allocator-basic-runtime-v1 reference failed"
cmp -s "$expected_stdout" "$reference_stdout" \
    || fail "pinned-musl ordinary-exit allocator marker drifted"

mkdir "$crt_dir"
for object in crt1 crti crtn; do
    rustup run nightly-2026-07-24 rustc --edition=2021 --crate-type=lib --emit=obj \
        --target x86_64-unknown-linux-musl -C panic=abort \
        -C force-unwind-tables=no -C debuginfo=0 -C opt-level=2 \
        -C overflow-checks=off -C debug-assertions=off \
        -C relocation-model=static -C code-model=small -C link-dead-code=no \
        --remap-path-prefix "$ROOT_DIR=/crabc" \
        --crate-name "crabc_x86_64_${object}" \
        "crt/src/x86_64_${object}.rs" -o "$crt_dir/${object}.o"
done

CARGO_TARGET_DIR="$cargo_target" cargo rustc --release --locked \
    -p crabc-libc --lib --features x86-allocator-observability \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort -C lto=off \
    -C codegen-units=256
[ -f "$archive" ] || fail "cargo did not emit the feature-built x86 libc archive"

mapfile -t observability_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_allocator_observability_v1
)
mapfile -t usable_members < <(
    archive_member_for_symbol "$archive" malloc_usable_size
)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t backend_members < <(ar t "$archive" | grep -- '-static\.o$')
[ "${#observability_members[@]}" -eq 1 ] \
    || fail "observability witness must have exactly one crate object owner"
[ "${#usable_members[@]}" -eq 1 ] \
    || fail "malloc_usable_size must have exactly one crate object owner"
[ "${observability_members[0]}" = "${usable_members[0]}" ] \
    || fail "observability witness and malloc_usable_size have different owners"
[ "${#allocator_members[@]}" -eq 1 ] \
    || fail "allocator wrapper must have exactly one crate object owner"
[ "${observability_members[0]}" != "${allocator_members[0]}" ] \
    || fail "strong observability and weak allocation entries share one object"
[ "${#backend_members[@]}" -eq 1 ] \
    || fail "allocator backend must have exactly one bundled static object"

mkdir "$work_dir/owners"
(
    cd "$work_dir/owners"
    ar x "$archive" "${allocator_members[0]}" "${observability_members[0]}" \
        "${backend_members[0]}"
)
mapfile -t wrapper_exports < <(
    nm -g --defined-only --format=posix \
        "$work_dir/owners/${allocator_members[0]}" |
        awk '$2 ~ /^[TW]$/ && $1 !~ /^_R/ { print $1 }' | sort -u
)
expected_wrapper_symbols=(
    __crabc_x86_allocator_runtime_v1
    aligned_alloc
    calloc
    free
    malloc
    memalign
    posix_memalign
    realloc
    reallocarray
    valloc
)
if [ "${wrapper_exports[*]}" != "${expected_wrapper_symbols[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_wrapper_symbols[*]}" \
        "${wrapper_exports[*]}" >&2
    fail "allocator wrapper export surface drifted"
fi
wrapper_elf_symbols="$work_dir/wrapper-symbols"
readelf --symbols --wide "$work_dir/owners/${allocator_members[0]}" \
    >"$wrapper_elf_symbols"
if awk '$5 ~ /^(GLOBAL|WEAK)$/ && $7 != "UND" && $4 != "FUNC" {
    found = 1
} END { exit(found ? 0 : 1) }' "$wrapper_elf_symbols"; then
    fail "allocator wrapper exposes non-function public data"
fi
for symbol in "${expected_wrapper_symbols[@]}"; do
    case "$symbol" in
        malloc) binding=WEAK ;;
        *) binding=GLOBAL ;;
    esac
    assert_elf_function_binding "$wrapper_elf_symbols" "$symbol" "$binding" \
        "allocator wrapper"
done
mapfile -t observability_exports < <(
    nm -g --defined-only --format=posix \
        "$work_dir/owners/${observability_members[0]}" |
        awk '$2 ~ /^[T]$/ && $1 !~ /^_R/ { print $1 }' | sort -u
)
expected_observability_symbols=(
    __crabc_x86_allocator_observability_v1
    malloc_usable_size
)
if [ "${observability_exports[*]}" != "${expected_observability_symbols[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_observability_symbols[*]}" \
        "${observability_exports[*]}" >&2
    fail "allocator-observability object export surface drifted"
fi
for symbol in mi_malloc_aligned mi_zalloc mi_realloc_aligned mi_free mi_usable_size; do
    nm -g --defined-only "$work_dir/owners/${backend_members[0]}" |
        grep -Eq "[[:space:]]T[[:space:]]${symbol}$" \
        || fail "bundled AArch64-equivalent backend lacks ${symbol}"
done
for symbol in "${expected_wrapper_symbols[@]}" malloc_usable_size; do
    if nm -g --defined-only "$work_dir/owners/${backend_members[0]}" |
        grep -Eq "[[:space:]][TW][[:space:]]${symbol}$"; then
        fail "bundled backend unexpectedly exports public allocator symbol ${symbol}"
    fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_ALLOCATOR_BASIC_RUNTIME_V1_CANDIDATE \
    -fno-pie -ffreestanding -fno-builtin -fno-stack-protector \
    -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_allocator_basic_runtime_v1_probe.c -o "$probe_object"

# `libc.lo` keeps only the backend's required `__libc`/`__hwcap` state. The
# candidate owns the program-name globals, so weaken only those duplicate musl
# definitions in a candidate-local support archive.
cp "$MUSL_LIBC" "$backend_musl_libc"
mkdir "$musl_patch_dir"
(
    cd "$musl_patch_dir"
    ar x "$MUSL_LIBC" libc.lo
    objcopy --weaken-symbol=__progname --weaken-symbol=__progname_full libc.lo
    readelf --symbols --wide libc.lo >"$patched_musl_symbols"
    for symbol in __progname __progname_full; do
        awk -v symbol="$symbol" \
            '$8 == symbol && $4 == "OBJECT" && $5 == "WEAK" { found = 1 }
             END { exit(found ? 0 : 1) }' "$patched_musl_symbols" \
            || fail "patched musl libc.lo did not weaken ${symbol}"
    done
    for symbol in __libc __hwcap; do
        awk -v symbol="$symbol" \
            '$8 == symbol && $4 == "OBJECT" && $5 == "GLOBAL" { found = 1 }
             END { exit(found ? 0 : 1) }' "$patched_musl_symbols" \
            || fail "patched musl libc.lo lost ${symbol}"
    done
    ar rcs "$backend_musl_libc" libc.lo
)

"$link_editor" -static --no-dynamic-linker --no-undefined \
    -z relro -z now -e _start -Map="$link_map" \
    "$crt_dir/crt1.o" "$crt_dir/crti.o" "$probe_object" \
    --start-group "$archive" "$backend_musl_libc" --end-group \
    "$crt_dir/crtn.o" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"

for symbol in _start __crabc_x86_allocator_runtime_v1 \
    __crabc_x86_allocator_observability_v1 __crabc_x86_static_tls_bootstrap \
    __libc_start_main malloc calloc realloc reallocarray free aligned_alloc \
    posix_memalign memalign valloc malloc_usable_size mi_malloc_aligned \
    mi_zalloc mi_realloc_aligned mi_free mi_usable_size pthread_create \
    pthread_join pthread_atfork fork atexit exit __funcs_on_exit waitpid _exit \
    mmap munmap clock_gettime; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks ${symbol}"
done
for symbol in "${expected_wrapper_symbols[@]}"; do
    case "$symbol" in
        malloc) binding=WEAK ;;
        *) binding=GLOBAL ;;
    esac
    assert_elf_function_binding "$candidate_symbols" "$symbol" "$binding" \
        "candidate"
done
assert_elf_function_binding "$candidate_symbols" malloc_usable_size GLOBAL \
    "candidate observer"
for symbol in __progname __progname_full; do
    awk -v symbol="$symbol" \
        '$4 == "OBJECT" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
         END { exit(found ? 0 : 1) }' "$candidate_symbols" \
        || fail "candidate does not retain crabc's strong ${symbol} owner"
done
if grep -Eq 'GLOBAL +DEFAULT +.*__crabc_x86_static_tls_bootstrap$' \
    "$candidate_symbols"; then
    fail "candidate exposes the hidden static-TLS bootstrap"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
[ "$(awk '$1 == "TLS" { count += 1 } END { print count + 0 }' \
    "$candidate_headers")" = 1 ] \
    || fail "candidate must contain exactly one static TLS image"
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' \
    "$candidate_headers" "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi
grep -Eq '\$0x39(,|[[:space:]]|$)' "$candidate_disassembly" \
    || fail "candidate lacks the selected public x86 fork syscall"

# The three named symbols previously lived in the support tail. Their map
# ownership must remain crabc-local, not broaden the residual musl provider.
for symbol in fputs sleep __stack_chk_fail; do
    assert_crabc_backend_support_owner "$archive" "$link_map" "$symbol"
done

awk -v archive="${backend_musl_libc}(" '
    index($0, archive) {
        member = substr($0, index($0, archive) + length(archive))
        sub(/\).*/, "", member)
        print member
    }
' "$link_map" | sort -u >"$actual_musl_members"
printf '%s\n' \
    __lock.lo \
    abort.lo \
    abort_lock.lo \
    block.lo \
    libc.lo \
    prctl.lo \
    realpath.lo \
    strchrnul.lo \
    strdup.lo \
    syscall.lo \
    syscall_ret.lo | sort -u >"$expected_musl_members"
if ! cmp -s "$expected_musl_members" "$actual_musl_members"; then
    diff -u "$expected_musl_members" "$actual_musl_members" >&2 || true
    fail "pinned-musl backend-support member boundary drifted"
fi
if grep -Eq '^(aligned_alloc|calloc|free|malloc|malloc_usable_size|memalign|posix_memalign|realloc|reallocarray|valloc)\.lo$' \
    "$actual_musl_members"; then
    fail "candidate selected a pinned-musl allocator implementation"
fi
if grep -Eq '^malloc_usable_size\.lo$' "$actual_musl_members"; then
    fail "candidate selected a pinned-musl observer implementation"
fi
if grep -Eq '(^|/)(__libc_start_main|__init_tls|pthread_|fork|wait|exit|crt|clone|mmap|munmap|clock_gettime)\.lo$' \
    "$actual_musl_members"; then
    fail "candidate selected a pinned-musl runtime implementation"
fi

set +e
env -i LC_ALL=C TZ=UTC "$candidate" >"$candidate_stdout"
candidate_status=$?
set -e
[ "$candidate_status" -eq 0 ] \
    || fail "crabc allocator-basic-runtime-v1 candidate failed with exit ${candidate_status}"
cmp -s "$expected_stdout" "$candidate_stdout" \
    || fail "candidate ordinary-exit allocator marker drifted"

printf 'x86 libc allocator-basic-runtime-v1: PASS\n'
