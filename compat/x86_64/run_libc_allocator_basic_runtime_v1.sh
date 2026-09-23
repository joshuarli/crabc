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
# The candidate's accepted mimalloc backend and every runtime-support owner
# link from crabc alone.  Pinned musl executes only the separate reference
# process: no musl archive member may enter the final candidate link.  This
# does not claim full allocator lifecycle, allocator-family completion, a
# static sysroot, product closure, promotion, or public x86 support.
set -euo pipefail

# The abort contract intentionally exercises terminating SIGABRT dispositions.
# Keep those process-isolated children from depositing host-owned core files
# beside the checkout when the pinned container permits core dumping.
ulimit -c 0

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
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
for tool in ar awk cargo cmp grep nm objdump python3 readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_rustc="$(rustup which rustc)"
    toolchain_root="$(dirname "$(dirname "$toolchain_rustc")")"
    link_editor="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    [ -x "$link_editor" ] || fail "requires the pinned Rust x86-64 linker"
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d "${TMPDIR:?x86 runner must provide repository-local TMPDIR}/crabc-x86-64-libc-allocator-basic-runtime-v1.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
crt_dir="$work_dir/crt"
reference="$work_dir/pinned-musl-allocator-basic-runtime-v1-reference"
candidate="$work_dir/crabc-allocator-basic-runtime-v1-candidate"
probe_object="$work_dir/probe.o"
header_trace="$work_dir/header-trace"
reference_stdout="$work_dir/reference.stdout"
candidate_stdout="$work_dir/candidate.stdout"
expected_stdout="$work_dir/expected.stdout"
link_map="$work_dir/candidate.map"
link_trace="$work_dir/candidate-link-trace"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_allocator_basic_runtime_v1_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h malloc.h pthread.h stdint.h stdlib.h sys/mman.h sys/prctl.h \
    sys/syscall.h sys/wait.h features.h signal.h unistd.h bits/alltypes.h \
    bits/signal.h bits/syscall.h; do
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
    rustup run "$(python3 "$ROOT_DIR/scripts/rust_toolchain.py")" rustc --edition=2021 --crate-type=lib --emit=obj \
        --target x86_64-unknown-linux-musl -C panic=abort \
        -C force-unwind-tables=no -C debuginfo=0 -C opt-level=2 \
        -C overflow-checks=off -C debug-assertions=off \
        -C relocation-model=static -C code-model=small -C link-dead-code=no \
        --remap-path-prefix "$ROOT_DIR=/crabc" \
        --crate-name "crabc_x86_64_${object}" \
        "crt/src/x86_64_${object}.rs" -o "$crt_dir/${object}.o"
done

# Build the candidate with source-owned core/alloc/compiler_builtins and the
# exact non-crypt C allocator profile. `alloc` is authenticated as an available
# source artifact, but this C backend must not place its members in libc.a.
source_runtime_helper="$ROOT_DIR/compat/x86_64/native_static_source_runtime_closure.py"
source_runtime_work="${work_dir#"$ROOT_DIR/.work/x86_64/"}"
[ "$source_runtime_work" != "$work_dir" ] \
    || fail "runner work directory escaped the repository-local native boundary"
source_runtime_work="$source_runtime_work/source-runtime"
if ! archive="$(python3 "$source_runtime_helper" build \
    --work "$source_runtime_work" \
    --features x86-owned-static-runtime-core --print-archive)"; then
    fail "source-built allocator-basic runtime archive construction failed"
fi
source_runtime_receipt="$ROOT_DIR/.work/x86_64/$source_runtime_work/receipt.json"
[ -f "$archive" ] || fail "source-runtime helper did not emit the allocator-basic archive"
[ -f "$source_runtime_receipt" ] || fail "source-runtime helper did not emit its closure receipt"
builtins_archive="$work_dir/libcrabc-builtins.a"
python3 "$ROOT_DIR/builtins/build_x86_64.py" --output "$builtins_archive" \
    >"$work_dir/builtins-build.log"
[ -f "$builtins_archive" ] || fail "owned compiler helper builder did not emit an archive"
nm -g --defined-only "$builtins_archive" | grep -Eq '[[:space:]]T[[:space:]]__popcountdi2$' \
    || fail "owned compiler helper archive lacks __popcountdi2"

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
wrapper_elf_symbols="$work_dir/wrapper-symbols"
readelf --symbols --wide "$work_dir/owners/${allocator_members[0]}" \
    >"$wrapper_elf_symbols"
for symbol in "${expected_wrapper_symbols[@]}"; do
    case "$symbol" in
        malloc) binding=WEAK ;;
        *) binding=GLOBAL ;;
    esac
    assert_elf_function_binding "$wrapper_elf_symbols" "$symbol" "$binding" \
        "allocator wrapper"
done
# Codegen may place unrelated owned runtime definitions in either object. The
# source closure and final-link audit own the complete archive boundary; these
# object checks pin only the allocator ABI and its distinct weak/strong owners.
observer_elf_symbols="$work_dir/observer-symbols"
readelf --symbols --wide "$work_dir/owners/${observability_members[0]}" \
    >"$observer_elf_symbols"
assert_elf_function_binding "$observer_elf_symbols" \
    __crabc_x86_allocator_observability_v1 GLOBAL "allocator observer"
assert_elf_function_binding "$observer_elf_symbols" \
    malloc_usable_size GLOBAL "allocator observer"
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

# This is the closure judge: the candidate sees its CRT, probe, and one
# feature-composed crabc archive and its bounded owned compiler helpers. The
# pinned musl archive is used only by the separate reference process above.
if ! "$link_editor" -static --no-dynamic-linker --no-undefined \
    -z relro -z now -e _start -Map="$link_map" \
    --trace-symbol=rust_eh_personality \
    "$crt_dir/crt1.o" "$crt_dir/crti.o" "$probe_object" \
    --start-group "$archive" "$builtins_archive" --end-group \
    "$crt_dir/crtn.o" -o "$candidate" >"$link_trace" 2>&1; then
    cat "$link_trace" >&2
    fail "candidate final link failed"
fi
python3 "$source_runtime_helper" audit-final-link \
    --receipt "$source_runtime_receipt" --candidate "$candidate" \
    --link-map "$link_map" --trace "$link_trace" --label allocator-basic-runtime-v1
grep -F "$builtins_archive(crabc-builtins.o)" "$link_map" | grep -F '__popcountdi2' >/dev/null \
    || fail "candidate did not select __popcountdi2 from the owned compiler helper archive"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"

# The target std `alloc` archive contains unwind/personality references even
# under panic=abort. This gate does not select the alloc-backed crypt leaf, so
# no target alloc member or unwind identity may enter its C final link.
if grep -Eq 'libc\.a\(alloc-[^)]*\.o\)' "$link_map"; then
    fail "candidate extracted the unrelated target alloc runtime"
fi
if grep -Eq 'rust_eh_personality|_Unwind_[A-Za-z0-9_]*|panic_(abort|unwind)' \
    "$link_map" "$candidate_symbols"; then
    fail "candidate selected a target unwind or panic runtime identity"
fi

for symbol in _start __crabc_x86_allocator_runtime_v1 \
    __crabc_x86_allocator_observability_v1 __crabc_x86_static_tls_bootstrap \
    __libc_start_main malloc calloc realloc reallocarray free aligned_alloc \
    posix_memalign memalign valloc malloc_usable_size mi_malloc_aligned \
    mi_zalloc mi_realloc_aligned mi_free mi_usable_size pthread_create \
    pthread_join pthread_atfork fork atexit exit __funcs_on_exit waitpid _exit \
    mmap munmap clock_gettime syscall prctl realpath abort strdup strndup \
    strchrnul; do
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
for symbol in syscall prctl realpath abort strdup strndup; do
    assert_elf_function_binding "$candidate_symbols" "$symbol" GLOBAL \
        "owned static support"
done
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

# Preserve the old allocator-runtime ownership ratchet: all three support
# symbols remain crabc-local after the foreign tail is removed.
for symbol in fputs sleep __stack_chk_fail; do
    assert_crabc_backend_support_owner "$archive" "$link_map" "$symbol"
done

for symbol in syscall prctl realpath abort strdup strndup strchrnul; do
    mapfile -t owners < <(archive_member_for_symbol "$archive" "$symbol")
    [ "${#owners[@]}" -eq 1 ] \
        || fail "owned static support must have exactly one crabc ${symbol} owner"
done
if grep -Eqi 'pinned-musl|/opt/musl|(^|/)libc\.a\([^)]*\.lo\)' \
    "$link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected a foreign musl support object"
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
