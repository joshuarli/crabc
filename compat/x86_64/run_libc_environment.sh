#!/usr/bin/env bash
# Native Linux/x86-64 allocator-backed C environment evidence.
#
# The same project-header C fixture first executes against pinned musl 1.2.6,
# then against the opt-in crabc environment runtime. The candidate owns the
# musl-shaped environment globals and mutation state, the existing x86 C
# allocator wrapper, crabc static startup/Initial TLS, and the bundled
# allocator backend. A tightly ratcheted pinned-musl support member provides
# only backend internals still outside the staged x86 runtime; it must not
# supply an environment or allocator entry point.
# The fixture includes real-CRT `.init_array` initial-environment publication
# and constructor-to-main mutation visibility, caller-owned vector
# replacement/removal, direct reassignment after an owned append vector,
# over-128-entry growth, and repeated setenv/unsetenv/clearenv reclamation.
# Both runs are static and use fixture-only malloc/realloc linker wrappers to
# inject one replacement-string, direct-vector append, or owned-vector append
# allocation failure before publication; they make no claim about later
# ownership-registry bookkeeping.
#
# This proves a substantive environment-mutation runtime, not a general
# dynamic libc, async-signal-safe/fork-recovering lifecycle, exec/spawn policy,
# loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIBC=/opt/musl-1.2.6/lib/libc.a
readonly -a MUSL_BACKEND_MEMBERS=(
    __lock.lo
    abort.lo
    abort_lock.lo
    block.lo
    libc.lo
    prctl.lo
    realpath.lo
    strchrnul.lo
    strdup.lo
    syscall.lo
    syscall_ret.lo
)
readonly -a ALLOCATION_WRAP_FLAGS=(
    -Wl,--wrap=malloc
    -Wl,--wrap=realloc
)
readonly -a ENVIRONMENT_ALLOCATOR_SYMBOLS=(
    malloc
    realloc
    free
)

fail() {
    printf 'ERROR: x86 libc environment runtime: %s\n' "$*" >&2
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

symbol_value() {
    local symbols_path="$1"
    local symbol="$2"

    awk -v symbol="$symbol" '$8 == symbol && $7 != "UND" { print $2; exit }' \
        "$symbols_path"
}

verify_wrapper_object() {
    local object_path="$1"
    local symbols_path="$2"
    local label="$3"
    local symbol

    readelf --symbols --wide "$object_path" >"$symbols_path"
    for symbol in malloc realloc; do
        awk -v symbol="__wrap_${symbol}" '
            $4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == symbol {
                found = 1
            }
            END { exit(found ? 0 : 1) }
        ' "$symbols_path" ||
            fail "${label} fixture does not define ${symbol}"
        awk -v symbol="__real_${symbol}" '
            $7 == "UND" && $8 == symbol { found = 1 }
            END { exit(found ? 0 : 1) }
        ' "$symbols_path" ||
            fail "${label} fixture does not use linker-provided ${symbol}"
    done
}

verify_wrapped_allocator_path() {
    local executable="$1"
    local disassembly_path="$2"
    local label="$3"
    local symbol

    : >"$disassembly_path"
    for symbol in malloc realloc; do
        objdump -d --disassemble="__wrap_${symbol}" "$executable" \
            >>"$disassembly_path"
        grep -Eq "(call|jmp).*<${symbol}>" "$disassembly_path" ||
            fail "${label} environment wrappers bypassed the selected allocator ${symbol}"
        if grep -Eq "(call|jmp).*<__wrap_${symbol}>" "$disassembly_path"; then
            fail "${label} environment wrapper recursively calls ${symbol}"
        fi
    done
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff grep nm objcopy objdump readelf \
    rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$MUSL_LIBC" ] || fail "missing pinned musl static libc"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-environment.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
crt_dir="$work_dir/crt"
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/release/libc.a"
reference="$work_dir/musl-environment-reference"
candidate="$work_dir/crabc-environment-candidate"
reference_probe_object="$work_dir/musl-environment-probe.o"
reference_probe_symbols="$work_dir/musl-environment-probe-symbols"
probe_object="$work_dir/environment-probe.o"
probe_symbols="$work_dir/environment-probe-symbols"
allocator_owner_symbols="$work_dir/allocator-owner-symbols"
probe_sections="$work_dir/environment-probe-sections"
reference_wrapper_disassembly="$work_dir/musl-environment-allocation-wrappers"
header_trace="$work_dir/header-trace"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_sections="$work_dir/candidate-sections"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_wrapper_disassembly="$work_dir/candidate-allocation-wrappers"
errno_disassembly="$work_dir/errno-disassembly"
actual_musl_members="$work_dir/actual-musl-members"
expected_musl_members="$work_dir/expected-musl-members"
available_musl_members="$work_dir/available-musl-members"
backend_musl_libc="$work_dir/pinned-musl-backend-support.a"
musl_patch_dir="$work_dir/musl-program-name-bridge"
patched_musl_symbols="$work_dir/patched-musl-libc-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_environment_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdlib.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ENVIRONMENT_ALLOCATION_WRAP \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" -c compat/x86_64/libc_environment_probe.c \
    -o "$reference_probe_object"
verify_wrapper_object "$reference_probe_object" "$reference_probe_symbols" \
    "pinned-musl reference"
"$ORACLE_CC" -static -fno-pie -no-pie "${ALLOCATION_WRAP_FLAGS[@]}" \
    "$reference_probe_object" -o "$reference"
verify_wrapped_allocator_path "$reference" "$reference_wrapper_disassembly" \
    "pinned-musl reference"
env -i CRABC_X86_INITIAL=entry "$reference" ||
    fail "pinned-musl environment reference failed"

mkdir "$crt_dir"
for object in crt1 crti crtn; do
    rustup run nightly-2026-07-24 rustc --edition=2021 --crate-type=lib --emit=obj \
        --target x86_64-unknown-linux-musl -C panic=abort \
        -C force-unwind-tables=no -C debuginfo=0 -C opt-level=2 \
        -C overflow-checks=off -C debug-assertions=off \
        -C relocation-model=static -C code-model=small -C link-dead-code=no \
        --remap-path-prefix "$ROOT_DIR=/crabc" \
        --crate-name "crabc_x86_environment_${object}" \
        "crt/src/x86_64_${object}.rs" -o "$crt_dir/${object}.o"
done

CARGO_TARGET_DIR="$cargo_target" cargo rustc --release --locked -p crabc-libc --lib \
    --features x86-environment-runtime --target x86_64-unknown-linux-musl -- \
    -C force-unwind-tables=no -C debuginfo=0 -C opt-level=2 \
    -C overflow-checks=off -C debug-assertions=off \
    -C relocation-model=static -C code-model=small -C panic=abort \
    -C link-dead-code=no -C lto=off -C codegen-units=256
[ -f "$archive" ] || fail "cargo did not emit the environment runtime archive"

mapfile -t environment_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_environment_runtime_v1
)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(
    archive_member_for_symbol "$archive" __errno_location
)
mapfile -t backend_members < <(ar t "$archive" | grep -- '-static\.o$')
[ "${#environment_members[@]}" -eq 1 ] ||
    fail "environment runtime witness must have exactly one crate object owner"
[ "${#allocator_members[@]}" -eq 1 ] ||
    fail "allocator wrapper must have exactly one crate object owner"
for symbol in "${ENVIRONMENT_ALLOCATOR_SYMBOLS[@]}"; do
    mapfile -t allocator_symbol_members < <(
        archive_member_for_symbol "$archive" "$symbol"
    )
    [ "${#allocator_symbol_members[@]}" -eq 1 ] ||
        fail "selected allocator must have exactly one ${symbol} object owner"
    [ "${allocator_symbol_members[0]}" = "${allocator_members[0]}" ] ||
        fail "selected allocator witness and ${symbol} have different object owners"
done
[ "${#errno_members[@]}" -eq 1 ] ||
    fail "errno must have exactly one crate object owner"
[ "${#backend_members[@]}" -eq 1 ] ||
    fail "allocator backend must have exactly one bundled static object"
[ "${environment_members[0]}" != "${allocator_members[0]}" ] ||
    fail "environment runtime and allocator wrapper unexpectedly share one object"
[ "${environment_members[0]}" != "${errno_members[0]}" ] ||
    fail "environment runtime and errno ownership unexpectedly share one object"
for symbol in __environ environ _environ ___environ getenv setenv putenv unsetenv clearenv; do
    mapfile -t symbol_members < <(archive_member_for_symbol "$archive" "$symbol")
    [ "${#symbol_members[@]}" -eq 1 ] ||
        fail "environment runtime must have exactly one $symbol object owner"
    [ "${symbol_members[0]}" = "${environment_members[0]}" ] ||
        fail "environment runtime witness and $symbol have different object owners"
done

mkdir "$work_dir/environment-owner"
(
    cd "$work_dir/environment-owner"
    ar x "$archive" "${environment_members[0]}"
)
mapfile -t environment_symbols < <(
    nm -g --defined-only --format=posix \
        "$work_dir/environment-owner/${environment_members[0]}" |
        awk '$2 ~ /^[TWDVB]$/ && $1 !~ /^_R/ { print $1 }' | sort -u
)
expected_environment_symbols=(
    ___environ
    __crabc_x86_environment_runtime_v1
    __environ
    _environ
    clearenv
    environ
    getenv
    putenv
    setenv
    unsetenv
)
if [ "${environment_symbols[*]}" != "${expected_environment_symbols[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_environment_symbols[*]}" \
        "${environment_symbols[*]}" >&2
    fail "environment runtime object export surface drifted"
fi
for forbidden in __putenv __env_rm_add; do
    if nm -g --defined-only "$archive" 2>/dev/null | grep -Eq "[[:space:]]${forbidden}$"; then
        fail "archive accidentally exports musl-private ${forbidden}"
    fi
done

mkdir "$work_dir/allocator-owner"
(
    cd "$work_dir/allocator-owner"
    ar x "$archive" "${allocator_members[0]}"
)
readelf --symbols --wide \
    "$work_dir/allocator-owner/${allocator_members[0]}" >"$allocator_owner_symbols"
if ! awk '$4 == "FUNC" && $5 == "WEAK" && $8 == "malloc" { found = 1 }
    END { exit(found ? 0 : 1) }' "$allocator_owner_symbols"; then
    awk '$4 == "FUNC" && $8 == "malloc" { print }' "$allocator_owner_symbols" >&2
    fail "candidate wrapper path selected a strong malloc override"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ENVIRONMENT_RUNTIME_CANDIDATE \
    -DCRABC_ENVIRONMENT_ALLOCATION_WRAP -fno-pie -ffreestanding -fno-builtin \
    -fno-stack-protector \
    -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_environment_probe.c -o "$probe_object"
verify_wrapper_object "$probe_object" "$probe_symbols" "candidate"
readelf --sections --wide "$probe_object" >"$probe_sections"
grep -Eq '[[:space:]]\.init_array[[:space:]]' "$probe_sections" ||
    fail "fixture lacks .init_array constructor entry"

# Build the candidate-local support archive only from the ratcheted members.
# `libc.lo` provides retained backend globals, while crabc static startup owns
# strong program-name globals. Make only those two local musl definitions weak;
# all environment/allocator code is absent, not merely unselected by the map.
mkdir "$musl_patch_dir"
(
    cd "$musl_patch_dir"
    ar x "$MUSL_LIBC" "${MUSL_BACKEND_MEMBERS[@]}"
    objcopy --weaken-symbol=__progname --weaken-symbol=__progname_full libc.lo
    readelf --symbols --wide libc.lo >"$patched_musl_symbols"
    for symbol in __progname __progname_full; do
        awk -v symbol="$symbol" \
            '$8 == symbol && $4 == "OBJECT" && $5 == "WEAK" { found = 1 }
             END { exit(found ? 0 : 1) }' "$patched_musl_symbols" ||
            fail "patched musl libc.lo did not weaken ${symbol}"
    done
    for symbol in __libc __hwcap; do
        awk -v symbol="$symbol" \
            '$8 == symbol && $4 == "OBJECT" && $5 == "GLOBAL" { found = 1 }
             END { exit(found ? 0 : 1) }' "$patched_musl_symbols" ||
            fail "patched musl libc.lo lost ${symbol}"
    done
    ar rcs "$backend_musl_libc" "${MUSL_BACKEND_MEMBERS[@]}"
)
ar t "$backend_musl_libc" | sort -u >"$available_musl_members"
printf '%s\n' "${MUSL_BACKEND_MEMBERS[@]}" | sort -u >"$expected_musl_members"
if ! cmp -s "$expected_musl_members" "$available_musl_members"; then
    diff -u "$expected_musl_members" "$available_musl_members" >&2 || true
    fail "pinned-musl backend-support archive boundary drifted"
fi
if nm -A --defined-only "$backend_musl_libc" 2>/dev/null |
    awk '$NF == "malloc" || $NF == "realloc" || $NF == "free" { found = 1 }
         END { exit(found ? 0 : 1) }'; then
    fail "pinned musl support archive defines wrapped allocation spelling"
fi

if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_rustc="$(rustup which rustc)"
    toolchain_root="$(dirname "$(dirname "$toolchain_rustc")")"
    link_editor="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    [ -x "$link_editor" ] || fail "requires the pinned Rust x86-64 linker"
fi
"$link_editor" -static --no-dynamic-linker --no-undefined \
    --wrap=malloc --wrap=realloc -z relro -z now -e _start -Map="$link_map" \
    "$crt_dir/crt1.o" "$crt_dir/crti.o" "$probe_object" \
    --start-group "$archive" "$backend_musl_libc" --end-group \
    "$crt_dir/crtn.o" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq '[[:space:]]\.init_array[[:space:]]' "$candidate_sections" ||
    fail "candidate lacks .init_array constructor entry"
for symbol in _start __crabc_x86_environment_runtime_v1 \
    __crabc_x86_static_tls_bootstrap __libc_start_main __environ environ \
    _environ ___environ getenv setenv putenv unsetenv clearenv malloc realloc \
    free mi_malloc_aligned mi_realloc mi_free; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks ${symbol}"
done
for symbol in getenv setenv putenv unsetenv clearenv; do
    awk -v symbol="$symbol" \
        '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
         END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
        fail "candidate ${symbol} is not a strong global function"
done
# LLD promotes the final `malloc` spelling while resolving `--wrap`; the
# input owner above is the binding boundary. The link map below then proves
# that the wrapped candidate actually retained that selected owner instead of
# acquiring a strong malloc from the pinned support archive.
for symbol in realloc free; do
    awk -v symbol="$symbol" \
        '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
         END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
        fail "candidate ${symbol} is not the selected strong allocator entry"
done
environ_value="$(symbol_value "$candidate_symbols" __environ)"
[ -n "$environ_value" ] || fail "candidate has no __environ object value"
awk '$8 == "__environ" && $7 != "UND" && $3 == 8 && $4 == "OBJECT" && $5 == "GLOBAL" { found = 1 }
    END { exit !found }' "$candidate_symbols" ||
    fail "environment object does not have x86 LP64 size/type/binding"
for alias in environ _environ ___environ; do
    alias_value="$(symbol_value "$candidate_symbols" "$alias")"
    [ "$alias_value" = "$environ_value" ] ||
        fail "${alias} is not an ELF alias of __environ"
    awk -v alias="$alias" '$8 == alias && $7 != "UND" && $3 == 8 &&
        $4 == "OBJECT" && $5 == "WEAK" { found = 1 }
        END { exit !found }' "$candidate_symbols" ||
        fail "environment alias is not a weak x86 LP64 object: ${alias}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' \
    "$candidate_program_headers" "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi
if grep -Eq 'libc\.a\((getenv|setenv|putenv|unsetenv|clearenv|malloc|realloc|free)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl environment or allocator implementation"
fi
grep -Fq "$archive(${allocator_members[0]})" "$link_map" ||
    fail "candidate wrapper path did not retain the selected allocator owner"
grep -Fq "$backend_musl_libc(libc.lo)" "$link_map" ||
    fail "candidate did not retain the ratcheted backend-support member"
awk -v archive="${backend_musl_libc}(" '
    index($0, archive) {
        member = substr($0, index($0, archive) + length(archive))
        sub(/\).*/, "", member)
        print member
    }
' "$link_map" | sort -u >"$actual_musl_members"
if ! cmp -s "$expected_musl_members" "$actual_musl_members"; then
    diff -u "$expected_musl_members" "$actual_musl_members" >&2 || true
    fail "pinned-musl backend-support member boundary drifted"
fi
if grep -Eq '^(malloc|calloc|realloc|free|aligned_alloc|posix_memalign|malloc_usable_size|pthread_|mmap|munmap|clock_gettime|wait|__libc_start_main|__init_tls|__set_thread_area)' \
    "$actual_musl_members"; then
    fail "pinned musl owns an allocator/observer or replaced x86 runtime prerequisite"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
verify_wrapped_allocator_path "$candidate" "$candidate_wrapper_disassembly" \
    "candidate"

env -i CRABC_X86_INITIAL=entry "$candidate" ||
    fail "candidate environment behavior failed"

printf 'x86 libc environment runtime: PASS\n'
