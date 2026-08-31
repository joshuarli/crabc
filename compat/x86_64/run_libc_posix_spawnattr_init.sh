#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc posix_spawnattr_init evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then as a true `-nostdlib -static` candidate linked only with exactly one
# crabc-libc object. It proves musl's full caller-owned record zeroing and
# successful return without selecting spawn execution, child lifecycle, file
# actions, attribute accessors, signals, scheduler policy, libc.so, a CRT, a
# loader, a sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc posix_spawnattr_init: %s\n' "$*" >&2
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

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" |
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

assert_selected_c_abi_surface() {
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objcopy objdump readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_posix_spawnattr_init_header_abi.sh" >/dev/null
grep -Fqx $'posix_spawnattr_init\tposix_spawnattr_init.lo\tT\tGLOBAL\t0\t1c' \
    "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost posix_spawnattr_init ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-spawnattr-init.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-posix-spawnattr-init.a"
selected_object="$work_dir/owner/posix_spawnattr_init.o"
reference="$work_dir/musl-posix-spawnattr-init-reference"
candidate="$work_dir/crabc-static-posix-spawnattr-init-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-posix-spawnattr-init.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/posix-spawnattr-init-undefined"
object_relocations="$work_dir/posix-spawnattr-init-relocations"
object_disassembly="$work_dir/posix-spawnattr-init-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" posix_spawnattr_init.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq \
    '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]].*[[:space:]]posix_spawnattr_init$' ||
    fail "pinned musl posix_spawnattr_init.lo lacks strong posix_spawnattr_init"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_posix_spawnattr_init_probe.c >/dev/null 2>"$header_trace"
for header in spawn.h features.h sys/types.h bits/alltypes.h errno.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_spawnattr_init_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl posix_spawnattr_init fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq "[[:space:]][TW][[:space:]]posix_spawnattr_init$" "$archive_symbols" ||
    fail "archive does not define posix_spawnattr_init"

mapfile -t members < <(archive_member_for_symbol "$archive" posix_spawnattr_init)
[ "${#members[@]}" -eq 1 ] || fail "posix_spawnattr_init must have exactly one crate object owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "${members[0]}"
    # Rust may batch unrelated `global_asm!` modules into one archive member.
    # Select the emitted function section, rather than treating that physical
    # codegen batch as the ABI ownership boundary. The selected function has
    # no relocations or data dependencies, so this retains exactly the owned
    # implementation that the candidate links.
    objcopy --only-section=.text.posix_spawnattr_init \
        --keep-symbol=posix_spawnattr_init "${members[0]}" \
        "$(basename "$selected_object")"
    ar crs "$selected_archive" "$(basename "$selected_object")"
)
object="$selected_object"

mapfile -t exports < <(
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${exports[*]}" != "posix_spawnattr_init" ]; then
    printf 'expected: %s\nactual:   %s\n' "posix_spawnattr_init" "${exports[*]}" >&2
    fail "posix_spawnattr_init object export surface drifted"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if [ -s "$object_undefined" ]; then
    sed -n '1,120p' "$object_undefined" >&2
    fail "posix_spawnattr_init object unexpectedly depends on another symbol"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$object_disassembly"; then
    fail "posix_spawnattr_init object unexpectedly performs a call or syscall"
fi

"$ORACLE_CC" -std=c11 -DCRABC_POSIX_SPAWNATTR_INIT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$link_map" compat/x86_64/libc_posix_spawnattr_init_probe.c \
    compat/x86_64/libc_posix_spawnattr_init_start.S "$selected_archive" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "posix_spawnattr_init" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
    fail "candidate lacks global posix_spawnattr_init"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers"; then
    fail "candidate unexpectedly selects TLS"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' \
    "$object_relocations" "$candidate_relocations" "$candidate_symbols" \
    "$candidate_disassembly"; then
    fail "candidate unexpectedly retains errno or TLS"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
for unselected in posix_spawn posix_spawnp posix_spawnattr_destroy \
    posix_spawnattr_setflags posix_spawnattr_getflags \
    posix_spawnattr_setpgroup posix_spawnattr_getpgroup \
    posix_spawnattr_setsigmask posix_spawnattr_getsigmask \
    posix_spawnattr_setsigdefault posix_spawnattr_getsigdefault \
    posix_spawnattr_setschedparam posix_spawnattr_getschedparam \
    posix_spawnattr_setschedpolicy posix_spawnattr_getschedpolicy \
    posix_spawn_file_actions_init posix_spawn_file_actions_destroy \
    posix_spawn_file_actions_addopen posix_spawn_file_actions_addclose \
    posix_spawn_file_actions_adddup2 fork vfork clone execve wait4; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt|memset|memcpy|memmove|bzero' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned allocator, runtime, or memory utility"
fi

"$candidate" || fail "freestanding posix_spawnattr_init fixture failed"

printf 'x86 static libc posix_spawnattr_init: PASS\n'
