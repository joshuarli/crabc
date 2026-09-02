#!/usr/bin/env bash
# Native Linux/x86-64 opt-in h_errno status-object/static-TLS evidence.
#
# One project-header fixture executes first through pinned musl and then as a
# true static candidate built with x86-h-errno. It selects only musl's legacy
# data object/accessor and the already selected initial-TLS + one-worker
# pthread boundary. Resolver configuration, DNS, sockets, network databases,
# and the wider resolver-runtime profile remain outside this artifact.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-h-errno
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/h_errno.rs"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_h_errno_header_abi.sh"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_h_errno_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_h_errno_start.S"

fail() {
    printf 'ERROR: x86 static libc h_errno: %s\n' "$*" >&2
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

archive_members_for_symbol() {
    local archive_path="$1" symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' | LC_ALL=C sort -u
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

assert_feature_delta() {
    local baseline_symbols="$1" featured_symbols="$2"
    local additions="$3" removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "${FEATURE} removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf '__h_errno_location\nh_errno\n') "$additions"; then
        diff -u <(printf '__h_errno_location\nh_errno\n') "$additions" >&2 || true
        fail "${FEATURE} changes more than __h_errno_location plus h_errno"
    fi
}

assert_h_errno_symbols() {
    local symbols_path="$1" label="$2"

    grep -Eq 'FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]].*[[:space:]]__h_errno_location$' "$symbols_path" ||
        fail "$label lacks global-default __h_errno_location"
    grep -Eq '[[:space:]]+4[[:space:]]+OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]].*[[:space:]]h_errno$' "$symbols_path" ||
        fail "$label lacks four-byte global-default h_errno object"
}

assert_no_dynamic_tls() {
    local label="$1"
    shift
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' "$@"; then
        fail "$label retains a dynamic TLS model"
    fi
}

filter_debug_relocations() {
    local input="$1" output="$2"

    # Rust debug records can describe one direct-TLS datum with DTPOFF even
    # when the executable code uses only TPOFF. Inspect runtime relocation
    # sections separately so debug metadata cannot disguise or falsely report
    # a dynamic TLS model.
    awk '
        /^Relocation section/ { debug_section = ($3 ~ /\.rela\.debug/) }
        !debug_section { print }
    ' "$input" >"$output"
}

assert_no_resolver_runtime() {
    local label="$1"
    shift
    if grep -Eq 'resolver_runtime|__res_state|__res_mkquery|__res_send|res_mkquery|res_send|res_query(domain)?|res_search|dn_comp|getaddrinfo|getnameinfo|crabc_core|mimalloc|sha_crypt' "$@"; then
        fail "$label selects resolver, allocator, crypt, or crabc-core state"
    fi
}

run_fixture() {
    local executable="$1" label="$2" status=0
    timeout 15 "$executable" || status=$?
    [ "$status" -eq 0 ] || fail "$label fixture exited $status"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mapfile mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 static ABI oracle"
[ -f "$SOURCE" ] || fail "missing h_errno source owner"
[ -f "$PROBE" ] || fail "missing h_errno fixture"
[ -f "$START" ] || fail "missing h_errno fixture entry"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null
grep -Fqx $'__h_errno_location\th_errno.lo\tT\tGLOBAL\t0\t20' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost __h_errno_location ownership"
grep -Fqx $'h_errno\th_errno.lo\tB\tGLOBAL\t0\t4' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost h_errno ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-h-errno.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
resolver_target="$work_dir/cargo-resolver"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
resolver_archive="$resolver_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-h-errno-reference"
candidate="$work_dir/crabc-static-h-errno-candidate"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_object="$work_dir/musl-h-errno.o"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
featured_symbols="$work_dir/featured-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
owner_object="$work_dir/h-errno-owner.o"
owner_symbols="$work_dir/h-errno-owner-symbols"
owner_relocations="$work_dir/h-errno-owner-relocations"
owner_runtime_relocations="$work_dir/h-errno-owner-runtime-relocations"
owner_disassembly="$work_dir/h-errno-owner-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_runtime_relocations="$work_dir/candidate-runtime-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" h_errno.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$work_dir/musl-h-errno-symbols"
assert_h_errno_symbols "$work_dir/musl-h-errno-symbols" "pinned musl h_errno.lo"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in netdb.h pthread.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" "$PROBE" -o "$reference"
run_fixture "$reference" "pinned-musl h_errno"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl --features "$FEATURE" -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "baseline cargo build did not emit libc.a"
[ -f "$featured_archive" ] || fail "feature cargo build did not emit libc.a"
collect_global_surface "$baseline_archive" "$baseline_symbols" "$work_dir/baseline-members"
collect_global_surface "$featured_archive" "$featured_symbols" "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
if grep -Fqx -e h_errno -e __h_errno_location "$STATIC_C_ABI_EXPORTS"; then
    fail "default static export ratchet absorbed opt-in h_errno symbols"
fi

mapfile -t owner_members < <(archive_members_for_symbol "$featured_archive" __h_errno_location)
[ "${#owner_members[@]}" -eq 1 ] || fail "feature archive has ambiguous __h_errno_location ownership"
data_members="$(archive_members_for_symbol "$featured_archive" h_errno)"
[ "$data_members" = "${owner_members[0]}" ] ||
    fail "h_errno object and accessor do not share one source owner"
ar p "$featured_archive" "${owner_members[0]}" >"$owner_object"
readelf --symbols --wide "$owner_object" >"$owner_symbols"
readelf --relocs --wide "$owner_object" >"$owner_relocations"
filter_debug_relocations "$owner_relocations" "$owner_runtime_relocations"
objdump -dr "$owner_object" >"$owner_disassembly"
assert_h_errno_symbols "$owner_symbols" "feature owner"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$owner_runtime_relocations" ||
    fail "feature owner lacks direct initial-TLS h_errno relocation"
assert_no_dynamic_tls "feature owner" "$owner_runtime_relocations" "$owner_disassembly"
assert_no_resolver_runtime "feature owner" "$owner_symbols" "$owner_runtime_relocations" "$owner_disassembly"

# The planned resolver feature must compose this one owner rather than revive
# a duplicate object/accessor definition when its wider package is enabled.
CARGO_TARGET_DIR="$resolver_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl --features x86-resolver-runtime -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$resolver_archive" ] || fail "resolver cargo build did not emit libc.a"
mapfile -t resolver_accessor_members < <(archive_members_for_symbol "$resolver_archive" __h_errno_location)
mapfile -t resolver_data_members < <(archive_members_for_symbol "$resolver_archive" h_errno)
[ "${#resolver_accessor_members[@]}" -eq 1 ] ||
    fail "resolver profile duplicates __h_errno_location ownership"
[ "${#resolver_data_members[@]}" -eq 1 ] ||
    fail "resolver profile duplicates h_errno ownership"
[ "${resolver_accessor_members[0]}" = "${resolver_data_members[0]}" ] ||
    fail "resolver profile splits h_errno object/accessor ownership"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_H_ERRNO_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections -Wl,-Map,"$candidate_map" "$PROBE" "$START" \
    "$featured_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
filter_debug_relocations "$candidate_relocations" "$candidate_runtime_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
assert_h_errno_symbols "$candidate_symbols" "candidate"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected direct-TLS storage"
assert_no_dynamic_tls "candidate" "$candidate_runtime_relocations" "$candidate_symbols" "$candidate_disassembly"
grep -Eq '%fs:' "$candidate_disassembly" ||
    fail "candidate lacks direct x86 TLS access"
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
assert_no_resolver_runtime "candidate" "$candidate_symbols" "$candidate_disassembly" "$candidate_map"
if grep -Eq '(/opt/musl-|glibc|ld-linux|libc\.so\.6)' \
    "$candidate_map" "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi

run_fixture "$candidate" "freestanding h_errno"

printf 'x86 static crabc-libc h_errno: PASS\n'
