#!/usr/bin/env bash
# Native Linux/x86-64 opt-in static crabc-libc sethostent/setnetent evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then through one extracted `-nostdlib -static` candidate. The opt-in owner
# maps musl's empty stayopen-ignoring setter and its same-address weak alias;
# it does not select host/network enumeration, files, resolver behavior, or
# legacy netdb state.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-netdb-setent
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/sethostent.rs"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_endhostent_header_abi.sh"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_sethostent_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_sethostent_start.S"

fail() {
    printf 'ERROR: x86 static libc sethostent: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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
    local baseline_symbols="$1" featured_symbols="$2" additions="$3" removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "x86-netdb-setent removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'sethostent\nsetnetent\n') "$additions"; then
        diff -u <(printf 'sethostent\nsetnetent\n') "$additions" >&2 || true
        fail "x86-netdb-setent changes more than sethostent/setnetent"
    fi
}

assert_static_candidate_closure() {
    local candidate_path="$1" label="$2"
    local symbols="$work_dir/$label-symbols"
    local headers="$work_dir/$label-program-headers"
    local sections="$work_dir/$label-sections"
    local dynamic="$work_dir/$label-dynamic"
    local relocations="$work_dir/$label-relocations"
    local disassembly="$work_dir/$label-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols"
    readelf --program-headers --wide "$candidate_path" >"$headers"
    readelf --sections --wide "$candidate_path" >"$sections"
    readelf --dynamic --wide "$candidate_path" >"$dynamic" || true
    readelf --relocs --wide "$candidate_path" >"$relocations"
    objdump -d "$candidate_path" >"$disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
        fail "$label candidate retains an unresolved symbol"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "$label candidate selects a dynamic dependency"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]' "$headers"; then
        fail "$label candidate unexpectedly selects TLS"
    fi
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' \
        "$relocations" "$symbols" "$disassembly"; then
        fail "$label candidate retains errno or TLS"
    fi
    if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$sections"; then
        fail "$label candidate retains a PLT"
    fi
    if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
        "$candidate_link_map" "$headers" "$dynamic"; then
        fail "$label candidate selected an ambient libc runtime"
    fi
    if grep -Eq '[[:space:]](endhostent|endnetent|gethostent|getnetent|gethostbyname|gethostbyaddr|getnetbyname|getnetbyaddr|getaddrinfo|getnameinfo|res_init)$' \
        "$symbols"; then
        fail "$label candidate exports an unselected netdb enumeration or resolver entry"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|memset|strchr|strtol|strtoul|strtoimax' \
        "$symbols" "$disassembly"; then
        fail "$label candidate selects an unowned runtime dependency"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null
grep -Fqx $'sethostent\tent.lo\tT\tGLOBAL\t0\t4' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost sethostent ownership"
grep -Fqx $'setnetent\tent.lo\tW\tWEAK\t0\t4' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost setnetent alias ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sethostent.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-sethostent.a"
reference="$work_dir/musl-sethostent-reference"
candidate="$work_dir/crabc-static-sethostent-candidate"
override_candidate="$work_dir/crabc-static-sethostent-override-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-ent.o"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
expected_symbols="$work_dir/expected-symbols"
featured_symbols="$work_dir/featured-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
archive_symbols="$work_dir/archive-symbols"
owner_relocations="$work_dir/sethostent-relocations"
owner_disassembly="$work_dir/sethostent-disassembly"
candidate_link_map="$work_dir/candidate.map"
sethostent_disassembly="$work_dir/sethostent-disassembly-candidate"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" ent.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq \
    '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]].*[[:space:]]sethostent$' ||
    fail "pinned musl ent.lo lacks strong sethostent"
readelf --symbols --wide "$musl_object" | grep -Eq \
    '[[:space:]]FUNC[[:space:]]+WEAK[[:space:]].*[[:space:]]setnetent$' ||
    fail "pinned musl ent.lo lacks weak setnetent alias"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in limits.h netdb.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" "$PROBE" -o "$reference"
"$reference" || fail "pinned-musl sethostent fixture failed"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "cargo did not emit the baseline x86 static libc archive"
collect_global_surface "$baseline_archive" "$baseline_symbols" "$work_dir/baseline-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_symbols"
if ! cmp -s "$expected_symbols" "$baseline_symbols"; then
    diff -u "$expected_symbols" "$baseline_symbols" >&2 || true
    fail "selected static C ABI export surface drifted"
fi
if grep -Eq '^(sethostent|setnetent)$' "$baseline_symbols"; then
    fail "baseline archive unexpectedly defines opt-in netdb setter symbols"
fi

CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$SOURCE" ] || fail "missing sethostent source"
[ -f "$featured_archive" ] || fail "cargo did not emit the featured x86 static libc archive"
collect_global_surface "$featured_archive" "$featured_symbols" "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
nm -A --defined-only "$featured_archive" >"$archive_symbols"
grep -Eq '[[:space:]]T[[:space:]]sethostent$' "$archive_symbols" ||
    fail "featured archive does not define strong sethostent"
grep -Eq '[[:space:]]W[[:space:]]setnetent$' "$archive_symbols" ||
    fail "featured archive does not define weak setnetent"
for marker in 'src/network/ent.c::sethostent' 'weak_alias(sethostent, setnetent)' \
    '.weak setnetent' '.set setnetent, sethostent'; do
    grep -Fq "$marker" "$SOURCE" || fail "source lacks $marker"
done

mapfile -t sethostent_members < <(archive_member_for_symbol "$featured_archive" sethostent)
mapfile -t setnetent_members < <(archive_member_for_symbol "$featured_archive" setnetent)
[ "${#sethostent_members[@]}" -eq 1 ] || fail "sethostent must have exactly one crate object owner"
[ "${#setnetent_members[@]}" -eq 1 ] || fail "setnetent must have exactly one crate object owner"
[ "${sethostent_members[0]}" = "${setnetent_members[0]}" ] ||
    fail "sethostent/setnetent must share one crate object owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$featured_archive" "${sethostent_members[0]}"
    ar crs "$selected_archive" "${sethostent_members[0]}"
)
sethostent_object="$work_dir/owner/${sethostent_members[0]}"
grep -Eq '[[:space:]]T[[:space:]]sethostent$' <(nm -A --defined-only "$sethostent_object") ||
    fail "sethostent owner lacks its strong body"
grep -Eq '[[:space:]]W[[:space:]]setnetent$' <(nm -A --defined-only "$sethostent_object") ||
    fail "sethostent owner lacks its weak alias"
readelf --relocs --wide "$sethostent_object" >"$owner_relocations"
objdump -dr --disassemble=sethostent "$sethostent_object" >"$owner_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$owner_relocations" "$owner_disassembly"; then
    fail "sethostent code section selects a call, TLS, syscall, or an unowned runtime"
fi

"$ORACLE_CC" -std=c11 -DCRABC_SETHOSTENT_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections -Wl,-Map,"$candidate_link_map" "$PROBE" "$START" \
    "$selected_archive" -o "$candidate"
assert_static_candidate_closure "$candidate" candidate
host_address="$(nm -g --defined-only --format=posix "$candidate" | awk '$1 == "sethostent" && $2 == "T" { print $3; exit }')"
net_address="$(nm -g --defined-only --format=posix "$candidate" | awk '$1 == "setnetent" && $2 == "W" { print $3; exit }')"
[ -n "$host_address" ] || fail "candidate lacks strong sethostent"
[ -n "$net_address" ] || fail "candidate lacks weak setnetent"
[ "$host_address" = "$net_address" ] ||
    fail "candidate setnetent is not the same-address weak sethostent alias"
objdump -d --disassemble=sethostent "$candidate" >"$sethostent_disassembly"
grep -Eq '[[:space:]]ret([[:space:]]|$)' "$sethostent_disassembly" ||
    fail "sethostent lacks its no-op return"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$sethostent_disassembly"; then
    fail "sethostent unexpectedly performs a call or syscall"
fi
"$candidate" || fail "freestanding sethostent fixture failed"

# A caller's strong setnetent must replace the archive's weak alias while the
# direct sethostent reference still extracts this same selected archive member.
"$ORACLE_CC" -std=c11 -DCRABC_SETHOSTENT_FREESTANDING \
    -DCRABC_SETHOSTENT_OVERRIDE -I "$ROOT_DIR/include" -nostdlib -static \
    -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector \
    -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-Map,"$candidate_link_map" "$PROBE" "$START" "$selected_archive" \
    -o "$override_candidate"
assert_static_candidate_closure "$override_candidate" override
override_host_address="$(nm -g --defined-only --format=posix "$override_candidate" | awk '$1 == "sethostent" && $2 == "T" { print $3; exit }')"
override_net_address="$(nm -g --defined-only --format=posix "$override_candidate" | awk '$1 == "setnetent" && $2 == "T" { print $3; exit }')"
[ -n "$override_host_address" ] || fail "override candidate lacks archive sethostent"
[ -n "$override_net_address" ] || fail "caller strong setnetent did not override the archive weak binding"
[ "$override_host_address" != "$override_net_address" ] ||
    fail "caller strong setnetent still has the archive alias address"
if nm -g --defined-only --format=posix "$override_candidate" |
    awk '$1 == "setnetent" && $2 == "W" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail "caller override retained the archive weak setnetent binding"
fi
"$override_candidate" || fail "freestanding setnetent override fixture failed"

printf 'x86 static libc sethostent/setnetent: PASS\n'
