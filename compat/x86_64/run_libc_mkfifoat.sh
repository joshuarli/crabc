#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc mkfifoat evidence.
#
# One project-header C fixture first runs through pinned musl 1.2.6 and then
# as a true `-nostdlib -static` candidate linked only with the selected crabc
# archive. Ordered case records compare CWD and caller-supplied-dirfd
# resolution, kernel mode masking, pathname errors, and fixture cleanup.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc mkfifoat: %s\n' "$*" >&2
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

assert_static_closure() {
    local candidate_path="$1"
    local symbols_path="$work_dir/candidate-symbols"
    local headers_path="$work_dir/candidate-program-headers"
    local dynamic_path="$work_dir/candidate-dynamic"
    local relocs_path="$work_dir/candidate-relocations"
    local disassembly_path="$work_dir/candidate-disassembly"
    local errno_disassembly="$work_dir/candidate-errno-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep . >/dev/null; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers_path" "$dynamic_path"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path" ||
        fail "candidate lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols_path" "$disassembly_path"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    objdump -d --disassemble=__errno_location "$candidate_path" >"$errno_disassembly"
    grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
        fail "candidate errno does not use direct fs initial TLS"
}

require_native_linux_x86_64
for tool in ar awk cargo chmod cmp cp diff grep mkdir mktemp nm objdump readelf rmdir rustup sha256sum sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_mkfifoat_header_abi.sh" >/dev/null

report_root="$ROOT_DIR/.work/x86_64/reports/libc-mkfifoat"
mkdir -p "$report_root"
work_dir="$(mktemp -d "$report_root/run.XXXXXX")"
chmod 755 "$work_dir"
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-mkfifoat-reference"
candidate="$work_dir/crabc-static-mkfifoat-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
mkfifoat_disassembly="$work_dir/mkfifoat-disassembly"
reference_stdout="$work_dir/musl.stdout"
reference_stderr="$work_dir/musl.stderr"
candidate_stdout="$work_dir/crabc.stdout"
candidate_stderr="$work_dir/crabc.stderr"

cd "$ROOT_DIR"
mkdir "$reference_work" "$candidate_work"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_mkfifoat_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stdint.h sys/stat.h sys/syscall.h sys/types.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_mkfifoat_probe.c -o "$reference"
if (cd "$reference_work" && (umask 000; "$reference")) \
    >"$reference_stdout" 2>"$reference_stderr"; then
    printf '0\n' >"$work_dir/musl.exit"
else
    status=$?
    printf '%s\n' "$status" >"$work_dir/musl.exit"
    fail "pinned-musl mkfifoat fixture exited $status; raw evidence: $work_dir"
fi

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap mkfifoat; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -DCRABC_MKFIFOAT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_mkfifoat_probe.c compat/x86_64/libc_mkfifoat_start.S \
    "$archive" -o "$candidate"
assert_static_closure "$candidate"

if grep -Eq '[[:space:]](mkfifo|mknod|mknodat)$' "$work_dir/candidate-symbols"; then
    fail "mkfifoat candidate exports an unselected special-node entry"
fi
objdump -d --disassemble=mkfifoat "$candidate" >"$mkfifoat_disassembly"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$mkfifoat_disassembly" ||
    fail "mkfifoat lacks a direct Linux syscall"
grep -Eq '\$0x103,%e?ax' "$mkfifoat_disassembly" ||
    fail "mkfifoat lacks Linux x86-64 mknodat=259"
if grep -Eq 'call.*(mkfifo|mknod|mknodat|umask)' "$mkfifoat_disassembly"; then
    fail "mkfifoat delegates to an unselected C entry"
fi

(cd "$candidate_work" && (umask 000; "$candidate")) \
    >"$candidate_stdout" 2>"$candidate_stderr" && status=0 || status=$?
printf '%s\n' "$status" >"$work_dir/crabc.exit"
if [ "$status" -ne 0 ]; then
    fail "freestanding mkfifoat fixture exited $status; raw evidence: $work_dir"
fi
[ -s "$reference_stdout" ] || fail "pinned-musl fixture emitted no cases"
if ! cmp -s "$reference_stdout" "$candidate_stdout"; then
    diff -u "$reference_stdout" "$candidate_stdout" >&2 || true
    fail "mkfifoat case records differ; raw evidence: $work_dir"
fi
if ! cmp -s "$reference_stderr" "$candidate_stderr"; then
    diff -u "$reference_stderr" "$candidate_stderr" >&2 || true
    fail "mkfifoat stderr differs; raw evidence: $work_dir"
fi
rmdir "$reference_work" "$candidate_work" ||
    fail "mkfifoat fixture left filesystem entries; raw evidence: $work_dir"

cp "$ROOT_DIR/compat/x86_64/libc_mkfifoat_probe.c" "$work_dir/"
cp "$ROOT_DIR/compat/x86_64/libc_mkfifoat_start.S" "$work_dir/"
cp "$ROOT_DIR/compat/x86_64/run_libc_mkfifoat.sh" "$work_dir/"
(
    cd "$work_dir"
    sha256sum musl-mkfifoat-reference crabc-static-mkfifoat-candidate \
        musl.stdout musl.stderr musl.exit crabc.stdout crabc.stderr crabc.exit \
        libc_mkfifoat_probe.c libc_mkfifoat_start.S run_libc_mkfifoat.sh \
        candidate-program-headers candidate-symbols mkfifoat-disassembly \
        selected-c-abi-symbols >sha256sums.txt
)

cat "$reference_stdout"
printf 'mkfifoat physical receipt: %s\n' "$work_dir"
printf 'x86 static crabc-libc mkfifoat: PASS\n'
