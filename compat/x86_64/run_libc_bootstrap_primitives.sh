#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc bootstrap-primitives evidence.
#
# A single freestanding C executable resolves the selected musl-derived bulk
# memory, fenv, and setjmp leaves from the x86 `libc.a` after the same semantic
# fixture passes under pinned musl. This is an artifact boundary, not a claim
# to a general libc, libc.so, CRT, pthread/TLS lifecycle, dynamic loader, or
# sysroot.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly SOURCE="$ROOT_DIR/compat/x86_64/libc_bootstrap_primitives_probe.c"
static_input=''
dynamic_input=''

usage() {
    printf 'usage: %s [--static-product STATIC_PRODUCT --dynamic-product DYNAMIC_PRODUCT]\n' "$0" >&2
    exit 2
}

if [ "$#" -eq 4 ] && [ "$1" = --static-product ] && [ "$3" = --dynamic-product ]; then
    static_input="$2"
    dynamic_input="$4"
elif [ "$#" -ne 0 ]; then
    usage
fi

fail() {
    printf 'ERROR: x86 static libc bootstrap primitives: %s\n' "$*" >&2
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

require_scratch_root() {
    local scratch="${TMPDIR:-}"
    case "$scratch" in
        "$ROOT_DIR"/.work/x86_64/*) ;;
        *) fail "TMPDIR must be a physical checkout .work/x86_64 directory" ;;
    esac
    [ -d "$scratch" ] && [ "$(realpath "$scratch")" = "$scratch" ] \
        || fail "TMPDIR must be a physical checkout .work/x86_64 directory"
}

assert_selected_c_abi_surface() {
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members

    # `libc/Cargo.toml` fixes the Rust staticlib crate name to `c`. Its archive
    # also contains compiler-builtins members, which are toolchain support and
    # not crabc's C ABI surface. Inspect only the `c.*.rcgu.o` members so this
    # gate catches a new C export from the selected runtime. The signal
    # restorer is the one audited hidden frame-internal exception.
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

require_native_linux_x86_64
for tool in ar cargo cmp diff nm objdump readelf realpath rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
require_scratch_root

validate_installed_products() {
    local checked
    checked="$(python3 -B - "$ROOT_DIR" "$static_input" "$dynamic_input" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_dynamic_qualification as dynamic
import owned_posix_product_evidence as products

try:
    selected = []
    for kind, raw in (('static', sys.argv[2]), ('dynamic', sys.argv[3])):
        path = products._physical_directory(Path(raw).absolute(), f'{kind} product')
        if not path.is_relative_to(root / '.work') or path == root / '.work':
            raise products.ProductEvidenceError(f'{kind} product must be a physical checkout .work child')
        if kind == 'static':
            products._validate_static_product(path)
        else:
            products._validate_dynamic_product(path)
        selected.append(path)
    if selected[0] == selected[1]:
        raise products.ProductEvidenceError('static and dynamic products must be separate')
    source = dynamic.source_digest()
    for kind, path in zip(('static', 'dynamic'), selected):
        product_format = products.STATIC_PRODUCT_FORMAT if kind == 'static' else products.DYNAMIC_PRODUCT_FORMAT
        _, manifest, _ = products._product_manifest(path, kind, product_format)
        if manifest.get('source_sha256') != source:
            raise products.ProductEvidenceError(f'{kind} product source differs from the current checkout')
        print(path)
except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit(str(error))
PY
)" || exit 1
    mapfile -t checked_products <<<"$checked"
    [ "${#checked_products[@]}" -eq 2 ] || fail "installed product selection is incomplete"
    static_input="${checked_products[0]}"
    dynamic_input="${checked_products[1]}"
}

if [ -n "$static_input" ]; then
    for tool in cp env python3 timeout; do
        require_tool "$tool"
    done
    validate_installed_products
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-64-libc-bootstrap-primitives.XXXXXX")"
if [ -n "$static_input" ]; then
    chmod a+rx "$work_dir"
    trap 'status=$?; if [ "$status" -ne 0 ]; then printf "x86 static crabc-libc bootstrap primitives failed; evidence: %s\\n" "$work_dir" >&2; fi' EXIT
else
    trap 'rm -rf -- "$work_dir"' EXIT
fi
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-bootstrap-primitives-reference"
candidate="$work_dir/crabc-static-bootstrap-primitives-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

if [ -n "$static_input" ]; then
    umask 022
    ulimit -c 0
    readonly static_product="$static_input"
    readonly dynamic_product="$dynamic_input"
    readonly candidate_object="$work_dir/workload.o"
    readonly oracle_binary="$work_dir/oracle"
    readonly candidate_env=(/usr/bin/env -i PATH=/usr/bin:/bin "TMPDIR=$TMPDIR" /usr/bin/timeout 60s)
    readonly runtime_env=(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/timeout 10s)
    readonly dynamic_pie_root="$work_dir/dynamic-pie-root"
    readonly dynamic_non_pie_root="$work_dir/dynamic-non-pie-root"
    cd "$work_dir"

    run_recorded() {
        local label="$1"
        local output="$2"
        local status=0
        shift 2
        "$@" >"$work_dir/$label.stdout" 2>"$work_dir/$label.stderr" || status=$?
        printf '%s\n' "$status" >"$work_dir/$label.status"
        python3 -B - "$work_dir/$label.command.json" "$work_dir" "$status" "$output" "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

record_path = Path(sys.argv[1])
cwd = sys.argv[2]
status = int(sys.argv[3])
output = sys.argv[4]
argv = sys.argv[5:]
identity = None
if output != '-' and Path(output).is_file() and not Path(output).is_symlink():
    data = Path(output).read_bytes()
    identity = {'path': output, 'sha256': hashlib.sha256(data).hexdigest()}
with record_path.open('x', encoding='utf-8', newline='\n') as stream:
    json.dump({'argv': argv, 'cwd': cwd, 'status': status, 'output': identity},
              stream, sort_keys=True, separators=(',', ':'))
    stream.write('\n')
PY
        [ "$status" -eq 0 ] || fail "$label exited with status $status; raw evidence retained"
    }

    compare_bootstrap_run() {
        local candidate="$1"
        local stream
        for stream in status stdout stderr; do
            cmp "$work_dir/run-oracle.$stream" "$work_dir/$candidate.$stream" \
                || fail "$candidate differs from pinned musl in $stream"
        done
    }

    step=installed-candidate-compile
    run_recorded compile-candidate "$candidate_object" "${candidate_env[@]}" \
        "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE \
        -fno-builtin -fno-stack-protector -H -c "$SOURCE" -o "$candidate_object"

    step=installed-musl-link
    run_recorded link-oracle "$oracle_binary" "${candidate_env[@]}" "$ORACLE_CC" \
        -static -fno-pie -no-pie "$candidate_object" -o "$oracle_binary"

    step=installed-musl-oracle
    run_recorded run-oracle - "${runtime_env[@]}" "$oracle_binary"

    for mode in static static-pie; do
        step="installed-$mode-link"
        run_recorded "link-$mode" "$work_dir/$mode" "${candidate_env[@]}" \
            "$static_product/bin/crabc-cc" "-$mode" --link-receipt "$mode.receipt.json" \
            "$candidate_object" -o "$work_dir/$mode"
    done
    for mode in dynamic-pie dynamic-non-pie; do
        step="installed-$mode-link"
        run_recorded "link-$mode" "$work_dir/$mode" "${candidate_env[@]}" \
            "$dynamic_product/bin/crabc-cc-dynamic" "--$mode" "$candidate_object" \
            -o "$work_dir/$mode"
    done

    step=dynamic-pie-payload-copy
    cp -a "$dynamic_product" "$dynamic_pie_root"
    cp "$work_dir/dynamic-pie" "$dynamic_pie_root/consumer"
    step=dynamic-non-pie-payload-copy
    cp -a "$dynamic_product" "$dynamic_non_pie_root"
    cp "$work_dir/dynamic-non-pie" "$dynamic_non_pie_root/consumer"
    for mode in dynamic-pie dynamic-non-pie; do
        root="$work_dir/$mode-root"
        step="$mode-payload-record"
        python3 -B "$ROOT_DIR/compat/x86_64/owned_crypt_runtime_evidence.py" record \
            --product "$dynamic_product" --execution-root "$root" \
            --source-consumer "$work_dir/$mode" --execution-consumer "$root/consumer" \
            --record "$work_dir/$mode-payload.json"
        step="$mode-payload-before-audit"
        python3 -B "$ROOT_DIR/compat/x86_64/owned_crypt_runtime_evidence.py" audit \
            --product "$dynamic_product" --execution-root "$root" \
            --source-consumer "$work_dir/$mode" --execution-consumer "$root/consumer" \
            --record "$work_dir/$mode-payload.json" >/dev/null
    done

    step=run-static
    run_recorded run-static - "${runtime_env[@]}" "$work_dir/static"
    compare_bootstrap_run run-static
    step=run-static-pie
    run_recorded run-static-pie - "${runtime_env[@]}" "$work_dir/static-pie"
    compare_bootstrap_run run-static-pie
    for mode in dynamic-pie dynamic-non-pie; do
        root="$work_dir/$mode-root"
        step="run-$mode-kernel"
        run_recorded "run-$mode-kernel" - "${runtime_env[@]}" /usr/sbin/chroot "$root" /consumer
        compare_bootstrap_run "run-$mode-kernel"
        step="run-$mode-direct"
        run_recorded "run-$mode-direct" - "${runtime_env[@]}" /usr/sbin/chroot "$root" \
            /lib/ld-crabc-x86_64.so.1 /consumer
        compare_bootstrap_run "run-$mode-direct"
    done

    for mode in dynamic-pie dynamic-non-pie; do
        root="$work_dir/$mode-root"
        step="$mode-payload-after-audit"
        python3 -B "$ROOT_DIR/compat/x86_64/owned_crypt_runtime_evidence.py" audit \
            --product "$dynamic_product" --execution-root "$root" \
            --source-consumer "$work_dir/$mode" --execution-consumer "$root/consumer" \
            --record "$work_dir/$mode-payload.json" >/dev/null
    done

    step=installed-bootstrap-replay
    python3 -B - "$ROOT_DIR" "$work_dir" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root, work, static, dynamic = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_native_observations as observations

observations.collect_bootstrap_primitives(
    work, static_product=static, dynamic_product=dynamic,
)
PY
    printf 'x86 installed crabc-libc bootstrap primitives: PASS (four sealed links, six execution modes); evidence: %s\n' "$work_dir"
    exit 0
fi

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_bootstrap_primitives_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fenv.h setjmp.h bits/setjmp.h features.h signal.h bits/alltypes.h bits/signal.h string.h strings.h sys/mman.h \
    sys/syscall.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    compat/x86_64/libc_bootstrap_primitives_probe.c -o "$reference"
"$reference"

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location stat lstat fstat fstatat __xstat __lxstat __fxstat \
    __fxstatat setgroups setuid setgid setresuid setresgid seteuid setegid \
    setreuid setregid memcpy memmove memset memcmp bcmp feclearexcept feraiseexcept \
    fegetround fegetenv fesetenv fetestexcept fegetexceptflag feholdexcept \
    fesetexceptflag fesetround feupdateenv __flt_rounds setjmp __setjmp _setjmp \
    longjmp _longjmp sigsetjmp __sigsetjmp siglongjmp; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not define ${symbol}"
done
for unselected in syscall malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" \
    || fail "archive errno lacks an initial-TLS TPOFF relocation"
# Rust's static object retains a local DTPOFF link relocation for ERRNO. The
# final static candidate must resolve that relocation, and rejects every TLS
# model form below; an archive-level DTPOFF match alone is not dynamic TLS.
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_BOOTSTRAP_PRIMITIVES_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    compat/x86_64/libc_bootstrap_primitives_probe.c \
    compat/x86_64/libc_bootstrap_primitives_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location memcpy memmove memset memcmp bcmp feclearexcept feraiseexcept \
    fegetround fegetenv fesetenv fetestexcept fesetround setjmp longjmp sigsetjmp \
    siglongjmp; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
    || fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" \
    || fail "candidate errno does not use direct fs initial TLS"
for instruction in fnstenv fldenv stmxcsr ldmxcsr fnclex; do
    grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$candidate_disassembly" \
        || fail "candidate lacks ${instruction}"
done
# The bulk-memory leaf's backward memmove never sets the direction flag.
if grep -Eq "[[:space:]]std([[:space:]]|$)" "$candidate_disassembly"; then
    fail "candidate sets the direction flag"
fi
grep -Eq 'rep[[:space:]]+movs' "$candidate_disassembly" \
    || fail "candidate lacks the selected string-copy instruction path"

"$candidate"

printf 'x86 static crabc-libc bootstrap primitives: PASS\n'
