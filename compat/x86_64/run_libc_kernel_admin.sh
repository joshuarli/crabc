#!/usr/bin/env bash
# Pinned-musl and installed-owned x86 kernel-administration ABI evidence.
#
# One C object compiled by the installed dynamic driver is linked unchanged by
# pinned musl, the owned static ET_EXEC/static-PIE drivers, and owned dynamic
# PIE/non-PIE drivers. It reads ARCH_GET_FS/ARCH_GET_GS and performs only
# non-mutating invalid arch_prctl calls; iopl/ioperm retain their invalid-only
# EINVAL-versus-EPERM fingerprint. No success case grants I/O access and the
# runner requests no capability or seccomp exception.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/libc_kernel_admin_probe.c"
readonly ARCH_SOURCE="$ROOT/libc/src/c_abi/x86_64/arch_prctl.rs"
readonly IO_SOURCE="$ROOT/libc/src/c_abi/x86_64/io_permissions.rs"
readonly STATIC_PROVIDER_READER="$ROOT/compat/x86_64/kernel_admin_static_provider_reader.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

fail() {
    printf 'ERROR: x86 owned kernel administration: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_checkout_work() {
    local temporary="${TMPDIR:-}"
    [ -n "$temporary" ] || fail "TMPDIR must name checkout-local .work scratch"
    [ -d "$temporary" ] || fail "TMPDIR is not a directory: $temporary"
    [ "$(realpath "$temporary")" = "$temporary" ] ||
        fail "TMPDIR must be a physical checkout-local .work directory"
    case "$temporary" in
        "$ROOT"/.work/*) ;;
        *) fail "TMPDIR escapes checkout .work: $temporary" ;;
    esac
}

assert_provider_symbols() {
    local artifact="$1" selector="$2" report="$3" inspection_dir

    if [ "$selector" = archive ]; then
        # `nm` distinguishes only weak/strong binding here; it cannot prove
        # ELF DEFAULT visibility. Extract the defining archive members and
        # validate their raw symbol table metadata instead.
        inspection_dir="$work/static-provider-symbol-objects"
        mkdir "$inspection_dir"
        (
            cd "$inspection_dir"
            ar x "$artifact"
        )
        readelf --wide --symbols "$inspection_dir"/* >"$report"
        python3 -B "$STATIC_PROVIDER_READER" "$report"
    else
        readelf --dyn-syms --wide "$artifact" >"$report"
        python3 -B - "$report" <<'PY'
from pathlib import Path
import sys

expected = {"arch_prctl", "iopl", "ioperm"}
seen = set()
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in expected:
        if fields[3:6] != ["FUNC", "GLOBAL", "DEFAULT"] or fields[6] == "UND":
            raise SystemExit(f"shared provider shape mismatch: {fields}")
        seen.add(fields[7])
if seen != expected:
    raise SystemExit(f"shared providers missing: {expected - seen}")
PY
    fi
}

assert_provider_instructions() {
    local artifact="$1" label="$2" symbol immediate report inspection_dir="" inspected_artifact
    local raw_helper_suffix raw_helper_line raw_helper_object raw_helper_symbol raw_helper_report

    # Archive members must be selected before GNU objdump can disassemble a
    # named Rust C ABI symbol. A linked shared library is already one ELF file.
    inspected_artifact="$artifact"
    if ar t "$artifact" >/dev/null 2>&1; then
        inspection_dir="$work/$label-provider-objects"
        mkdir "$inspection_dir"
        (
            cd "$inspection_dir"
            ar x "$artifact"
        )
    fi

    for symbol in arch_prctl iopl ioperm; do
        case "$symbol" in
            arch_prctl)
                immediate='\$0x9e(,|[[:space:]]|$)'
                raw_helper_suffix=syscall2
                ;;
            iopl)
                immediate='\$0xac(,|[[:space:]]|$)'
                raw_helper_suffix=syscall1
                ;;
            ioperm)
                immediate='\$0xad(,|[[:space:]]|$)'
                raw_helper_suffix=syscall3
                ;;
        esac
        report="$work/$label-$symbol.disassembly"
        if [ -n "$inspection_dir" ]; then
            inspected_artifact="$(nm -A --defined-only "$inspection_dir"/* |
                awk -v name="$symbol" '$NF == name && $(NF - 1) == "T" && !found { sub(/:.*/, "", $1); result = $1; found = 1 } END { print result }')"
            [ -n "$inspected_artifact" ] || fail "$label archive lacks $symbol object"
        fi
        objdump -dr --disassemble="$symbol" "$inspected_artifact" >"$report"
        grep -Eq "$immediate" "$report" ||
            fail "$label $symbol has the wrong Linux syscall number"
        if ! grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$report"; then
            if [ -n "$inspection_dir" ]; then
                raw_helper_line="$(nm -A --defined-only "$inspection_dir"/* |
                    awk -v suffix="$raw_helper_suffix" '$NF ~ ("raw_syscall.*" suffix) && !found { path = $1; sub(/:.*/, "", path); print path "\t" $NF; found = 1 } END { }')"
            else
                raw_helper_line="$(nm -A --defined-only "$artifact" |
                    awk -v suffix="$raw_helper_suffix" '$NF ~ ("raw_syscall.*" suffix) && !found { path = $1; sub(/:.*/, "", path); print path "\t" $NF; found = 1 } END { }')"
            fi
            raw_helper_object="${raw_helper_line%%$'\t'*}"
            raw_helper_symbol="${raw_helper_line#*$'\t'}"
            [ -n "$raw_helper_object" ] && [ "$raw_helper_symbol" != "$raw_helper_line" ] ||
                fail "$label lacks the raw $raw_helper_suffix helper"
            raw_helper_report="$work/$label-$symbol-$raw_helper_suffix.disassembly"
            objdump -d --disassemble="$raw_helper_symbol" "$raw_helper_object" >"$raw_helper_report"
            grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$raw_helper_report" ||
                fail "$label $symbol helper lacks a syscall instruction"
            grep -Fq "$raw_helper_symbol" "$report" ||
                fail "$label $symbol does not call its raw $raw_helper_suffix helper"
        fi
        if [ "$symbol" != arch_prctl ] &&
            grep -Eq '(^|[[:space:]])(in|out)([bwl])?([[:space:]]|$)|(^|[[:space:]])(ins|outs)[bwl]([[:space:]]|$)' "$report"; then
            fail "$label $symbol unexpectedly contains a port-I/O instruction"
        fi
    done
}

assert_executable_shape() {
    local binary="$1" mode="$2" header="$work/$mode.header" programs="$work/$mode.programs"
    local dynamic="$work/$mode.dynamic" symbols="$work/$mode.symbols"

    readelf --file-header --wide "$binary" >"$header"
    readelf --program-headers --wide "$binary" >"$programs"
    readelf --dynamic --wide "$binary" >"$dynamic" || true
    readelf --symbols --wide "$binary" >"$symbols"
    for symbol in arch_prctl iopl ioperm; do
        grep -Eq "[[:space:]]${symbol}$" "$symbols" ||
            fail "$mode executable does not retain $symbol"
    done
    case "$mode" in
        static)
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$header" ||
                fail "static executable is not ET_EXEC"
            if grep -Eq 'Requesting program interpreter|NEEDED' "$programs" "$dynamic"; then
                fail "static executable selects a dynamic runtime"
            fi
            ;;
        static-pie)
            grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' "$header" ||
                fail "static-PIE executable is not ET_DYN"
            if grep -Eq 'Requesting program interpreter|NEEDED' "$programs" "$dynamic"; then
                fail "static-PIE executable selects a dynamic runtime"
            fi
            ;;
        dynamic-pie)
            grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' "$header" ||
                fail "dynamic PIE executable is not ET_DYN"
            ;;
        dynamic-non-pie)
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' "$header" ||
                fail "dynamic non-PIE executable is not ET_EXEC"
            ;;
    esac
    case "$mode" in
        dynamic-*)
            grep -Fq "Requesting program interpreter: $INTERPRETER" "$programs" ||
                fail "$mode has the wrong interpreter"
            grep -Fq 'Shared library: [libc.so]' "$dynamic" ||
                fail "$mode does not depend on owned libc.so"
            ;;
    esac
}

capture_status() {
    local label="$1"
    shift
    local status

    set +e
    timeout 20 env -i PATH="$PATH" chroot "$work/root" "$@" \
        >"$work/$label.stdout" 2>"$work/$label.stderr"
    status=$?
    set -e
    (( status <= 85 )) || fail "$label exited $status instead of an I/O errno fingerprint"
    printf '%s\n' "$status" >"$work/$label.status"
    printf '%s' "$status"
}

compare_mode() {
    local label="$1"
    shift
    local status

    status="$(capture_status "$label" "$@")"
    [ "$status" = "$oracle_status" ] ||
        fail "$label fingerprint differs from pinned musl ($status != $oracle_status)"
    cmp "$work/oracle.stdout" "$work/$label.stdout" || fail "$label stdout differs from pinned musl"
    cmp "$work/oracle.stderr" "$work/$label.stderr" || fail "$label stderr differs from pinned musl"
}

require_checkout_work
for tool in ar cmp gcc grep nm objdump python3 readelf realpath sha256sum timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
for path in "$PROBE" "$ARCH_SOURCE" "$IO_SOURCE" "$STATIC_PROVIDER_READER"; do
    [ -f "$path" ] || fail "missing source input: $path"
done

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
work="$(mktemp -d "$TMPDIR/owned-kernel-admin.XXXXXX")"
readonly work
chmod a+rx "$work"
mkdir -p "$work/root"

for marker in \
    'src/linux/arch_prctl.c::arch_prctl' 'SYS_ARCH_PRCTL' \
    'pub unsafe extern "C" fn arch_prctl' 'ARCH_GET_FS' 'ARCH_GET_GS' \
    'src/linux/iopl.c::iopl' 'src/linux/ioperm.c::ioperm'; do
    grep -Fq "$marker" "$ARCH_SOURCE" "$IO_SOURCE" "$PROBE" ||
        fail "kernel-administration inputs omit $marker"
done

# Both product builders select the owned runtime. Its dependency graph in
# libc/Cargo.toml includes x86-kernel-admin and the retained x86-io-permissions
# leaf; the standalone I/O-only archive remains a separate selected profile.
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
    --output "$work/static-sysroot" >"$work/static-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
    --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"

readonly static_product="$work/static-sysroot"
readonly dynamic_product="$work/dynamic-sysroot"
# The sealed installed driver intentionally rejects preprocessing controls.
# Use GCC only as a no-link header tracer with its builtin and ambient include
# roots disabled; the installed driver below compiles the one candidate object.
gcc -std=c11 -nostdinc -isystem "$dynamic_product/usr/include" -H -E "$PROBE" \
    >/dev/null 2>"$work/header-trace"
for header in errno.h stdint.h sys/io.h sys/syscall.h bits/syscall.h; do
    grep -Fq "$dynamic_product/usr/include/$header" "$work/header-trace" ||
        fail "installed workload omitted <$header>"
done
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
sha256sum "$PROBE" "$work/workload.o" >"$work/input.sha256"

assert_provider_symbols "$static_product/usr/lib/libc.a" archive "$work/static-symbols"
assert_provider_symbols "$dynamic_product/usr/lib/libc.so" shared "$work/dynamic-symbols"
assert_provider_instructions "$static_product/usr/lib/libc.a" static-archive
assert_provider_instructions "$dynamic_product/usr/lib/libc.so" shared-libc

"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -o "$work/root/oracle"
oracle_status="$(capture_status oracle /oracle)"

for mode in static static-pie; do
    binary="$work/root/$mode"
    "$static_product/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$binary"
    assert_executable_shape "$binary" "$mode"
    compare_mode "$mode" "/$mode"
done

cp -a "$dynamic_product/." "$work/root/"
for mode in pie non-pie; do
    binary="$work/root/dynamic-$mode"
    "$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$binary"
    assert_executable_shape "$binary" "dynamic-$mode"
    compare_mode "dynamic-$mode-kernel" "/dynamic-$mode"
    compare_mode "dynamic-$mode-direct" "$INTERPRETER" "/dynamic-$mode"
done

sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf '%s\n' \
    "x86 owned kernel administration: PASS (same object; pinned musl, static/static-PIE, dynamic PIE/non-PIE kernel/direct; ARCH_GET_FS/GS, non-mutating failures, invalid iopl/ioperm only); evidence: $work"
