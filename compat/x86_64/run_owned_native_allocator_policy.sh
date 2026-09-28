#!/usr/bin/env bash
# Installed native-shadow libc malloc-family policy against pinned musl.
#
# Three unmodified C programs define the `memory.allocator-basic` and
# `memory.allocator-observability` policy: the allocator-basic runtime probe
# (zero size, natural and explicit alignment, calloc overflow, realloc
# failure and realloc(p, 0), posix_memalign output preservation, errno,
# threads, fork/atfork, atexit allocation), the observability fixture
# (malloc_usable_size), and the size-class policy probe (the same rules
# across small through huge blocks). Each runs through pinned musl and then
# through the native-shadow static, static-PIE and dynamic PIE/non-PIE
# (kernel and direct loader) products, which must reproduce musl's exit
# status and transcript. Without supplied products the runner builds both
# native-shadow sysroots.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly programs=(basic observability policy)
readonly receipt_runner=owned-native-allocator-policy
readonly case_timeout=120

source_seal() {
    python3 -B - "$ROOT" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
from native_shadow_receipt import source_seal
print(json.dumps(source_seal(root), sort_keys=True, separators=(',', ':')))
PY
}

program_source() {
    case "$1" in
        basic) printf '%s\n' "$ROOT/compat/x86_64/libc_allocator_basic_runtime_v1_probe.c" ;;
        observability) printf '%s\n' "$ROOT/tests/fixtures/allocator_observability_test.c" ;;
        policy) printf '%s\n' "$ROOT/compat/x86_64/owned_native_allocator_policy_probe.c" ;;
    esac
}

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

static_sysroot=''
dynamic_sysroot=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$static_sysroot" ] && [ -n "$2" ] || usage
            static_sysroot="$(realpath -e "$2")"
            shift 2
            ;;
        -*|'') usage ;;
        *)
            [ -z "$dynamic_sysroot" ] || usage
            dynamic_sysroot="$(realpath -e "$1")"
            shift
            ;;
    esac
done

python3 -B - "$ROOT" "${TMPDIR:-}" "$static_sysroot" "$dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('native-allocator-policy TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    if argument and not Path(argument).is_relative_to(root / '.work'):
        raise SystemExit('native-allocator-policy products must be checkout .work directories')
PY

work="$(mktemp -d "$TMPDIR/owned-native-allocator-policy.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-allocator-policy evidence: %s\n' "$work"

rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
receipt_cases=()
receipt_products=()
source_before="$(source_seal)"
publish_receipt() {
    local status=$?
    trap - EXIT
    local source_after=''
    if ! source_after="$(source_seal)" || [ "$source_after" != "$source_before" ]; then
        printf 'native-allocator-policy: source changed during the run\n' >&2
        status=1
    fi
    printf '%s\n' "$status" >"$work/runner.status"
    receipt_cases+=("runner=$status:runner.status")
    local -a arguments=(--runner "$receipt_runner" --work "$work" --canonical yes
        --parameter "CASE_TIMEOUT=$case_timeout"
        --parameter 'PROGRAMS=basic,observability,policy'
        --parameter 'STATIC_MODES=static,static-pie'
        --parameter 'DYNAMIC_MODES=kernel-pie,direct-pie,kernel-non-pie,direct-non-pie'
        --parameter 'ENVIRONMENT=empty-with-pinned-PATH')
    local entry
    for entry in "${receipt_cases[@]}"; do arguments+=(--case "$entry"); done
    for entry in "${receipt_products[@]}"; do arguments+=(--product "$entry"); done
    if ! python3 -B "$ROOT/compat/x86_64/native_shadow_receipt.py" write "${arguments[@]}"; then
        status=1
    elif [ "$(source_seal)" != "$source_before" ]; then
        rm -rf "$ROOT/.work/x86_64/reports/native-shadow/$receipt_runner/latest"
        printf 'native-allocator-policy: source changed while publishing the receipt\n' >&2
        status=1
    fi
    exit "$status"
}
trap publish_receipt EXIT

if [ -z "$static_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --output "$work/static-sysroot" >"$work/static-build.json"
    static_sysroot="$work/static-sysroot"
fi
if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
python3 -B - "$static_sysroot/share/crabc/manifest.json" \
    "$dynamic_sysroot/share/crabc/libc-shared.provenance.json" <<'PY'
import json
import sys
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as stream:
        backend = json.load(stream).get('allocator_backend')
    if backend != 'native-shadow':
        raise SystemExit(f'{path}: allocator_backend is {backend!r}, not native-shadow')
PY
receipt_products+=(
    "static-manifest=$static_sysroot/share/crabc/manifest.json"
    "static-libc-provenance=$static_sysroot/share/crabc/libc-static.provenance.json"
    "static-libc-archive=$static_sysroot/usr/lib/libc.a"
    "static-driver=$static_sysroot/bin/crabc-cc"
    "static-crt1=$static_sysroot/usr/lib/crt1.o"
    "static-rcrt1=$static_sysroot/usr/lib/rcrt1.o"
    "static-crti=$static_sysroot/usr/lib/crti.o"
    "static-crtn=$static_sysroot/usr/lib/crtn.o"
    "static-builtins=$static_sysroot/usr/lib/libcrabc-builtins.a"
    "dynamic-manifest=$dynamic_sysroot/share/crabc/manifest.json"
    "dynamic-product-state=$dynamic_sysroot/share/crabc/dynamic-product-state.json"
    "dynamic-libc-provenance=$dynamic_sysroot/share/crabc/libc-shared.provenance.json"
    "dynamic-driver=$dynamic_sysroot/bin/crabc-cc-dynamic"
    "dynamic-libc=$work/execution-root/usr/lib/libc.so"
    "dynamic-loader=$work/execution-root/lib/ld-crabc-x86_64.so.1"
    "dynamic-crt1=$dynamic_sysroot/usr/lib/crt1.o"
    "dynamic-scrt1=$dynamic_sysroot/usr/lib/Scrt1.o"
    "dynamic-crti=$dynamic_sysroot/usr/lib/crti.o"
    "dynamic-crtn=$dynamic_sysroot/usr/lib/crtn.o"
    "dynamic-attach=$dynamic_sysroot/usr/lib/crabc-dynamic-attach.o"
    "dynamic-builtins=$dynamic_sysroot/usr/lib/libcrabc-builtins.a"
)
readonly oracle_musl_lib=/opt/musl-1.2.6/lib
readonly oracle_gcc="$(realpath -e /usr/bin/gcc)"
readonly oracle_libgcc="$(realpath -e "$("$oracle_cc" -print-libgcc-file-name)")"
readonly oracle_libgcc_eh="$(realpath -e "$("$oracle_cc" -print-file-name=libgcc_eh.a)")"
readonly oracle_crtbegin="$(realpath -e "$("$oracle_cc" -print-file-name=crtbeginS.o)")"
readonly oracle_crtend="$(realpath -e "$("$oracle_cc" -print-file-name=crtendS.o)")"
receipt_products+=(
    "oracle-wrapper=$oracle_cc"
    "oracle-gcc=$oracle_gcc"
    "oracle-specs=$oracle_musl_lib/musl-gcc.specs"
    "oracle-musl-libc=$oracle_musl_lib/libc.a"
    "oracle-musl-libssp=$oracle_musl_lib/libssp_nonshared.a"
    "oracle-musl-libpthread=$oracle_musl_lib/libpthread.a"
    "oracle-musl-scrt1=$oracle_musl_lib/Scrt1.o"
    "oracle-musl-crti=$oracle_musl_lib/crti.o"
    "oracle-musl-crtn=$oracle_musl_lib/crtn.o"
    "oracle-crtbegin=$oracle_crtbegin"
    "oracle-crtend=$oracle_crtend"
    "oracle-libgcc=$oracle_libgcc"
    "oracle-libgcc-eh=$oracle_libgcc_eh"
)
if [ -f "$work/static-build.json" ]; then receipt_products+=("static-build=$work/static-build.json"); fi
if [ -f "$work/dynamic-build.json" ]; then receipt_products+=("dynamic-build=$work/dynamic-build.json"); fi

# The allocator-basic probe builds a small symlink graph below the relative
# directory `.work/x86_64` and compares realpath results with getcwd, so
# every mode runs from a non-root directory that provides it.
mkdir -p "$work/host-cwd/.work/x86_64"
cp -a "$dynamic_sysroot" "$work/execution-root"
mkdir -p "$work/execution-root/run/.work/x86_64"
# chroot(1) always enters `/`; this enters the execution root at /run.
readonly enter_root=(python3 -B -c 'import os, sys; os.chroot(sys.argv[1]); os.chdir("/run"); os.execv(sys.argv[2], sys.argv[2:])'
    "$work/execution-root")

# Run one program in one mode; retain stdout, stderr and status, then compare
# status and stdout with the oracle's for the same program.
run_case() {
    local mode="$1"
    local program="$2"
    local name="$mode-$program"
    shift 2
    local status=0
    (cd "$work/host-cwd" && timeout "$case_timeout" env -i PATH="$PATH" "$@") \
        >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    receipt_cases+=("$name=$status:$name.stdout,$name.stderr,$name.status")
    if [ "$status" -ne 0 ] || [ -s "$work/$name.stderr" ]; then
        printf 'native-allocator-policy: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
    [ "$mode" != oracle ] || return 0
    cmp "$work/oracle-$program.stdout" "$work/$name.stdout" || {
        printf 'native-allocator-policy: %s transcript differs from musl\n' "$name" >&2
        return 1
    }
}

readonly common_flags=(-std=c11 -D_GNU_SOURCE -pthread -fno-builtin)
record_compile() {
    local mode="$1" program="$2" source="$3" object="$4" compiler="$5"
    python3 -B - "$ROOT" "$work" "$mode" "$program" "$source" "$object" "$compiler" \
        "$oracle_gcc" "$oracle_musl_lib/musl-gcc.specs" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root, work, mode, program, source, obj, compiler, gcc, specs = sys.argv[1:]
root, work, source, obj, compiler = map(Path, (root, work, source, obj, compiler))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
flags = ['-std=c11', '-D_GNU_SOURCE', '-pthread', '-fno-builtin']
selection = (['-static', '-fno-pie', '-no-pie'] if mode == 'oracle'
             else ['--dynamic-' + mode.removeprefix('dynamic-')] if mode.startswith('dynamic-')
             else ['-' + mode])
record = {
    'schema': 'crabc.x86_64-allocator-policy-compile/v1',
    'mode': mode, 'program': program,
    'source_path': source.relative_to(root).as_posix(), 'source_sha256': sha(source),
    'object_sha256': sha(obj), 'compiler_sha256': sha(compiler),
    'flags': selection + flags + ['-c'],
}
if mode == 'oracle':
    record['compiler_inputs'] = {
        'oracle-gcc': {'path': gcc, 'sha256': sha(Path(gcc))},
        'oracle-specs': {'path': specs, 'sha256': sha(Path(specs))},
    }
(work / f'compile-{mode}-{program}.json').write_text(json.dumps(record, sort_keys=True) + '\n')
PY
    receipt_products+=("compile-$mode-$program=$work/compile-$mode-$program.json")
    receipt_products+=("object-$mode-$program=$object")
}

record_oracle_link() {
    local program="$1"
    python3 -B - "$work" "$program" "$oracle_cc" "$oracle_gcc" \
        "$oracle_musl_lib" "$oracle_crtbegin" "$oracle_crtend" "$oracle_libgcc" "$oracle_libgcc_eh" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
work, program, compiler, gcc, musl, crtbegin, crtend, libgcc, libgcc_eh = sys.argv[1:]
work, compiler, gcc, musl, crtbegin, crtend, libgcc, libgcc_eh = map(
    Path, (work, compiler, gcc, musl, crtbegin, crtend, libgcc, libgcc_eh))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
runtime = {
    'oracle-musl-scrt1': musl / 'Scrt1.o', 'oracle-musl-crti': musl / 'crti.o',
    'oracle-musl-libc': musl / 'libc.a', 'oracle-musl-crtn': musl / 'crtn.o',
    'oracle-musl-libssp': musl / 'libssp_nonshared.a',
    'oracle-musl-libpthread': musl / 'libpthread.a',
    'oracle-crtbegin': crtbegin, 'oracle-crtend': crtend,
    'oracle-libgcc': libgcc, 'oracle-libgcc-eh': libgcc_eh,
}
record = {
    'schema': 'crabc.x86_64-allocator-policy-oracle-link/v1', 'program': program,
    'mode': 'static-et-exec', 'compiler_sha256': sha(compiler),
    'object_sha256': sha(work / f'object-oracle-{program}.o'),
    'object_path': str(work / f'object-oracle-{program}.o'),
    'output_sha256': sha(work / f'oracle-{program}.exe'),
    'output_path': str(work / f'oracle-{program}.exe'),
    'trace_sha256': sha(work / f'trace-oracle-{program}.txt'),
    'compiler_inputs': {
        'oracle-gcc': {'path': str(gcc), 'sha256': sha(gcc)},
        'oracle-specs': {'path': str(musl / 'musl-gcc.specs'), 'sha256': sha(musl / 'musl-gcc.specs')},
    },
    'runtime_inputs': {name: {'path': str(path), 'sha256': sha(path)} for name, path in sorted(runtime.items())},
    'flags': ['-static', '-fno-pie', '-no-pie', '-std=c11', '-D_GNU_SOURCE', '-pthread', '-fno-builtin'],
}
(work / f'link-oracle-{program}.json').write_text(json.dumps(record, sort_keys=True) + '\n')
PY
    receipt_products+=("link-oracle-$program=$work/link-oracle-$program.json")
    receipt_products+=("trace-oracle-$program=$work/trace-oracle-$program.txt")
}

for program in "${programs[@]}"; do
    source="$(program_source "$program")"
    receipt_products+=("source-$program=$source")
    "$oracle_cc" -static -fno-pie -no-pie "${common_flags[@]}" -c "$source" -o "$work/object-oracle-$program.o"
    record_compile oracle "$program" "$source" "$work/object-oracle-$program.o" "$oracle_cc"
    "$oracle_cc" -static -fno-pie -no-pie "${common_flags[@]}" -Wl,-t \
        "$work/object-oracle-$program.o" -o "$work/oracle-$program.exe" >"$work/trace-oracle-$program.txt"
    record_oracle_link "$program"
    receipt_products+=("oracle-$program=$work/oracle-$program.exe")
    run_case oracle "$program" "$work/oracle-$program.exe"
    for mode in static static-pie; do
        "$static_sysroot/bin/crabc-cc" "-$mode" "${common_flags[@]}" -c "$source" \
            -o "$work/object-$mode-$program.o"
        record_compile "$mode" "$program" "$source" "$work/object-$mode-$program.o" "$static_sysroot/bin/crabc-cc"
        (cd "$work" && "$static_sysroot/bin/crabc-cc" "-$mode" "${common_flags[@]}" \
            --link-receipt "link-$mode-$program.json" "$work/object-$mode-$program.o" \
            -o "$work/$mode-$program.exe")
        receipt_products+=(
            "link-$mode-$program=$work/link-$mode-$program.json"
            "map-$mode-$program=$work/link-$mode-$program.map"
            "trace-$mode-$program=$work/link-$mode-$program.trace"
        )
        receipt_products+=("$mode-$program=$work/$mode-$program.exe")
        run_case "$mode" "$program" "$work/$mode-$program.exe"
    done
    for mode in pie non-pie; do
        "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "${common_flags[@]}" -c "$source" \
            -o "$work/object-dynamic-$mode-$program.o"
        record_compile "dynamic-$mode" "$program" "$source" "$work/object-dynamic-$mode-$program.o" \
            "$dynamic_sysroot/bin/crabc-cc-dynamic"
        "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "${common_flags[@]}" \
            "$work/object-dynamic-$mode-$program.o" \
            -o "$work/dynamic-$mode-$program.exe"
        receipt_products+=(
            "link-dynamic-$mode-$program=$work/dynamic-$mode-$program.exe.crabc-link.json"
            "elf-dynamic-$mode-$program=$work/dynamic-$mode-$program.exe.crabc-elf.json"
            "map-dynamic-$mode-$program=$work/dynamic-$mode-$program.exe.crabc-link.map"
        )
        cp "$work/dynamic-$mode-$program.exe" "$work/execution-root/consumer-$mode-$program"
        receipt_products+=("dynamic-$mode-$program=$work/execution-root/consumer-$mode-$program")
        run_case "kernel-$mode" "$program" "${enter_root[@]}" "/consumer-$mode-$program"
        run_case "direct-$mode" "$program" "${enter_root[@]}" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode-$program"
    done
done
printf 'owned native-allocator policy: PASS (musl + native-shadow static/static-PIE/dynamic PIE/non-PIE kernel/direct; allocator-basic, observability and size-class policy programs); evidence: %s\n' "$work"
