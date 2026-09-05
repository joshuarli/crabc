#!/usr/bin/env bash
# Installed POSIX timers; the application and callback-loaded TLS objects are
# separately compiled once, then each object keeps its role across every link.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_posix_timers_probe.c"
readonly tls_source="$ROOT/compat/x86_64/owned_posix_timers_tls.c"
readonly timer_evidence="$ROOT/compat/x86_64/owned_posix_timers_evidence.py"
readonly interpreter=/lib/ld-crabc-x86_64.so.1
declare -a link_identity_records=()
application_compile_identity=''

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

provided_static=''
provided_dynamic=''
static_was_supplied=0
dynamic_was_supplied=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] || usage
            [ "$static_was_supplied" -eq 0 ] || usage
            [ -n "$2" ] || usage
            case "$2" in --*) usage ;; esac
            provided_static="$2"
            static_was_supplied=1
            shift 2
            ;;
        --*)
            usage
            ;;
        *)
            [ "$dynamic_was_supplied" -eq 0 ] || usage
            [ -n "$1" ] || usage
            provided_dynamic="$1"
            dynamic_was_supplied=1
            shift
            ;;
    esac
done
if [ "$static_was_supplied" -eq 1 ]; then
    provided_static="$(python3 -B -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$provided_static")"
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    provided_dynamic="$(python3 -B -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
static_product = Path(sys.argv[3]) if sys.argv[3] else None
dynamic_product = Path(sys.argv[4]) if sys.argv[4] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('posix-timers TMPDIR must be a physical checkout .work directory')
for product, name in ((static_product, 'static'), (dynamic_product, 'dynamic')):
    if product and (not product.is_dir() or not product.is_relative_to(root / '.work')):
        if name == 'dynamic':
            raise SystemExit('posix-timers product must be a physical checkout .work directory')
        raise SystemExit('posix-timers static product must be a physical checkout .work directory')
PY

work="$(mktemp -d "$TMPDIR/owned-posix-timers.XXXXXX")"
readonly work
finish() { chmod -R a+rX "$work"; printf 'evidence: %s\n' "$work"; }
trap finish EXIT

fail() {
    printf 'owned POSIX timers: %s\n' "$*" >&2
    exit 1
}

# Retain the exact process result.  The runner intentionally keeps the prior
# ordinary and dynamic differential boundaries; failure reclamation remains
# candidate-only evidence with its own raw result.
run_capture() {
    local output="$1"
    shift
    local status

    set +e
    timeout 20 "$@" >"$output" 2>"${output}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"${output}.status"
    [ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

compare_oracle() {
    local oracle="$1" candidate="$2" label="$3"

    cmp "${oracle}.stdout" "${candidate}.stdout" || fail "stdout differs from pinned musl for ${label}"
    cmp "${oracle}.stdout.stderr" "${candidate}.stdout.stderr" || fail "stderr differs from pinned musl for ${label}"
    cmp "${oracle}.stdout.status" "${candidate}.stdout.status" || fail "status differs from pinned musl for ${label}"
}

# The shared executable validator keeps its single-object scope.  The timer
# TLS DSO gets its own shared-mode validator below because it is dlopen'd only
# by a live callback and must not become an initial application dependency.
validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/${linkage}.link-identity.json"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" "$linkage" >"$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat' / 'x86_64'))
from owned_posix_product_evidence import validate_link

identity = validate_link(
    Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
)
json.dump(identity, sys.stdout, sort_keys=True, separators=(',', ':'))
sys.stdout.write('\n')
PY
    link_identity_records+=("$linkage:$identity")
}

retain_link_identities() {
    python3 -B - "$work/link-identities.json" "$application_compile_identity" "${link_identity_records[@]}" <<'PY'
import json
from pathlib import Path
import sys

output, application_path, *items = sys.argv[1:]
fields = {
    'linkage', 'product', 'product_format', 'product_manifest_sha256',
    'workload_sha256', 'executable_sha256', 'receipt_sha256',
}
application_fields = {
    'schema', 'product', 'product_manifest_sha256', 'source_sha256', 'object_sha256',
    'driver_sha256', 'compile_audit_sha256', 'header_trace_sha256', 'headers',
}
try:
    application = json.loads(Path(application_path).read_text(encoding='utf-8'))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f'retained application compile identity is unreadable: {error}') from error
if not isinstance(application, dict) or set(application) != application_fields:
    raise SystemExit('retained application compile identity fields drifted')
if application['schema'] != 'crabc.x86_64-owned-posix-timers-application/v1':
    raise SystemExit('retained application compile identity schema drifted')
if not all(isinstance(application[field], str) and len(application[field]) == 64
               for field in ('product_manifest_sha256', 'source_sha256', 'object_sha256',
                             'driver_sha256', 'compile_audit_sha256', 'header_trace_sha256')):
    raise SystemExit('retained application compile identity hash drifted')
if not isinstance(application['product'], str) or not isinstance(application['headers'], list):
    raise SystemExit('retained application compile identity value drifted')
links = {}
for item in items:
    linkage, path = item.split(':', 1)
    if linkage in links:
        raise SystemExit(f'duplicate retained link identity: {linkage}')
    try:
        identity = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f'retained {linkage} link identity is unreadable: {error}') from error
    if not isinstance(identity, dict) or set(identity) != fields or identity['linkage'] != linkage:
        raise SystemExit(f'retained {linkage} link identity drifted')
    links[linkage] = identity
if set(links) not in ({'pie', 'non-pie'}, {'static', 'static-pie', 'pie', 'non-pie'}):
    raise SystemExit('retained timer executable link identities have the wrong matrix')
for linkage, identity in links.items():
    if identity['workload_sha256'] != application['object_sha256']:
        raise SystemExit(f'retained {linkage} workload differs from the application compile audit')
for linkage in ('pie', 'non-pie'):
    identity = links[linkage]
    if (identity['product'], identity['product_manifest_sha256']) != (
        application['product'], application['product_manifest_sha256']
    ):
        raise SystemExit(f'retained {linkage} link differs from the application compile product')
Path(output).write_text(
    json.dumps({'schema': 'crabc.x86_64-owned-posix-timers-link-identities/v1',
                'application_compile': application, 'links': links},
               sort_keys=True, separators=(',', ':')) + '\n',
    encoding='utf-8',
)
PY
}

record_compile_audit() {
    local role="$1" source="$2" object="$3" audit="$4" driver="$5"
    python3 -B "$timer_evidence" record-compile "$installed" "$role" "$source" "$object" \
        "$driver" "$audit"
}

validate_timer_application_compile() {
    python3 -B "$timer_evidence" validate-application-compile "$installed" "$probe" "$work/probe.o" \
        "$work/probe.compile-audit.json" >"$work/probe-compile-identity.json"
    application_compile_identity="$work/probe-compile-identity.json"
}

validate_timer_tls_dso() {
    python3 -B "$timer_evidence" validate-tls-dso "$installed" "$tls_source" "$work/tls.o" \
        "$work/tls.compile-audit.json" "$work/libtimer-tls.so" \
        "$work/libtimer-tls.so.crabc-link.json" >"$work/tls-dso-identity.json"
}

if [ "$dynamic_was_supplied" -eq 0 ]; then
    run_capture "$work/dynamic-build.stdout" \
        python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot"
    provided_dynamic="$work/dynamic-sysroot"
fi
readonly installed="$(python3 -B -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$provided_dynamic")"
# Compile and header-audit both different roles through the selected dynamic
# product. The evidence helper invokes the installed driver's own source
# compiler and clean environment with its exact flags in dependency-only mode;
# it admits no compiler builtin or ambient header root.
run_capture "$work/probe-compile.stdout" \
    "$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -c "$probe" -o "$work/probe.o"
record_compile_audit application "$probe" "$work/probe.o" \
    "$work/probe.compile-audit.json" "$installed/bin/crabc-cc-dynamic"

run_capture "$work/tls-compile.stdout" \
    "$installed/bin/crabc-cc-dynamic" -shared -std=c11 -c "$tls_source" -o "$work/tls.o"
record_compile_audit timer-tls-dso "$tls_source" "$work/tls.o" \
    "$work/tls.compile-audit.json" "$installed/bin/crabc-cc-dynamic"

run_capture "$work/oracle-link.stdout" "$oracle_cc" -pthread "$work/probe.o" -o "$work/oracle"
run_capture "$work/oracle-tls-link.stdout" "$oracle_cc" -shared "$work/tls.o" -o "$work/oracle-tls.so"
run_capture "$work/oracle-ordinary.stdout" "$work/oracle" ordinary
run_capture "$work/oracle-dynamic.stdout" "$work/oracle" dynamic "$work/oracle-tls.so"

# Isolate musl's startup cancellation race in fresh processes. Retain the
# hung parent's actual syscall/task state, then reap only our child.
python3 -B - "$work/oracle" "$work" <<'PYTRACE'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[2])
for attempt in range(1, 17):
    stdout = root / f'oracle-failure-{attempt}.stdout'
    stderr = root / f'oracle-failure-{attempt}.stderr'
    status_file = root / f'oracle-failure-{attempt}.status'
    with stdout.open('wb') as out, stderr.open('wb') as err:
        child = subprocess.Popen([sys.argv[1], 'failure-once'], stdout=out, stderr=err)
        try:
            try:
                status = child.wait(timeout=0.1)
                status_file.write_text(f'{status}\n', encoding='utf-8')
                if status:
                    raise SystemExit(f'oracle single failure returned {status}')
                continue
            except subprocess.TimeoutExpired:
                tasks = {}
                for task in Path(f'/proc/{child.pid}/task').iterdir():
                    entry = {}
                    for name in ('status', 'wchan', 'syscall'):
                        try:
                            entry[name] = (task / name).read_text()
                        except OSError as error:
                            entry[name] = str(error)
                    tasks[task.name] = entry
                (root / f'oracle-failure-{attempt}.json').write_text(
                    json.dumps({'pid': child.pid, 'tasks': tasks}, indent=2) + '\n'
                )
                break
        finally:
            if child.poll() is None:
                child.kill()
            status = child.wait()
            if not status_file.exists():
                status_file.write_text(f'{status}\n', encoding='utf-8')
PYTRACE

run_capture "$work/tls-reset-build.stdout" rustc --edition=2021 --test \
    --cfg 'feature="x86_64-owned-dynamic-runtime"' \
    --cfg crabc_general_initial_graph --cfg crabc_general_initial_lifecycle \
    --cfg crabc_general_initial_tls_materialization_v1 --cfg crabc_general_loader_libc_tls_runtime_v1 \
    --cfg crabc_dynamic_main_thread_runtime_v1 \
    "$ROOT/ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs" -o "$work/tls-reset-tests"
run_capture "$work/tls-reset-tests.stdout" "$work/tls-reset-tests" timer_reset
run_capture "$work/tls-import-tests.stdout" "$work/tls-reset-tests" installed_runtime_function_imports_validate_shape

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    run_capture "$work/static-build.stdout" \
        python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot"
    static_product="$work/static-sysroot"
fi
if [ -n "$static_product" ]; then
    for mode in static static-pie; do
        receipt="$work/$mode.receipt.json"
        (
            cd "$work"
            run_capture "$work/$mode-link.stdout" "$static_product/bin/crabc-cc" "-$mode" --link-receipt \
                "$(basename "$receipt")" -std=c11 "$work/probe.o" -o "$work/$mode"
        )
        validate_sealed_link "$static_product" "$work/probe.o" "$work/$mode" "$receipt" "$mode"
        run_capture "$work/$mode-ordinary.stdout" "$work/$mode" ordinary
        compare_oracle "$work/oracle-ordinary" "$work/$mode-ordinary" "$mode/ordinary"
        run_capture "$work/$mode-failure.stdout" "$work/$mode" failure
    done
fi

cp -a "$installed" "$work/execution-root"
run_capture "$work/tls-link.stdout" \
    "$installed/bin/crabc-cc-dynamic" -shared "$work/tls.o" -o "$work/libtimer-tls.so"
validate_timer_tls_dso
cp "$work/libtimer-tls.so" "$work/execution-root/libtimer-tls.so"
for mode in pie non-pie; do
    run_capture "$work/dynamic-$mode-link.stdout" \
        "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$work/probe.o" -o "$work/dynamic-$mode"
    validate_sealed_link "$installed" "$work/probe.o" "$work/dynamic-$mode" \
        "$work/dynamic-$mode.crabc-link.json" "$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    run_capture "$work/dynamic-$mode-ordinary.stdout" \
        chroot "$work/execution-root" "/consumer-$mode" dynamic
    compare_oracle "$work/oracle-dynamic" "$work/dynamic-$mode-ordinary" "dynamic-$mode/kernel"
    run_capture "$work/direct-$mode-ordinary.stdout" \
        chroot "$work/execution-root" "$interpreter" "/consumer-$mode" dynamic
    compare_oracle "$work/oracle-dynamic" "$work/direct-$mode-ordinary" "dynamic-$mode/direct"
    run_capture "$work/dynamic-$mode-failure.stdout" \
        chroot "$work/execution-root" "/consumer-$mode" failure
    run_capture "$work/direct-$mode-failure.stdout" \
        chroot "$work/execution-root" "$interpreter" "/consumer-$mode" failure
done
validate_timer_application_compile
retain_link_identities

printf 'owned POSIX timers: PASS (separate source-bound application and callback TLS objects through musl and sealed static/static-PIE/dynamic PIE/non-PIE links; raw stdout/stderr/status, executable receipts and callback-loaded shared-DSO receipt retained; timer lifecycle, callback TSD/TLS/cancel/exit reset, failure reclamation)\n'
