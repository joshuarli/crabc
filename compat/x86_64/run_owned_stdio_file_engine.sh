#!/usr/bin/env bash
# Nine frozen FILE-engine probes through one installed-header object each.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly RUNNER="$ROOT/compat/x86_64/run_owned_stdio_file_engine.sh"
readonly READER="$ROOT/compat/x86_64/owned_stdio_file_engine_receipt.py"
readonly COPIES="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly CONTROL_BUSYBOX="$(realpath -e /bin/busybox)"
readonly CONTROL_LOADER="$(realpath -e /lib/ld-musl-x86_64.so.1)"
readonly CONTROL_MOUNT="$(realpath -e /bin/mount)"
readonly CONTROL_UMOUNT="$(realpath -e /bin/umount)"
readonly COMMON_FLAGS=(-std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector)
readonly CONTROL_FLAGS=(-std=c11 -fno-builtin -fno-stack-protector)

usage() {
    printf 'usage: %s [STATIC_SYSROOT DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
fail() {
    printf 'owned FILE engine: %s\n' "$*" >&2
    exit 1
}
case "$#" in
    0) supplied_static='' supplied_dynamic='' ;;
    2) supplied_static="$1" supplied_dynamic="$2" ;;
    *) usage ;;
esac
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'
[ -x "$ORACLE_CC" ] && [ -x "$CONTROL_BUSYBOX" ] && [ -x "$CONTROL_LOADER" ] &&
    [ -x "$CONTROL_MOUNT" ] && [ -x "$CONTROL_UMOUNT" ] || fail 'missing pinned control tool'
[ -f "$READER" ] && [ -f "$COPIES" ] || fail 'missing receipt reader or payload auditor'
command -v chroot >/dev/null || fail 'missing chroot'
command -v timeout >/dev/null || fail 'missing timeout'

python3 -B - "$ROOT" "$TMPDIR" "$supplied_static" "$supplied_dynamic" <<'PY'
from pathlib import Path
import stat, sys
root, temporary, static, dynamic = map(Path, sys.argv[1:])
products = [] if str(static) == '.' else [(static, 'static product'), (dynamic, 'dynamic product')]
root = root.resolve(strict=True)
def shared_worktree(checkout):
    for parent in (checkout, *checkout.parents):
        if parent.name == '.work':
            return parent.parent / '.work'
    return checkout / '.work'
worktree = shared_worktree(root)
for item, label in ((temporary, 'TMPDIR'), *products):
    item = item.absolute()
    if '..' in item.parts or not item.is_relative_to(worktree):
        raise SystemExit(f'owned FILE engine {label} must stay below checkout .work')
    current = Path(item.anchor)
    for part in item.parts[1:]:
        current /= part
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit(f'owned FILE engine {label} traverses a symlink')
    if not item.is_dir():
        raise SystemExit(f'owned FILE engine {label} is not a physical directory')
PY

readonly WORK="$(mktemp -d "$TMPDIR/owned-stdio-file-engine.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned FILE engine evidence: %s\n' "$WORK"

# Without a supplied pair, build current static and dynamic products so the
# single command replays every row against the checkout's own source.
if [ -z "$supplied_dynamic" ]; then
    supplied_static="$WORK/static-product"
    supplied_dynamic="$WORK/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$supplied_static" \
        >"$WORK/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$supplied_dynamic" \
        >"$WORK/dynamic-build.json"
fi
readonly STATIC_PRODUCT="$supplied_static"
readonly DYNAMIC_PRODUCT="$supplied_dynamic"
[ -x "$STATIC_PRODUCT/bin/crabc-cc" ] && [ -x "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" ] ||
    fail 'missing supplied installed product driver'

capture() {
    local stem="$1"
    shift
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    local status
    set +e
    timeout 90 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status"
}

compare_oracle() {
    local oracle="$1" candidate="$2"
    cmp "$WORK/$oracle.stdout" "$WORK/$candidate.stdout" || fail "$candidate stdout differs from pinned musl"
    cmp "$WORK/$oracle.stderr" "$WORK/$candidate.stderr" || fail "$candidate stderr differs from pinned musl"
    cmp "$WORK/$oracle.status" "$WORK/$candidate.status" || fail "$candidate status differs from pinned musl"
}

resolve_compiler() {
    python3 -B - "$DYNAMIC_PRODUCT" <<'PY'
import importlib.util
from pathlib import Path
import sys
product = Path(sys.argv[1])
helper = product / 'share/crabc/crabc_cc_static.py'
spec = importlib.util.spec_from_file_location('owned_stdio_file_engine_compiler', helper)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    print(Path(module.compiler()).resolve(strict=True))
finally:
    sys.modules.pop(spec.name, None)
PY
}

capture_tools() {
    local output="$1"
    python3 -B - "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$ORACLE_CC" "$CONTROL_BUSYBOX" "$CONTROL_LOADER" \
        "$CONTROL_MOUNT" "$CONTROL_UMOUNT" "$output" <<'PY'
import hashlib, importlib.util, json
from pathlib import Path
import stat, sys
static_text, dynamic_text, oracle_text, busybox_text, loader_text, mount_text, umount_text, output_text = sys.argv[1:]
static, dynamic = Path(static_text), Path(dynamic_text)
def physical(path):
    path = Path(path).resolve(strict=True)
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit(f'control tool is not a physical regular file: {path}')
    return path
def identity(path):
    path = physical(path)
    data = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'mode': stat.S_IMODE(path.stat().st_mode)}
helper = physical(dynamic / 'share/crabc/crabc_cc_static.py')
spec = importlib.util.spec_from_file_location('owned_stdio_file_engine_tools', helper)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    result = {'oracle': identity(oracle_text), 'static_driver': identity(static / 'bin/crabc-cc'),
              'dynamic_driver': identity(dynamic / 'bin/crabc-cc-dynamic'),
              'compiler': identity(Path(module.compiler())), 'linker': identity(Path(module.linker(dynamic))),
              'control_busybox': identity(busybox_text), 'control_loader': identity(loader_text),
              'control_mount': identity(mount_text), 'control_umount': identity(umount_text)}
finally:
    sys.modules.pop(spec.name, None)
Path(output_text).write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

capture_source_product_seal() {
    local point="$1"
    python3 -B - "$ROOT" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$RUNNER" "$READER" "$WORK/$point.json" <<'PY'
import json
from pathlib import Path
import stat, sys
root, static, dynamic, runner, reader, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_stdio_file_engine_receipt as receipt

def source(path):
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(root):
        raise SystemExit(f'FILE engine source is not a physical checkout file: {path}')
    return receipt.source_identity(root, path)
def product(path, kind):
    path = path.resolve(strict=True)
    manifest, _ = (receipt.products._validate_static_product(path) if kind == 'static'
                   else receipt.products._validate_dynamic_product(path))
    return {'path': str(path), 'manifest': {'path': str(manifest), 'sha256': receipt.digest(manifest),
            'size': manifest.stat().st_size}, 'tree': receipt.tree_identity(path)}
record = {'sources': {role: source(root / data['source']) for role, data in receipt.ROLES.items()},
          'static': product(static, 'static'), 'dynamic': product(dynamic, 'dynamic')}
record['sources']['runner'] = source(runner)
record['sources']['reader'] = source(reader)
output.write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
}

validate_link() {
    local stem="$1" product="$2" workload="$3" executable="$4" receipt="$5" linkage="$6"
    capture "$stem-validate" python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" "$linkage" <<'PY'
import json
from pathlib import Path
import sys
root, product, workload, executable, receipt, linkage = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link
print(json.dumps(validate_link(product, workload, executable, receipt, str(linkage)),
                 sort_keys=True, separators=(',', ':')))
PY
    cp "$WORK/$stem-validate.stdout" "$WORK/$stem.product-link.json"
    rm "$WORK/$stem-validate.argv.json" "$WORK/$stem-validate.stdout" "$WORK/$stem-validate.stderr" "$WORK/$stem-validate.status"
}

COMPILER=''
capture_source_product_seal source-product-before
capture_tools "$WORK/tools-before.json"
COMPILER="$(resolve_compiler)"
readonly COMPILER
[ -x "$COMPILER" ] || fail 'installed helper selected a non-executable compiler'

declare -a ROLES=(
    stdio.file-backends
    stdio.process-streams
    stdio.wide-stream
    stdio.wide-format
    stdio.file-extensions
    stdio.printf-float
    stdio.scanf
    stdio.frozen-surface
    stdio.engine-model
)
declare -A SOURCE=(
    [stdio.file-backends]="$ROOT/compat/x86_64/owned_stdio_backends_probe.c"
    [stdio.process-streams]="$ROOT/compat/x86_64/owned_stdio_process_probe.c"
    [stdio.wide-stream]="$ROOT/compat/x86_64/owned_wide_stdio_probe.c"
    [stdio.wide-format]="$ROOT/compat/x86_64/owned_wide_format_probe.c"
    [stdio.file-extensions]="$ROOT/compat/x86_64/owned_stdio_extensions_probe.c"
    [stdio.printf-float]="$ROOT/compat/x86_64/owned_static_printf_float_probe.c"
    [stdio.scanf]="$ROOT/compat/x86_64/owned_static_scanf_probe.c"
    [stdio.frozen-surface]="$ROOT/compat/x86_64/owned_stdio_surface_probe.c"
    [stdio.engine-model]="$ROOT/compat/x86_64/owned_stdio_engine_model_probe.c"
)
role_flags() {
    if [ "$1" = stdio.scanf ]; then printf '%s\0' -DCRABC_OWNED_SCANF; fi
}

# The applet text is generated from the reader's closed source definition; it
# never accepts a caller-provided command name.
for applet in sh cat sleep; do
    python3 -B - "$ROOT" "$WORK/control-$applet.c" "$applet" <<'PY'
from pathlib import Path
import sys
root, output, applet = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_stdio_file_engine_receipt import control_launcher_source
output.write_bytes(control_launcher_source(str(applet)))
PY
    capture "control-$applet-header" "$COMPILER" -nostdinc -isystem "$DYNAMIC_PRODUCT/usr/include" \
        "${CONTROL_FLAGS[@]}" -E -H "$WORK/control-$applet.c"
    capture "control-$applet-compile" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        "${CONTROL_FLAGS[@]}" -c "$WORK/control-$applet.c" -o "$WORK/control-$applet.o"
done

for role in "${ROLES[@]}"; do
    [ -f "${SOURCE[$role]}" ] || fail "missing $role source"
    mapfile -d '' -t flags < <(role_flags "$role")
    capture "$role-header" "$COMPILER" -nostdinc -isystem "$DYNAMIC_PRODUCT/usr/include" \
        "${COMMON_FLAGS[@]}" "${flags[@]}" -E -H "${SOURCE[$role]}"
    capture "$role-compile" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        "${COMMON_FLAGS[@]}" "${flags[@]}" -c "${SOURCE[$role]}" -o "$WORK/$role.o"
done

sha256sum "${SOURCE[stdio.file-backends]}" "${SOURCE[stdio.process-streams]}" "${SOURCE[stdio.wide-stream]}" \
    "${SOURCE[stdio.wide-format]}" "${SOURCE[stdio.file-extensions]}" "${SOURCE[stdio.printf-float]}" \
    "${SOURCE[stdio.scanf]}" "${SOURCE[stdio.frozen-surface]}" "${SOURCE[stdio.engine-model]}" "$RUNNER" \
    "$WORK/control-sh.c" "$WORK/control-cat.c" "$WORK/control-sleep.c" \
    "$WORK/stdio.file-backends.o" "$WORK/stdio.process-streams.o" "$WORK/stdio.wide-stream.o" \
    "$WORK/stdio.wide-format.o" "$WORK/stdio.file-extensions.o" "$WORK/stdio.printf-float.o" "$WORK/stdio.scanf.o" \
    "$WORK/stdio.frozen-surface.o" "$WORK/stdio.engine-model.o" \
    "$WORK/control-sh.o" "$WORK/control-cat.o" "$WORK/control-sleep.o" >"$WORK/source-object-before.sha256"

for applet in sh cat sleep; do
    object="$WORK/control-$applet.o"
    capture "control-$applet-oracle-link" "$ORACLE_CC" -static -fno-pie -no-pie "$object" -o "$WORK/control-$applet-oracle"
    for linkage in static static-pie; do
        receipt="$WORK/control-$applet-$linkage.crabc-link.json"
        ( cd "$WORK"; capture "control-$applet-$linkage-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$linkage" \
            --link-receipt "$(basename "$receipt")" "$object" -o "$WORK/control-$applet-$linkage" )
        validate_link "control-$applet-$linkage" "$STATIC_PRODUCT" "$object" "$WORK/control-$applet-$linkage" "$receipt" "$linkage"
    done
    for linkage in pie non-pie; do
        binary="$WORK/control-$applet-$linkage"
        capture "control-$applet-$linkage-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$linkage" \
            "${CONTROL_FLAGS[@]}" "$object" -o "$binary"
        validate_link "control-$applet-$linkage" "$DYNAMIC_PRODUCT" "$object" "$binary" "$binary.crabc-link.json" "$linkage"
    done
done

control_stage_root() {
    case "$1" in
        oracle) printf '%s\n' "$WORK/process-control-oracle-stage" ;;
        static) printf '%s\n' "$WORK/process-control-static-stage" ;;
        static-pie) printf '%s\n' "$WORK/process-control-static-pie-stage" ;;
        pie) printf '%s\n' "$WORK/process-control-pie-stage" ;;
        non-pie) printf '%s\n' "$WORK/process-control-non-pie-stage" ;;
        *) fail "unknown control stage linkage: $1" ;;
    esac
}
install_control_stage() {
    local linkage="$1" stage
    stage="$(control_stage_root "$linkage")"
    mkdir -p "$stage/control" "$stage/bin"
    cp -p "$CONTROL_BUSYBOX" "$stage/control/busybox"
    cp -p "$CONTROL_LOADER" "$stage/control/ld-musl-x86_64.so.1"
    for applet in sh cat sleep; do cp -p "$WORK/control-$applet-$linkage" "$stage/bin/$applet"; done
}
install_control_runtime() {
    local linkage="$1" root="$2" stage
    stage="$(control_stage_root "$linkage")"
    [ ! -e "$root/control" ] || fail "process root already has a control directory"
    for applet in sh cat sleep; do [ ! -e "$root/bin/$applet" ] || fail "process root already has /bin/$applet"; done
    mkdir -p "$root/control" "$root/bin" "$root/dev"
    cp -p "$stage/control/busybox" "$root/control/busybox"
    cp -p "$stage/control/ld-musl-x86_64.so.1" "$root/control/ld-musl-x86_64.so.1"
    for applet in sh cat sleep; do cp -p "$stage/bin/$applet" "$root/bin/$applet"; done
    mknod -m 666 "$root/dev/null" c 1 3
}
remove_control_runtime() {
    local root="$1"
    rm -f "$root/bin/sh" "$root/bin/cat" "$root/bin/sleep" "$root/control/busybox" "$root/control/ld-musl-x86_64.so.1" "$root/dev/null"
    rmdir "$root/control" "$root/dev"
}
for linkage in oracle static static-pie pie non-pie; do install_control_stage "$linkage"; done

process_root() {
    case "$1" in
        oracle) printf '%s\n' "$WORK/process-oracle-root" ;;
        static) printf '%s\n' "$WORK/process-static-root" ;;
        static-pie) printf '%s\n' "$WORK/process-static-pie-root" ;;
        pie) printf '%s\n' "$WORK/dynamic-stdio.process-streams-pie-root" ;;
        non-pie) printf '%s\n' "$WORK/dynamic-stdio.process-streams-non-pie-root" ;;
        wide-format-pie) printf '%s\n' "$WORK/dynamic-stdio.wide-format-pie-root" ;;
        wide-format-non-pie) printf '%s\n' "$WORK/dynamic-stdio.wide-format-non-pie-root" ;;
        *) fail "unknown process linkage: $1" ;;
    esac
}

proc_setup() {
    local linkage="$1" root="$2" state="$WORK/process-$linkage-proc-lifecycle.json"
    python3 -B - "$ROOT" "$root" "$state" "$WORK/process-$linkage-proc-mountinfo.txt" <<'PY'
import json
from pathlib import Path
import sys
root, runtime, state, mountinfo = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_os_test as control
# This component's finite descriptor-inheritance observation needs read-only
# procfs. Reuse the tracked lifecycle, but make the local mount contract
# explicit rather than changing the unrelated OS-test default.
control.PRIVATE_PROC_MOUNT_OPTIONS = 'ro,nosuid,nodev,noexec'
private = control.reserve_private_proc_mountpoint(runtime, 'basic')
assert private is not None
lifecycle = control.private_proc_lifecycle(private)
def persist():
    state.write_text(json.dumps(lifecycle, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
try:
    control.mount_private_proc_tracked(runtime, lifecycle)
except BaseException:
    try:
        control.unmount_private_proc_tracked(lifecycle)
    finally:
        persist()
    raise
persist()
mountinfo.write_bytes(Path('/proc/self/mountinfo').read_bytes())
PY
}

proc_teardown() {
    local linkage="$1" root="$2" state="$WORK/process-$linkage-proc-lifecycle.json"
    [ -f "$state" ] || fail "missing private proc lifecycle for $linkage"
    python3 -B - "$ROOT" "$root" "$state" "$WORK/process-$linkage-private-proc.json" <<'PY'
import json
from pathlib import Path
import sys
root, runtime, state, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_os_test as control
control.PRIVATE_PROC_MOUNT_OPTIONS = 'ro,nosuid,nodev,noexec'
lifecycle = json.loads(state.read_text(encoding='utf-8'))
try:
    control.unmount_private_proc_tracked(lifecycle)
finally:
    state.write_text(json.dumps(lifecycle, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
if not control.private_proc_lifecycle_postwalk_safe(lifecycle):
    raise SystemExit('private procfs teardown remains unsafe; refusing root walk')
private = lifecycle['receipt']
if not control.private_proc_fixture_passed(private):
    raise SystemExit('private procfs fixture receipt is incomplete')
output.write_text(json.dumps(private, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
state.unlink()
PY
}

cleanup() {
    local status="$?" cleanup_status=0 state linkage
    trap - EXIT
    set +e
    for state in "$WORK"/process-*-proc-lifecycle.json; do
        [ -f "$state" ] || continue
        linkage="${state##*/process-}"
        linkage="${linkage%-proc-lifecycle.json}"
        proc_teardown "$linkage" "$(process_root "$linkage")" || cleanup_status=1
    done
    if [ "$cleanup_status" -ne 0 ]; then
        printf 'owned FILE engine: private procfs teardown failed; retained failure evidence without walking roots: %s\n' "$WORK" >&2
    elif [ "$status" -ne 0 ]; then
        # An unsuccessful producer has no sealed report. Make its retained
        # failure artifacts reviewable only after every private procfs mount
        # has been torn down.
        chmod -R a+rX "$WORK"
    fi
    exit "$status"
}
trap 'cleanup' EXIT

run_process_chroot() {
    local linkage="$1" root="$2" stem="$3"
    proc_setup "$linkage" "$root"
    capture "$stem" chroot "$root" /consumer /scratch/stream
    proc_teardown "$linkage" "$root"
}


for role in "${ROLES[@]}"; do
    object="$WORK/$role.o"
    oracle="$WORK/oracle-$role"
    capture "$role-oracle-link" "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie "$object" -o "$oracle"
    if [ "$role" = stdio.process-streams ]; then
        root="$(process_root oracle)"
        mkdir -p "$root/scratch"
        cp "$oracle" "$root/consumer"
        install_control_runtime oracle "$root"
        run_process_chroot oracle "$root" "$role-oracle-run"
        remove_control_runtime "$root"
        rmdir "$root/scratch"
    else
        scratch="$WORK/oracle-$role-stream"
        capture "$role-oracle-run" env -i LC_ALL=C LANG=C TZ=UTC "$oracle" "$scratch"
        [ "$role" != stdio.file-backends ] || rm "$scratch"
    fi

    for linkage in static static-pie; do
        executable="$WORK/$role-$linkage"
        receipt="$WORK/$role-$linkage.crabc-link.json"
        ( cd "$WORK"; capture "$role-$linkage-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$linkage" \
            --link-receipt "$(basename "$receipt")" "$object" -o "$executable" )
        validate_link "$role-$linkage" "$STATIC_PRODUCT" "$object" "$executable" "$receipt" "$linkage"
        if [ "$role" = stdio.process-streams ]; then
            root="$(process_root "$linkage")"
            mkdir -p "$root/scratch"
            cp "$executable" "$root/consumer"
            install_control_runtime "$linkage" "$root"
            run_process_chroot "$linkage" "$root" "$role-$linkage-run"
            remove_control_runtime "$root"
            rmdir "$root/scratch"
            capture "$role-$linkage-cleanup" test ! -e "$root/scratch/stream"
        else
            scratch="$WORK/$role-$linkage-stream"
            capture "$role-$linkage-run" env -i LC_ALL=C LANG=C TZ=UTC "$executable" "$scratch"
            if [ "$role" = stdio.file-backends ]; then
                cp "$scratch" "$WORK/stdio.file-backends-$linkage-exit"
                rm "$scratch"
            else
                capture "$role-$linkage-cleanup" test ! -e "$scratch"
            fi
        fi
        compare_oracle "$role-oracle-run" "$role-$linkage-run"
    done

    for linkage in pie non-pie; do
        executable="$WORK/dynamic-$role-$linkage"
        capture "$role-$linkage-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$linkage" \
            "${COMMON_FLAGS[@]}" "$object" -o "$executable"
        validate_link "$role-$linkage" "$DYNAMIC_PRODUCT" "$object" "$executable" "$executable.crabc-link.json" "$linkage"
        root="$WORK/dynamic-$role-$linkage-root"
        mkdir "$root"
        cp -a "$DYNAMIC_PRODUCT/." "$root"
        cp "$executable" "$root/consumer"
        mkdir "$root/scratch" "$root/tmp"
        chmod 1777 "$root/tmp"
        capture "$role-$linkage-copy-before" python3 -B "$COPIES" record --product "$DYNAMIC_PRODUCT" \
            --execution-root "$root" --source-consumer "$executable" --execution-consumer "$root/consumer" \
            --record "$WORK/$role-$linkage-execution-payload.json"
        capture "$role-$linkage-copy-audit-before" python3 -B "$COPIES" audit --product "$DYNAMIC_PRODUCT" \
            --execution-root "$root" --source-consumer "$executable" --execution-consumer "$root/consumer" \
            --record "$WORK/$role-$linkage-execution-payload.json"
        proc_linkage="$linkage"
        if [ "$role" = stdio.wide-format ]; then proc_linkage="wide-format-$linkage"; fi
        if [ "$role" = stdio.process-streams ] || [ "$role" = stdio.wide-format ]; then
            install_control_runtime "$linkage" "$root"
            proc_setup "$proc_linkage" "$root"
        fi
        capture "$role-$linkage-kernel" chroot "$root" /consumer /scratch/stream
        if [ "$role" = stdio.file-backends ]; then cp "$root/scratch/stream" "$WORK/stdio.file-backends-dynamic-$linkage-kernel-exit"; fi
        capture "$role-$linkage-direct" chroot "$root" "$INTERPRETER" /consumer /scratch/stream
        if [ "$role" = stdio.file-backends ]; then cp "$root/scratch/stream" "$WORK/stdio.file-backends-dynamic-$linkage-direct-exit"; fi
        if [ "$role" = stdio.process-streams ] || [ "$role" = stdio.wide-format ]; then
            proc_teardown "$proc_linkage" "$root"
            remove_control_runtime "$root"
        fi
        rm -f "$root/scratch/stream"
        rmdir "$root/scratch" "$root/tmp"
        capture "$role-$linkage-copy-audit-after" python3 -B "$COPIES" audit --product "$DYNAMIC_PRODUCT" \
            --execution-root "$root" --source-consumer "$executable" --execution-consumer "$root/consumer" \
            --record "$WORK/$role-$linkage-execution-payload.json"
        if [ "$role" != stdio.file-backends ]; then capture "$role-$linkage-cleanup" test ! -e "$root/scratch/stream"; fi
        compare_oracle "$role-oracle-run" "$role-$linkage-kernel"
        compare_oracle "$role-oracle-run" "$role-$linkage-direct"
    done
done

capture_tools "$WORK/tools-after.json"
cmp "$WORK/tools-before.json" "$WORK/tools-after.json" || fail 'tool roster changed during replay'
capture_source_product_seal source-product-after
cmp "$WORK/source-product-before.json" "$WORK/source-product-after.json" || fail 'source or supplied product changed during replay'
sha256sum -c "$WORK/source-object-before.sha256" >"$WORK/source-object-after.txt" || fail 'source or object changed during replay'

# Identity records include physical modes. Make the retained pre-report
# artifacts readable before recording them, so the EXIT trap never changes a
# sealed artifact after reconstruction. All private procfs mounts are gone at
# this point; cleanup still protects an earlier failure path.
chmod -R a+rX "$WORK"

python3 -B - "$ROOT" "$WORK" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" <<'PY'
import hashlib, json, stat, sys
from pathlib import Path
root, work, static, dynamic = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_stdio_file_engine_receipt as receipt

def artifact(path):
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(work):
        raise SystemExit(f'FILE engine artifact is not a physical work file: {path}')
    data = path.read_bytes()
    return {'path': path.relative_to(work).as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data), 'mode': stat.S_IMODE(path.stat().st_mode)}
def source(path):
    path = path.resolve(strict=True)
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(root):
        raise SystemExit(f'FILE engine source is not physical: {path}')
    return artifact_from_root(root, path)
def artifact_from_root(base, path):
    data = path.read_bytes()
    return {'path': path.relative_to(base).as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data), 'mode': stat.S_IMODE(path.stat().st_mode)}
commands = {}
for argv in sorted(work.glob('*.argv.json')):
    stem = argv.name.removesuffix('.argv.json')
    commands[stem] = {name: artifact(work / f'{stem}.{suffix}') for name, suffix in
                      (('argv', 'argv.json'), ('stdout', 'stdout'), ('stderr', 'stderr'), ('status', 'status'))}
roles = tuple(receipt.ROLES)
control = {'sources': {applet: artifact(work / f'control-{applet}.c') for applet in receipt.CONTROL_APPLETS},
           'objects': {applet: artifact(work / f'control-{applet}.o') for applet in receipt.CONTROL_APPLETS},
           'launchers': {applet: {mode: artifact(work / f'control-{applet}-{mode}') for mode in
                                  ('oracle', 'static', 'static-pie', 'pie', 'non-pie')}
                         for applet in receipt.CONTROL_APPLETS},
           'links': {applet: {mode: artifact(work / f'control-{applet}-{mode}.product-link.json') for mode in
                              ('static', 'static-pie', 'pie', 'non-pie')}
                     for applet in receipt.CONTROL_APPLETS},
           'staged': {mode: {name: artifact(path) for name, path in {
                         'busybox': work / f'process-control-{mode if mode != "static-pie" else "static-pie"}-stage/control/busybox',
                         'loader': work / f'process-control-{mode if mode != "static-pie" else "static-pie"}-stage/control/ld-musl-x86_64.so.1',
                         **{applet: work / f'process-control-{mode if mode != "static-pie" else "static-pie"}-stage/bin/{applet}' for applet in receipt.CONTROL_APPLETS},
                       }.items()} for mode in ('oracle', 'static', 'static-pie', 'pie', 'non-pie')}}
record = {
    'schema': receipt.SCHEMA, 'scope': list(receipt.SCOPE),
    'rows': {role: receipt.row_value(role) for role in roles},
    'source': {role: source(root / value['source']) for role, value in receipt.ROLES.items()} | {
        'runner': source(root / 'compat/x86_64/run_owned_stdio_file_engine.sh'),
        'reader': source(root / 'compat/x86_64/owned_stdio_file_engine_receipt.py')},
    'workloads': {role: artifact(work / f'{role}.o') for role in roles},
    'products': {'static': str(static.resolve(strict=True)), 'dynamic': str(dynamic.resolve(strict=True))},
    'seals': {name: artifact(work / f'{name}.json') for name in
              ('source-product-before', 'source-product-after', 'tools-before', 'tools-after')},
    'object_seals': {'before': artifact(work / 'source-object-before.sha256'),
                     'after': artifact(work / 'source-object-after.txt')},
    'commands': commands,
    'links': {f'{role}-{mode}': artifact(work / f'{role}-{mode}.product-link.json') for role in roles
              for mode in ('static', 'static-pie', 'pie', 'non-pie')},
    'execution_payloads': {role: {mode: {'record': artifact(work / f'{role}-{mode}-execution-payload.json'),
                                          'before': artifact(work / f'{role}-{mode}-copy-audit-before.stdout'),
                                          'after': artifact(work / f'{role}-{mode}-copy-audit-after.stdout')}
                                  for mode in ('pie', 'non-pie')} for role in roles},
    'side_effects': {'stdio.file-backends': {cell: artifact(work / f'stdio.file-backends-{cell}-exit')
                     for cell in receipt.EXECUTION_CELLS}},
    'control': control,
    'process_proc': {mode: {'receipt': artifact(work / f'process-{mode}-private-proc.json'),
                            'mountinfo': artifact(work / f'process-{mode}-proc-mountinfo.txt')}
                     for mode in ('oracle', 'static', 'static-pie', 'pie', 'non-pie', 'wide-format-pie', 'wide-format-non-pie')},
    'family_completion': False, 'promotion_ready': False, 'public_support': False,
}
(work / 'owned-stdio-file-engine.json').write_text(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY

python3 -B "$READER" "$WORK/owned-stdio-file-engine.json" --checkout "$ROOT" --require-static
chmod a+r "$WORK/owned-stdio-file-engine.json"
printf 'owned FILE engine: PASS (nine closed FILE/format/process/surface/model rows; pinned musl, supplied static/static-PIE, dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$WORK"
