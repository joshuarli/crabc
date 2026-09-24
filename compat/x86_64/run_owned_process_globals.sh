#!/usr/bin/env bash
# Frozen process.globals roster through sealed owned x86 products and musl.
#
# The installed dynamic driver compiles one PIE and one non-PIE object from
# owned_process_globals_probe.c. Each object is linked unchanged through the
# pinned musl 1.2.6 oracle and the matching owned static/static-PIE or dynamic
# PIE/non-PIE mode, and every run's stdout, stderr, and status must equal musl
# for the same object and link class. Dynamic candidates run through kernel
# and direct-interpreter entry; kernel entry also runs with an empty argv.
# owned_process_globals.py separately compares the 31 provider rows of the
# owned libc.a/libc.so with musl's libc.a/libc.so and requires executable COPY
# storage in both non-PIE dynamic consumers.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib
readonly PROBE="$ROOT/compat/x86_64/owned_process_globals_probe.c"
readonly LAUNCHER="$ROOT/compat/x86_64/libc_process_globals_empty_argv_launcher.c"
readonly AUDIT="$ROOT/compat/x86_64/owned_process_globals.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
declare -a link_identity_records=()

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
            case "$2" in -*) usage ;; esac
            provided_static="$2"
            static_was_supplied=1
            shift 2
            ;;
        -*)
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
# Both products are required: the roster is a static and shared closure.
[ "$static_was_supplied" -eq "$dynamic_was_supplied" ] || usage
if [ "$static_was_supplied" -eq 1 ]; then
    provided_static="$(realpath -e "$provided_static")"
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned process globals TMPDIR must be a physical checkout .work directory")
for raw, name in ((sys.argv[3], "static"), (sys.argv[4], "dynamic")):
    if raw and (not Path(raw).is_dir() or not Path(raw).is_relative_to(root / ".work")):
        raise SystemExit(f"owned process globals {name} product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-process-globals.XXXXXX")"
chmod a+rx "$work"
printf 'owned process globals evidence: %s\n' "$work"

fail() {
    printf 'owned process globals: %s\n' "$*" >&2
    exit 1
}

for tool in chroot cmp cp ln nm python3 readelf realpath sed sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
python3 -B "$AUDIT" roster >"$work/roster.json"

run_capture() {
    local output="$1"
    shift
    local status

    set +e
    timeout 40 env -i PATH="$PATH" PG_PROBE=alpha "$@" >"$output" 2>"${output}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"${output}.status"
    [ "$status" -eq 0 ] || fail "expected success, got ${status}: $*"
}

# Compare one candidate execution with the musl run for the same object and
# link class. The transcript must also be nonempty, so that a probe that
# exits early cannot trivially agree with a second early exit.
compare_oracle() {
    local oracle="$1" label="$2"
    shift 2
    local output="$work/run-${label}.stdout"

    run_capture "$output" "$@"
    [ -s "$output" ] || fail "${label} produced no transcript"
    cmp "$work/run-${oracle}.stdout" "$output" ||
        fail "stdout differs from pinned musl for ${label}"
    cmp "$work/run-${oracle}.stdout.stderr" "${output}.stderr" ||
        fail "stderr differs from pinned musl for ${label}"
    cmp "$work/run-${oracle}.stdout.status" "${output}.status" ||
        fail "status differs from pinned musl for ${label}"
}

validate_sealed_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local identity="$work/${linkage}.link-identity.json"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
        "$linkage" >"$identity" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "compat" / "x86_64"))
from owned_posix_product_evidence import validate_link

identity = validate_link(
    Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
)
json.dump(identity, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
    link_identity_records+=("$linkage:$identity")
}

# A static consumer must resolve every roster spelling to a definition in the
# final image; there is no interpreter to supply a missing provider later.
assert_static_roster_defined() {
    local executable="$1" label="$2"
    local symbols="$work/${label}.symbols"

    readelf --symbols --wide "$executable" >"$symbols"
    python3 -B - "$ROOT" "$symbols" "$label" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / "compat" / "x86_64"))
from owned_process_globals import ROSTER, parse_symbols

transcript = Path(sys.argv[2]).read_text(encoding="utf-8")
defined = {row.name for row in parse_symbols(transcript)}
missing = sorted(set(ROSTER) - defined)
if missing:
    raise SystemExit(f"{sys.argv[3]} leaves roster names unresolved: {', '.join(missing)}")
undefined = [line.split()[-1] for line in transcript.splitlines()
             if " UND " in line and line.split()[-1] in ROSTER]
if undefined:
    raise SystemExit(f"{sys.argv[3]} retains undefined roster names: {', '.join(undefined)}")
PY
}

if [ "$dynamic_was_supplied" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-product" >"$work/dynamic-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    provided_dynamic="$work/dynamic-product"
    provided_static="$work/static-product"
fi
readonly installed="$(realpath -e "$provided_dynamic")"
readonly static_product="$(realpath -e "$provided_static")"

# Provider closure: the owned archive and shared libc against pinned musl.
readelf --symbols --wide "$static_product/usr/lib/libc.a" >"$work/owned-libc.a.symbols"
nm --print-armap "$static_product/usr/lib/libc.a" 2>"$work/owned-libc.a.nm.stderr" | sed -n '/^Archive index:/,/^$/p' \
    >"$work/owned-libc.a.index"
readelf --symbols --wide "$MUSL_LIB/libc.a" >"$work/musl-libc.a.symbols"
nm --print-armap "$MUSL_LIB/libc.a" 2>"$work/musl-libc.a.nm.stderr" | sed -n '/^Archive index:/,/^$/p' \
    >"$work/musl-libc.a.index"
python3 -B "$AUDIT" static "$work/owned-libc.a.symbols" "$work/owned-libc.a.index" \
    "$work/musl-libc.a.symbols" "$work/musl-libc.a.index" >"$work/static-closure.json"
readelf --dyn-syms --wide "$installed/usr/lib/libc.so" >"$work/owned-libc.so.symbols"
readelf --dyn-syms --wide "$MUSL_LIB/libc.so" >"$work/musl-libc.so.symbols"
python3 -B "$AUDIT" shared "$work/owned-libc.so.symbols" "$work/musl-libc.so.symbols" \
    >"$work/shared-closure.json"

# One object per code model, both from the installed dynamic driver.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/pie.o"
"$installed/bin/crabc-cc-dynamic" --dynamic-non-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/non-pie.o"
sha256sum "$work/pie.o" "$work/non-pie.o" >"$work/workloads.sha256"
"$ORACLE_CC" -std=c11 -I"$installed/usr/include" -nostdinc \
    -E -H "$PROBE" >/dev/null 2>"$work/headers.trace"
for header in errno.h getopt.h math.h netdb.h pthread.h stdio.h stdlib.h \
    sys/auxv.h time.h unistd.h; do
    grep -Fq "$installed/usr/include/$header" "$work/headers.trace" ||
        fail "workload did not use the installed ${header}"
done
"$ORACLE_CC" -static -fno-pie -no-pie "$LAUNCHER" -o "$work/launcher"

# Each root holds exactly the consumer, the empty-argv launcher, and the
# runtime that its link class needs.
make_root() {
    local root="$1" consumer="$2" runtime="$3"

    case "$runtime" in
        none) mkdir "$root" ;;
        musl)
            mkdir -p "$root$MUSL_LIB"
            cp "$MUSL_LIB/libc.so" "$root$MUSL_LIB/libc.so"
            ln -s libc.so "$root$MUSL_LIB/ld-musl-x86_64.so.1"
            ;;
        owned) cp -a "$installed" "$root" ;;
    esac
    cp "$consumer" "$root/consumer"
    cp "$work/launcher" "$root/launcher"
}

run_class() {
    local label="$1" root="$2" direct="$3"

    run_capture "$work/run-${label}.stdout" chroot "$root" /consumer
    run_capture "$work/run-${label}-empty.stdout" chroot "$root" /launcher /consumer
    if [ -n "$direct" ]; then
        run_capture "$work/run-${label}-direct.stdout" chroot "$root" "$direct" /consumer
    fi
}

compare_class() {
    local oracle="$1" label="$2" root="$3" direct="$4"

    compare_oracle "$oracle" "$label" chroot "$root" /consumer
    compare_oracle "${oracle}-empty" "${label}-empty" chroot "$root" /launcher /consumer
    if [ -n "$direct" ]; then
        compare_oracle "$oracle" "${label}-direct" chroot "$root" "$direct" /consumer
    fi
}

# Pinned musl oracle for each object and link class.
"$ORACLE_CC" -static -no-pie "$work/non-pie.o" -o "$work/musl-static"
# The pinned musl tree installs no rcrt1.o, so the static-PIE class uses the
# same PIE object in musl's ordinary static link; no dynamic state differs.
"$ORACLE_CC" -static -no-pie "$work/pie.o" -o "$work/musl-static-pie"
"$ORACLE_CC" -pie "$work/pie.o" -o "$work/musl-pie"
"$ORACLE_CC" -no-pie "$work/non-pie.o" -o "$work/musl-non-pie"
make_root "$work/musl-static-root" "$work/musl-static" none
make_root "$work/musl-static-pie-root" "$work/musl-static-pie" none
make_root "$work/musl-pie-root" "$work/musl-pie" musl
make_root "$work/musl-non-pie-root" "$work/musl-non-pie" musl
run_class musl-static "$work/musl-static-root" ''
run_class musl-static-pie "$work/musl-static-pie-root" ''
run_class musl-pie "$work/musl-pie-root" ''
run_class musl-non-pie "$work/musl-non-pie-root" ''
readelf --dyn-syms --wide "$work/musl-non-pie" >"$work/musl-non-pie.dynsyms"
readelf --relocs --wide "$work/musl-non-pie" >"$work/musl-non-pie.relocs"
python3 -B "$AUDIT" copy musl-non-pie "$work/musl-non-pie.dynsyms" \
    "$work/musl-non-pie.relocs" "$work/musl-libc.so.symbols" >"$work/musl-non-pie.copy.json"

# Owned static ET_EXEC and static PIE through the sealed static driver.
for mode in static static-pie; do
    object="$work/non-pie.o"
    [ "$mode" = static ] || object="$work/pie.o"
    receipt="$work/consumer-$mode.receipt.json"
    (
        cd "$work"
        "$static_product/bin/crabc-cc" "-$mode" \
            --link-receipt "$(basename "$receipt")" "$object" -o "$work/consumer-$mode"
    )
    validate_sealed_link "$static_product" "$object" "$work/consumer-$mode" "$receipt" "$mode"
    assert_static_roster_defined "$work/consumer-$mode" "$mode"
    make_root "$work/$mode-root" "$work/consumer-$mode" none
    compare_class "musl-$mode" "$mode" "$work/$mode-root" ''
done

# Owned dynamic PIE and non-PIE through kernel and direct-interpreter entry.
for mode in pie non-pie; do
    object="$work/pie.o"
    [ "$mode" = pie ] || object="$work/non-pie.o"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$object" -o "$work/consumer-$mode"
    validate_sealed_link "$installed" "$object" "$work/consumer-$mode" \
        "$work/consumer-$mode.crabc-link.json" "$mode"
    make_root "$work/$mode-root" "$work/consumer-$mode" owned
    compare_class "musl-$mode" "dynamic-$mode" "$work/$mode-root" "$INTERPRETER"
done
readelf --dyn-syms --wide "$work/consumer-non-pie" >"$work/owned-non-pie.dynsyms"
readelf --relocs --wide "$work/consumer-non-pie" >"$work/owned-non-pie.relocs"
python3 -B "$AUDIT" copy owned-non-pie "$work/owned-non-pie.dynsyms" \
    "$work/owned-non-pie.relocs" "$work/owned-libc.so.symbols" >"$work/owned-non-pie.copy.json"

python3 -B - "$work/link-identities.json" "${link_identity_records[@]}" <<'PY'
import json
from pathlib import Path
import sys

records = {}
for item in sys.argv[2:]:
    linkage, raw_path = item.split(":", 1)
    if linkage in records:
        raise SystemExit(f"duplicate retained link identity: {linkage}")
    records[linkage] = json.loads(Path(raw_path).read_text(encoding="utf-8"))
if sorted(records) != ["non-pie", "pie", "static", "static-pie"]:
    raise SystemExit("owned process globals must retain all four link identities")
Path(sys.argv[1]).write_text(
    json.dumps({"schema": "crabc.x86_64-owned-posix-link-identities/v1", "links": records},
               sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

printf 'owned process globals: PASS (31-name roster: owned libc.a/libc.so provider type, binding, visibility, object size, unversioned alias partition and archive extraction equal pinned musl; PIE and non-PIE objects through musl and sealed owned static/static-PIE/dynamic PIE/non-PIE kernel, direct and empty-argv entry with identical stdout/stderr/status; non-PIE dynamic COPY storage in both runtimes); evidence: %s\n' "$work"
