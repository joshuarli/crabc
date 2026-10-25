#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$(uname -sm)" = 'Linux x86_64' ]
supplied=0
explicit_work=0
resumed=0
action=full
allocator_backend=accepted-c
case_product=
case_name=
usage='[--work NEW_DIR [--prepare] [--allocator-backend accepted-c|native-shadow] | --resume WORK --next | --resume WORK --case PRODUCT CASE | --resume WORK --finish | --supplied-work WORK]'
case "$#" in
    0) ;;
    2) if [ "$1" = --work ] && [ -n "$2" ]; then
           explicit_work=1
       elif [ "$1" = --supplied-work ] && [ -n "$2" ]; then
           supplied=1
       else
           printf 'usage: %s %s\n' "$0" "$usage" >&2; exit 2
       fi ;;
    3) if [ "$1" = --work ] && [ -n "$2" ] && [ "$3" = --prepare ]; then
           explicit_work=1
           action=prepare
       elif [ "$1" = --resume ] && [ -n "$2" ]; then
           resumed=1
           case "$3" in
               --next) action=next ;;
               --finish) action=finish ;;
               *) printf 'usage: %s %s\n' "$0" "$usage" >&2; exit 2 ;;
           esac
       else
           printf 'usage: %s %s\n' "$0" "$usage" >&2; exit 2
       fi ;;
    4) if [ "$1" = --work ] && [ -n "$2" ] && [ "$3" = --allocator-backend ]; then
           explicit_work=1
           allocator_backend="$4"
       else
           printf 'usage: %s %s\n' "$0" "$usage" >&2; exit 2
       fi ;;
    5) if [ "$1" = --work ] && [ -n "$2" ] && [ "$3" = --prepare ] && [ "$4" = --allocator-backend ]; then
           explicit_work=1
           action=prepare
           allocator_backend="$5"
       elif [ "$1" = --resume ] && [ -n "$2" ] && [ "$3" = --case ] && [ -n "$4" ] && [ -n "$5" ]; then
           resumed=1
           action=case
           case_product="$4"
           case_name="$5"
       else
           printf 'usage: %s %s\n' "$0" "$usage" >&2; exit 2
       fi ;;
    *) printf 'usage: %s %s\n' "$0" "$usage" >&2; exit 2 ;;
esac
case "$allocator_backend" in
    accepted-c|native-shadow) ;;
    *) printf 'unsupported materialized dynamic allocator backend: %s\n' "$allocator_backend" >&2; exit 2 ;;
esac
readonly supplied explicit_work resumed action allocator_backend case_product case_name
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('materialized dynamic TMPDIR must be a physical checkout .work directory')
PY
if [ "$supplied" -eq 1 ]; then
    python3 -B - "$ROOT" "$2" <<'PY'
from pathlib import Path
import sys
root, work = Path(sys.argv[1]), Path(sys.argv[2])
if not work.is_absolute() or not work.is_dir() or work.resolve() != work or not work.is_relative_to(root / '.work'):
    raise SystemExit('materialized dynamic supplied work must be a physical checkout .work directory')
for name in ('installed', 'second', 'extracted'):
    if not (work / name).is_dir() or (work / name).is_symlink():
        raise SystemExit(f'materialized dynamic supplied work lacks the {name} tree')
for name in ('runtime.tar', 'second-runtime.tar'):
    if not (work / name).is_file() or (work / name).is_symlink():
        raise SystemExit(f'materialized dynamic supplied work lacks {name}')
for name in ('qualification-prepare.json', 'qualification-cases', 'qualification.json', 'expected.stdout'):
    if (work / name).exists() or (work / name).is_symlink():
        raise SystemExit(f'materialized dynamic supplied work already holds {name}')
PY
    work="$2"
elif [ "$resumed" -eq 1 ]; then
    python3 -B - "$ROOT" "$2" <<'PY'
from pathlib import Path
import sys
root, work = map(Path, sys.argv[1:])
if not work.is_absolute() or not work.is_dir() or work.is_symlink() or work.resolve() != work or not work.is_relative_to(root / '.work'):
    raise SystemExit('materialized dynamic resume work must be a physical checkout .work directory')
PY
    work="$2"
elif [ "$explicit_work" -eq 1 ]; then
    python3 -B - "$ROOT" "$2" <<'PY'
from pathlib import Path
import sys

root, work = map(Path, sys.argv[1:])
boundary = root / '.work'
if (not work.is_absolute() or work == boundary or not work.is_relative_to(boundary)
        or work.exists() or work.is_symlink() or not work.parent.is_dir()
        or work.parent.resolve(strict=True) != work.parent or work.resolve() != work):
    raise SystemExit('materialized dynamic --work must be a new physical checkout .work directory')
try:
    work.mkdir()
except OSError as error:
    raise SystemExit(f'materialized dynamic --work cannot be created: {error}') from error
PY
    work="$2"
else
    work="$(mktemp -d "$TMPDIR/materialized-dynamic.XXXXXX")"
fi
readonly work
if [ "$resumed" -eq 1 ]; then
    python3 -B - "$ROOT" "$work" <<'PY'
from pathlib import Path
import sys
root, work = map(Path, sys.argv[1:])
for path in (work / 'qualification-scratch', work / 'qualification-scratch/tmp'):
    if not path.is_dir() or path.is_symlink() or path.resolve() != path or not path.is_relative_to(root / '.work'):
        raise SystemExit('materialized dynamic resume work lacks physical retained case scratch')
PY
    export CRABC_WORK_DIR="$work/qualification-scratch"
    export TMPDIR="$work/qualification-scratch/tmp"
    case "$action" in
        next)
            python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" run-next --work "$work"
            ;;
        case)
            python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" run-resumed \
                --work "$work" --product "$case_product" --case "$case_name"
            ;;
        finish)
            python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" finish --work "$work"
            ;;
    esac
    exit 0
fi
check_spawn_interposition() {
    local installed="$1" execution_root="$2" name="$3"
    "$installed/bin/crabc-cc-dynamic" --dynamic-pie -DCRABC_SPAWN_ELF_INTERPOSITION \
        "$ROOT/compat/x86_64/owned_spawn_interposition_probe.c" -o "$work/$name"
    readelf --dyn-syms -W "$work/$name" >"$work/$name.symbols"
    for symbol in memcpy memset; do
        awk -v name="$symbol" '$5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { found = 1 }
            END { exit !found }' "$work/$name.symbols"
    done
    [ -d "$execution_root/bin" ]
    cp "$work/$name" "$execution_root/spawn-interposition"
    cp "$work/$name" "$execution_root/bin/true"
    timeout 20 chroot "$execution_root" /spawn-interposition >"$work/$name.stdout"
    [ ! -s "$work/$name.stdout" ]
}

check_non_pie() {
    local installed_root="$1" execution_root="$2" dependency="$3" name="$4"
    "$installed_root/bin/crabc-cc-dynamic" --dynamic-non-pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
        --application-dso "$dependency" -o "$work/$name"
    readelf -hW "$work/$name" >"$work/$name.header"
    grep -Eq 'Type: +EXEC' "$work/$name.header"
    readelf -lW "$work/$name" >"$work/$name.segments"
    grep -Fq '/lib/ld-crabc-x86_64.so.1' "$work/$name.segments"
    cp "$work/$name" "$execution_root/non-pie"
    timeout 20 chroot "$execution_root" /non-pie >"$work/$name.stdout"
    cmp "$work/expected.stdout" "$work/$name.stdout"
}
python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" prepare --work "$work"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIC -shared "$ROOT/compat/x86_64/owned_dynamic_dependency.c" \
    -Wl,-soname,liboracle-dependency.so -o "$work/liboracle-dependency.so"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
    -L"$work" -Wl,-rpath,"$work" -l:liboracle-dependency.so -o "$work/oracle"
timeout 20 "$work/oracle" >"$work/oracle.stdout"
check_basic_product() {
    local product="$1" label="$2"
    local driver="$product/bin/crabc-cc-dynamic"
    local dependency="$work/lib$label.so"
    local consumer="$work/$label-consumer"
    local execution_root="$work/$label-execution-root"
    "$driver" --dynamic-shared-object "$ROOT/compat/x86_64/owned_dynamic_dependency.c" -o "$dependency"
    "$driver" --dynamic-pie "$ROOT/compat/x86_64/owned_dynamic_consumer.c" \
        --application-dso "$dependency" -o "$consumer"
    for artifact in "$product/lib/ld-crabc-x86_64.so.1" "$product/usr/lib/libc.so"; do
        readelf -dW "$artifact" >"$work/$label-$(basename "$artifact").dynamic.txt"
        ! grep -E '\(NEEDED\)|\(TEXTREL\)' "$work/$label-$(basename "$artifact").dynamic.txt"
    done
    readelf -lW "$consumer" >"$consumer.segments.txt"
    grep -Fq '/lib/ld-crabc-x86_64.so.1' "$consumer.segments.txt"
    cp -a "$product" "$execution_root"
    mkdir "$execution_root/tmp"
    cp "$consumer" "$execution_root/consumer"
    cp "$dependency" "$execution_root/usr/lib/$(basename "$dependency")"
    timeout 20 chroot "$execution_root" /consumer >"$consumer.stdout"
    cmp "$work/expected.stdout" "$consumer.stdout"
    cmp "$work/oracle.stdout" "$consumer.stdout"
    check_spawn_interposition "$product" "$execution_root" "spawn-$label"
    check_non_pie "$product" "$execution_root" "$dependency" "non-pie-$label"
}

check_runtime_suites() {
    local label="$1" cases case_name
    cases="$(python3 -B - "$ROOT" <<'PYTHON'
import sys
sys.path.insert(0, sys.argv[1] + '/compat/x86_64')
from owned_dynamic_qualification import CASES
print('\n'.join(CASES))
PYTHON
)"
    while IFS= read -r case_name; do
        python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" run \
            --work "$work" --product "$label" --case "$case_name"
    done <<<"$cases"
}

if [ "$supplied" -eq 0 ]; then
    allocator_arguments=()
    if [ "$allocator_backend" = native-shadow ]; then
        allocator_arguments=(--allocator-backend native-shadow)
    fi
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/installed" "${allocator_arguments[@]}"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/second" "${allocator_arguments[@]}"
    python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" package "$work/installed" "$work/runtime.tar"
    python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" package "$work/second" "$work/second-runtime.tar"
    python3 -B "$ROOT/compat/x86_64/owned_dynamic_package.py" extract "$work/runtime.tar" "$work/extracted"
fi
cmp "$work/installed/share/crabc/manifest.json" "$work/second/share/crabc/manifest.json"
cmp "$work/runtime.tar" "$work/second-runtime.tar"
if [ "$explicit_work" -eq 1 ]; then
    mkdir "$work/qualification-scratch"
    mkdir "$work/qualification-scratch/tmp"
    printf 'retained\n' >"$work/qualification-scratch/retained-case-evidence"
    export CRABC_WORK_DIR="$work/qualification-scratch"
    export TMPDIR="$work/qualification-scratch/tmp"
fi
printf 'installed dynamic: allocation errno stdio threads\nordinary exit\n' >"$work/expected.stdout"
for label in installed second extracted; do
    check_basic_product "$work/$label" "$label"
    printf 'materialized dynamic product: PASS (%s)\n' "$label"
done
if [ "$action" = prepare ]; then
    next_case="$(python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" next --work "$work")"
    printf 'materialized dynamic products prepared; next case: %s\n' "$next_case"
    exit 0
fi
for label in installed second extracted; do
    check_runtime_suites "$label"
done
python3 -B "$ROOT/compat/x86_64/owned_dynamic_qualification.py" finish --work "$work"
printf 'materialized dynamic sysroot: PASS (two clean builds and extracted initial/runtime graphs); evidence: %s\n' "$work"
