#!/usr/bin/env bash
# Bounded installed-header composition for selected numeric, locale, and wide
# conversion behavior.  This has two Musl-parity workloads: the ordinary
# probes combine behind one driver, while locale_alias_contract_probe.c keeps
# its public replacement definitions in a separate executable.  A third,
# candidate-only workload records existing macro-gated profile observations
# without using a Musl comparison.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly RECEIPT="$ROOT/compat/x86_64/owned_text_locale_numeric_component_receipt.py"
readonly PROVIDER="$ROOT/compat/x86_64/owned_text_locale_numeric_component_evidence.py"
readonly CONTRACT="$ROOT/compat/x86_64/owned_text_locale_numeric_component_contract.py"
readonly COPIES="$ROOT/compat/x86_64/owned_crypt_runtime_evidence.py"
readonly ALIAS_CONTRACT="$ROOT/compat/x86_64/locale_alias_contract.json"
readonly ALIAS_SYMBOLS="$ROOT/compat/x86_64/locale_alias_contract_symbols.py"
readonly NM=/usr/bin/nm
readonly READELF=/usr/bin/readelf

usage() {
    printf 'usage: %s --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned text/locale/numeric component: %s\n' "$*" >&2
    exit 1
}

provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$provided_static" ] && [ -n "$2" ] && [[ "$2" != -* ]] || usage
            provided_static="$2"
            shift 2
            ;;
        -*) usage ;;
        *)
            [ -z "$provided_dynamic" ] && [ -n "$1" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
[ -n "$provided_static" ] && [ -n "$provided_dynamic" ] || usage

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail 'requires checkout-local TMPDIR'

# Product inputs and every disposable path are physical checkout-local copies.
# The source products are read only by this runner; each dynamic launch gets a
# fresh full copy below the evidence directory, never a hard link.
python3 -B - "$ROOT" "$TMPDIR" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import stat
import sys

root, temporary, static, dynamic = map(Path, sys.argv[1:])
root = root.resolve(strict=True)
for path, label in ((temporary, 'TMPDIR'), (static, 'static product'), (dynamic, 'dynamic product')):
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(root / '.work'):
        raise SystemExit(f'owned text/locale/numeric component {label} must stay below checkout .work')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit(f'owned text/locale/numeric component {label} traverses a symbolic link')
    if not path.is_dir() or path.is_symlink():
        raise SystemExit(f'owned text/locale/numeric component {label} is not a physical directory')
PY

provided_static="$(realpath -e -- "$provided_static")"
provided_dynamic="$(realpath -e -- "$provided_dynamic")"
readonly STATIC_PRODUCT="$provided_static"
readonly DYNAMIC_PRODUCT="$provided_dynamic"

for tool in chroot cmp cp mkdir mktemp python3 realpath sha256sum timeout "$NM" "$READELF"; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl oracle compiler'
[ -x "$STATIC_PRODUCT/bin/crabc-cc" ] || fail 'missing supplied static driver'
[ -x "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" ] || fail 'missing supplied dynamic driver'
for path in "$RECEIPT" "$PROVIDER" "$CONTRACT" "$COPIES" "$ALIAS_CONTRACT" "$ALIAS_SYMBOLS"; do
    [ -f "$path" ] || fail "missing retained component input: $path"
done

python3 -B - "$ROOT" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" <<'PY'
from pathlib import Path
import sys

root, static, dynamic = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_product_evidence as products
products._validate_static_product(static)
products._validate_dynamic_product(dynamic)
PY

readonly WORK="$(mktemp -d "$TMPDIR/owned-text-locale-numeric.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned text/locale/numeric component evidence: %s\n' "$WORK"

readonly -a ROLE_SOURCES=(
    'driver|compat/x86_64/owned_text_locale_numeric_component_driver.c|'
    'float-parse|compat/x86_64/libc_float_parse_probe.c|main=crabc_text_locale_numeric_float_parse_private_main'
    'ctype-locators|compat/x86_64/libc_locale_ctype_locators_probe.c|main=crabc_text_locale_numeric_ctype_locators_private_main'
    'locale-narrow|compat/x86_64/libc_locale_narrow_probe.c|main=crabc_text_locale_numeric_locale_narrow_private_main'
    'locale-object-wide|compat/x86_64/libc_locale_object_wide_probe.c|main=crabc_text_locale_numeric_locale_object_wide_private_main'
    'locale-wide-iconv|compat/x86_64/libc_locale_wide_iconv_probe.c|main=crabc_text_locale_numeric_locale_wide_iconv_private_main'
    'locale-multibyte|compat/x86_64/libc_locale_multibyte_probe.c|main=crabc_text_locale_numeric_locale_multibyte_private_main'
    'wide-character|compat/x86_64/libc_wide_character_probe.c|main=crabc_text_locale_numeric_wide_character_private_main'
    'locale-alias-contract|compat/x86_64/locale_alias_contract_probe.c|'
    'strfmon|compat/x86_64/owned_strfmon_probe.c|main=crabc_text_locale_numeric_strfmon_private_main'
    'wide-conversion|compat/x86_64/owned_wide_conversion_probe.c|main=crabc_text_locale_numeric_wide_conversion_private_main'
    'source-specific-driver|compat/x86_64/owned_text_locale_numeric_source_specific_driver.c|'
    'candidate-locale-object-wide-profile|compat/x86_64/libc_locale_object_wide_probe.c|CRABC_LOCALE_OBJECT_WIDE_FREESTANDING;CRABC_OWNED_LOCALE_ENVIRONMENT;main=crabc_text_locale_numeric_candidate_locale_object_wide_private_main'
    'candidate-locale-wide-iconv-profile|compat/x86_64/libc_locale_wide_iconv_probe.c|CRABC_LOCALE_WIDE_ICONV_FREESTANDING;main=crabc_text_locale_numeric_candidate_locale_wide_iconv_private_main'
    'candidate-locale-multibyte-profile|compat/x86_64/libc_locale_multibyte_probe.c|CRABC_LOCALE_MULTIBYTE_FREESTANDING;main=crabc_text_locale_numeric_candidate_locale_multibyte_private_main'
)
readonly -a NORMAL_ROLES=(driver float-parse ctype-locators locale-narrow locale-object-wide locale-wide-iconv locale-multibyte wide-character strfmon wide-conversion)
readonly -a SOURCE_SPECIFIC_ROLES=(source-specific-driver candidate-locale-object-wide-profile candidate-locale-wide-iconv-profile candidate-locale-multibyte-profile)
declare -a ROLE_OBJECTS=() NORMAL_OBJECTS=() SOURCE_SPECIFIC_OBJECTS=() SEALED_SOURCES=()
for entry in "${ROLE_SOURCES[@]}"; do
    IFS='|' read -r role relative define <<<"$entry"
    ROLE_OBJECTS+=("$WORK/$role.o")
    case " ${NORMAL_ROLES[*]} " in *" $role "*) NORMAL_OBJECTS+=("$WORK/$role.o") ;; esac
    case " ${SOURCE_SPECIFIC_ROLES[*]} " in *" $role "*) SOURCE_SPECIFIC_OBJECTS+=("$WORK/$role.o") ;; esac
done
while IFS= read -r source; do
    SEALED_SOURCES+=("$ROOT/$source")
done < <(python3 -B - "$ROOT" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_text_locale_numeric_component_contract as contract
for value in contract.direct_sources():
    print(value.as_posix())
PY
)

capture() {
    local stem="$1" status=0
    shift
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    pwd -P >"$WORK/$stem.cwd"
    set +e
    timeout 120 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status"
}

resolve_tool() {
    local attribute="$1"
    python3 -B - "$DYNAMIC_PRODUCT" "$attribute" <<'PY'
import importlib.util
from pathlib import Path
import sys

product, attribute = map(Path, sys.argv[1:])
helper = product / 'share/crabc/crabc_cc_static.py'
spec = importlib.util.spec_from_file_location('owned_text_locale_numeric_component_resolve', helper)
if spec is None or spec.loader is None:
    raise SystemExit('cannot load supplied compiler helper')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
    print(Path(getattr(module, str(attribute))()).resolve(strict=True))
finally:
    sys.modules.pop(spec.name, None)
PY
}

validate_header_traces() {
    python3 -B - "$ROOT" "$WORK" "$DYNAMIC_PRODUCT" <<'PY'
from pathlib import Path
import sys
root, work, dynamic = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_text_locale_numeric_component_evidence as evidence
evidence.validate_header_traces(root, work, dynamic, source_mount='/workspace')
PY
}

validate_link() {
    local stem="$1" product="$2" workload="$3" executable="$4" receipt="$5" linkage="$6" export_dynamic="$7"
    capture "$stem-validate" python3 -B - /workspace "$product" "$workload" "$executable" "$receipt" "$linkage" "$export_dynamic" <<'PY'
import json
from pathlib import Path
import sys

source_mount, product, workload, executable, receipt, linkage, export_dynamic = sys.argv[1:]
sys.path.insert(0, '/workspace/compat/x86_64')
from owned_posix_product_evidence import validate_link
record = validate_link(Path(product), Path(workload), Path(executable), Path(receipt), linkage,
                       export_dynamic=(export_dynamic == '1'))
print(json.dumps(record, sort_keys=True, separators=(',', ':')))
PY
    cp "$WORK/$stem-validate.stdout" "$WORK/$stem.product-link.json"
}

compare_oracle() {
    local workload="$1" stem="$2"
    for suffix in stdout stderr status; do
        cmp "$WORK/oracle-$workload-run.$suffix" "$WORK/$stem.$suffix" ||
            fail "$stem $suffix differs from pinned musl $workload oracle"
    done
}

compare_source_specific() {
    local stem="$1"
    for suffix in stdout stderr status; do
        cmp "$WORK/source-specific-static-run.$suffix" "$WORK/$stem.$suffix" ||
            fail "$stem $suffix differs from the candidate static source-specific baseline"
    done
}

capture source-product-before python3 -B "$RECEIPT" seal --root "$ROOT" --static "$STATIC_PRODUCT" \
    --dynamic "$DYNAMIC_PRODUCT" --output "$WORK/source-product-before.json"
capture tools-before python3 -B "$RECEIPT" tools --root "$ROOT" --static "$STATIC_PRODUCT" \
    --dynamic "$DYNAMIC_PRODUCT" --output "$WORK/tools-before.json"
readonly COMPILER="$(resolve_tool compiler)"
readonly LINKER="$(resolve_tool linker)"

for entry in "${ROLE_SOURCES[@]}"; do
    IFS='|' read -r role relative define <<<"$entry"
    header_arguments=(env -i LC_ALL=C PATH=/usr/bin:/bin SOURCE_DATE_EPOCH=1 TZ=UTC "$COMPILER"
        -nostdinc -isystem "$DYNAMIC_PRODUCT/usr/include" -ffreestanding -fno-builtin -fstack-protector-strong
        -std=c11 -D_GNU_SOURCE -fno-builtin -frounding-math -fno-stack-protector)
    if [ -n "$define" ]; then
        IFS=';' read -r -a define_values <<<"$define"
        for value in "${define_values[@]}"; do header_arguments+=("-D$value"); done
    fi
    header_arguments+=(-fPIE -E -H "$ROOT/$relative")
    capture "header-$role" "${header_arguments[@]}"
done
validate_header_traces || fail 'installed header trace escaped the supplied dynamic product'

for entry in "${ROLE_SOURCES[@]}"; do
    IFS='|' read -r role relative define <<<"$entry"
    compile_arguments=(--dynamic-pie -std=c11 -D_GNU_SOURCE -fno-builtin -frounding-math -fno-stack-protector)
    if [ -n "$define" ]; then
        IFS=';' read -r -a define_values <<<"$define"
        for value in "${define_values[@]}"; do compile_arguments+=("-D$value"); done
    fi
    compile_arguments+=(-c "$ROOT/$relative" -o "$WORK/$role.o")
    capture "compile-$role" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "${compile_arguments[@]}"
done
capture combine "$LINKER" -r -o "$WORK/normal-workload.o" "${NORMAL_OBJECTS[@]}"
capture combine-source-specific "$LINKER" -r -o "$WORK/source-specific-workload.o" "${SOURCE_SPECIFIC_OBJECTS[@]}"
sha256sum "${SEALED_SOURCES[@]}" "${ROLE_OBJECTS[@]}" "$WORK/normal-workload.o" \
    "$WORK/source-specific-workload.o" >"$WORK/source-object-before.sha256"

capture normal-imports "$NM" --undefined-only --format=posix "$WORK/normal-workload.o"
capture dynamic-provider-symbols "$READELF" --dyn-syms -W "$DYNAMIC_PRODUCT/usr/lib/libc.so"
capture static-provider-symbols "$NM" -A -g --defined-only --format=posix "$STATIC_PRODUCT/usr/lib/libc.a"
provider_arguments=(python3 -B "$PROVIDER" --imports "$WORK/normal-imports.stdout" \
    --dynamic-definitions "$WORK/dynamic-provider-symbols.stdout" \
    --static-definitions "$WORK/static-provider-symbols.stdout")
capture component-preflight "${provider_arguments[@]}"

for workload in normal alias; do
    if [ "$workload" = normal ]; then object="$WORK/normal-workload.o"; else object="$WORK/locale-alias-contract.o"; fi
    capture "oracle-$workload-link" "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie "$object" -lm -o "$WORK/oracle-$workload"
    capture "oracle-$workload-run" env -i LC_ALL=C LANG=C TZ=UTC "$WORK/oracle-$workload"
    [ ! -s "$WORK/oracle-$workload-run.stderr" ] || fail "pinned musl $workload oracle emitted stderr"
    for linkage in static static-pie; do
        executable="$WORK/$workload-$linkage"
        receipt="$WORK/$workload-$linkage.crabc-link.json"
        (
            cd "$WORK"
            capture "$workload-$linkage-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$linkage" --link-receipt \
                "$(basename "$receipt")" "$object" -o "$executable"
        )
        validate_link "$workload-$linkage" "$STATIC_PRODUCT" "$object" "$executable" "$receipt" "$linkage" 0
        capture "$workload-$linkage-run" env -i LC_ALL=C LANG=C TZ=UTC "$executable"
        compare_oracle "$workload" "$workload-$linkage-run"
    done
    for mode in pie non-pie; do
        linkage="dynamic-$mode"
        executable="$WORK/$workload-$linkage"
        dynamic_arguments=("$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode")
        export_dynamic=0
        if [ "$workload" = alias ]; then dynamic_arguments+=(-rdynamic); export_dynamic=1; fi
        dynamic_arguments+=("$object" -o "$executable")
        capture "$workload-$linkage-link" "${dynamic_arguments[@]}"
        validate_link "$workload-$linkage" "$DYNAMIC_PRODUCT" "$object" "$executable" \
            "$executable.crabc-link.json" "$mode" "$export_dynamic"
        root_copy="$WORK/$workload-dynamic-$mode-root"
        mkdir "$root_copy"
        cp -a "$DYNAMIC_PRODUCT/." "$root_copy"
        cp "$executable" "$root_copy/consumer"
        record="$WORK/$workload-dynamic-$mode-execution-payload.json"
        capture "$workload-$linkage-copy-before" python3 -B "$COPIES" record --product "$DYNAMIC_PRODUCT" \
            --execution-root "$root_copy" --source-consumer "$executable" --execution-consumer "$root_copy/consumer" \
            --record "$record"
        capture "$workload-$linkage-copy-audit-before" python3 -B "$COPIES" audit --product "$DYNAMIC_PRODUCT" \
            --execution-root "$root_copy" --source-consumer "$executable" --execution-consumer "$root_copy/consumer" \
            --record "$record"
        capture "$workload-$linkage-kernel" chroot "$root_copy" /consumer
        compare_oracle "$workload" "$workload-$linkage-kernel"
        capture "$workload-$linkage-direct" chroot "$root_copy" "$INTERPRETER" /consumer
        compare_oracle "$workload" "$workload-$linkage-direct"
        capture "$workload-$linkage-copy-audit-after" python3 -B "$COPIES" audit --product "$DYNAMIC_PRODUCT" \
            --execution-root "$root_copy" --source-consumer "$executable" --execution-consumer "$root_copy/consumer" \
            --record "$record"
    done
done

# The existing selectors below assert source-specific candidate behavior.  The
# static candidate transcript is a retained baseline only; no pinned-musl
# executable is linked for this workload because its assertions intentionally
# differ from Musl for the named profile boundaries.
workload=source-specific
object="$WORK/source-specific-workload.o"
for linkage in static static-pie; do
    executable="$WORK/$workload-$linkage"
    receipt="$WORK/$workload-$linkage.crabc-link.json"
    (
        cd "$WORK"
        capture "$workload-$linkage-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$linkage" --link-receipt \
            "$(basename "$receipt")" "$object" -o "$executable"
    )
    validate_link "$workload-$linkage" "$STATIC_PRODUCT" "$object" "$executable" "$receipt" "$linkage" 0
    capture "$workload-$linkage-run" env -i LC_ALL=C LANG=C TZ=UTC "$executable"
    [ ! -s "$WORK/$workload-$linkage-run.stderr" ] || fail "$workload $linkage emitted stderr"
    if [ "$linkage" = static-pie ]; then compare_source_specific "$workload-$linkage-run"; fi
done
for mode in pie non-pie; do
    linkage="dynamic-$mode"
    executable="$WORK/$workload-$linkage"
    capture "$workload-$linkage-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$object" -o "$executable"
    validate_link "$workload-$linkage" "$DYNAMIC_PRODUCT" "$object" "$executable" \
        "$executable.crabc-link.json" "$mode" 0
    root_copy="$WORK/$workload-dynamic-$mode-root"
    mkdir "$root_copy"
    cp -a "$DYNAMIC_PRODUCT/." "$root_copy"
    cp "$executable" "$root_copy/consumer"
    record="$WORK/$workload-dynamic-$mode-execution-payload.json"
    capture "$workload-$linkage-copy-before" python3 -B "$COPIES" record --product "$DYNAMIC_PRODUCT" \
        --execution-root "$root_copy" --source-consumer "$executable" --execution-consumer "$root_copy/consumer" \
        --record "$record"
    capture "$workload-$linkage-copy-audit-before" python3 -B "$COPIES" audit --product "$DYNAMIC_PRODUCT" \
        --execution-root "$root_copy" --source-consumer "$executable" --execution-consumer "$root_copy/consumer" \
        --record "$record"
    capture "$workload-$linkage-kernel" chroot "$root_copy" /consumer
    compare_source_specific "$workload-$linkage-kernel"
    capture "$workload-$linkage-direct" chroot "$root_copy" "$INTERPRETER" /consumer
    compare_source_specific "$workload-$linkage-direct"
    capture "$workload-$linkage-copy-audit-after" python3 -B "$COPIES" audit --product "$DYNAMIC_PRODUCT" \
        --execution-root "$root_copy" --source-consumer "$executable" --execution-consumer "$root_copy/consumer" \
        --record "$record"
done

capture oracle-static-symbols "$READELF" -Ws /opt/musl-1.2.6/lib/libc.a
capture oracle-dynamic-symbols "$READELF" --dyn-syms -W /opt/musl-1.2.6/lib/libc.so
capture oracle-shared-symbols "$READELF" -Ws /opt/musl-1.2.6/lib/libc.so
capture candidate-static-symbols "$READELF" -Ws "$STATIC_PRODUCT/usr/lib/libc.a"
capture candidate-dynamic-symbols "$READELF" --dyn-syms -W "$DYNAMIC_PRODUCT/usr/lib/libc.so"
capture candidate-shared-symbols "$READELF" -Ws "$DYNAMIC_PRODUCT/usr/lib/libc.so"
capture executable-dynamic-pie-symbols "$READELF" --dyn-syms -W "$WORK/alias-dynamic-pie"
capture executable-dynamic-non-pie-symbols "$READELF" --dyn-syms -W "$WORK/alias-dynamic-non-pie"
capture alias-symbol-observation python3 -B "$ALIAS_SYMBOLS" "$ALIAS_CONTRACT" \
    "$WORK/oracle-static-symbols.stdout" "$WORK/oracle-dynamic-symbols.stdout" \
    "$WORK/oracle-shared-symbols.stdout" "$WORK/candidate-static-symbols.stdout" \
    "$WORK/candidate-dynamic-symbols.stdout" "$WORK/candidate-shared-symbols.stdout" \
    "$WORK/executable-dynamic-pie-symbols.stdout" "$WORK/executable-dynamic-non-pie-symbols.stdout" \
    "$WORK/alias-observation.json"

capture tools-after python3 -B "$RECEIPT" tools --root "$ROOT" --static "$STATIC_PRODUCT" \
    --dynamic "$DYNAMIC_PRODUCT" --output "$WORK/tools-after.json"
cmp "$WORK/tools-before.json" "$WORK/tools-after.json" || fail 'tool roster changed during execution'
capture source-product-after python3 -B "$RECEIPT" seal --root "$ROOT" --static "$STATIC_PRODUCT" \
    --dynamic "$DYNAMIC_PRODUCT" --output "$WORK/source-product-after.json"
cmp "$WORK/source-product-before.json" "$WORK/source-product-after.json" ||
    fail 'component source or supplied product changed during execution'
sha256sum -c "$WORK/source-object-before.sha256" >"$WORK/source-object-after.txt" ||
    fail 'component source or installed-header ET_REL object changed during execution'
capture component-collector "${provider_arguments[@]}"
cmp "$WORK/component-preflight.stdout" "$WORK/component-collector.stdout" ||
    fail 'normal provider collector changed during execution'

python3 -B "$RECEIPT" write-report --root "$ROOT" --work "$WORK" --static "$STATIC_PRODUCT" \
    --dynamic "$DYNAMIC_PRODUCT" --output "$WORK/owned-text-locale-numeric.json"
python3 -B "$RECEIPT" validate-report --root "$ROOT" --report "$WORK/owned-text-locale-numeric.json"

printf 'owned text/locale/numeric component: PASS (11 bounded Musl-parity rows; 3 non-credit source-specific candidate observations; selected normal imports rebound to physical static/dynamic providers; separate public-alias executable; static/static-PIE and dynamic PIE/non-PIE kernel/direct; no family completion) evidence: %s\n' "$WORK"
