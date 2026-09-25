#!/usr/bin/env bash
# Focused native proof for musl-shaped pthread/C11 aliases and interposition.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_pthread_alias_contract_probe.c"
readonly READER="$ROOT/compat/x86_64/owned_pthread_alias_contract_reader.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

# The sealed static driver admits its own relative receipt/map/trace trio.
# Run from the checkout so that path cannot silently escape the supplied
# sysroot or become a host linker flag.
cd "$ROOT"

usage() {
    printf 'usage: %s [--receipt-dir DIR --product-report REPORT [--historical-inputs INPUTS --historical-source-commit COMMIT]] STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned pthread alias contract: %s\n' "$*" >&2
    exit 1
}

RECEIPT_DIR=""
PRODUCT_REPORT=""
HISTORICAL_INPUTS=""
HISTORICAL_SOURCE_COMMIT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --receipt-dir)
            [ "$#" -ge 2 ] && [ -z "$RECEIPT_DIR" ] || usage
            RECEIPT_DIR="$2"
            shift 2
            ;;
        --product-report)
            [ "$#" -ge 2 ] && [ -z "$PRODUCT_REPORT" ] || usage
            PRODUCT_REPORT="$2"
            shift 2
            ;;
        --historical-inputs)
            [ "$#" -ge 2 ] && [ -z "$HISTORICAL_INPUTS" ] || usage
            HISTORICAL_INPUTS="$2"
            shift 2
            ;;
        --historical-source-commit)
            [ "$#" -ge 2 ] && [ -z "$HISTORICAL_SOURCE_COMMIT" ] || usage
            HISTORICAL_SOURCE_COMMIT="$2"
            shift 2
            ;;
        --*) usage ;;
        *) break ;;
    esac
done
[ "$#" -eq 2 ] || usage
if [ -n "$RECEIPT_DIR" ]; then
    # The earlier plain runner's input ledger is optional provenance.
    [ -n "$PRODUCT_REPORT" ] || usage
    if { [ -n "$HISTORICAL_INPUTS" ] && [ -z "$HISTORICAL_SOURCE_COMMIT" ]; } ||
        { [ -z "$HISTORICAL_INPUTS" ] && [ -n "$HISTORICAL_SOURCE_COMMIT" ]; }; then
        usage
    fi
else
    [ -z "$PRODUCT_REPORT" ] && [ -z "$HISTORICAL_INPUTS" ] && [ -z "$HISTORICAL_SOURCE_COMMIT" ] || usage
fi
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'
for tool in chroot cmp python3 readelf realpath sha256sum timeout; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$READER"; do
    [ -f "$source" ] || fail "missing source $source"
done

static_product="$(realpath -e "$1")"
dynamic_product="$(realpath -e "$2")"
if [ -n "$RECEIPT_DIR" ]; then
    RECEIPT_DIR="$(python3 -B - "$ROOT" "$TMPDIR" "$RECEIPT_DIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve(strict=True)
temporary = Path(sys.argv[2]).resolve(strict=True)
requested = Path(sys.argv[3])
candidate = requested.resolve(strict=False)
if candidate.exists() or candidate.is_symlink():
    raise SystemExit("owned pthread alias receipt directory must be fresh")
if not candidate.is_relative_to(root / ".work"):
    raise SystemExit("owned pthread alias receipt directory must remain below checkout .work")
print(candidate)
PY
)"
    PRODUCT_REPORT="$(realpath -e "$PRODUCT_REPORT")"
    if [ -n "$HISTORICAL_INPUTS" ]; then
        HISTORICAL_INPUTS="$(realpath -e "$HISTORICAL_INPUTS")"
    fi
fi
python3 -B - "$ROOT" "$TMPDIR" "$static_product" "$dynamic_product" "$RECEIPT_DIR" "$PRODUCT_REPORT" "$HISTORICAL_INPUTS" <<'PY'
import hashlib
import os
from pathlib import Path
import sys

root, temporary, static, dynamic = (Path(value).resolve(strict=True) for value in sys.argv[1:5])
receipt, product_report, historical = (sys.argv[5:])
retained_value = os.environ.get("CRABC_RETAINED_640C0939_ROOT")
allowed = [root / ".work"]
if retained_value:
    retained = Path(retained_value).resolve(strict=True)
    expected_static = retained / "static/products/primary"
    expected_dynamic = retained / "dynamic"
    if static != expected_static or dynamic != expected_dynamic:
        raise SystemExit(
            "owned pthread alias contract retained inputs must be the sealed "
            "640c0939 primary static and dynamic products"
        )
    expected_hashes = {
        static / "usr/lib/libc.a": "ba36c1db3e38c97f50c02c4cdffae845221a1070192b9149e01825867f96f5c8",
        dynamic / "usr/lib/libc.so": "2d32042be95daf2ba65f3b2eb7e3d738e3a429444fdf45c46699137c04e8725a",
    }
    for path, expected in expected_hashes.items():
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != expected:
            raise SystemExit(f"sealed retained product hash drifted: {path}")
    allowed.append(retained)
for path, label in ((temporary, "TMPDIR"), (static, "static product"), (dynamic, "dynamic product")):
    if not any(path.is_relative_to(base) for base in allowed):
        raise SystemExit(f"owned pthread alias contract {label} must remain below checkout .work")
for path, label in ((static / "bin/crabc-cc", "static compiler"),
                    (static / "usr/lib/libc.a", "static libc"),
                    (dynamic / "bin/crabc-cc-dynamic", "dynamic compiler"),
                    (dynamic / "usr/lib/libc.so", "dynamic libc"),
                    (dynamic / "lib/ld-crabc-x86_64.so.1", "dynamic loader")):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"owned pthread alias contract missing physical {label}: {path}")


def overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


# The runner writes its evidence under either TMPDIR or --receipt-dir. Check
# both physical work roots before mkdir, source capture, or any command can
# write into a caller-supplied selected product.
for product, label in ((static, "static product"), (dynamic, "dynamic product")):
    if overlaps(temporary, product):
        raise SystemExit(f"owned pthread alias contract TMPDIR overlaps {label}")
if receipt:
    receipt_path = Path(receipt).resolve(strict=False)
    if receipt_path.exists() or receipt_path.is_symlink() or not receipt_path.is_relative_to(root / ".work"):
        raise SystemExit("owned pthread alias contract receipt directory is unsafe")
    for product, label in ((static, "static product"), (dynamic, "dynamic product")):
        if overlaps(receipt_path, product):
            raise SystemExit(f"owned pthread alias contract receipt directory overlaps {label}")
    supplied = [(Path(product_report), "product anchor")]
    if historical:
        supplied.append((Path(historical), "historical input identities"))
    for path, label in supplied:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"owned pthread alias contract missing physical {label}: {path}")
PY

readonly STATIC_PRODUCT="$static_product"
readonly DYNAMIC_PRODUCT="$dynamic_product"
if [ -n "$RECEIPT_DIR" ]; then
    mkdir "$RECEIPT_DIR"
    readonly WORK="$RECEIPT_DIR"
else
    readonly WORK="$(mktemp -d "$TMPDIR/owned-pthread-alias-contract.XXXXXX")"
fi
chmod a+rx "$WORK"
case "$WORK" in
    "$ROOT"/.work/*) readonly WORK_RELATIVE="${WORK#"$ROOT"/}" ;;
    *) fail "work directory escaped checkout .work: $WORK" ;;
esac
printf 'owned pthread alias contract evidence: %s\n' "$WORK"

if [ -n "$RECEIPT_DIR" ]; then
    python3 -B "$READER" --capture-source --root "$ROOT" --output "$WORK/source-before.json"
fi

if [ -n "$RECEIPT_DIR" ]; then
python3 -B - "$WORK/input-identities.json" "$CONTRACT_SOURCE" "$READER" "$0" \
    "$ORACLE_CC" "$MUSL_LIB" "$MUSL_ARCHIVE" "$STATIC_PRODUCT/bin/crabc-cc" \
    "$STATIC_PRODUCT/usr/lib/libc.a" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" \
    "$DYNAMIC_PRODUCT/usr/lib/libc.so" "$DYNAMIC_PRODUCT/lib/ld-crabc-x86_64.so.1" \
    "$PRODUCT_REPORT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
names = ("probe", "reader", "runner", "oracle_compiler", "musl_shared", "musl_archive",
         "static_driver", "static_libc", "dynamic_driver", "dynamic_libc", "dynamic_loader",
         "product_report")
paths = [Path(value).resolve(strict=True) for value in sys.argv[2:]]
output.write_text(json.dumps({
    "format": "owned-pthread-alias-contract-inputs-v2",
    "inputs": {
        name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
               "size": path.stat().st_size}
        for name, path in zip(names, paths)
    },
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
else
python3 -B - "$WORK/input-identities.json" "$CONTRACT_SOURCE" "$READER" "$0" \
    "$MUSL_LIB" "$MUSL_ARCHIVE" "$STATIC_PRODUCT/bin/crabc-cc" \
    "$STATIC_PRODUCT/usr/lib/libc.a" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" \
    "$DYNAMIC_PRODUCT/usr/lib/libc.so" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
names = ("probe", "reader", "runner", "musl_shared", "musl_archive", "static_driver",
         "static_libc", "dynamic_driver", "dynamic_libc")
paths = [Path(value).resolve(strict=True) for value in sys.argv[2:]]
output.write_text(json.dumps({
    "format": "owned-pthread-alias-contract-inputs-v1",
    "inputs": {
        name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for name, path in zip(names, paths)
    },
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

run() {
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
    timeout 45 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status; evidence: $WORK"
}

same_transcript() {
    local expected="$1" actual="$2"
    cmp "$WORK/$expected.stdout" "$WORK/$actual.stdout" || fail "$actual stdout differs from $expected"
    cmp "$WORK/$expected.stderr" "$WORK/$actual.stderr" || fail "$actual stderr differs from $expected"
    cmp "$WORK/$expected.status" "$WORK/$actual.status" || fail "$actual status differs from $expected"
}

assert_elf_type() {
    local label="$1" binary="$2" expected="$3"
    readelf --file-header --wide "$binary" >"$WORK/$label.file-header.txt"
    case "$expected" in
        rel)
            grep -Eq 'Type:[[:space:]]+REL[[:space:]]+\(Relocatable file\)' \
                "$WORK/$label.file-header.txt" || fail "$label is not ET_REL"
            ;;
        exec)
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
                "$WORK/$label.file-header.txt" || fail "$label is not ET_EXEC"
            ;;
        pie)
            grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' \
                "$WORK/$label.file-header.txt" || fail "$label is not PIE ET_DYN"
            ;;
        *) fail "unknown ELF type expectation $expected for $label" ;;
    esac
}

compile_object() {
    run contract-compile "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        -std=c11 -fno-builtin -fno-stack-protector -pthread -c "$CONTRACT_SOURCE" \
        -o "$WORK/contract.o"
}

compile_object
assert_elf_type contract.o "$WORK/contract.o" rel

run oracle-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -pthread \
    "$WORK/contract.o" "-Wl,-Map,$WORK/oracle-contract.map" -o "$WORK/oracle-contract"
run oracle "$WORK/oracle-contract"
[ "$(cat "$WORK/oracle.stdout")" = 'owned-pthread-alias-contract-ok' ] ||
    fail 'pinned musl alias contract transcript drifted'
[ ! -s "$WORK/oracle.stderr" ] || fail 'pinned musl alias contract emitted stderr'
assert_elf_type oracle-contract "$WORK/oracle-contract" exec

for mode in static static-pie; do
    if [ -n "$RECEIPT_DIR" ]; then
        run "$mode-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" -pthread \
            "$WORK/contract.o" --link-receipt "$WORK_RELATIVE/$mode-contract.link.json" \
            -o "$WORK/$mode-contract"
    else
        run "$mode-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" -pthread \
            "$WORK/contract.o" -o "$WORK/$mode-contract"
    fi
    case "$mode" in
        static) assert_elf_type "$mode-contract" "$WORK/$mode-contract" exec ;;
        static-pie) assert_elf_type "$mode-contract" "$WORK/$mode-contract" pie ;;
    esac
    run "$mode" "$WORK/$mode-contract"
    same_transcript oracle "$mode"
done

for mode in pie non-pie; do
    case "$mode" in
        pie) oracle_mode=(-pie); oracle_type=pie ;;
        non-pie) oracle_mode=(-no-pie); oracle_type=exec ;;
    esac
    run "musl-dynamic-$mode-link" "$ORACLE_CC" -std=c11 -pthread -rdynamic \
        "${oracle_mode[@]}" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
        "$WORK/contract.o" "-Wl,-Map,$WORK/musl-dynamic-$mode-contract.map" \
        -o "$WORK/musl-dynamic-$mode-contract"
    assert_elf_type "musl-dynamic-$mode-contract" \
        "$WORK/musl-dynamic-$mode-contract" "$oracle_type"

    musl_root="$WORK/musl-dynamic-$mode-root"
    mkdir "$musl_root" "$musl_root/lib" "$musl_root/usr" "$musl_root/usr/lib"
    cp "$MUSL_LIB" "$musl_root/lib/ld-musl-x86_64.so.1"
    cp "$MUSL_LIB" "$musl_root/usr/lib/libc.so"
    cp "$WORK/musl-dynamic-$mode-contract" "$musl_root/contract"
    run "musl-dynamic-$mode-kernel" chroot "$musl_root" /contract
    run "musl-dynamic-$mode-direct" chroot "$musl_root" /lib/ld-musl-x86_64.so.1 /contract
    same_transcript "musl-dynamic-$mode-kernel" "musl-dynamic-$mode-direct"
done

for mode in pie non-pie; do
    run "dynamic-$mode-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -pthread -rdynamic "$WORK/contract.o" \
        -o "$WORK/dynamic-$mode-contract"
    case "$mode" in
        pie) assert_elf_type "dynamic-$mode-contract" "$WORK/dynamic-$mode-contract" pie ;;
        non-pie) assert_elf_type "dynamic-$mode-contract" "$WORK/dynamic-$mode-contract" exec ;;
    esac

    root="$WORK/dynamic-$mode-root"
    mkdir "$root" "$root/scratch"
    cp -a "$DYNAMIC_PRODUCT/." "$root"
    cp "$WORK/dynamic-$mode-contract" "$root/contract"
    run "dynamic-$mode-kernel" chroot "$root" /contract
    same_transcript "musl-dynamic-$mode-kernel" "dynamic-$mode-kernel"
    run "dynamic-$mode-direct" chroot "$root" "$INTERPRETER" /contract
    same_transcript "musl-dynamic-$mode-direct" "dynamic-$mode-direct"
done

readelf --dyn-syms --wide "$MUSL_LIB" >"$WORK/musl-dynamic-symbols.txt"
readelf --dyn-syms --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-dynamic-symbols.txt"
readelf --symbols --wide "$MUSL_LIB" >"$WORK/musl-shared-symbols.txt"
readelf --symbols --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-shared-symbols.txt"
readelf --symbols --wide "$MUSL_ARCHIVE" >"$WORK/musl-static-symbols.txt"
readelf --symbols --wide "$STATIC_PRODUCT/usr/lib/libc.a" >"$WORK/candidate-static-symbols.txt"
readelf --relocs --wide "$MUSL_ARCHIVE" >"$WORK/musl-static-relocations.txt"
readelf --relocs --wide "$STATIC_PRODUCT/usr/lib/libc.a" >"$WORK/candidate-static-relocations.txt"
for binary in "$WORK"/dynamic-*-contract; do
    readelf --dyn-syms --wide "$binary" >"$binary.symbols.txt"
done

python3 -B "$READER" --check-work --work "$WORK"

if [ -n "$RECEIPT_DIR" ]; then
    historical=()
    if [ -n "$HISTORICAL_INPUTS" ]; then
        historical=(--historical-inputs "$HISTORICAL_INPUTS" --historical-source-commit "$HISTORICAL_SOURCE_COMMIT")
    fi
    python3 -B "$READER" --collect-report --root "$ROOT" --work "$WORK" \
        --product-report "$PRODUCT_REPORT" "${historical[@]}"
    python3 -B "$READER" --validate-report "$WORK/report.json"
fi

printf 'owned pthread alias contract: PASS (pinned musl archive/shared aliases and matching static/shared execution matrix, exact executable ELF modes, strong public override, mq_notify public detach relocation, synchronous pthread_join hidden-provider route); evidence: %s\n' "$WORK"
