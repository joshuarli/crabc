#!/usr/bin/env bash
# Differential glob result, append, link, and error evidence in isolated roots.
set -euo pipefail
ulimit -c 0

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly interpreter=/lib/ld-crabc-x86_64.so.1
readonly probe="$root/compat/x86_64/owned_glob_sequence_probe.c"

[ "$#" -le 2 ] || { printf 'usage: %s [STATIC_SYSROOT [DYNAMIC_SYSROOT]]\n' "$0" >&2; exit 2; }
python3 -B - "$root" "${TMPDIR:-}" "$@" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('glob sequence TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    product = Path(argument).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('glob sequence product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-glob-sequence.XXXXXX")"
chmod a+rx "$work"
printf 'glob sequence evidence: %s\n' "$work"

static_product="${1:-$work/static-product}"
dynamic_product="${2:-$work/dynamic-product}"
bash "$root/compat/x86_64/run_musl_oracle.sh" >"$work/oracle-check.stdout"
if [ "$#" -lt 1 ]; then
    python3 -B "$root/scripts/build_x86_64_owned_sysroot.py" \
        --output "$static_product" >"$work/static-build.json"
fi
if [ "$#" -lt 2 ]; then
    python3 -B "$root/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$dynamic_product" >"$work/dynamic-build.json"
fi

"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$probe" -o "$work/probe.o"
"$oracle_cc" -static -fno-pie -no-pie "$work/probe.o" -o "$work/oracle"
"$static_product/bin/crabc-cc" -static "$work/probe.o" -o "$work/static"
"$static_product/bin/crabc-cc" -static-pie "$work/probe.o" -o "$work/static-pie"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie "$work/probe.o" -o "$work/dynamic-pie"
"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-non-pie "$work/probe.o" -o "$work/dynamic-non-pie"

prepare_fixture() {
    local target="$1"
    mkdir -p "$target/fixture/dir" "$target/fixture/blocked"
    : >"$target/fixture/dir/alpha"
    : >"$target/fixture/dir/zeta"
    : >"$target/fixture/dir/.hidden"
    : >"$target/fixture/dir/"$'\200'"name"
    : >"$target/fixture/escaped*"
    : >"$target/fixture/file"
    : >"$target/fixture/blocked/secret"
    ln -s dir "$target/fixture/link-dir"
    ln -s absent "$target/fixture/dangling"
    ln -s loop "$target/fixture/loop"
    chmod 755 "$target" "$target/fixture" "$target/fixture/dir"
    chmod 700 "$target/fixture/blocked"
}

run_one() {
    local name="$1" image="$2"
    shift 2
    cp "$image" "$work/$name-root/consumer"
    if ! timeout 60 env -i PATH="$PATH" chroot "$work/$name-root" "$@" \
        >"$work/$name.stdout" 2>"$work/$name.stderr"; then
        printf 'glob sequence %s failed; evidence: %s\n' "$name" "$work" >&2
        return 1
    fi
    if ! cmp "$work/oracle.stdout" "$work/$name.stdout" ||
        ! cmp "$work/oracle.stderr" "$work/$name.stderr"; then
        printf 'glob sequence %s differs from pinned musl; evidence: %s\n' "$name" "$work" >&2
        return 1
    fi
}

mkdir "$work/oracle-root"
prepare_fixture "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
timeout 60 env -i PATH="$PATH" chroot "$work/oracle-root" /consumer \
    >"$work/oracle.stdout" 2>"$work/oracle.stderr"

for mode in static static-pie; do
    mkdir "$work/$mode-root"
    prepare_fixture "$work/$mode-root"
    run_one "$mode" "$work/$mode" /consumer
done
for mode in dynamic-pie dynamic-non-pie; do
    for entry in kernel direct; do
        target="$work/$mode-$entry-root"
        cp -a "$dynamic_product" "$target"
        prepare_fixture "$target"
        if [ "$entry" = direct ]; then
            run_one "$mode-$entry" "$work/$mode" "$interpreter" /consumer
        else
            run_one "$mode-$entry" "$work/$mode" /consumer
        fi
    done
done
sha256sum "$probe" "$work/probe.o" "$work/oracle" "$work/static" \
    "$work/static-pie" "$work/dynamic-pie" "$work/dynamic-non-pie" \
    "$work"/*.stdout "$work"/*.stderr >"$work/sha256.txt"
printf 'glob sequence: PASS (pinned musl, static/static PIE, dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
