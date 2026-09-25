#!/usr/bin/env bash
# Pinned-musl differential for application replacement of libc functions in
# the installed static archive.
#
# The link sweep (compat/x86_64/owned_static_replacement_sweep.py) links, for
# every public function both archives define, a program that defines it and
# names every other public symbol outside its musl member, and retains the
# whole link-result table. Each function in
# compat/x86_64/owned-static-replacement-roster.txt must link with musl and
# with the candidate in both static modes.
#
# Each probe role (compat/x86_64/owned_static_replacement_probe.c) is compiled
# once with the project headers and linked unchanged by static musl and by the
# installed crabc driver in static ET_EXEC and static-PIE mode. Musl's libc.a
# gives each source file its own member, so the role's own definitions link
# without a duplicate definition and libc callers that use the public symbol
# reach them. The candidate must link every role and reproduce musl's status
# and output byte for byte.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_static_replacement_probe.c"
readonly roles=(MALLOC_TRIO MALLOC_FULL STRINGS PRINTF VSNPRINTF SCANF)
readonly roster="$ROOT/compat/x86_64/owned-static-replacement-roster.txt"

[ "$#" -le 1 ] || {
    printf 'usage: %s [STATIC_SYSROOT]\n' "$0" >&2
    exit 2
}
[ "$(uname -sm)" = 'Linux x86_64' ]

python3 -B - "$ROOT" "${TMPDIR:-}" "${1:-}" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned static replacement TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned static replacement product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-static-replacement.XXXXXX")"
chmod a+rx "$work"
printf 'owned static replacement evidence: %s\n' "$work"
trap 'printf "owned static replacement failed near %s; evidence: %s\\n" "${step:-setup}" "$work" >&2' ERR

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null

product="${1:-}"
if [ -z "$product" ]; then
    step=build-static-product
    product="$work/static-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$product" >"$work/static-build.json"
fi
product="$(realpath -e "$product")"

step=link-sweep
required=()
while read -r function; do
    required+=(--require "$function")
done < <(grep -v '^#' "$roster" | tr -s ' ' '\n' | grep .)
python3 -B "$ROOT/compat/x86_64/owned_static_replacement_sweep.py" \
    --oracle-cc "$oracle_cc" --oracle-archive /opt/musl-1.2.6/lib/libc.a \
    --product "$product" --work "$work/sweep" "${required[@]}"

# Run one linked role in its own empty chroot; retain status and streams.
run_role() {
    local label="$1" executable="$2"
    local root="$work/$label-root" status=0
    mkdir -p "$root"
    cp "$executable" "$root/consumer"
    step="run-$label"
    timeout 40 env -i PATH="$PATH" chroot "$root" /consumer </dev/null \
        >"$work/$label.stdout" 2>"$work/$label.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$label.status"
}

for role in "${roles[@]}"; do
    name="$(printf '%s' "$role" | tr 'A-Z_' 'a-z-')"
    object="$work/$name.o"
    step="compile-$name"
    "$oracle_cc" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector -fPIC \
        -I"$ROOT/include" "-DCRABC_REPLACE_$role" -c "$probe" -o "$object"

    step="link-oracle-$name"
    "$oracle_cc" -static -fno-pie -no-pie "$object" -o "$work/oracle-$name"
    run_role "oracle-$name" "$work/oracle-$name"
    # The oracle must itself pass; a matching failure cannot qualify a role.
    [ "$(cat "$work/oracle-$name.status")" = 0 ]
    grep -qx owned-static-replacement-ok "$work/oracle-$name.stdout"

    for mode in static static-pie; do
        label="$mode-$name"
        step="link-$label"
        (
            cd "$work"
            "$product/bin/crabc-cc" "-$mode" --link-receipt "$label.receipt.json" \
                "$object" -o "$work/$label"
        )
        readelf -hW "$work/$label" >"$work/$label.header"
        if [ "$mode" = static ]; then
            grep -Eq 'Type:[[:space:]]+EXEC' "$work/$label.header"
        else
            grep -Eq 'Type:[[:space:]]+DYN' "$work/$label.header"
        fi
        run_role "$label" "$work/$label"
        step="compare-$label"
        cmp "$work/oracle-$name.status" "$work/$label.status"
        cmp "$work/oracle-$name.stdout" "$work/$label.stdout"
        cmp "$work/oracle-$name.stderr" "$work/$label.stderr"
    done
    printf 'owned static replacement %s: PASS\n' "$name"
done

printf 'owned static replacement: PASS (%s required replaceable functions; roles: %s; pinned-musl static link and transcript matched in static and static-PIE); evidence: %s\n' \
    "$(( ${#required[@]} / 2 ))" "${roles[*]}" "$work"
