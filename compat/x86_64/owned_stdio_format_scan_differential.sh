#!/usr/bin/env bash
# Run one installed-header format/scan object against pinned musl and both owned products.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="$ROOT/compat/x86_64/owned_stdio_format_scan_probe.c"
ORACLE=/usr/local/bin/crabc-x86_64-musl-gcc
[ "$#" -eq 2 ] || { printf 'usage: %s STATIC_PRODUCT DYNAMIC_PRODUCT\n' "$0" >&2; exit 2; }
STATIC_PRODUCT="$1"
DYNAMIC_PRODUCT="$2"
[ -x "$ORACLE" ] && [ -x "$STATIC_PRODUCT/bin/crabc-cc" ] &&
    [ -x "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" ] || exit 2
case "$TMPDIR" in "$ROOT"/.work/*) ;; *) printf 'TMPDIR must be inside this checkout .work\n' >&2; exit 2 ;; esac
WORK="$(mktemp -d "$TMPDIR/owned-stdio-format-scan.XXXXXX")"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'stdio format/scan differential: %s\n' "$WORK"

"$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE \
    -fno-builtin -fno-stack-protector -c "$SOURCE" -o "$WORK/probe.o"
"$ORACLE" -static -fno-pie -no-pie "$WORK/probe.o" -o "$WORK/oracle"
env -i LC_ALL=C LANG=C TZ=UTC "$WORK/oracle" >"$WORK/oracle.stdout" 2>"$WORK/oracle.stderr"

for mode in static static-pie; do
    "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" "$WORK/probe.o" -o "$WORK/$mode"
    env -i LC_ALL=C LANG=C TZ=UTC "$WORK/$mode" >"$WORK/$mode.stdout" 2>"$WORK/$mode.stderr"
    cmp "$WORK/oracle.stdout" "$WORK/$mode.stdout"
    cmp "$WORK/oracle.stderr" "$WORK/$mode.stderr"
done

for mode in pie non-pie; do
    "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" "$WORK/probe.o" -o "$WORK/$mode"
    mkdir "$WORK/$mode-root"
    cp -a "$DYNAMIC_PRODUCT/." "$WORK/$mode-root/"
    cp "$WORK/$mode" "$WORK/$mode-root/consumer"
    env -i LC_ALL=C LANG=C TZ=UTC /usr/sbin/chroot "$WORK/$mode-root" /consumer \
        >"$WORK/$mode.stdout" 2>"$WORK/$mode.stderr"
    cmp "$WORK/oracle.stdout" "$WORK/$mode.stdout"
    cmp "$WORK/oracle.stderr" "$WORK/$mode.stderr"
done

printf 'owned stdio format/scan differential: PASS\n'
