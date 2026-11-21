#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ]
[ "$#" -eq 1 ]
product="$1"
oracle=/opt/musl-1.2.6/lib/libc.so
for shared in "$oracle" "$product/usr/lib/libc.so"; do
    symbols="$(readelf --dyn-syms -W "$shared")"
    if awk '$8 == "___errno_location" && $7 != "UND" { found=1 } END { exit !found }' <<<"$symbols"; then
        printf 'private errno alias exported by %s\n' "$shared" >&2
        exit 1
    fi
    readelf -sW "$shared" | awk '
        $4 == "FUNC" && $8 == "__errno_location" && $5 == "GLOBAL" && $7 != "UND" { public=$2 ":" $7 }
        $4 == "FUNC" && $8 == "___errno_location" && $5 == "LOCAL" && $7 != "UND" { private=$2 ":" $7 }
        END { if (!public || public != private) exit 1 }
    '
done
printf 'arm64 errno alias: PASS\n'
