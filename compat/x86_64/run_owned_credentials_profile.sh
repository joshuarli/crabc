#!/usr/bin/env bash
# Selected x86-64 credential profile through installed owned products.
#
# One object is compiled with the supplied dynamic product's installed driver
# and headers, then linked unchanged to pinned musl, owned static ET_EXEC,
# static PIE, and owned dynamic PIE/non-PIE consumers.  Each execution enters
# a new mapped user namespace before chrooting into its disposable root.  The
# probe itself has no live application workers and forks a fresh child for
# every setter call, so it neither mutates the harness nor claims an all-thread
# credential rendezvous.
#
# The direct setters have the same musl result.  The four historical aliases
# are an explicit selected-profile difference: musl succeeds for the unchanged
# IDs while crabc returns -1/EOPNOTSUPP without an ID change.  They therefore
# have independent expected raw streams rather than an invalid byte-for-byte
# differential assertion.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_credentials_profile_probe.c"

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || {
        printf 'owned credentials profile requires native Linux\n' >&2
        exit 1
    }
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) printf 'owned credentials profile refuses emulation on %s\n' "$(uname -m)" >&2; exit 1 ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || {
    printf 'owned credentials profile requires pinned musl compiler\n' >&2
    exit 1
}
command -v chroot >/dev/null
command -v unshare >/dev/null

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("credentials profile TMPDIR must be a physical checkout .work directory")
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("credentials profile product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-credentials-profile.XXXXXX")"
chmod a+rx "$work"
printf 'owned credentials profile evidence: %s\n' "$work"

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -E -H "$PROBE" >/dev/null 2>"$work/header-trace"
for header in errno.h grp.h stddef.h stdint.h stdio.h sys/syscall.h sys/types.h sys/wait.h unistd.h; do
    grep -Fq "$installed/usr/include/$header" "$work/header-trace" || {
        printf 'owned credentials profile did not use installed %s\n' "$header" >&2
        exit 1
    }
done
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"

assert_static_symbols() {
    local archive="$1" table="$work/static-symbols.txt" symbol

    nm -g --defined-only "$archive" >"$table"
    for symbol in setegid seteuid setgid setgroups setregid setresgid setresuid setreuid setuid; do
        [ "$(awk -v symbol="$symbol" '$3 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned credentials profile static provider missing or duplicates %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_symbols() {
    local shared="$1" table="$work/dynamic-symbols.txt" symbol

    readelf --dyn-syms -W "$shared" >"$table"
    for symbol in setegid seteuid setgid setgroups setregid setresgid setresuid setreuid setuid; do
        [ "$(awk -v symbol="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned credentials profile dynamic provider missing or duplicates %s\n' "$symbol" >&2
            return 1
        }
    done
}

run_in_user_namespace_root() {
    local root="$1" stdout="$2" stderr="$3"
    shift 3

    timeout 30 env -i PATH="$PATH" \
        unshare --user --map-root-user -- chroot "$root" "$@" \
        >"$stdout" 2>"$stderr"
}

run_oracle() {
    mkdir "$work/oracle-root"
    "$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" \
        -o "$work/oracle-root/consumer"
    for scenario in direct aliases-musl; do
        run_in_user_namespace_root "$work/oracle-root" \
            "$work/oracle-$scenario.stdout" "$work/oracle-$scenario.stderr" \
            /consumer "$scenario"
    done
    grep -qx 'credentials-profile direct: no-change/rejected IDs-unchanged' \
        "$work/oracle-direct.stdout"
    grep -qx 'credentials-profile aliases: musl-success IDs-unchanged' \
        "$work/oracle-aliases-musl.stdout"
    [ ! -s "$work/oracle-direct.stderr" ]
    [ ! -s "$work/oracle-aliases-musl.stderr" ]
}

run_candidate() {
    local label="$1" root="$2" consumer="$3" entry="$4"
    local command=("/consumer")

    cp "$consumer" "$root/consumer"
    if [ "$entry" = direct ]; then
        command=(/lib/ld-crabc-x86_64.so.1 /consumer)
    fi
    run_in_user_namespace_root "$root" \
        "$work/$label-direct.stdout" "$work/$label-direct.stderr" \
        "${command[@]}" direct
    cmp "$work/oracle-direct.stdout" "$work/$label-direct.stdout"
    cmp "$work/oracle-direct.stderr" "$work/$label-direct.stderr"

    run_in_user_namespace_root "$root" \
        "$work/$label-aliases-profile.stdout" "$work/$label-aliases-profile.stderr" \
        "${command[@]}" aliases-profile
    grep -qx 'credentials-profile aliases: crabc-eopnotsupp IDs-unchanged' \
        "$work/$label-aliases-profile.stdout"
    [ ! -s "$work/$label-aliases-profile.stderr" ]
}

run_oracle

if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    assert_static_symbols "$work/static-product/usr/lib/libc.a"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/workload.o" \
            -o "$work/consumer-$mode"
        mkdir "$work/$mode-root"
        run_candidate "$mode" "$work/$mode-root" "$work/consumer-$mode" kernel
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so"
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/consumer-$mode"
    for entry in kernel direct; do
        root="$work/$mode-$entry-root"
        cp -a "$installed" "$root"
        run_candidate "dynamic-$mode-$entry" "$root" "$work/consumer-$mode" "$entry"
    done
done

cat >"$work/profile-differential.txt" <<'EOF'
same-object direct result: pinned musl and crabc both pass no-change/rejected calls with unchanged IDs
mapped user namespace setgroups result: the namespace denies setgroups with EPERM before the oversized count is evaluated
pinned musl aliases: setreuid, seteuid, setregid, and setegid succeed for unchanged IDs
selected crabc profile aliases: setreuid, seteuid, setregid, and setegid return -1/EOPNOTSUPP with unchanged IDs
no all-thread credential rendezvous is claimed or tested
EOF

printf 'owned credentials profile: PASS (same installed-driver object, pinned musl direct differential, explicit four-alias profile difference, user namespaces, private children, static/static-PIE/dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
