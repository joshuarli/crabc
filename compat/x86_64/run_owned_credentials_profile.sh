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
if [ "$static_was_supplied" -eq 1 ]; then
    provided_static="$(realpath -e "$provided_static")"
fi
if [ "$dynamic_was_supplied" -eq 1 ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi

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

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("credentials profile TMPDIR must be a physical checkout .work directory")
for product_text, name in ((sys.argv[3], "static"), (sys.argv[4], "dynamic")):
    if not product_text:
        continue
    product = Path(product_text).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit(f"credentials profile {name} product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-credentials-profile.XXXXXX")"
chmod a+rx "$work"
printf 'owned credentials profile evidence: %s\n' "$work"

if [ "$dynamic_was_supplied" -eq 0 ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

# The sealed driver intentionally accepts only translation/link inputs. Its
# fixed-image source translator is `/usr/bin/gcc`; use that same translator
# with the driver's `-nostdinc` and installed include root only to retain a
# header trace. The actual application object below still comes from the
# installed driver, which supplies the identical target-header boundary.
/usr/bin/gcc -nostdinc -isystem "$installed/usr/include" -ffreestanding \
    -fno-builtin -fstack-protector-strong -std=c11 -fPIE -E -H "$PROBE" \
    >/dev/null 2>"$work/header-trace"
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

audit_product_link() {
    local product="$1" workload="$2" executable="$3" receipt="$4" linkage="$5"
    local audit="$executable.product-link.json"

    python3 -B - "$ROOT" "$product" "$workload" "$executable" "$receipt" \
        "$linkage" "$audit" <<'PY'
import json
import os
from pathlib import Path
import sys

root, product, workload, executable, receipt, linkage, audit = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / "compat/x86_64"))
from owned_posix_product_evidence import validate_link

identity = validate_link(product, workload, executable, receipt, str(linkage))
payload = {
    "schema": "crabc.x86_64-owned-posix-product-link-audit/v1",
    "linkage": str(linkage),
    "identity": identity,
}
descriptor = os.open(audit, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(payload, output, sort_keys=True)
    output.write("\n")
PY
}

run_in_user_namespace_root() {
    local root="$1" stdout="$2" stderr="$3"
    shift 3
    local status

    set +e
    timeout 30 env -i PATH="$PATH" \
        unshare --user --map-root-user -- chroot "$root" "$@" \
        >"$stdout" 2>"$stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"${stdout}.status"
    if [ "$status" -ne 0 ]; then
        printf 'owned credentials profile process failed with status %s: %s\n' \
            "$status" "$*" >&2
        return 1
    fi
}

validate_transcript() {
    local scenario="$1" transcript="$2"

    python3 -B - "$scenario" "$transcript" <<'PY'
import errno
import re
import sys
from pathlib import Path

scenario, transcript_text = sys.argv[1:]
transcript = Path(transcript_text)
expected = {
    "direct": [
        ("setresuid-current", 0, None),
        ("setresgid-current", 0, None),
        ("setuid-current", 0, None),
        ("setgid-current", 0, None),
        ("setresuid-all-ones", 0, None),
        ("setresgid-all-ones", 0, None),
        ("setuid-unmapped", -1, errno.EINVAL),
        ("setgid-unmapped", -1, errno.EINVAL),
        ("setgroups-current", -1, errno.EPERM),
    ],
    "aliases-musl": [
        ("setreuid-current", 0, None),
        ("seteuid-current", 0, None),
        ("setregid-current", 0, None),
        ("setegid-current", 0, None),
    ],
    "aliases-profile": [
        ("setreuid-current", -1, errno.EOPNOTSUPP),
        ("seteuid-current", -1, errno.EOPNOTSUPP),
        ("setregid-current", -1, errno.EOPNOTSUPP),
        ("setegid-current", -1, errno.EOPNOTSUPP),
    ],
}[scenario]
summaries = {
    "direct": "credentials-profile direct: successful-current/no-change/rejected IDs-unchanged",
    "aliases-musl": "credentials-profile aliases: musl-success IDs-unchanged",
    "aliases-profile": "credentials-profile aliases: crabc-eopnotsupp IDs-unchanged",
}
pattern = re.compile(
    r"^credentials-profile (?P<scenario>direct|aliases-musl|aliases-profile) "
    r"(?P<name>[a-z0-9-]+): status=(?P<status>-?[0-9]+) errno=(?P<errno>[0-9]+) "
    r"before=uid=(?P<before_uid>[0-9]+/[0-9]+/[0-9]+),gid=(?P<before_gid>[0-9]+/[0-9]+/[0-9]+) "
    r"after=uid=(?P<after_uid>[0-9]+/[0-9]+/[0-9]+),gid=(?P<after_gid>[0-9]+/[0-9]+/[0-9]+) "
    r"ids=unchanged$")
lines = transcript.read_text(encoding="utf-8").splitlines()
if len(lines) != len(expected) + 1 or lines[-1] != summaries[scenario]:
    raise SystemExit(f"credentials profile transcript shape differs: {transcript}")
for line, (name, status, expected_errno) in zip(lines[:-1], expected):
    match = pattern.fullmatch(line)
    if match is None or match["scenario"] != scenario or match["name"] != name:
        raise SystemExit(f"credentials profile transcript label differs: {line}")
    if int(match["status"]) != status:
        raise SystemExit(f"credentials profile raw status differs: {line}")
    if expected_errno is not None and int(match["errno"]) != expected_errno:
        raise SystemExit(f"credentials profile raw errno differs: {line}")
    if (match["before_uid"], match["before_gid"]) != (match["after_uid"], match["after_gid"]):
        raise SystemExit(f"credentials profile IDs changed: {line}")
PY
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
    validate_transcript direct "$work/oracle-direct.stdout"
    validate_transcript aliases-musl "$work/oracle-aliases-musl.stdout"
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
    validate_transcript direct "$work/$label-direct.stdout"
    cmp "$work/oracle-direct.stdout" "$work/$label-direct.stdout"
    cmp "$work/oracle-direct.stderr" "$work/$label-direct.stderr"
    cmp "$work/oracle-direct.stdout.status" "$work/$label-direct.stdout.status"

    run_in_user_namespace_root "$root" \
        "$work/$label-aliases-profile.stdout" "$work/$label-aliases-profile.stderr" \
        "${command[@]}" aliases-profile
    validate_transcript aliases-profile "$work/$label-aliases-profile.stdout"
    [ ! -s "$work/$label-aliases-profile.stderr" ]
    cmp "$work/oracle-aliases-musl.stdout.status" \
        "$work/$label-aliases-profile.stdout.status"
}

run_oracle

static_product=''
if [ "$static_was_supplied" -eq 1 ]; then
    static_product="$provided_static"
elif [ "$dynamic_was_supplied" -eq 0 ]; then
    static_product="$work/static-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$static_product" >"$work/static-build.json"
fi
if [ -n "$static_product" ]; then
    assert_static_symbols "$static_product/usr/lib/libc.a"
    for mode in static static-pie; do
        receipt="$work/consumer-$mode.receipt.json"
        (cd "$work" && "$static_product/bin/crabc-cc" "-$mode" \
            --link-receipt "$(basename "$receipt")" "$work/workload.o" \
            -o "$work/consumer-$mode")
        audit_product_link "$static_product" "$work/workload.o" \
            "$work/consumer-$mode" "$receipt" "$mode"
        mkdir "$work/$mode-root"
        run_candidate "$mode" "$work/$mode-root" "$work/consumer-$mode" kernel
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so"
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/consumer-$mode"
    audit_product_link "$installed" "$work/workload.o" "$work/consumer-$mode" \
        "$work/consumer-$mode.crabc-link.json" "$mode"
    for entry in kernel direct; do
        root="$work/$mode-$entry-root"
        cp -a "$installed" "$root"
        run_candidate "dynamic-$mode-$entry" "$root" "$work/consumer-$mode" "$entry"
    done
done

cat >"$work/profile-differential.txt" <<'EOF'
same-object direct result: pinned musl and crabc both pass explicit current-ID, all-ones no-change, and rejected calls with unchanged IDs
mapped user namespace setgroups result: a valid one-element current-gid slice is denied with EPERM before any ID transition
pinned musl aliases: setreuid, seteuid, setregid, and setegid succeed for unchanged IDs
selected crabc profile aliases: setreuid, seteuid, setregid, and setegid return -1/EOPNOTSUPP with unchanged IDs
no all-thread credential rendezvous is claimed or tested
EOF

if [ "$static_was_supplied" -eq 0 ] && [ "$dynamic_was_supplied" -eq 0 ]; then
    printf 'owned credentials profile: PASS (same installed-driver object, pinned musl direct differential, explicit four-alias profile difference, user namespaces, private children, static/static-PIE/dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
elif [ "$static_was_supplied" -eq 1 ] && [ "$dynamic_was_supplied" -eq 1 ]; then
    printf 'owned credentials profile: PASS (supplied static and installed products, same installed-driver object, pinned musl direct differential, explicit four-alias profile difference, user namespaces, private children, static/static-PIE/dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
elif [ "$static_was_supplied" -eq 1 ]; then
    printf 'owned credentials profile: PASS (supplied static product and default installed product, same installed-driver object, pinned musl direct differential, explicit four-alias profile difference, user namespaces, private children, static/static-PIE/dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
else
    printf 'owned credentials profile: PASS (supplied installed product, same installed-driver object, pinned musl direct differential, explicit four-alias profile difference, user namespaces, private children, dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
fi
