#!/usr/bin/env bash
# Launch the installed clock/calendar component inside the pinned x86 image.
#
# `run_owned_calendar_component.py` owns every behavior row and its receipt.
# This launcher only supplies what that producer deliberately does not own:
# current static/dynamic products when none are supplied, a fresh TZif input
# derived from the hash-pinned IANA archives, and the observed image identity
# that the dispatcher resolved before entering this container.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly RUNNER="$ROOT/compat/x86_64/run_owned_calendar_component.py"
readonly DOWNLOAD="$ROOT/.work/x86_64/calendar-tzif-input-2025b/download"

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned calendar component: %s\n' "$*" >&2
    exit 1
}

provided_static=''
provided_dynamic=''
case "$#" in
    0) ;;
    3)
        [ "$1" = --static-sysroot ] && [ -n "$2" ] && [ -n "$3" ] \
            && [[ "$2" != -* ]] && [[ "$3" != -* ]] || usage
        provided_static="$2"
        provided_dynamic="$3"
        ;;
    *) usage ;;
esac

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'
[ -n "${CRABC_X86_CALENDAR_IMAGE_ID:-}" ] || fail 'requires the dispatcher-observed image identity'
[ -f "$RUNNER" ] || fail 'missing calendar component producer'
for name in tzcode2025b.tar.gz tzcode2025b.tar.gz.asc tzdata2025b.tar.gz tzdata2025b.tar.gz.asc; do
    [ -f "$DOWNLOAD/$name" ] && [ ! -L "$DOWNLOAD/$name" ] || fail "missing fixed IANA input $DOWNLOAD/$name"
done

readonly WORK="$(mktemp -d "$TMPDIR/owned-calendar-component.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned calendar component launcher: %s\n' "$WORK"

if [ -z "$provided_dynamic" ]; then
    provided_static="$WORK/static-product"
    provided_dynamic="$WORK/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$provided_static" \
        >"$WORK/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" \
        >"$WORK/dynamic-build.json"
fi

# A fresh derivation binds the fixture's zic/compiler identities to this image
# rather than reusing an input prepared under a different pinned image.
python3 -B "$RUNNER" prepare-tzif-input \
    --output "$WORK/tzif-input" \
    --tzcode-archive "$DOWNLOAD/tzcode2025b.tar.gz" \
    --tzcode-signature "$DOWNLOAD/tzcode2025b.tar.gz.asc" \
    --tzdata-archive "$DOWNLOAD/tzdata2025b.tar.gz" \
    --tzdata-signature "$DOWNLOAD/tzdata2025b.tar.gz.asc" \
    --image-id "$CRABC_X86_CALENDAR_IMAGE_ID"

python3 -B "$RUNNER" \
    --static-sysroot "$provided_static" \
    --dynamic-sysroot "$provided_dynamic" \
    --tzif-input "$WORK/tzif-input" \
    --image-id "$CRABC_X86_CALENDAR_IMAGE_ID"
