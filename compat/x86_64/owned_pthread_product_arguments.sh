# Shared supplied-product argument contract for focused installed pthread runners.
#
# Source this file after defining ROOT, then call
# `owned_pthread_product_arguments LABEL "$@"`. The three accepted forms are:
#
#   (none)                                        build both owned products and
#                                                 check static and dynamic entries
#   DYNAMIC_SYSROOT                               check dynamic entries of one
#                                                 supplied installed product only
#   --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT
#                                                 check static and dynamic entries
#                                                 of supplied products; build none
#
# The dynamic-only form is the existing dynamic-qualification interface. The
# supplied static form lets the installed pthread family replay static ET_EXEC
# and static-PIE entries on its sealed product cohort instead of rebuilding a
# product that the family receipt could not bind.
#
# Sets provided_static_sysroot, provided_dynamic_sysroot (physical paths or
# empty) and check_static (1 or 0). TMPDIR and every supplied product must be
# physical directories below the checkout's `.work`.
owned_pthread_product_arguments() {
    local label="$1"
    shift
    local usage="usage: $0 [DYNAMIC_SYSROOT | --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT]"
    provided_static_sysroot=
    provided_dynamic_sysroot=
    case "$#" in
        0) check_static=1 ;;
        1)
            [ "$1" != --static-sysroot ] || { printf '%s\n' "$usage" >&2; exit 2; }
            provided_dynamic_sysroot="$1"
            check_static=0
            ;;
        3)
            [ "$1" = --static-sysroot ] || { printf '%s\n' "$usage" >&2; exit 2; }
            provided_static_sysroot="$2"
            provided_dynamic_sysroot="$3"
            check_static=1
            ;;
        *) printf '%s\n' "$usage" >&2; exit 2 ;;
    esac
    python3 -B - "$ROOT" "$label" "${TMPDIR:-}" "$provided_static_sysroot" "$provided_dynamic_sysroot" <<'PY'
from pathlib import Path
import sys

root, label, temporary, static, dynamic = sys.argv[1:]
root = Path(root).resolve(strict=True)
work = root / '.work'
path = Path(temporary) if temporary else None
if path is None or not path.is_dir() or path.resolve() != path or not path.is_relative_to(work):
    raise SystemExit(f'{label} TMPDIR must be a physical checkout .work directory')
for role, value in (('static', static), ('dynamic', dynamic)):
    if not value:
        continue
    product = Path(value)
    if not product.is_dir() or not product.resolve().is_relative_to(work):
        raise SystemExit(f'{label} {role} product must be a checkout .work directory')
PY
    if [ -n "$provided_static_sysroot" ]; then
        provided_static_sysroot="$(realpath -e "$provided_static_sysroot")"
    fi
    if [ -n "$provided_dynamic_sysroot" ]; then
        provided_dynamic_sysroot="$(realpath -e "$provided_dynamic_sysroot")"
    fi
}
