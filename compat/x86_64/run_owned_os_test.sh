#!/usr/bin/env sh
# The native Docker dispatcher supplies the pinned host control plane.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
exec python3 -B "$root/compat/x86_64/owned_os_test.py" "$@"
