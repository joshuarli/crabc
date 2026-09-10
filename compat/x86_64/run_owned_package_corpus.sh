#!/bin/sh
# Narrow native launcher.  Product selection is explicit and the Python
# runner rejects a missing or replacement build boundary.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
exec python3 -B "$root/compat/corpus/run_x86.py" "$@"
