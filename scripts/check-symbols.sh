#!/bin/sh
# Compatibility logic lives in Python; retain this stable entry point for CI
# and users that already invoke scripts/check-symbols.sh.
exec python3 "$(dirname "$0")/check_symbols.py" "$@"
