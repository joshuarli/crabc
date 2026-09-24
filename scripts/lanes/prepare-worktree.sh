#!/bin/sh
# Prepare a fresh lane worktree for offline native runs: fetch the locked
# registry closure into its own .work/x86_64/cargo, vendor that closure where
# the source-runtime libc builder authenticates it, and seed the allocator's
# verified mimalloc archive cache from the primary checkout when absent.
# The allocator runner re-verifies the copied archive before use.
set -eu
root=$(git rev-parse --show-toplevel)
common=$(cd "$(git rev-parse --git-common-dir)" && pwd)
primary=$(dirname "$common")
here=$(dirname "$0")
"$here/rust-check.sh" cargo fetch --locked
vendor=.work/x86_64/cargo/native-static-source-runtime-vendor
if [ ! -d "$root/$vendor" ]; then
    "$here/rust-check.sh" cargo vendor --locked --offline --versioned-dirs \
        "/workspace/$vendor" >/dev/null
fi
cache=.work/allocator-cache
if [ ! -f "$root/$cache/mimalloc-3.5.0.tar.gz" ] && [ "$primary" != "$root" ] &&
    [ -f "$primary/$cache/mimalloc-3.5.0.tar.gz" ]; then
    mkdir -p "$root/$cache"
    cp "$primary/$cache/mimalloc-3.5.0.tar.gz" "$primary/$cache/mimalloc-3.5.0.tag.json" "$root/$cache/"
fi
