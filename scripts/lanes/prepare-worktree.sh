#!/bin/sh
# Prepare a fresh lane worktree for offline native runs: fetch the locked
# registry closure into its own .work/x86_64/cargo, vendor that closure where
# the source-runtime libc builder authenticates it, and seed the allocator's
# verified mimalloc archive caches from the primary checkout when absent.
# The allocator runner re-verifies the copied archive before use. It also
# materializes the pinned x86 package-corpus input that
# `materialized-dynamic-sysroot` consumes: `compat/corpus/fetch_x86.py` keeps
# only archives matching their manifest SHA-256, copying from the primary
# checkout before downloading, and the corpus runner re-authenticates the
# index with the pinned signing key.
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
# The host runner caches under .work/allocator-cache (with its tag record);
# the x86 container launcher caches under .work/allocator-x86_64.
for cache in .work/allocator-cache .work/allocator-x86_64/allocator-cache; do
    if [ ! -f "$root/$cache/mimalloc-3.5.0.tar.gz" ] && [ "$primary" != "$root" ] &&
        [ -f "$primary/$cache/mimalloc-3.5.0.tar.gz" ]; then
        mkdir -p "$root/$cache"
        for file in "$primary/$cache"/mimalloc-3.5.0.*; do
            cp "$file" "$root/$cache/"
        done
    fi
done
corpus=.work/x86_64/owned-package-corpus-input
if [ ! -d "$root/$corpus/apks" ]; then
    python3 -B "$root/compat/corpus/fetch_x86.py" ||
        printf 'prepare-worktree: x86 package-corpus input unavailable; run ./scripts/dev-x86_64.sh owned-package-corpus-input\n' >&2
fi
