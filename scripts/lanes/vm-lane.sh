#!/bin/sh
# CRAB-8: create a Mac worktree on lane/<name> plus the matching worktree in
# the ctrs arm64 devbox at /work/crabc/.work/wt/<name>, seeded from the
# devbox's main mirror with the pinned musl source trees, source oracles,
# package-corpus input and verified mimalloc archive, so
# scripts/lanes/vm-run.sh can drive it. Usage: vm-lane.sh <name> <commit>
set -eu
[ "$#" -eq 2 ] || { printf 'usage: vm-lane.sh <name> <commit>\n' >&2; exit 2; }
name=$1
DEVBOX_NAME=${DEVBOX_NAME:-crabc}
export DEVBOX_NAME
devbox=${CTRS_DEVBOX:-$HOME/repos/ctrs/examples/devbox/devbox.sh}
root=$(git rev-parse --show-toplevel)
rev=$(git -C "$root" rev-parse --verify "$2^{commit}")
common=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)
git -C "$root" worktree add -q -b "lane/$name" "$root/.work/wt/$name" "$rev"
"$devbox" exec sh -c "set -eu
    cd /work/crabc
    git cat-file -e $rev^{commit} 2>/dev/null || git fetch -q '$common' $rev
    git worktree add -q --detach .work/wt/$name $rev
    seed=/work/crabc/.work/wt/main
    lane=/work/crabc/.work/wt/$name
    mkdir -p \$lane/.work/aarch64 \$lane/.work/allocator-aarch64
    for item in musl-src source-oracles owned-package-corpus-input; do
        [ ! -d \$seed/.work/aarch64/\$item ] || cp -a \$seed/.work/aarch64/\$item \$lane/.work/aarch64/
    done
    [ ! -d \$seed/.work/allocator-aarch64/allocator-cache ] || cp -a \$seed/.work/allocator-aarch64/allocator-cache \$lane/.work/allocator-aarch64/
    for cache in compat/allocator/.cache compat/corpus/.cache compat/lua/.cache; do
        [ ! -d \$seed/\$cache ] || { mkdir -p \$lane/\$cache; cp -a \$seed/\$cache/. \$lane/\$cache/; }
    done
    cd \$lane
    scripts/lanes/rust-check.sh cargo fetch --locked -q >/dev/null"
printf 'lane %s ready at %s\n' "$name" "$rev"
