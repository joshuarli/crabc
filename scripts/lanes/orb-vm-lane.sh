#!/bin/sh
# CRAB-8: create a Mac worktree on lane/<name> plus the matching worktree in
# the OrbStack Linux/arm64 machine `crabc` at /mnt/crabc/crabc/.work/wt/<name>, seeded
# from the VM's main mirror with the pinned musl source trees, source oracles,
# package-corpus input and verified mimalloc archive, so
# scripts/lanes/orb-vm-run.sh can drive it. Usage: orb-vm-lane.sh <name> <commit>
set -eu
[ "$#" -eq 2 ] || { printf 'usage: orb-vm-lane.sh <name> <commit>\n' >&2; exit 2; }
name=$1
root=$(git rev-parse --show-toplevel)
rev=$(git -C "$root" rev-parse --verify "$2^{commit}")
common=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)
git -C "$root" worktree add -q -b "lane/$name" "$root/.work/wt/$name" "$rev"
orb -m crabc sh -c "set -eu
    cd /mnt/crabc/crabc
    git cat-file -e $rev^{commit} 2>/dev/null || git fetch -q '$common' $rev
    git worktree add -q --detach .work/wt/$name $rev
    seed=/mnt/crabc/crabc/.work/wt/main
    lane=/mnt/crabc/crabc/.work/wt/$name
    mkdir -p \$lane/.work/aarch64
    for item in musl-src source-oracles owned-package-corpus-input; do
        [ ! -d \$seed/.work/aarch64/\$item ] || cp -a \$seed/.work/aarch64/\$item \$lane/.work/aarch64/
    done
    for cache in compat/allocator/.cache compat/corpus/.cache compat/lua/.cache; do
        [ ! -d \$seed/\$cache ] || { mkdir -p \$lane/\$cache; cp -a \$seed/\$cache/. \$lane/\$cache/; }
    done
    cd \$lane
    scripts/lanes/rust-check.sh cargo fetch --locked -q >/dev/null"
printf 'lane %s ready at %s\n' "$name" "$rev"
