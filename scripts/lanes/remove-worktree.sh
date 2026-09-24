#!/bin/sh
# Remove a lane worktree whose container-written, root-owned build output makes
# a plain `git worktree remove` fail partway. The pinned image deletes the
# contents with only this worktree mounted; its branch and commits are kept.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 WORKTREE_PATH" >&2; exit 2; }
path=$(cd "$1" && pwd -P)
root=$(git -C "$path" rev-parse --path-format=absolute --git-common-dir | xargs dirname)
case "$path" in "$root"/.work/worktrees/*) ;; *) echo "refusing path outside $root/.work/worktrees" >&2; exit 2;; esac
if [ -n "$(git -C "$path" status --porcelain --untracked-files=no)" ]; then
    echo "refusing to remove $path: tracked changes are uncommitted" >&2; exit 1
fi
docker run --rm --network none -v "$path":/target crabc-core-evidence:x86_64 \
    sh -c 'find /target -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +'
git -C "$root" worktree remove --force "$path"
