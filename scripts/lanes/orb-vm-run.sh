#!/bin/sh
# CRAB-8 relay for an Apple Silicon Mac driving an OrbStack Linux/arm64 VM.
# Mirror the current Mac git worktree into the matching VM worktree and run a
# command there. The VM worktree's HEAD and index follow the Mac HEAD, so git
# based collectors see the same commit; uncommitted Mac edits appear as
# working-tree changes. Usage (from the worktree root): vm-run.sh <command...>
set -eu
top=$(git rev-parse --show-toplevel)
lane=$(basename "$top")
case "$top" in */.work/wt/*) remote=crabc/.work/wt/$lane ;; *) remote=crabc ;; esac
ssh crabc@orb "test -e $remote/.git" || {
    echo "vm-run: VM worktree ~/$remote missing" >&2; exit 2; }
head=$(git rev-parse HEAD)
git -C "$top" push -q -f a64 "$head:refs/heads/vmrun/$lane" >/dev/null 2>&1 || {
    echo "vm-run: cannot push $head to the VM" >&2; exit 2; }
ssh crabc@orb "cd $remote && git update-ref --no-deref HEAD $head && git read-tree $head" || {
    echo "vm-run: cannot move VM HEAD to $head" >&2; exit 2; }
rsync -a --delete --rsync-path="sudo rsync" --exclude /.work/ --exclude /.git --exclude __pycache__/ ./ "crabc@orb:$remote/"
q=
for a in "$@"; do q="$q '$(printf %s "$a" | sed "s/'/'\\\\''/g")'"; done
exec ssh crabc@orb "cd $remote && export PYTHONDONTWRITEBYTECODE=1 && $q"
