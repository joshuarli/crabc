#!/bin/sh
# CRAB-8: create a Mac worktree on lane/<name> plus the matching VM worktree
# with Cargo dependencies and the pinned musl source trees, so
# scripts/lanes/orb-vm-run.sh can drive it. Usage: orb-vm-lane.sh <name> <commit>
set -eu
name=$1 rev=$2
root=$(git rev-parse --show-toplevel)
cd "$root"
git push -q a64 "$rev:refs/heads/crab8/lane-base-$name"
git worktree add -q -b "lane/$name" ".work/wt/$name" "$rev"
ssh crabc@orb "set -e; cd crabc && git worktree add -q --detach .work/wt/$name $rev && git branch -q -D crab8/lane-base-$name && mkdir -p .work/wt/$name/.work/aarch64 && cp -a .work/aarch64/musl-src .work/wt/$name/.work/aarch64/ && cd .work/wt/$name && scripts/lanes/rust-check.sh cargo fetch --locked -q >/dev/null 2>&1"
echo "lane $name ready at $rev"
