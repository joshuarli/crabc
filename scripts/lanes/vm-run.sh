#!/bin/sh
# CRAB-8 relay for an Apple Silicon Mac driving the arm64 Linux devbox on the
# ctrs engine (~/repos/ctrs, examples/devbox). Mirror the current Mac git
# worktree into its devbox worktree under the clone's .work/wt/<name> on the
# devbox's ext4 /work volume and run a command there. The devbox worktree is
# detached at the Mac HEAD, so git-based collectors see the same commit;
# uncommitted Mac edits, additions and deletions appear as working-tree
# changes. The devbox mounts the Mac checkout read-only at its Mac path.
# Usage (from a worktree root): vm-run.sh [--no-sync] <command...>
# Environment: DEVBOX_NAME (default crabc), CTRS_DEVBOX (default
# ~/repos/ctrs/examples/devbox/devbox.sh), CTRS_SOCKET as for devbox.sh.
set -eu
sync=1
if [ "${1:-}" = --no-sync ]; then
    sync=0
    shift
fi
DEVBOX_NAME=${DEVBOX_NAME:-crabc}
export DEVBOX_NAME
devbox=${CTRS_DEVBOX:-$HOME/repos/ctrs/examples/devbox/devbox.sh}
top=$(git rev-parse --show-toplevel)
common=$(git -C "$top" rev-parse --path-format=absolute --git-common-dir)
case "$top" in
    */.work/wt/*) name=$(basename "$top") ;;
    *) name=main ;;
esac
vm=/work/crabc/.work/wt/$name
if [ "$sync" = 1 ]; then
    head=$(git -C "$top" rev-parse HEAD)
    mkdir -p "$top/.work"
    list=$top/.work/vm-files.lst
    git -C "$top" ls-files -co --exclude-standard -z >"$list"
    deleted=$top/.work/vm-deleted.lst
    git -C "$top" ls-files -d -z >"$deleted"
    "$devbox" exec sh -c "set -eu
        cd /work/crabc
        git cat-file -e $head^{commit} 2>/dev/null || git fetch -q '$common' $head
        [ -d '$vm/.git' ] || [ -f '$vm/.git' ] || git worktree add -q --detach '$vm' $head
        cd '$vm'
        exclude=\$(git rev-parse --git-common-dir)/info/exclude
        grep -qx '/.work/' \"\$exclude\" || echo /.work/ >>\"\$exclude\"
        git reset -q --hard $head
        git clean -q -fd -e /.work/
        rsync -a --ignore-missing-args --from0 --files-from='$list' '$top/' '$vm/'
        xargs -0 -r rm -f -- <'$deleted'"
fi
q=
for a in "$@"; do q="$q '$(printf %s "$a" | sed "s/'/'\\\\''/g")'"; done
exec "$devbox" exec sh -c "cd '$vm' && export PYTHONDONTWRITEBYTECODE=1 && $q"
