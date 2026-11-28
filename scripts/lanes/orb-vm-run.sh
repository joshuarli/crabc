#!/bin/sh
# CRAB-8 relay for an Apple Silicon Mac driving the OrbStack Linux/arm64
# machine `crabc`. Mirror the current Mac git worktree into its VM worktree
# under /mnt/crabc/wt/<name> (ext4) and run a command there. The VM worktree
# is detached at the Mac HEAD, so git-based collectors see the same commit;
# uncommitted Mac edits, additions and deletions appear as working-tree
# changes. Usage (from a worktree root): orb-vm-run.sh [--no-sync] <command...>
set -eu
sync=1
if [ "${1:-}" = --no-sync ]; then
    sync=0
    shift
fi
top=$(git rev-parse --show-toplevel)
common=$(git -C "$top" rev-parse --path-format=absolute --git-common-dir)
case "$top" in
    */.work/wt/*) name=$(basename "$top") ;;
    *) name=main ;;
esac
vm=/mnt/crabc/wt/$name
if [ "$sync" = 1 ]; then
    head=$(git -C "$top" rev-parse HEAD)
    mkdir -p "$top/.work"
    list=$top/.work/orb-vm-files.lst
    git -C "$top" ls-files -co --exclude-standard -z >"$list"
    deleted=$top/.work/orb-vm-deleted.lst
    git -C "$top" ls-files -d -z >"$deleted"
    orb -m crabc sh -c "set -eu
        cd /mnt/crabc/crabc
        git cat-file -e $head^{commit} 2>/dev/null || git fetch -q '$common' $head
        [ -d '$vm' ] || git worktree add -q --detach '$vm' $head
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
exec orb -m crabc sh -c "cd '$vm' && export PYTHONDONTWRITEBYTECODE=1 && $q"
