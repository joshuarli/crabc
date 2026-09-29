#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw and source-built C inotify reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
. "$ROOT_DIR/compat/x86_64/source_runtime_libc.sh"

fail() { printf 'ERROR: x86 inotify reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64/tmp"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/tmp/inotify-reference.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-inotify-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_inotify_reference_probe.c" -o "$probe"

expected='syscalls=inotify_init1:294,inotify_add_watch:254,inotify_rm_watch:255 layout=size16:align4:wd0:mask4:cookie8:len12:name16 flags=nonblock:0x800:cloexec:0x80000 musl=nonblock:cloexec:create-byte-name:remove-ignored raw=matches-musl errors=invalid-flags:EINVAL:missing-path:ENOENT:overlong-path:ENAMETOOLONG:bad-fd:EBADF:bad-watch:EINVAL c-api-selection=excluded'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 inotify reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

fixture="$ROOT_DIR/compat/x86_64/x86_inotify_c_boundary_probe.c"
start="$ROOT_DIR/compat/x86_64/libc_event_descriptors_start.S"
reference="$work_dir/musl-inotify-c-boundary"
candidate="$work_dir/crabc-inotify-c-boundary"
archive="$work_dir/x86_64-unknown-linux-musl/debug/libc.a"
mkdir "$work_dir/musl-work" "$work_dir/candidate-work"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" "$fixture" -o "$reference"
if (cd "$work_dir/musl-work" && timeout 20s "$reference"); then
    :
else
    status=$?
    fail "pinned-musl C boundary exited $status"
fi

build_source_runtime_libc "$archive" -- -C codegen-units=1
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 -DCRABC_EVENT_DESCRIPTORS_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections "$fixture" "$start" "$archive" -o "$candidate"
if readelf -l "$candidate" | grep -q INTERP ||
   readelf -d "$candidate" 2>/dev/null | grep -q NEEDED; then
    fail "candidate selected a dynamic runtime"
fi
if (cd "$work_dir/candidate-work" && timeout 20s "$candidate"); then
    :
else
    status=$?
    fail "source-built candidate C boundary exited $status"
fi
printf 'x86 pinned-musl/raw and source-built crabc C inotify reference: PASS\n'
