#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${CRABC_COMPILER_HELPER_WORK_DIR:-$root/.work/aarch64/compiler-helper-aggregate}"
image="${CRABC_X86_COMPILER_HELPER_IMAGE:-}"
[[ "$image" =~ ^crabc-core-evidence@sha256:[0-9a-f]{64}$ ]]
case "$work" in "$root"/.work/aarch64/*) ;; *) exit 1 ;; esac
[ ! -e "$work" ] && [ ! -L "$work" ]
mkdir -p "$(dirname "$work")"
[ "$(realpath "$(dirname "$work")")" = "$(dirname "$work")" ]
mkdir "$work"
source_before="$(python3 -B -c 'import sys; sys.path.insert(0,"compat/x86_64"); import source_seal; print(source_seal.product_source_digest(source_seal.ROOT))')"
tools_dir="$(rustc --print sysroot)/lib/rustlib/aarch64-unknown-linux-musl/bin"
python3 -B "$root/builtins/build.py" --output "$work/libcrabc-builtins.a" \
    --llvm-ar "$tools_dir/llvm-ar" --llvm-nm "$tools_dir/llvm-nm" \
    --llvm-readelf /usr/bin/readelf --ld-lld /usr/bin/mold --verify-reproducible \
    >"$work/build.stdout" 2>"$work/build.stderr"
bash "$root/builtins/tests/test_aarch64_compiler_helpers.sh" "$work/libcrabc-builtins.a" \
    >"$work/probe.stdout" 2>"$work/probe.stderr"
source_after="$(python3 -B -c 'import sys; sys.path.insert(0,"compat/x86_64"); import source_seal; print(source_seal.product_source_digest(source_seal.ROOT))')"
[ "$source_before" = "$source_after" ]
cat "$work/probe.stdout"
printf 'native arm64 compiler-helper aggregate: PASS (%s)\n' "$work"
