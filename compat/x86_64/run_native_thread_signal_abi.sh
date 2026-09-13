#!/usr/bin/env bash
# Focused native x86 proof for the frozen crabc tgkill C extension.
#
# One C workload object is compiled through the supplied installed candidate
# header tree, then linked unchanged with either a separate pinned-musl
# syscall(SYS_tgkill) adapter or selected static/dynamic crabc products. Musl
# 1.2.6 has no public tgkill ABI; its adapter is a Linux errno behavior oracle,
# never a provider-equivalence claim.
set -euo pipefail
ulimit -c 0
export LC_ALL=C

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly RUNNER="$ROOT/compat/x86_64/run_native_thread_signal_abi.sh"
readonly PROBE="$ROOT/compat/x86_64/native_thread_signal_abi_probe.c"
readonly ADAPTER="$ROOT/compat/x86_64/native_thread_signal_oracle_adapter.c"
readonly CPP_GNU_PROBE="$ROOT/compat/x86_64/native_thread_signal_header_gnu.cc"
readonly CPP_STRICT_PROBE="$ROOT/compat/x86_64/native_thread_signal_header_strict.cc"
readonly CONTRACT="$ROOT/compat/x86_64/native_thread_signal_abi.json"
readonly SYMBOL_READER="$ROOT/compat/x86_64/native_thread_signal_abi_symbols.py"
readonly PROVIDER="$ROOT/libc/src/c_abi/x86_64/thread_signal.rs"
readonly STATIC_ROOT="$ROOT/libc/src/c_abi/x86_64/static_c_abi.rs"
readonly RAW_SYSCALL="$ROOT/libc/src/c_abi/x86_64/syscall.rs"
readonly HEADER="$ROOT/include/signal.h"
readonly MUSL_ORACLE="$ROOT/compat/x86_64/run_musl_oracle.sh"
readonly PRODUCT_VALIDATOR="$ROOT/compat/x86_64/owned_posix_product_evidence.py"
readonly RECEIPT_CONTRACT="$ROOT/compat/x86_64/owned_dynamic_receipt.py"
readonly STATIC_EXPORTS="$ROOT/compat/x86_64/static_c_abi_exports.txt"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CC=/usr/bin/clang
readonly CXX=/usr/bin/clang++
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly MUSL_ARCHIVE="$MUSL_ROOT/lib/libc.a"
readonly MUSL_LIBRARY="$MUSL_ROOT/lib/libc.so"
readonly MUSL_LOADER="$MUSL_ROOT/lib/ld-musl-x86_64.so.1"
readonly FROZEN_COMMIT=3e100d45c5a0798c2d3862d5e2eef584c610ccf9
readonly TIMEOUT=30
readonly EXPECTED_OUTPUT="tgkill-c-abi=caller-selected-child:signal0:delivery:ESRCH:EINVAL"

usage() {
    printf 'usage: %s --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'native x86 tgkill C ABI: %s\n' "$*" >&2
    exit 1
}

static_product=''
dynamic_product=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$static_product" ] && [ -n "$2" ] || usage
            static_product="$2"
            shift 2
            ;;
        -*) usage ;;
        *)
            [ -z "$dynamic_product" ] && [ -n "$1" ] || usage
            dynamic_product="$1"
            shift
            ;;
    esac
done
[ -n "$static_product" ] && [ -n "$dynamic_product" ] || usage

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires explicit checkout-local TMPDIR'
for tool in ar awk chroot cmp comm cp env git grep ln mkdir mktemp nm objdump python3 readelf realpath sha256sum sort timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
readonly CHROOT="$(command -v chroot)"
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -x "$CC" ] || fail 'missing pinned C header compiler'
[ -x "$CXX" ] || fail 'missing pinned C++17 header compiler'
[ -f "$MUSL_ARCHIVE" ] && [ -f "$MUSL_LIBRARY" ] && [ -f "$MUSL_LOADER" ] ||
    fail 'missing pinned musl 1.2.6 library inputs'
for path in "$RUNNER" "$PROBE" "$ADAPTER" "$CPP_GNU_PROBE" "$CPP_STRICT_PROBE" \
    "$CONTRACT" "$SYMBOL_READER" "$PROVIDER" \
    "$STATIC_ROOT" "$RAW_SYSCALL" "$HEADER" "$MUSL_ORACLE" "$PRODUCT_VALIDATOR" \
    "$RECEIPT_CONTRACT" "$STATIC_EXPORTS"; do
    [ -f "$path" ] || fail "missing thread-signal input: $path"
done

work_parent="$(realpath -e "$TMPDIR")"
case "$work_parent" in "$ROOT"/.work/*) ;; *) fail 'TMPDIR must remain below this checkout .work' ;; esac
[ ! -L "$work_parent" ] || fail 'TMPDIR must be physical'
[ "$(git rev-parse --show-toplevel)" = "$ROOT" ] || fail 'runner must execute from its checkout'
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] ||
    fail 'source must be clean before a source-bound installed-product proof'

static_product="$(realpath -e "$static_product")"
dynamic_product="$(realpath -e "$dynamic_product")"
for product in "$static_product" "$dynamic_product"; do
    [ -d "$product" ] && [ ! -L "$product" ] || fail "product root must be a physical directory: $product"
done
[ -x "$static_product/bin/crabc-cc" ] || fail 'static product lacks installed driver'
[ -x "$dynamic_product/bin/crabc-cc-dynamic" ] || fail 'dynamic product lacks installed driver'

python3 -B - "$ROOT" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
static = Path(sys.argv[2])
dynamic = Path(sys.argv[3])
sys.path.insert(0, str(root / 'compat/x86_64'))
import owned_posix_product_evidence as products

products._validate_static_product(static)
products._validate_dynamic_product(dynamic)
PY

work="$(mktemp -d "$work_parent/native-thread-signal-abi.XXXXXX")"
chmod a+rx "$work"
trap 'chmod -R a+rX "$work" 2>/dev/null || true' EXIT
printf 'native x86 tgkill C ABI evidence: %s\n' "$work"

action() {
    local stem="$1"
    shift
    python3 -B - "$work/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    local status
    set +e
    timeout "$TIMEOUT" "$@" >"$work/$stem.stdout" 2>"$work/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status; evidence: $work"
}

expected_compile_failure() {
    local stem="$1"
    shift
    python3 -B - "$work/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    local status
    set +e
    timeout "$TIMEOUT" "$@" >"$work/$stem.stdout" 2>"$work/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$stem.status"
    [ "$status" -ne 0 ] && [ "$status" -ne 124 ] ||
        fail "$stem did not produce the required finite compile failure; evidence: $work"
}

same_transcript() {
    local expected="$1" actual="$2"
    cmp "$work/$expected.stdout" "$work/$actual.stdout" || fail "$actual stdout differs from $expected"
    cmp "$work/$expected.stderr" "$work/$actual.stderr" || fail "$actual stderr differs from $expected"
    cmp "$work/$expected.status" "$work/$actual.status" || fail "$actual status differs from $expected"
}

snapshot() {
    local point="$1"
    git rev-parse HEAD >"$work/$point.commit"
    git status --porcelain=v1 --untracked-files=all >"$work/$point.status"
    sha256sum "$RUNNER" "$PROBE" "$ADAPTER" "$CPP_GNU_PROBE" "$CPP_STRICT_PROBE" \
        "$CONTRACT" "$SYMBOL_READER" \
        "$PROVIDER" "$STATIC_ROOT" "$RAW_SYSCALL" "$HEADER" "$MUSL_ORACLE" \
        "$PRODUCT_VALIDATOR" "$RECEIPT_CONTRACT" "$STATIC_EXPORTS" "$static_product/usr/lib/libc.a" \
        "$dynamic_product/usr/lib/libc.so" "$dynamic_product/share/crabc/manifest.json" \
        >"$work/$point.sha256"
}

require_elf_type() {
    local executable="$1" expected="$2"
    grep -Eq "^[[:space:]]*Type:[[:space:]]+$expected\\b" "$work/$executable-header.stdout" ||
        fail "$executable has wrong ELF type; expected $expected"
    grep -Fq 'Advanced Micro Devices X86-64' "$work/$executable-header.stdout" ||
        fail "$executable is not x86-64"
}

snapshot before
action oracle-pin bash "$MUSL_ORACLE"
action frozen-crabc-source git show "$FROZEN_COMMIT:libc/src/c_abi.rs"
action frozen-crabc-header git show "$FROZEN_COMMIT:include/signal.h"
grep -Fq 'pub unsafe extern "C" fn tgkill(tgid: c_int, tid: c_int, sig: c_int) -> c_int' \
    "$work/frozen-crabc-source.stdout" || fail 'frozen crabc source lost tgkill signature'
grep -Fq 'int tgkill(int, int, int);' "$work/frozen-crabc-header.stdout" ||
    fail 'frozen crabc header lost GNU/BSD tgkill declaration'
action cc-tool-version "$CC" --version
action cxx-tool-version "$CXX" --version

# The sealed installed driver deliberately rejects compiler diagnostic `-H`.
# Trace the same physical installed header tree with the pinned compiler, then
# compile the one workload object only through the installed driver below.
action installed-header-preprocess "$CC" --target=x86_64-linux-musl -std=c11 -nostdinc \
    -isystem "$dynamic_product/usr/include" -D_GNU_SOURCE -H -E "$PROBE"
grep -Fq "$dynamic_product/usr/include/signal.h" "$work/installed-header-preprocess.stderr" ||
    fail 'workload did not include the supplied installed signal.h'
action installed-header-cxx17-gnu-preprocess "$CXX" --target=x86_64-linux-musl -std=c++17 \
    -nostdinc -isystem "$dynamic_product/usr/include" -D_GNU_SOURCE -H -E "$CPP_GNU_PROBE"
grep -Fq "$dynamic_product/usr/include/signal.h" "$work/installed-header-cxx17-gnu-preprocess.stderr" ||
    fail 'GNU C++17 witness did not include the supplied installed signal.h'
action installed-header-cxx17-gnu-compile "$CXX" --target=x86_64-linux-musl -std=c++17 \
    -nostdinc -isystem "$dynamic_product/usr/include" -D_GNU_SOURCE -c "$CPP_GNU_PROBE" \
    -o "$work/tgkill-cxx17-gnu.o"
action installed-header-cxx17-gnu-symbols readelf -Ws "$work/tgkill-cxx17-gnu.o"
[ "$(grep -Ec '[[:space:]]UND[[:space:]]+tgkill$' "$work/installed-header-cxx17-gnu-symbols.stdout")" -eq 1 ] ||
    fail 'GNU C++17 witness did not retain exactly one unmangled tgkill reference'
grep -Fq '_Z6tgkill' "$work/installed-header-cxx17-gnu-symbols.stdout" &&
    fail 'GNU C++17 witness unexpectedly mangled the C tgkill reference'
expected_compile_failure installed-header-cxx17-strict "$CXX" --target=x86_64-linux-musl -std=c++17 \
    -nostdinc -isystem "$dynamic_product/usr/include" -U_GNU_SOURCE -U_BSD_SOURCE \
    -U_DEFAULT_SOURCE -U_ALL_SOURCE -H -fsyntax-only "$CPP_STRICT_PROBE"
grep -Fq "$dynamic_product/usr/include/signal.h" "$work/installed-header-cxx17-strict.stderr" ||
    fail 'strict C++17 witness did not include the supplied installed signal.h'
grep -Fq "undeclared identifier 'tgkill'" "$work/installed-header-cxx17-strict.stderr" ||
    fail 'strict C++17 witness did not reject tgkill as undeclared'
action compile "$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie \
    -std=c11 -D_GNU_SOURCE -Werror=implicit-function-declaration -fno-builtin \
    -fno-stack-protector -c "$PROBE" -o "$work/probe.o"
action oracle-adapter-compile "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin \
    -fno-stack-protector -c "$ADAPTER" -o "$work/oracle-adapter.o"
action probe-object-before sha256sum "$work/probe.o"

action oracle-static-link "$ORACLE_CC" -static -no-pie "$work/probe.o" \
    "$work/oracle-adapter.o" -o "$work/oracle-static"
action candidate-static-link "$static_product/bin/crabc-cc" -static "$work/probe.o" \
    -o "$work/candidate-static"
action candidate-static-pie-link "$static_product/bin/crabc-cc" -static-pie "$work/probe.o" \
    -o "$work/candidate-static-pie"
for mode in pie non-pie; do
    if [ "$mode" = pie ]; then
        oracle_flags=(-rdynamic -fPIE -pie)
    else
        oracle_flags=(-rdynamic -no-pie)
    fi
    action "oracle-dynamic-$mode-link" "$ORACLE_CC" "${oracle_flags[@]}" "$work/probe.o" \
        "$work/oracle-adapter.o" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
        -o "$work/oracle-dynamic-$mode"
    action "candidate-dynamic-$mode-link" "$dynamic_product/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -rdynamic "$work/probe.o" -o "$work/candidate-dynamic-$mode"
done
action probe-object-after sha256sum "$work/probe.o"
cmp "$work/probe-object-before.stdout" "$work/probe-object-after.stdout" ||
    fail 'one installed-header workload object changed during links'

for executable in oracle-static candidate-static candidate-static-pie \
                  oracle-dynamic-pie oracle-dynamic-non-pie \
                  candidate-dynamic-pie candidate-dynamic-non-pie; do
    action "$executable-header" readelf -h "$work/$executable"
done
require_elf_type oracle-static EXEC
require_elf_type candidate-static EXEC
require_elf_type candidate-static-pie DYN
require_elf_type oracle-dynamic-pie DYN
require_elf_type oracle-dynamic-non-pie EXEC
require_elf_type candidate-dynamic-pie DYN
require_elf_type candidate-dynamic-non-pie EXEC

action oracle-static-run env -i "$work/oracle-static"
[ "$(cat "$work/oracle-static-run.stdout")" = "$EXPECTED_OUTPUT" ] ||
    fail "pinned-musl syscall-adapter transcript changed"
for mode in static static-pie; do
    action "candidate-$mode-run" env -i "$work/candidate-$mode"
    same_transcript oracle-static-run "candidate-$mode-run"
done

prepare_oracle_root() {
    local root="$1"
    mkdir -p "$root/lib"
    cp "$MUSL_LIBRARY" "$root/lib/ld-musl-x86_64.so.1"
    ln -s ld-musl-x86_64.so.1 "$root/lib/libc.so"
    for mode in pie non-pie; do
        cp "$work/oracle-dynamic-$mode" "$root/consumer-$mode"
    done
}

prepare_candidate_root() {
    local root="$1"
    cp -a "$dynamic_product/." "$root"
    for mode in pie non-pie; do
        cp "$work/candidate-dynamic-$mode" "$root/consumer-$mode"
    done
}

oracle_root="$work/oracle-dynamic-root"
candidate_root="$work/candidate-dynamic-root"
prepare_oracle_root "$oracle_root"
prepare_candidate_root "$candidate_root"
for mode in pie non-pie; do
    for entry in kernel direct; do
        if [ "$entry" = kernel ]; then
            action "oracle-dynamic-$mode-$entry" env -i "$CHROOT" "$oracle_root" "/consumer-$mode"
            action "candidate-dynamic-$mode-$entry" env -i "$CHROOT" "$candidate_root" "/consumer-$mode"
        else
            action "oracle-dynamic-$mode-$entry" env -i "$CHROOT" "$oracle_root" \
                /lib/ld-musl-x86_64.so.1 "/consumer-$mode"
            action "candidate-dynamic-$mode-$entry" env -i "$CHROOT" "$candidate_root" \
                /lib/ld-crabc-x86_64.so.1 "/consumer-$mode"
        fi
        same_transcript "oracle-dynamic-$mode-$entry" "candidate-dynamic-$mode-$entry"
    done
done

action oracle-static-symbols readelf -Ws "$MUSL_ARCHIVE"
action oracle-dynamic-symbols readelf --dyn-syms -W "$MUSL_LIBRARY"
action oracle-shared-symbols readelf -Ws "$MUSL_LIBRARY"
action candidate-static-symbols readelf -Ws "$static_product/usr/lib/libc.a"
action candidate-dynamic-symbols readelf --dyn-syms -W "$dynamic_product/usr/lib/libc.so"
action candidate-shared-symbols readelf -Ws "$dynamic_product/usr/lib/libc.so"
action candidate-tgkill-disassembly objdump -d --disassemble=tgkill "$dynamic_product/usr/lib/libc.so"
grep -Eq '\$0xea(,|[[:space:]]|\$)' "$work/candidate-tgkill-disassembly.stdout" ||
    fail 'candidate tgkill lacks SYS_TGKILL=234 immediate'
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$work/candidate-tgkill-disassembly.stdout" ||
    fail 'candidate tgkill lacks syscall instruction'
action symbol-observation python3 -B "$SYMBOL_READER" "$CONTRACT" \
    "$work/oracle-static-symbols.stdout" "$work/oracle-dynamic-symbols.stdout" \
    "$work/oracle-shared-symbols.stdout" "$work/candidate-static-symbols.stdout" \
    "$work/candidate-dynamic-symbols.stdout" "$work/candidate-shared-symbols.stdout" \
    "$work/symbol-observation.json"

# The supplied owned-static archive contains the default providers and its
# selected runtime features. Retain that feature surplus separately from the
# default-static roster, which now includes tgkill. This subset check rejects
# a missing default provider and requires exactly one strong tgkill definition;
# complete profile-specific archive selection remains a separate contract.
cat >"$work/local-default-static-delta.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
archive="$1"
roster="$2"
work="$3"
mapfile -t members < <(ar t "$archive" | grep -E '^c\..+\.rcgu\.o$')
[ "${#members[@]}" -gt 0 ]
mkdir "$work/local-default-static-members"
(
    cd "$work/local-default-static-members"
    ar x "$archive" "${members[@]}"
    nm -g --defined-only --format=posix "${members[@]}"
) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' | sort -u >"$work/local-default-static-observed.txt"
grep -Ev '^(#|$)' "$roster" | sort -u >"$work/local-default-static-baseline.txt"
comm -13 "$work/local-default-static-baseline.txt" "$work/local-default-static-observed.txt" >"$work/local-default-static-additions.txt"
comm -23 "$work/local-default-static-baseline.txt" "$work/local-default-static-observed.txt" >"$work/local-default-static-missing.txt"
[ ! -s "$work/local-default-static-missing.txt" ]
grep -Fx tgkill "$work/local-default-static-baseline.txt" >/dev/null
[ "$(cd "$work/local-default-static-members" && nm -g --defined-only --format=posix "${members[@]}" | awk '$1 == "tgkill" && $2 == "T" { count += 1 } END { print count + 0 }')" = 1 ]
printf 'required-default-provider=tgkill\n'
printf 'owned-static-surplus=%s\n' "$(wc -l < "$work/local-default-static-additions.txt")"
SH
chmod 700 "$work/local-default-static-delta.sh"
action local-default-static-delta bash "$work/local-default-static-delta.sh" \
    "$static_product/usr/lib/libc.a" "$STATIC_EXPORTS" "$work"

snapshot after
cmp "$work/before.commit" "$work/after.commit" || fail 'source revision changed during proof'
cmp "$work/before.status" "$work/after.status" || fail 'source status changed during proof'
cmp "$work/before.sha256" "$work/after.sha256" ||
    fail 'source, helper, contract, or supplied product changed during proof'
printf 'native x86 tgkill C ABI: PASS (one installed-header object; static ET_EXEC/static-PIE and dynamic PIE/non-PIE kernel/direct; musl syscall adapter only); evidence: %s\n' "$work"
