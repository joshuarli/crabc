#!/usr/bin/env bash
# Exercise owned caller/public allocator edges against pinned musl.
#
# One installed-header object defines malloc/realloc/free in its executable.
# It verifies that asprintf gives its caller storage from that provider and
# that the passwd lookup returns its temporary getline allocation there too.
# List I/O uses the same public allocator for list state and private libc
# allocation for the request queues.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_c_allocation_interposition_probe.c"
readonly CRABC_INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly MUSL_INTERPRETER=/lib/ld-musl-x86_64.so.1
readonly PASSWD_RECORD='crabc:x:64:64:Crabc:/home/crabc:/bin/sh'
readonly -a scenarios=(asprintf passwd lio host timezone)

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
[ "$(uname -sm)" = 'Linux x86_64' ]

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned C allocator interposition TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned C allocator interposition product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-c-allocation-interposition.XXXXXX")"
chmod a+rx "$work"
printf 'owned C allocator interposition evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/installed" >"$work/dynamic-build.json"
    provided_dynamic="$work/installed"
fi
readonly installed="$provided_dynamic"
readonly provider="$installed/usr/lib/libc.so"

# Keep a direct product artifact beside the behavioral receipt. vasprintf's
# ordinary external malloc remains a dynamic public lookup; passwd's opaque
# tail must branch to free@plt rather than the selected private allocator.
readelf -rW "$provider" >"$work/provider.relocations"
readelf -sW "$provider" >"$work/provider.symbols"
objdump -d --no-show-raw-insn "$provider" >"$work/provider.disassembly"
awk '$3 == "R_X86_64_GLOB_DAT" && $5 == "malloc" { found = 1 } END { exit !found }' \
    "$work/provider.relocations" || {
    printf 'owned C allocator interposition: vasprintf malloc boundary is absent\n' >&2
    exit 1
}
awk '$4 == "FUNC" && $5 == "LOCAL" && $6 == "HIDDEN" && $8 == "__crabc_x86_passwd_cabi_free" { found = 1 } END { exit !found }' \
    "$work/provider.symbols" || {
    printf 'owned C allocator interposition: passwd public-free tail is absent\n' >&2
    exit 1
}
awk '
    /<__crabc_x86_passwd_cabi_free>:/ { in_tail = 1; next }
    in_tail && /jmp.*<free@plt>/ { found = 1; exit }
    in_tail && /^[[:xdigit:]]+ <.*>:/ { exit }
    END { exit !found }
' "$work/provider.disassembly" || {
    printf 'owned C allocator interposition: passwd public-free tail misses free@plt\n' >&2
    exit 1
}
for boundary in malloc free; do
    name="__crabc_x86_aio_cabi_$boundary"
    awk -v name="$name" '$4 == "FUNC" && $5 == "LOCAL" && $6 == "HIDDEN" && $8 == name { found = 1 } END { exit !found }' \
        "$work/provider.symbols" || {
        printf 'owned C allocator interposition: AIO public %s tail is absent\n' "$boundary" >&2
        exit 1
    }
    awk -v name="$name" -v boundary="$boundary" '
        $0 ~ "<" name ">:" { in_tail = 1; next }
        in_tail && $0 ~ "jmp.*<" boundary "@plt>" { found = 1; exit }
        in_tail && /^[[:xdigit:]]+ <.*>:/ { exit }
        END { exit !found }
    ' "$work/provider.disassembly" || {
        printf 'owned C allocator interposition: AIO public %s tail misses its PLT boundary\n' "$boundary" >&2
        exit 1
    }
done
for boundary in malloc free; do
    name="__crabc_x86_host_cache_cabi_$boundary"
    awk -v name="$name" '$4 == "FUNC" && $5 == "LOCAL" && $6 == "HIDDEN" && $8 == name { found = 1 } END { exit !found }' \
        "$work/provider.symbols" || {
        printf 'owned C allocator interposition: host-cache public %s tail is absent\n' "$boundary" >&2
        exit 1
    }
    awk -v name="$name" -v boundary="$boundary" '
        $0 ~ "<" name ">:" { in_tail = 1; next }
        in_tail && $0 ~ "jmp.*<" boundary "@plt>" { found = 1; exit }
        in_tail && /^[[:xdigit:]]+ <.*>:/ { exit }
        END { exit !found }
    ' "$work/provider.disassembly" || {
        printf 'owned C allocator interposition: host-cache public %s tail misses its PLT boundary\n' "$boundary" >&2
        exit 1
    }
done

# Compile once through the installed product, then link that exact object to
# the musl oracle and both executable kinds of the installed runtime.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
readelf -hW "$work/workload.o" >"$work/workload.header"
readelf -rW "$work/workload.o" >"$work/workload.relocations"

assert_exported_interposer() {
    local executable="$1" symbols="$2" name matches

    readelf --dyn-syms -W "$executable" >"$symbols"
    for name in malloc realloc free; do
        matches="$(awk -v name="$name" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")"
        [ "$matches" -eq 1 ] || {
            printf 'owned C allocator interposition: executable does not export %s\n' "$name" >&2
            return 1
        }
    done
}

write_passwd() {
    local root="$1"

    mkdir -p "$root/etc"
    printf '%s\n' "$PASSWD_RECORD" >"$root/etc/passwd"
}

prepare_oracle_root() {
    local root="$1" executable="$2"

    mkdir -p "$root/lib" "$root/tmp"
    chmod 1777 "$root/tmp"
    write_passwd "$root"
    cp "$executable" "$root/consumer"
    cp /opt/musl-1.2.6/lib/libc.so "$root$MUSL_INTERPRETER"
    ln -s ld-musl-x86_64.so.1 "$root/lib/libc.so"
}

prepare_candidate_root() {
    local root="$1" executable="$2"

    cp -a "$installed" "$root"
    mkdir -p "$root/tmp"
    chmod 1777 "$root/tmp"
    write_passwd "$root"
    cp "$executable" "$root/consumer"
}

run_in_root() {
    local root="$1" prefix="$2" status
    shift 2

    if timeout 25 env -i PATH="$PATH" chroot "$root" "$@" \
        >"$prefix.stdout" 2>"$prefix.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"$prefix.status"
    # Equal oracle/candidate failures are never successful interposition
    # evidence. Preserve the failed target's streams before stopping the run.
    [ "$status" -eq 0 ] || {
        printf 'owned C allocator interposition: target exited %s; evidence: %s\n' \
            "$status" "$prefix" >&2
        return 1
    }
}

for mode in pie non-pie; do
    if [ "$mode" = pie ]; then
        oracle_flags=(-fPIE -pie)
        candidate_mode=--dynamic-pie
    else
        oracle_flags=(-fno-pie -no-pie)
        candidate_mode=--dynamic-non-pie
    fi

    "$ORACLE_CC" -std=c11 "${oracle_flags[@]}" -rdynamic "$work/workload.o" \
        -Wl,--dynamic-linker,"$MUSL_INTERPRETER" -o "$work/oracle-$mode"
    "$installed/bin/crabc-cc-dynamic" "$candidate_mode" -rdynamic "$work/workload.o" \
        -o "$work/candidate-$mode"
    assert_exported_interposer "$work/oracle-$mode" "$work/oracle-$mode.symbols"
    assert_exported_interposer "$work/candidate-$mode" "$work/candidate-$mode.symbols"

    for entry in kernel direct; do
        oracle_root="$work/oracle-$mode-$entry-root"
        candidate_root="$work/candidate-$mode-$entry-root"
        prepare_oracle_root "$oracle_root" "$work/oracle-$mode"
        prepare_candidate_root "$candidate_root" "$work/candidate-$mode"

        for scenario in "${scenarios[@]}"; do
            oracle_prefix="$work/oracle-$mode-$entry-$scenario"
            candidate_prefix="$work/candidate-$mode-$entry-$scenario"
            if [ "$entry" = direct ]; then
                run_in_root "$oracle_root" "$oracle_prefix" "$MUSL_INTERPRETER" /consumer "$scenario"
                run_in_root "$candidate_root" "$candidate_prefix" "$CRABC_INTERPRETER" /consumer "$scenario"
            else
                run_in_root "$oracle_root" "$oracle_prefix" /consumer "$scenario"
                run_in_root "$candidate_root" "$candidate_prefix" /consumer "$scenario"
            fi
        done
    done
done

for mode in pie non-pie; do
    for entry in kernel direct; do
        for scenario in "${scenarios[@]}"; do
            oracle_prefix="$work/oracle-$mode-$entry-$scenario"
            candidate_prefix="$work/candidate-$mode-$entry-$scenario"
            cmp "$oracle_prefix.status" "$candidate_prefix.status"
            cmp "$oracle_prefix.stdout" "$candidate_prefix.stdout"
            cmp "$oracle_prefix.stderr" "$candidate_prefix.stderr"
        done
    done
done

printf '%s\n' \
    "owned C allocator interposition: PASS (same installed-header object; pinned musl and installed PIE/non-PIE kernel/direct roots; asprintf, passwd getline cleanup, lio_listio state, and host cache retain executable malloc-family ownership; AIO queues and timezone cache stay private); evidence: $work"
