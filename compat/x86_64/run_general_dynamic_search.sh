#!/usr/bin/env bash
# Installed search decisions, with the same graph in a separate pinned-musl root.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
readonly mode="${CRABC_GENERAL_DYNAMIC_ENTRY_MODE:---dynamic-pie}"
case "$mode" in --dynamic-pie) oracle_mode=-pie;; --dynamic-non-pie) oracle_mode=-no-pie;; *) exit 2;; esac
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PYTHON'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('general dynamic search TMPDIR must be a physical checkout .work directory')
PYTHON
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-search.XXXXXX")"
trap 'printf "general dynamic search: FAIL arm=%s case=%s; evidence: %s\n" "${arm:-setup}" "${test:-build}" "$work" >&2' ERR
mounted_proc=
privileged_files=()
cleanup() {
    if [ -n "$mounted_proc" ]; then
        umount "$mounted_proc" || { printf 'general dynamic search: failed to unmount %s\n' "$mounted_proc" >&2; exit 1; }
        mounted_proc=
    fi
    if [ "${#privileged_files[@]}" -ne 0 ]; then
        chmod 0755 "${privileged_files[@]}"
        privileged_files=()
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
readonly search_cases=(ancestor environment origin caller initial initial-environment relative delimiters missing stop-error breadth legacy precedence
    main-origin-missing main-origin secure-initial secure-runtime secure-main-origin secure-dso-origin secure-relative-origin
    preload preload-duplicate preload-whitespace preload-unused preload-missing preload-malformed preload-no-main-path preload-unresolved
    system-lib system-local system-file system-empty system-error system-read-error system-cache system-initial system-secure)
readonly source="$ROOT/compat/x86_64/general_dynamic_search.c"
bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >"$work/oracle-toolchain.log"
for arm in candidate oracle; do
    mkdir -p "$work/$arm" "$work/$arm-root/search" "$work/$arm-root/plugins/sub" "$work/$arm-root/environment" "$work/$arm-root/caller" "$work/$arm-root/loop" "$work/$arm-root/system" "$work/$arm-root/etc" "$work/$arm-root/usr/local/lib" "$work/$arm-root/lib" "$work/$arm-root/proc"
    build="$work/$arm"
    root="$work/$arm-root"
    if [ "$arm" = candidate ]; then
        cp -a "$installed/." "$root/"
        cc=("$installed/bin/crabc-cc-dynamic")
        "${cc[@]}" --dynamic-shared-object -DSEARCH_LEAF=7 "$source" -o "$build/libsearch_leaf.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_LEAF=8 "$source" -o "$build/environment.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_MIDDLE --application-runpath /missing "$source" --application-dso "$build/libsearch_leaf.so" -o "$build/libsearch_mid.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_MIDDLE --application-runpath '${ORIGIN}/sub' "$source" --application-dso "$build/libsearch_leaf.so" -o "$build/liborigin.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_CALLER --application-runpath /caller "$source" -o "$build/libcaller.so"
        "${cc[@]}" "$mode" --application-runpath /search:/usr/lib "$source" -o "$build/consumer"
        "${cc[@]}" "$mode" -DSEARCH_INITIAL --application-runpath /search:/usr/lib "$source" --application-dso "$build/libsearch_mid.so" --application-dso "$build/libsearch_leaf.so" -o "$build/initial"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_MIDDLE --application-runpath /environment "$source" --application-dso "$build/libsearch_leaf.so" -o "$build/libbreadth.so"
        "${cc[@]}" "$mode" -DSEARCH_INITIAL --application-runpath /search:/usr/lib "$source" --application-dso "$build/libbreadth.so" --application-dso "$build/libsearch_leaf.so" -o "$build/breadth"
        "${cc[@]}" "$mode" --application-runpath '$ORIGIN/search:/usr/lib' "$source" -o "$build/main-origin"
        "${cc[@]}" "$mode" -DSEARCH_SECURE --application-runpath '$ORIGIN/search:/usr/lib' "$source" -o "$build/secure-origin"
        "${cc[@]}" "$mode" -DSEARCH_SECURE --application-runpath /search:/usr/lib "$source" -o "$build/secure-runtime"
        "${cc[@]}" "$mode" -DSEARCH_SECURE -DSEARCH_INITIAL --application-runpath /search:/usr/lib "$source" --application-dso "$build/libsearch_mid.so" --application-dso "$build/libsearch_leaf.so" -o "$build/secure-initial"
        "${cc[@]}" "$mode" "$source" -o "$build/system-consumer"
        "${cc[@]}" "$mode" -DSEARCH_PATH_CACHE "$source" -o "$build/cache-consumer"
        "${cc[@]}" "$mode" -DSEARCH_INITIAL "$source" --application-dso "$build/libsearch_mid.so" --application-dso "$build/libsearch_leaf.so" -o "$build/system-initial"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_PRELOAD "$source" -o "$build/libpreload.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_PRELOAD -DSEARCH_UNUSED_PRELOAD "$source" -o "$build/libunused_preload.so"
        "${cc[@]}" --dynamic-shared-object -DSEARCH_UNRESOLVED_PRELOAD --binding lazy --runtime-import unresolved_preload_import "$source" -o "$build/libunresolved_preload.so"
    else
        cc=(/usr/local/bin/crabc-x86_64-musl-gcc)
        mkdir -p "$root/opt/musl-1.2.6/lib" "$root/usr/lib"
        cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
        cp /opt/musl-1.2.6/lib/libc.so "$root/lib/ld-musl-x86_64.so.1"
        "${cc[@]}" -fPIC -shared -Wl,-soname,libsearch_leaf.so -DSEARCH_LEAF=7 "$source" -o "$build/libsearch_leaf.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_LEAF=8 "$source" -o "$build/environment.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_MIDDLE "$source" -L"$build" -lsearch_leaf -Wl,-rpath,/missing -Wl,-soname,libsearch_mid.so -o "$build/libsearch_mid.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_MIDDLE "$source" -L"$build" -lsearch_leaf '-Wl,-rpath,${ORIGIN}/sub' -o "$build/liborigin.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_CALLER "$source" -Wl,-rpath,/caller -o "$build/libcaller.so"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 "$source" -Wl,-rpath,/search:/usr/lib -o "$build/consumer"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_INITIAL "$source" -L"$build" -lsearch_mid -lsearch_leaf -Wl,-rpath,/search:/usr/lib -o "$build/initial"
        "${cc[@]}" -fPIC -shared -DSEARCH_MIDDLE "$source" -L"$build" -lsearch_leaf -Wl,-rpath,/environment -Wl,-soname,libbreadth.so -o "$build/libbreadth.so"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_INITIAL "$source" -L"$build" -lbreadth -lsearch_leaf -Wl,-rpath,/search:/usr/lib -o "$build/breadth"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 "$source" '-Wl,-rpath,$ORIGIN/search:/usr/lib' -o "$build/main-origin"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_SECURE "$source" '-Wl,-rpath,$ORIGIN/search:/usr/lib' -o "$build/secure-origin"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_SECURE "$source" -Wl,-rpath,/search:/usr/lib -o "$build/secure-runtime"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_SECURE -DSEARCH_INITIAL "$source" -L"$build" -lsearch_mid -lsearch_leaf -Wl,-rpath,/search:/usr/lib -o "$build/secure-initial"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 "$source" -Wl,-rpath,/usr/lib -o "$build/system-consumer"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_PATH_CACHE "$source" -Wl,-rpath,/usr/lib -o "$build/cache-consumer"
        "${cc[@]}" -fPIE "$oracle_mode" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -DSEARCH_INITIAL "$source" -L"$build" -lsearch_mid -lsearch_leaf -Wl,-rpath,/usr/lib -o "$build/system-initial"
        "${cc[@]}" -fPIC -shared -DSEARCH_PRELOAD "$source" -o "$build/libpreload.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_PRELOAD -DSEARCH_UNUSED_PRELOAD "$source" -o "$build/libunused_preload.so"
        "${cc[@]}" -fPIC -shared -DSEARCH_UNRESOLVED_PRELOAD "$source" -o "$build/libunresolved_preload.so"
    fi
    cp "$build/consumer" "$build/initial" "$build/breadth" "$build/system-consumer" "$build/system-initial" "$build/cache-consumer" "$root/"
    cp "$build/main-origin" "$build/secure-origin" "$build/secure-runtime" "$build/secure-initial" "$root/"
    # Real exec-time privilege transition, not a synthesized auxv: chroot
    # drops to uid 65534 and the kernel executes these root-owned setuid files.
    chown 0:0 "$root/secure-origin" "$root/secure-runtime" "$root/secure-initial"
    privileged_files=("$root/secure-origin" "$root/secure-runtime" "$root/secure-initial")
    chmod 4755 "${privileged_files[@]}"
    # Source-tag admission variants of the same installed executable. Keep
    # all bytes unchanged except one dynamic entry: legacy RPATH replaces
    # RUNPATH; the precedence arm adds RPATH=/usr/lib in the inert DEBUG slot
    # while retaining RUNPATH=/search:/usr/lib. Both arms must still return 7.
    python3 -B - "$build/consumer" "$root" <<'PYTHON'
from pathlib import Path
import struct
import sys
source, root = map(Path, sys.argv[1:])
original = source.read_bytes()
phoff = struct.unpack_from('<Q', original, 32)[0]
phentsize, phnum = struct.unpack_from('<HH', original, 54)
dynamic = []
for index in range(phnum):
    offset = phoff + index * phentsize
    if struct.unpack_from('<I', original, offset)[0] == 2:
        start = struct.unpack_from('<Q', original, offset + 8)[0]
        size = struct.unpack_from('<Q', original, offset + 32)[0]
        for entry in range(start, start + size, 16):
            tag, value = struct.unpack_from('<qQ', original, entry)
            if not tag:
                break
            dynamic.append((entry, tag, value))
runpaths = [(entry, value) for entry, tag, value in dynamic if tag == 29]
debug = [entry for entry, tag, value in dynamic if tag == 21]
assert len(runpaths) == len(debug) == 1
entry, value = runpaths[0]
legacy = bytearray(original)
struct.pack_into('<q', legacy, entry, 15)
precedence = bytearray(original)
struct.pack_into('<qQ', precedence, debug[0], 15, value + len('/search:'))
for name, data in [('legacy', legacy), ('precedence', precedence)]:
    (root / name).write_bytes(data)
    (root / name).chmod(0o755)
PYTHON
    cp "$build/libsearch_leaf.so" "$build/libsearch_mid.so" "$build/libbreadth.so" "$root/search/"
    cp "$build/libsearch_mid.so" "$build/liborigin.so" "$root/plugins/"
    cp "$build/libsearch_leaf.so" "$root/plugins/sub/"
    cp "$build/environment.so" "$root/environment/libsearch_leaf.so"
    cp "$build/libcaller.so" "$root/caller/"
    # A caller-local same-name object is deliberately not chosen by dlopen.
    cp "$build/environment.so" "$root/caller/libsearch_mid.so"
    ln -s libsearch_leaf.so "$root/loop/libsearch_leaf.so"
    cp "$build/libpreload.so" "$build/libunused_preload.so" "$build/libunresolved_preload.so" "$root/plugins/"
    cp "$build/libpreload.so" "$root/search/libpreload.so"
    cp "$build/libsearch_leaf.so" "$build/libsearch_mid.so" "$root/system/"
    cp "$build/environment.so" "$root/system/libcache_seed.so"
    printf 'not an ELF object\n' >"$root/malformed-preload.so"
    for test in "${search_cases[@]}"; do
        command=(/consumer /plugins/libsearch_mid.so 7)
        environment=()
        expected_status=0
        credentials=()
        case "$test" in
            environment) environment=(LD_LIBRARY_PATH=/environment); command[2]=8;;
            origin) command[1]=/plugins/liborigin.so;;
            caller) command[1]=/caller/libcaller.so;;
            initial) command=(/initial unused 7);;
            initial-environment) environment=(LD_LIBRARY_PATH=/environment); command=(/initial unused 8);;
            relative) command[1]=plugins/libsearch_mid.so;;
            legacy) command[0]=/legacy;;
            precedence) command[0]=/precedence;;
            breadth) command=(/breadth unused 7);;
            missing) command[1]=/missing/libsearch_mid.so; command[2]=0;;
            stop-error) environment=(LD_LIBRARY_PATH=/loop); command[2]=0;;
            main-origin-missing) command=(/main-origin /plugins/libsearch_mid.so 0);;
            main-origin)
                if ! mount -t proc -o ro,nosuid,nodev,noexec proc "$root/proc"; then
                    printf 'general dynamic search: contained proc mount requires the dedicated SYS_ADMIN container\n' >&2
                    exit 1
                fi
                mounted_proc="$root/proc"
                command[0]=/main-origin;;
            secure-initial)
                credentials=(--userspec=65534:65534)
                environment=(LD_LIBRARY_PATH=/environment LD_PRELOAD=/plugins/libpreload.so)
                command=(/secure-initial unused 7);;
            secure-runtime)
                credentials=(--userspec=65534:65534)
                environment=(LD_LIBRARY_PATH=/environment LD_PRELOAD=/plugins/libpreload.so)
                command[0]=/secure-runtime;;
            secure-main-origin)
                credentials=(--userspec=65534:65534)
                command=(/secure-origin /plugins/libsearch_mid.so 0);;
            secure-dso-origin)
                credentials=(--userspec=65534:65534)
                environment=(LD_LIBRARY_PATH=/environment)
                command=(/secure-runtime /plugins/liborigin.so 7);;
            secure-relative-origin)
                credentials=(--userspec=65534:65534)
                command=(/secure-origin plugins/liborigin.so 0);;
            preload) environment=(LD_PRELOAD=/plugins/libpreload.so); command=(/initial unused 8);;
            preload-duplicate) environment=(LD_PRELOAD=$' :/plugins/libpreload.so\t/plugins/libpreload.so: '); command=(/initial unused 8);;
            preload-whitespace) environment=(LD_PRELOAD=$'/plugins/libpreload.so\v/plugins/libpreload.so'); command=(/initial unused 8);;
            preload-unused) environment=(LD_PRELOAD=/plugins/libunused_preload.so); command=(/initial unused 7);;
            preload-missing) environment=(LD_PRELOAD=/missing-preload.so); command=(/initial unused 7);;
            preload-malformed) environment=(LD_PRELOAD=/plugins/libpreload.so:/malformed-preload.so); command=(/initial unused 8);;
            preload-no-main-path) environment=(LD_PRELOAD=libpreload.so); command=(/initial unused 7);;
            preload-unresolved) environment=(LD_PRELOAD=/plugins/libpreload.so:/plugins/libunresolved_preload.so); command=(/initial unused 7); expected_status=127;;
            system-lib)
                cp "$build/libsearch_leaf.so" "$root/lib/libsearch_leaf.so"
                cp "$build/environment.so" "$root/usr/local/lib/libsearch_leaf.so"
                command[0]=/system-consumer;;
            system-local)
                rm "$root/lib/libsearch_leaf.so"
                command=(/system-consumer /plugins/libsearch_mid.so 8);;
            system-file)
                printf ':\n/missing:/system\n' >"$root/etc/ld-musl-x86_64.path"
                command[0]=/system-consumer;;
            system-empty)
                : >"$root/etc/ld-musl-x86_64.path"
                command=(/system-consumer /plugins/libsearch_mid.so 0);;
            system-error)
                rm "$root/etc/ld-musl-x86_64.path"
                ln -s ld-musl-x86_64.path "$root/etc/ld-musl-x86_64.path"
                command=(/system-consumer /plugins/libsearch_mid.so 0);;
            system-read-error)
                rm "$root/etc/ld-musl-x86_64.path"
                mkdir "$root/etc/ld-musl-x86_64.path"
                command=(/system-consumer /plugins/libsearch_mid.so 0);;
            system-cache)
                rmdir "$root/etc/ld-musl-x86_64.path"
                printf '/system\n' >"$root/etc/ld-musl-x86_64.path"
                command[0]=/cache-consumer;;
            system-initial)
                printf '/system\n' >"$root/etc/ld-musl-x86_64.path"
                command=(/system-initial unused 7);;
            system-secure)
                # Secure main ORIGIN suppresses its entire RUNPATH, including
                # /usr/lib. The explicit system file must also name libc's
                # installed directory rather than accidentally rely on defaults.
                printf '/system:/usr/lib\n' >"$root/etc/ld-musl-x86_64.path"
                credentials=(--userspec=65534:65534)
                command=(/secure-origin /plugins/libsearch_mid.so 7);;
            delimiters) environment=(LD_LIBRARY_PATH=$':\n/missing::/environment\n'); command[2]=8;;
        esac
        status=0
        timeout 20 env -u LD_LIBRARY_PATH -u LD_PRELOAD "${environment[@]}" chroot "${credentials[@]}" "$root" "${command[@]}" >"$work/$arm-$test.stdout" 2>"$work/$arm-$test.stderr" || status=$?
        [ "$status" -eq "$expected_status" ]
        if [ "$expected_status" -ne 0 ]; then [ ! -s "$work/$arm-$test.stdout" ]; fi
    done
    cleanup
done
for test in "${search_cases[@]}"; do
    cmp "$work/candidate-$test.stdout" "$work/oracle-$test.stdout"
done
printf 'general dynamic search: PASS (%s installed/musl decisions, %s); evidence: %s\n' "${#search_cases[@]}" "$mode" "$work"
