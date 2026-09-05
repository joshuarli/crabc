#!/usr/bin/env bash
# Installed command entry compared with a separate pinned-musl root.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-cli.XXXXXX")"
readonly source="$ROOT/compat/x86_64/general_dynamic_cli.c"
trap 'printf "direct interpreter FAIL arm=%s mode=%s case=%s; evidence: %s\n" "${arm:-setup}" "${mode:-setup}" "${test:-build}" "$work" >&2' ERR
for arm in oracle candidate; do
    root="$work/$arm"
    mkdir -p "$root/lib" "$root/usr/lib" "$root/plugins" "$root/override" "$root/prefix/lib" "$root/prefix/etc"
    if [ "$arm" = candidate ]; then
        cp -a "$installed/." "$root/"
        cc=("$installed/bin/crabc-cc-dynamic")
        "${cc[@]}" --dynamic-shared-object -DCLI_LIBRARY=7 "$source" -o "$root/plugins/libcli.so"
        "${cc[@]}" --dynamic-shared-object -DCLI_LIBRARY=9 "$source" -o "$root/override/libcli.so"
        interpreter=/lib/ld-crabc-x86_64.so.1
    else
        cp /opt/musl-1.2.6/lib/libc.so "$root/lib/ld-musl-x86_64.so.1"
        cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
        cc=(/usr/local/bin/crabc-x86_64-musl-gcc)
        "${cc[@]}" -fPIC -shared -DCLI_LIBRARY=7 "$source" -Wl,-soname,libcli.so -o "$root/plugins/libcli.so"
        "${cc[@]}" -fPIC -shared -DCLI_LIBRARY=9 "$source" -Wl,-soname,libcli.so -o "$root/override/libcli.so"
        interpreter=/lib/ld-musl-x86_64.so.1
    fi
    cp "$root$interpreter" "$root/prefix/lib/loader"
    cp "$root$interpreter" "$root/ldd"
    printf invalid >"$root/invalid"
    printf '/override:/usr/lib' >"$root/prefix/etc/ld-musl-x86_64.path"
    for mode in pie non-pie; do
        if [ "$arm" = candidate ]; then
            "${cc[@]}" "--dynamic-$mode" -DCLI_CHECK_AUXV "$source" --application-runpath '$ORIGIN/plugins:/usr/lib' --application-dso "$root/plugins/libcli.so" -o "$root/consumer-$mode"
        else
            "${cc[@]}" -fPIE "-${mode/non-pie/no-pie}" "$source" -L"$root/plugins" -lcli '-Wl,-rpath,$ORIGIN/plugins:/usr/lib' -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$root/consumer-$mode"
        fi
        if [ "$arm" = candidate ]; then
            "${cc[@]}" "--dynamic-$mode" -DCLI_CHECK_AUXV "$source" --application-runpath /usr/lib --application-dso "$root/plugins/libcli.so" -o "$root/system-$mode"
        else
            "${cc[@]}" -fPIE "-${mode/non-pie/no-pie}" "$source" -L"$root/plugins" -lcli -Wl,-rpath,/usr/lib -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$root/system-$mode"
        fi
        cp "$root/system-$mode" "$root/system"
        cp "$root/consumer-$mode" "$root/consumer"
        cp "$root/consumer" "$root/--consumer"
        for test in ordinary separator argv0 argv0-equals library-path library-path-equals preload preload-equals list unknown missing-value missing-program malformed missing-file prefix ldd combined library-over-environment missing-dependency invalid-executable; do
            selected_interpreter="$interpreter"
            options=()
            program=(/consumer argument)
            expected=0
            environment_path=
            case "$test" in
                combined) options=(--argv0 first --argv0=replacement --library-path=/plugins --library-path /override);;
                library-over-environment) environment_path=/override; options=(--library-path=/plugins);;
                missing-dependency) program=(/system argument); expected=127;;
                invalid-executable) program=(/invalid); expected=1;;
                prefix) selected_interpreter=/prefix/lib/loader; program=(/system argument);;
                ldd) selected_interpreter=/ldd;;
                separator) options=(--); program=(./--consumer argument);;
                argv0) options=(--argv0 replacement);;
                argv0-equals) options=(--argv0=replacement);;
                library-path) options=(--library-path /override);;
                library-path-equals) options=(--library-path=/override);;
                preload) options=(--preload /override/libcli.so);;
                preload-equals) options=(--preload=/override/libcli.so);;
                list) options=(--list);;
                unknown) options=(--unknown); expected=1;;
                missing-value) options=(--argv0); program=(); expected=1;;
                missing-program) program=(); expected=1;;
                malformed) options=(--library-path-extra); expected=1;;
                missing-file) program=(/absent); expected=1;;
            esac
            status=0
            CLI_ENV=preserved LD_LIBRARY_PATH="$environment_path" timeout 20 chroot "$root" "$selected_interpreter" "${options[@]}" "${program[@]}" >"$work/$arm-$mode-$test.stdout" 2>"$work/$arm-$mode-$test.stderr" || status=$?
            [ "$status" -eq "$expected" ]
            if [ "$test" = list ] || [ "$test" = ldd ]; then
                ! grep -q 'initialized\|application entered' "$work/$arm-$mode-$test.stdout"
                grep -q '/plugins/libcli.so' "$work/$arm-$mode-$test.stdout"
            elif [ "$arm" = candidate ]; then
                cmp "$work/oracle-$mode-$test.stdout" "$work/candidate-$mode-$test.stdout"
            fi
        done
    done
done
printf 'direct interpreter: PASS 40 cases per arm; evidence: %s\n' "$work"
