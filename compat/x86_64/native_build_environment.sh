_native_build_tools_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mapfile -d '' -t _native_build_tools_environment < <(
    python3 -B "$_native_build_tools_dir/native_rustc.py" environment
)
_native_build_tools_environment_pid=$!
if ! wait "$_native_build_tools_environment_pid"; then
    printf '%s\n' 'ERROR: native build environment resolution failed' >&2
    return 1
fi
if [ "${#_native_build_tools_environment[@]}" -eq 0 ] ||
   [ "$(( ${#_native_build_tools_environment[@]} % 2 ))" -ne 0 ]; then
    printf '%s\n' 'ERROR: native build environment output is malformed' >&2
    return 1
fi
for ((_native_build_tools_index = 0; _native_build_tools_index < ${#_native_build_tools_environment[@]}; _native_build_tools_index += 2)); do
    export "${_native_build_tools_environment[_native_build_tools_index]}=${_native_build_tools_environment[_native_build_tools_index + 1]}"
done
unset _native_build_tools_dir _native_build_tools_environment _native_build_tools_environment_pid _native_build_tools_index
