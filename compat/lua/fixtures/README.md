# Lua source-build fixtures

These files use the stock Lua 5.4 C API and have no third-party dependency.
Build the two DSOs separately, for example:

```sh
cc -fPIC -shared -I/path/to/lua-5.4/src -o crabc_probe.so crabc_probe.c
cc -fPIC -shared -I/path/to/lua-5.4/src -o crabc_fail.so crabc_fail.c
```

The harness should create a disposable directory and set
`CRABC_LUA_ENV=adapter-sysroot`.  With `CRABC_LUA_MAPS_WAIT=1`, the script
first prints `maps-ready` and waits for the line `continue` on standard input;
this is the harness's synchronization point for `/proc/<pid>/maps` capture.
Run either source or bytecode with the DSO directory as `arg[1]` and the
disposable directory as `arg[2]`:

```sh
lua exercise.lua "$module_dir" "$fixture_dir"
luac -o exercise.luac exercise.lua
lua exercise.luac "$module_dir" "$fixture_dir"
```

Without `CRABC_LUA_MAPS_WAIT`, expected stdout is:

```text
LUA_FIXTURE_OK alloc=32651 buffer=10 file=11 require=cached child=ok utf8=2
```

With the synchronization variable, stdout has `maps-ready` followed by the
same result line.  Expected stderr is `LUA_FIXTURE_STDERR` followed by a
newline.  The probe's
`openat_roundtrip` accepts only a single leaf name, creates and removes it
relative to the supplied directory descriptor, and reports system errors as
Lua errors.  `crabc_fail.so` exports the expected init symbol and deliberately
raises during module initialisation.  The harness copies `crabc_probe.so` to
`crabc_missing.so`; the script loads that copy under its synthetic name, so its
missing `luaopen_crabc_missing` symbol exercises Lua's missing-symbol path.
