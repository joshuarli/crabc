--
-- Deterministic Lua 5.4 source/bytecode witness for the crabc source-build gate.
--
-- arg[1] is the dynamic-module directory in the AArch64 lane and the linked
-- preload support directory in the native static lane.  arg[2] is a disposable
-- directory created by the harness.  The harness supplies CRABC_LUA_ENV as
-- documented in README.md.
--

local module_dir = assert(arg[1], "module directory argument is required")
local root = assert(arg[2], "fixture directory argument is required")
local dynamic_modules = os.getenv("CRABC_LUA_DYNAMIC_MODULES") ~= "0"
package.cpath = module_dir .. "/?.so;" .. package.cpath

local function check(condition, message)
    if not condition then
        error(message, 0)
    end
end

-- The dynamic lane resolves this through Lua's normal DSO searcher.  The
-- native static lane deliberately registers the exact same entry point in
-- package.preload, which proves linked C-module functionality but does not
-- claim dlopen or dynamic-loader coverage.
if not dynamic_modules then
    check(type(package.preload.crabc_probe) == "function",
          "static crabc_probe preload is missing")
    check(type(package.preload.crabc_fail) == "function",
          "static crabc_fail preload is missing")
end
local probe = assert(require("crabc_probe"))
local probe_again = assert(require("crabc_probe"))
check(probe == probe_again, "require did not cache crabc_probe")
check(probe.name == "crabc_probe", "module name mismatch")
check(probe.version == "fixture-1", "module version mismatch")

local expected_checksum = 0
for index = 0, 256 do
    expected_checksum = expected_checksum + ((index * 37 + 11) % 256)
end
check(probe.allocation_roundtrip(257) == expected_checksum,
      "allocation/free round trip mismatch")

local binary = "crabc\0lua\255"
check(probe.buffer_roundtrip(binary) == binary,
      "caller-owned byte buffer round trip mismatch")
check(probe.openat_roundtrip(root, "extension-roundtrip.bin", binary) == binary,
      "openat file round trip mismatch")

local missing_ok, missing_error = pcall(function()
    probe.openat_roundtrip(root .. "/no-such-directory", "missing.bin", "x")
end)
check(not missing_ok and type(missing_error) == "string",
      "openat error propagation missing")

-- Strings, tables, UTF-8, and nontrivial math all remain in the script lane.
local text = "alpha:beta"
check(string.sub(text, 1, 5) == "alpha", "string.sub mismatch")
check(string.find(text, ":", 1, true) == 6, "string.find mismatch")
local values = { 4, 1, 3, 2 }
table.sort(values)
check(table.concat(values, ",") == "1,2,3,4", "table sort/concat mismatch")
check(utf8.len("h\195\169") == 2, "utf8 length mismatch")
check(utf8.codepoint("h\195\169", 2) == 0xE9, "utf8 codepoint mismatch")
check(math.abs(math.sin(math.pi / 6) - 0.5) < 1e-12, "math.sin mismatch")
check(math.sqrt(81) == 9 and math.floor(4.75) == 4, "math arithmetic mismatch")

-- Buffered create/read/seek/rename is intentionally separate from the C
-- openat witness, so both Lua stdio and descriptor-relative C I/O are seen.
local before_rename = root .. "/lua-buffered.txt"
local after_rename = root .. "/lua-buffered-renamed.txt"
os.remove(before_rename)
os.remove(after_rename)
local file = assert(io.open(before_rename, "w+b"))
assert(file:setvbuf("full", 1024))
assert(file:write("alpha\nbeta\n"))
assert(file:seek("set", 0) == 0)
check(file:read("*l") == "alpha", "buffered file first line mismatch")
check(file:seek("set", 6) == 6, "buffered file seek mismatch")
check(file:read(4) == "beta", "buffered file second line mismatch")
assert(file:close())
assert(os.rename(before_rename, after_rename))
local renamed = assert(io.open(after_rename, "rb"))
check(renamed:read("*a") == "alpha\nbeta\n", "renamed file mismatch")
assert(renamed:close())
assert(os.remove(after_rename))

-- Standard input is supplied by the harness.  Output is emitted only after
-- every check has passed, making each lane's result a deterministic record.
if os.getenv("CRABC_LUA_MAPS_WAIT") == "1" then
    io.stdout:write("maps-ready\n")
    io.stdout:flush()
    check(io.stdin:read("*l") == "continue", "stdin round trip mismatch")
end
check(os.getenv("CRABC_LUA_ENV") == "owned-sysroot", "environment lookup mismatch")
check(type(os.time()) == "number", "time lookup mismatch")
check(os.date("!%Y-%m-%dT%H:%M:%SZ", 0) == "1970-01-01T00:00:00Z",
      "UTC epoch formatting mismatch")

local child = assert(io.popen("printf 'crabc-child\\n'", "r"))
check(child:read("*a") == "crabc-child\n", "child pipe output mismatch")
local child_ok = child:close()
check(child_ok == true, "child process did not exit successfully")

-- The failure module has a valid exported init symbol but deliberately fails
-- during initialisation.  This checks Lua's protected require/error path.
local failure_ok, failure_error = pcall(require, "crabc_fail")
check(not failure_ok, "controlled failure module unexpectedly loaded")
check(type(failure_error) == "string" and
          string.find(failure_error, "crabc_fail: intentional init failure", 1, true),
      "controlled failure error mismatch")
if dynamic_modules then
    -- This copy lacks luaopen_crabc_missing and is specifically a runtime-DSO
    -- missing-symbol assertion.  Static mode has no corresponding DSO load.
    local missing_ok, missing_error = pcall(require, "crabc_missing")
    check(not missing_ok and type(missing_error) == "string" and
              string.find(missing_error, "luaopen_crabc_missing", 1, true),
          "controlled missing-symbol error mismatch: " .. tostring(missing_error))
end

assert(io.stdout:setvbuf("full", 1024))
assert(io.stderr:setvbuf("full", 1024))
local formatted = string.format(
    "LUA_FIXTURE_OK alloc=%d buffer=%d file=%d require=cached child=ok utf8=%d",
    expected_checksum,
    #binary,
    11,
    utf8.len("h\195\169"))
io.stdout:write(formatted, "\n")
io.stdout:flush()
io.stderr:write("LUA_FIXTURE_STDERR\n")
io.stderr:flush()
