/*
 * Small Lua 5.4 C-module witness for the Lua source-build gate. It is a
 * loadable module in the dynamic lane and a linked package.preload entry in
 * the native static lane.
 *
 * The module deliberately keeps its ABI surface narrow.  The file operation
 * uses a descriptor opened for the caller's directory and openat/unlinkat for
 * the leaf, so the fixture exercises descriptor-relative C I/O without
 * introducing a path policy into Lua.
 */

#include <errno.h>
#include <fcntl.h>
#include "lua.h"
#include "lauxlib.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROBE_MAX_ALLOCATION (1024u * 1024u)
#define PROBE_MAX_BUFFER 256u
#define PROBE_MAX_FILE (64u * 1024u)
#define PROBE_MAX_LEAF 255u

static int probe_allocation_roundtrip(lua_State *state)
{
    lua_Integer requested = luaL_checkinteger(state, 1);
    unsigned char *bytes;
    size_t count;
    size_t index;
    unsigned long checksum = 0;

    if (requested < 0 || (lua_Unsigned)requested > PROBE_MAX_ALLOCATION)
        return luaL_argerror(state, 1, "allocation size is out of range");
    count = (size_t)requested;
    bytes = (unsigned char *)malloc(count == 0 ? 1 : count);
    if (bytes == NULL)
        return luaL_error(state, "crabc_probe: malloc failed");

    for (index = 0; index < count; ++index) {
        bytes[index] = (unsigned char)((index * 37u + 11u) & 0xffu);
        checksum += bytes[index];
    }
    free(bytes);

    lua_pushinteger(state, (lua_Integer)checksum);
    return 1;
}

static int probe_buffer_roundtrip(lua_State *state)
{
    size_t length;
    const char *input = luaL_checklstring(state, 1, &length);
    unsigned char buffer[PROBE_MAX_BUFFER];

    if (length > sizeof(buffer))
        return luaL_argerror(state, 1, "buffer is too large");

    /* Lua copies this caller-owned byte buffer before returning the value. */
    buffer[0] = 0;
    if (length != 0)
        memcpy(buffer, input, length);
    lua_pushlstring(state, (const char *)buffer, length);
    return 1;
}

static int probe_errno(lua_State *state, const char *operation, int error)
{
    return luaL_error(state, "crabc_probe: %s: %s", operation, strerror(error));
}

static int probe_write_all(int fd, const char *bytes, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            if (written == 0)
                errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int probe_read_all(int fd, char *bytes, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int probe_valid_leaf(const char *name, size_t length)
{
    if (length == 0 || length > PROBE_MAX_LEAF || memchr(name, '/', length) != NULL)
        return 0;
    if (length == 1 && name[0] == '.')
        return 0;
    if (length == 2 && name[0] == '.' && name[1] == '.')
        return 0;
    return 1;
}

static int probe_openat_roundtrip(lua_State *state)
{
    size_t directory_length;
    size_t name_length;
    size_t payload_length;
    const char *directory = luaL_checklstring(state, 1, &directory_length);
    const char *name = luaL_checklstring(state, 2, &name_length);
    const char *payload = luaL_checklstring(state, 3, &payload_length);
    int directory_fd = -1;
    int file_fd = -1;
    int created = 0;
    int saved_errno;
    const char *operation = "open directory";
    char *actual = NULL;
    struct stat status;

    if (memchr(directory, '\0', directory_length) != NULL)
        return luaL_argerror(state, 1, "directory contains NUL");
    if (!probe_valid_leaf(name, name_length))
        return luaL_argerror(state, 2, "name must be a single path leaf");
    if (memchr(name, '\0', name_length) != NULL)
        return luaL_argerror(state, 2, "name contains NUL");
    if (payload_length > PROBE_MAX_FILE)
        return luaL_argerror(state, 3, "payload is too large");

    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        goto fail;

    operation = "openat for write";
    file_fd = openat(directory_fd,
                     name,
                     O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC,
                     0600);
    if (file_fd < 0)
        goto fail;
    created = 1;

    operation = "write file";
    if (probe_write_all(file_fd, payload, payload_length) < 0)
        goto fail;
    operation = "close file after write";
    if (close(file_fd) < 0) {
        file_fd = -1;
        goto fail;
    }
    file_fd = -1;

    operation = "openat for read";
    file_fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0)
        goto fail;
    operation = "stat file";
    if (fstat(file_fd, &status) < 0)
        goto fail;
    if (status.st_size < 0 || status.st_size > (off_t)PROBE_MAX_FILE) {
        errno = EFBIG;
        goto fail;
    }

    actual = (char *)malloc(status.st_size == 0 ? 1 : (size_t)status.st_size);
    if (actual == NULL) {
        errno = ENOMEM;
        operation = "allocate read buffer";
        goto fail;
    }
    operation = "read file";
    if (probe_read_all(file_fd, actual, (size_t)status.st_size) < 0)
        goto fail;
    if ((size_t)status.st_size != payload_length ||
        memcmp(actual, payload, payload_length) != 0) {
        errno = EIO;
        operation = "verify file";
        goto fail;
    }
    operation = "close file after read";
    if (close(file_fd) < 0) {
        file_fd = -1;
        goto fail;
    }
    file_fd = -1;

    operation = "unlinkat";
    if (unlinkat(directory_fd, name, 0) < 0)
        goto fail;
    created = 0;
    operation = "close directory";
    if (close(directory_fd) < 0) {
        directory_fd = -1;
        goto fail;
    }
    directory_fd = -1;

    free(actual);
    lua_pushlstring(state, payload, payload_length);
    return 1;

fail:
    saved_errno = errno;
    if (file_fd >= 0)
        close(file_fd);
    if (created && directory_fd >= 0)
        unlinkat(directory_fd, name, 0);
    if (directory_fd >= 0)
        close(directory_fd);
    free(actual);
    return probe_errno(state, operation, saved_errno);
}

static const luaL_Reg probe_functions[] = {
    {"allocation_roundtrip", probe_allocation_roundtrip},
    {"buffer_roundtrip", probe_buffer_roundtrip},
    {"openat_roundtrip", probe_openat_roundtrip},
    {NULL, NULL},
};

int luaopen_crabc_probe(lua_State *state)
{
    luaL_newlib(state, probe_functions);
    lua_pushliteral(state, "crabc_probe");
    lua_setfield(state, -2, "name");
    lua_pushliteral(state, "fixture-1");
    lua_setfield(state, -2, "version");
    return 1;
}
