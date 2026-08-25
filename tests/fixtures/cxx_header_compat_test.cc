// The headers below cover declarations using the C `restrict` spelling across
// stdio, allocation, strings, dynamic loading, integer conversion, signals,
// and Unix path APIs.  The fixture is compile-only: it tests the installed
// header language boundary, not C++ runtime linkage.
#include <dlfcn.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int crabc_cxx_header_compat_fixture()
{
    return EOF == -1 ? 0 : 1;
}
