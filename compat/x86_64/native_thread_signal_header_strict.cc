// Installed-header C++17 strict-visibility witness for native x86 tgkill.
// This file is intentionally compiled with every ordinary feature macro
// explicitly undefined. Taking the address must then fail as undeclared.
#include <signal.h>

int (*strict_tgkill_address)(int, int, int) = &tgkill;
