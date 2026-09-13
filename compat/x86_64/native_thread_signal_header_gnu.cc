// Installed-header C++17 GNU/BSD visibility witness for native x86 tgkill.
// The assigned address has C linkage and the exact three-int C function type;
// retained object symbols must therefore name `tgkill`, never a C++ mangling.
#include <signal.h>

extern "C" int (*tgkill_c_linkage)(int, int, int) = &tgkill;
