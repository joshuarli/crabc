// Each selected direct include below must fail because its transitive surface
// is intentionally absent in pinned musl.
#if defined(CRABC_TERMINAL_STREAMS_NEGATIVE_STROPTS_WINSIZE)
#include <stropts.h>
constexpr auto crabc_x86_unexpected_stropts_winsize = sizeof(struct winsize);
#elif defined(CRABC_TERMINAL_STREAMS_NEGATIVE_SYS_STROPTS_WINSIZE)
#include <sys/stropts.h>
constexpr auto crabc_x86_unexpected_sys_stropts_winsize = sizeof(struct winsize);
#elif defined(CRABC_TERMINAL_STREAMS_NEGATIVE_TTYDEFAULTS_TCGETATTR)
#include <sys/ttydefaults.h>
using crabc_x86_unexpected_tcgetattr = decltype(&tcgetattr);
#else
#error "select one negative direct-header topology assertion"
#endif
