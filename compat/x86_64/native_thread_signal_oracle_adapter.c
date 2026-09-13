/* Pinned-musl Linux behavior adapter for the crabc tgkill extension.
 *
 * musl 1.2.6 deliberately exports no public tgkill C entry. This object is
 * linked only into the musl reference executables beside the one application
 * object compiled through the installed candidate signal.h. It supplies the
 * frozen crabc signature by forwarding to musl's public syscall() boundary,
 * preserving Linux SYS_tgkill errno behavior without claiming a musl tgkill
 * ABI or recompiling the workload for the oracle.
 */

#define _GNU_SOURCE 1

#include <sys/syscall.h>
#include <unistd.h>

int tgkill(int tgid, int tid, int signal)
{
    return (int)syscall(SYS_tgkill, tgid, tid, signal);
}
