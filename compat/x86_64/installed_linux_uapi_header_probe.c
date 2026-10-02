/* These public wrappers must be consumable from installed target headers
 * without adding a host include path. Their dependent records and request
 * constants belong to the selected Linux UAPI source. */
#include <stddef.h>
#include <sys/kd.h>
#include <sys/soundcard.h>
#include <sys/vt.h>
#ifdef __cplusplus
#define HEADER_ASSERT static_assert
extern "C"
#else
#define HEADER_ASSERT _Static_assert
#endif
int installed_linux_uapi_header_probe(void);
HEADER_ASSERT(sizeof(struct vt_mode)==8,"virtual terminal mode layout");
HEADER_ASSERT(offsetof(struct vt_mode,relsig)==2,"virtual terminal release signal offset");
HEADER_ASSERT(sizeof(struct vt_stat)==6,"virtual terminal state layout");
HEADER_ASSERT(KD_TEXT==0 && KD_GRAPHICS==1,"keyboard display mode values");
HEADER_ASSERT(VT_OPENQRY==0x5600,"virtual terminal query request");
HEADER_ASSERT(SNDCTL_SEQ_RESET==0x5100,"sequencer reset request");
int installed_linux_uapi_header_probe(void) { return 0; }
