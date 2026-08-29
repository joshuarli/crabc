/*
 * C++17 counterpart to uapi_wrappers_header_abi_probe.c.
 *
 * Keep this free of <cstddef>: the runner deliberately uses -nostdinc++ and
 * tests the C-compatible wrapper surface, not a C++ standard library.
 */
#include <stddef.h>

#include <sys/kd.h>
#include <sys/soundcard.h>
#include <sys/vt.h>

#define CRABC_ASSERT_SIZE(type, expected) \
    static_assert(sizeof(type) == (expected), #type " size")
#define CRABC_ASSERT_ALIGN(type, expected) \
    static_assert(alignof(type) == (expected), #type " alignment")
#define CRABC_ASSERT_OFFSET(type, member, expected) \
    static_assert(__builtin_offsetof(type, member) == (expected), #type "." #member " offset")

static_assert(KD_TEXT == 0 && KD_GRAPHICS == 1, "KD text/graphics modes");
static_assert(KDSETMODE == 0x4b3a && KDGETMODE == 0x4b3b, "KD mode ioctls");
static_assert(KDGKBENT == 0x4b46 && KDSKBENT == 0x4b47, "KD keyboard ioctls");
static_assert(GIO_FONTX == 0x4b6b && PIO_FONTX == 0x4b6c, "KD font ioctls");
static_assert(KDFONTOP == 0x4b72, "KD font operation ioctl");

CRABC_ASSERT_SIZE(struct consolefontdesc, 16);
CRABC_ASSERT_ALIGN(struct consolefontdesc, 8);
CRABC_ASSERT_OFFSET(struct consolefontdesc, charcount, 0);
CRABC_ASSERT_OFFSET(struct consolefontdesc, charheight, 2);
CRABC_ASSERT_OFFSET(struct consolefontdesc, chardata, 8);
CRABC_ASSERT_SIZE(struct unipair, 4);
CRABC_ASSERT_ALIGN(struct unipair, 2);
CRABC_ASSERT_OFFSET(struct unipair, unicode, 0);
CRABC_ASSERT_OFFSET(struct unipair, fontpos, 2);
CRABC_ASSERT_SIZE(struct unimapdesc, 16);
CRABC_ASSERT_ALIGN(struct unimapdesc, 8);
CRABC_ASSERT_OFFSET(struct unimapdesc, entry_ct, 0);
CRABC_ASSERT_OFFSET(struct unimapdesc, entries, 8);
CRABC_ASSERT_SIZE(struct kbentry, 4);
CRABC_ASSERT_ALIGN(struct kbentry, 2);
CRABC_ASSERT_OFFSET(struct kbentry, kb_table, 0);
CRABC_ASSERT_OFFSET(struct kbentry, kb_index, 1);
CRABC_ASSERT_OFFSET(struct kbentry, kb_value, 2);
CRABC_ASSERT_SIZE(struct kbsentry, 513);
CRABC_ASSERT_ALIGN(struct kbsentry, 1);
CRABC_ASSERT_SIZE(struct kbd_repeat, 8);
CRABC_ASSERT_ALIGN(struct kbd_repeat, 4);
CRABC_ASSERT_SIZE(struct console_font_op, 32);
CRABC_ASSERT_ALIGN(struct console_font_op, 8);
CRABC_ASSERT_OFFSET(struct console_font_op, data, 24);
CRABC_ASSERT_SIZE(struct console_font, 24);
CRABC_ASSERT_ALIGN(struct console_font, 8);
CRABC_ASSERT_OFFSET(struct console_font, data, 16);

static_assert(MIN_NR_CONSOLES == 1 && MAX_NR_CONSOLES == 63, "VT console limits");
static_assert(VT_OPENQRY == 0x5600 && VT_GETMODE == 0x5601, "VT query ioctls");
static_assert(VT_SETMODE == 0x5602 && VT_GETSTATE == 0x5603, "VT state ioctls");
static_assert(VT_SENDSIG == 0x5604 && VT_RELDISP == 0x5605, "VT signal ioctls");
static_assert(VT_ACTIVATE == 0x5606 && VT_WAITACTIVE == 0x5607, "VT activation ioctls");
static_assert(VT_DISALLOCATE == 0x5608 && VT_RESIZE == 0x5609, "VT resize ioctls");
static_assert(VT_RESIZEX == 0x560a && VT_LOCKSWITCH == 0x560b, "VT extended ioctls");
static_assert(VT_UNLOCKSWITCH == 0x560c && VT_GETHIFONTMASK == 0x560d, "VT switch ioctls");
static_assert(VT_WAITEVENT == 0x560e && VT_SETACTIVATE == 0x560f, "VT event ioctls");
static_assert(VT_AUTO == 0 && VT_PROCESS == 1 && VT_ACKACQ == 2, "VT process modes");
static_assert(VT_EVENT_SWITCH == 1 && VT_EVENT_BLANK == 2, "VT event bits");
static_assert(VT_EVENT_UNBLANK == 4 && VT_EVENT_RESIZE == 8, "VT event bits");

CRABC_ASSERT_SIZE(struct vt_mode, 8);
CRABC_ASSERT_ALIGN(struct vt_mode, 2);
CRABC_ASSERT_OFFSET(struct vt_mode, mode, 0);
CRABC_ASSERT_OFFSET(struct vt_mode, waitv, 1);
CRABC_ASSERT_OFFSET(struct vt_mode, relsig, 2);
CRABC_ASSERT_OFFSET(struct vt_mode, acqsig, 4);
CRABC_ASSERT_OFFSET(struct vt_mode, frsig, 6);
CRABC_ASSERT_SIZE(struct vt_stat, 6);
CRABC_ASSERT_ALIGN(struct vt_stat, 2);
CRABC_ASSERT_OFFSET(struct vt_stat, v_active, 0);
CRABC_ASSERT_OFFSET(struct vt_stat, v_signal, 2);
CRABC_ASSERT_OFFSET(struct vt_stat, v_state, 4);
CRABC_ASSERT_SIZE(struct vt_sizes, 6);
CRABC_ASSERT_ALIGN(struct vt_sizes, 2);
CRABC_ASSERT_SIZE(struct vt_consize, 12);
CRABC_ASSERT_ALIGN(struct vt_consize, 2);
CRABC_ASSERT_SIZE(struct vt_event, 28);
CRABC_ASSERT_ALIGN(struct vt_event, 4);
CRABC_ASSERT_OFFSET(struct vt_event, event, 0);
CRABC_ASSERT_OFFSET(struct vt_event, oldev, 4);
CRABC_ASSERT_OFFSET(struct vt_event, newev, 8);
CRABC_ASSERT_OFFSET(struct vt_event, pad, 12);
CRABC_ASSERT_SIZE(struct vt_setactivate, 12);
CRABC_ASSERT_ALIGN(struct vt_setactivate, 4);
CRABC_ASSERT_OFFSET(struct vt_setactivate, console, 0);
CRABC_ASSERT_OFFSET(struct vt_setactivate, mode, 4);

static_assert(SOUND_VERSION == 0x030802, "OSS ABI version");
static_assert(AFMT_U8 == 0x00000008 && AFMT_S16_LE == 0x00000010,
              "OSS little-endian sample formats");
static_assert(AFMT_S16_BE == 0x00000020 && AFMT_S16_NE == AFMT_S16_LE,
              "OSS native sample format");
static_assert(PCM_ENABLE_INPUT == 1 && PCM_ENABLE_OUTPUT == 2, "OSS PCM directions");
static_assert(SOUND_MIXER_NRDEVICES == 25, "OSS mixer count");
static_assert(SOUND_MIXER_VOLUME == 0 && SOUND_MIXER_PCM == 4 && SOUND_MIXER_NONE == 31,
              "OSS mixer identifiers");
static_assert(SOUND_MASK_VOLUME == 1 && SOUND_MASK_PCM == 16, "OSS mixer masks");
static_assert(SNDCTL_DSP_SYNC == _SIO('P', 1), "OSS sync request encoding");

CRABC_ASSERT_SIZE(struct seq_event_rec, 8);
CRABC_ASSERT_ALIGN(struct seq_event_rec, 1);
CRABC_ASSERT_SIZE(struct audio_buf_info, 16);
CRABC_ASSERT_ALIGN(struct audio_buf_info, 4);
CRABC_ASSERT_OFFSET(struct audio_buf_info, fragments, 0);
CRABC_ASSERT_OFFSET(struct audio_buf_info, fragstotal, 4);
CRABC_ASSERT_OFFSET(struct audio_buf_info, fragsize, 8);
CRABC_ASSERT_OFFSET(struct audio_buf_info, bytes, 12);
CRABC_ASSERT_SIZE(struct count_info, 12);
CRABC_ASSERT_ALIGN(struct count_info, 4);
CRABC_ASSERT_OFFSET(struct count_info, bytes, 0);
CRABC_ASSERT_OFFSET(struct count_info, blocks, 4);
CRABC_ASSERT_OFFSET(struct count_info, ptr, 8);
CRABC_ASSERT_SIZE(struct buffmem_desc, 16);
CRABC_ASSERT_ALIGN(struct buffmem_desc, 8);
CRABC_ASSERT_OFFSET(struct buffmem_desc, buffer, 0);
CRABC_ASSERT_OFFSET(struct buffmem_desc, size, 8);
CRABC_ASSERT_SIZE(struct mixer_info, 92);
CRABC_ASSERT_ALIGN(struct mixer_info, 4);
CRABC_ASSERT_OFFSET(struct mixer_info, id, 0);
CRABC_ASSERT_OFFSET(struct mixer_info, name, 16);
CRABC_ASSERT_OFFSET(struct mixer_info, modify_counter, 48);
CRABC_ASSERT_SIZE(struct _old_mixer_info, 48);
CRABC_ASSERT_ALIGN(struct _old_mixer_info, 1);

static_assert(SNDCTL_DSP_SPEED == 0xc0045002U, "OSS speed ioctl value");
static_assert(SNDCTL_DSP_GETOSPACE == 0x8010500cU, "OSS output-space ioctl value");
static_assert(SNDCTL_DSP_GETIPTR == 0x800c5011U, "OSS input-pointer ioctl value");
static_assert(SOUND_MIXER_READ_VOLUME == 0x80044d00U, "OSS mixer-read ioctl value");
static_assert(SOUND_MIXER_WRITE_PCM == 0xc0044d04U, "OSS mixer-write ioctl value");
static_assert(OSS_GETVERSION == 0x80044d76U, "OSS version ioctl value");
static_assert(_IOC_DIR(SNDCTL_DSP_SPEED) == (_IOC_READ | _IOC_WRITE),
              "OSS speed ioctl direction");
static_assert(_IOC_TYPE(SNDCTL_DSP_SPEED) == 'P' && _IOC_NR(SNDCTL_DSP_SPEED) == 2,
              "OSS speed ioctl type and number");
static_assert(_IOC_SIZE(SNDCTL_DSP_SPEED) == sizeof(int), "OSS speed ioctl size");
static_assert(_IOC_SIZE(SNDCTL_DSP_GETOSPACE) == sizeof(struct audio_buf_info),
              "OSS output-space ioctl record size");
static_assert(_IOC_SIZE(SNDCTL_DSP_GETIPTR) == sizeof(struct count_info),
              "OSS input-pointer ioctl record size");
static_assert(_IOC_SIZE(SOUND_MIXER_READ_VOLUME) == sizeof(int),
              "OSS mixer-read ioctl scalar size");
