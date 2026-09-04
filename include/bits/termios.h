/* Linux termios record declaration, following pinned musl 1.2.6. */

struct termios {
	tcflag_t c_iflag, c_oflag, c_cflag, c_lflag;
	cc_t c_line;
	cc_t c_cc[NCCS];
#if defined(__x86_64__)
	speed_t __c_ispeed, __c_ospeed;
#else
	/* Preserve the established AArch64 project spelling. */
	speed_t __ispeed, __ospeed;
#endif
};
