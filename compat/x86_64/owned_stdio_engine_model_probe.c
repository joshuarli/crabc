#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

/*
 * Model-driven FILE-engine differential.
 *
 * The other FILE-engine rows exercise each entry point with chosen cases.
 * This row drives streams through long pseudo-random sequences of valid
 * operations and reports, after every step, what a conforming program can
 * observe: the result, errno, ftell, the error and end-of-file indicators,
 * the stdio_ext buffer state, and the backing object's own state (the
 * descriptor offset and file size, the bytes left in or written to a pipe,
 * or a memory or cookie object's contents). The backing state exposes when
 * the engine reads ahead and when it writes buffered bytes, so the row
 * compares musl's buffering policy as well as its results.
 *
 * Byte streams come from fopen in all six modes, fdopen on an adopted
 * descriptor, freopen of the same stream or of stdin/stdout, tmpfile,
 * fmemopen (on a caller or its own buffer), open_memstream, fopencookie
 * with short, failing, or missing transfers and seeks, pipes (with and
 * without a reader), and a file whose writes reach RLIMIT_FSIZE. Wide streams run the same way in
 * the C and C.UTF-8 locales over files with invalid UTF-8, and through
 * open_wmemstream. A thread scenario contends two threads for one stream.
 * Each stream may first be reconfigured by setvbuf, setbuf, setbuffer, or
 * setlinebuf.
 *
 * The generator tracks C 7.21.5.3: it never reads after a write without an
 * intervening fflush or successful positioning call, and never writes after
 * a read without a successful positioning call. ungetc follows only a
 * successful read past the first byte; wide streams position only to the
 * start, the end, or a saved fpos_t. Operands come from a fixed SplitMix64
 * stream, not an entropy source.
 *
 * argv[1] is private scratch for this process and is removed before exit.
 * Reports go to a duplicate of the original standard output, so the
 * scenarios may reopen stdout itself. By default each scenario prints one
 * line: its observation count and an FNV-1a digest of every observation
 * line. Building with -DMODEL_TRACE prints the observation lines themselves,
 * which localizes a digest difference to the first differing step.
 */

extern wint_t __fgetwc_unlocked(FILE *);
extern wint_t __fputwc_unlocked(wint_t, FILE *);
extern ssize_t __getdelim(char **, size_t *, int, FILE *);
extern int fpurge(FILE *);
extern int _IO_feof_unlocked(FILE *);
extern int _IO_ferror_unlocked(FILE *);
extern int _IO_getc(FILE *);
extern int _IO_getc_unlocked(FILE *);
extern int _IO_putc(int, FILE *);
extern int _IO_putc_unlocked(int, FILE *);
extern int __isoc99_fscanf(FILE *, const char *, ...);
/* C11 headers withdraw gets; musl still exports it. */
extern char *gets(char *);

#ifndef MODEL_SCENARIOS
#define MODEL_SCENARIOS 16384
#endif
#ifndef MODEL_SEED
#define MODEL_SEED UINT64_C(0x6372616263737464) /* "crabcstd" */
#endif

static uint64_t state;

static uint64_t next(void)
{
	uint64_t z = (state += UINT64_C(0x9e3779b97f4a7c15));
	z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
	return z ^ (z >> 31);
}

static unsigned below(unsigned bound)
{
	return (unsigned)(next() % bound);
}

static uint32_t fnv(const void *data, size_t size)
{
	const unsigned char *bytes = data;
	uint32_t hash = UINT32_C(2166136261);
	for (size_t index = 0; index < size; index++)
		hash = (hash ^ bytes[index]) * UINT32_C(16777619);
	return hash;
}

static int report_fd;
static uint32_t digest = UINT32_C(2166136261);
static unsigned digest_lines;
#ifdef MODEL_TRACE
static char trace[1 << 20];
static size_t trace_length;
#endif

static void emit(const char *line, int length)
{
	for (int done = 0; done < length;) {
		ssize_t count = write(report_fd, line + done, (size_t)(length - done));
		if (count <= 0) _Exit(93);
		done += (int)count;
	}
}

static int format_line(char *line, size_t size, const char *format, va_list arguments)
{
	int length = vsnprintf(line, size, format, arguments);
	if (length < 0 || (size_t)length >= size) _Exit(92);
	return length;
}

/* One observation: traced, or folded into the scenario digest. */
static void report(const char *format, ...)
{
	char line[512];
	va_list arguments;
	va_start(arguments, format);
	int length = format_line(line, sizeof line, format, arguments);
	va_end(arguments);
#ifdef MODEL_TRACE
	/* Held until the scenario ends: a scenario may lower RLIMIT_FSIZE,
	 * which also limits a file receiving the report. */
	if ((size_t)length > sizeof trace - trace_length) _Exit(94);
	memcpy(trace + trace_length, line, (size_t)length);
	trace_length += (size_t)length;
#else
	for (int index = 0; index < length; index++)
		digest = (digest ^ (unsigned char)line[index]) * UINT32_C(16777619);
#endif
	digest_lines++;
}

/* A line printed in every build. */
static void announce(const char *format, ...)
{
	char line[512];
	va_list arguments;
	va_start(arguments, format);
	int length = format_line(line, sizeof line, format, arguments);
	va_end(arguments);
	emit(line, length);
}

#define CHECK(x) do { if (!(x)) { announce("model:%d errno=%d\n", __LINE__, errno); _Exit(1); } } while (0)

/* Bytes are mostly letters with newlines and delimiters mixed in. */
static void fill(unsigned char *buffer, size_t size)
{
	for (size_t index = 0; index < size; index++) {
		unsigned choice = below(16);
		buffer[index] = choice == 0 ? '\n' : choice == 1 ? ';' :
			choice == 2 ? 0 : (unsigned char)('a' + below(26));
	}
}

/* Mostly valid UTF-8 with invalid and truncated sequences mixed in. */
static size_t fill_utf8(unsigned char *buffer, size_t capacity)
{
	size_t size = 0;
	while (size + 4 <= capacity) {
		unsigned choice = below(40);
		if (choice < 24) buffer[size++] = choice < 3 ? '\n' : (unsigned char)('a' + below(26));
		else if (choice < 31) { buffer[size++] = 0xc3; buffer[size++] = (unsigned char)(0x80 + below(64)); }
		else if (choice < 36) { buffer[size++] = 0xe2; buffer[size++] = 0x82; buffer[size++] = 0xac; }
		else if (choice < 38) { buffer[size++] = 0xf0; buffer[size++] = 0x9f; buffer[size++] = 0x98; buffer[size++] = 0x80; }
		else if (choice == 38) buffer[size++] = 0xff;
		else buffer[size++] = 0xe2; /* truncated */
		if (below(60) == 0) break;
	}
	return size;
}

enum direction { IDLE, READING, WRITING };
enum backing {
	BACKING_FILE, BACKING_MEMORY, BACKING_FMEM, BACKING_COOKIE,
	BACKING_PIPE_READ, BACKING_PIPE_WRITE,
};

/* A cookie object whose transfers may be short and, once a call budget is
 * spent, fail with EIO (a budget of zero never fails). */
struct cookie {
	unsigned char data[16384];
	size_t length, position;
	unsigned read_limit, write_limit;
	unsigned read_budget, write_budget;
	unsigned reads, writes, seeks;
};

struct stream_case {
	FILE *f;
	int fd;
	int readable, writable, standard_in, standard_out;
	enum backing backing;
	enum direction direction;
	int can_unget;
	int peer; /* pipe read end observed by a writing stream, or -1 */
	uint32_t drained_hash;
	long drained;
	char *memory;
	size_t memory_size;
	unsigned char *fmem;
	size_t fmem_size;
	struct cookie *cookie;
};

static ssize_t cookie_read(void *opaque, char *buffer, size_t length)
{
	struct cookie *c = opaque;
	c->reads++;
	if (c->read_budget && c->reads > c->read_budget) { errno = EIO; return -1; }
	if (length > c->read_limit) length = c->read_limit;
	size_t available = c->position < c->length ? c->length - c->position : 0;
	if (length > available) length = available;
	memcpy(buffer, c->data + c->position, length);
	c->position += length;
	return (ssize_t)length;
}

static ssize_t cookie_write(void *opaque, const char *buffer, size_t length)
{
	struct cookie *c = opaque;
	c->writes++;
	if (c->write_budget && c->writes > c->write_budget) { errno = EIO; return -1; }
	if (length > c->write_limit) length = c->write_limit;
	if (length > sizeof c->data - c->position) length = sizeof c->data - c->position;
	memcpy(c->data + c->position, buffer, length);
	c->position += length;
	if (c->position > c->length) c->length = c->position;
	return (ssize_t)length;
}

static int cookie_seek(void *opaque, off_t *offset, int whence)
{
	struct cookie *c = opaque;
	c->seeks++;
	long base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? (long)c->position : (long)c->length;
	long target = base + (long)*offset;
	if (target < 0 || target > (long)sizeof c->data) { errno = EINVAL; return -1; }
	c->position = (size_t)target;
	*offset = target;
	return 0;
}

static void observe(unsigned scenario, unsigned step, const char *op, long result,
	uint32_t data, int error, struct stream_case *c)
{
	long position = ftell(c->f);
	int position_error = position < 0 ? errno : 0;
	long offset = -1, size = -1;
	uint32_t backing = 0;
	switch (c->backing) {
	case BACKING_FILE: {
		struct stat st;
		offset = (long)lseek(c->fd, 0, SEEK_CUR);
		CHECK(!fstat(c->fd, &st));
		size = (long)st.st_size;
		break;
	}
	case BACKING_PIPE_READ: case BACKING_PIPE_WRITE: {
		/* A pipe has no offset: report the bytes the engine has left
		 * unread in it, or the bytes it has written since the last step
		 * (which are then drained so the writer never blocks). */
		int pending = 0;
		int queue = c->backing == BACKING_PIPE_READ ? c->fd : c->peer;
		if (queue >= 0) CHECK(!ioctl(queue, FIONREAD, &pending));
		offset = pending;
		if (c->backing == BACKING_PIPE_WRITE && queue >= 0) {
			unsigned char drained[65536];
			while (pending > 0) {
				ssize_t got = read(queue, drained, sizeof drained);
				CHECK(got > 0);
				c->drained_hash ^= fnv(drained, (size_t)got) + (uint32_t)c->drained;
				c->drained += got;
				pending -= (int)got;
			}
		}
		size = c->drained;
		break;
	}
	case BACKING_MEMORY:
		/* open_memstream publishes its buffer and size at fflush, fclose,
		 * and seeks; ftell alone must not. */
		size = (long)c->memory_size;
		if (c->memory && c->memory_size) backing = fnv(c->memory, c->memory_size);
		break;
	case BACKING_FMEM:
		/* A null-buffer fmemopen owns storage the caller cannot see. */
		size = (long)c->fmem_size;
		if (c->fmem) backing = fnv(c->fmem, c->fmem_size + 1);
		break;
	case BACKING_COOKIE:
		offset = (long)c->cookie->position;
		size = (long)c->cookie->length;
		backing = fnv(c->cookie->data, c->cookie->length) ^
			(c->cookie->reads << 20) ^ (c->cookie->writes << 10) ^ c->cookie->seeks;
		break;
	}
	report("%u.%u %s r=%ld d=%08x e=%d pos=%ld/%d eof=%d err=%d pend=%zu ahead=%zu rd=%d wr=%d "
		"fd=%ld size=%ld b=%08x\n",
		scenario, step, op, result, data, error, position, position_error,
		feof(c->f), ferror(c->f), __fpending(c->f), __freadahead(c->f),
		__freading(c->f) != 0, __fwriting(c->f) != 0, offset, size, backing);
}

static int seekable(const struct stream_case *c)
{
	return c->backing != BACKING_PIPE_READ && c->backing != BACKING_PIPE_WRITE;
}

static void prepare_read(struct stream_case *c)
{
	if (c->direction == WRITING) {
		CHECK(fflush(c->f) == 0 || ferror(c->f));
		c->direction = IDLE;
	}
}

static int prepare_write(struct stream_case *c)
{
	if (c->direction == READING) {
		if (fseek(c->f, 0, SEEK_CUR) != 0) return 0;
		c->direction = IDLE;
		c->can_unget = 0;
	}
	return 1;
}

static unsigned char big[262144];

static void byte_step(unsigned scenario, unsigned index, struct stream_case *c)
{
	unsigned char *buffer = big;
	char line[512];
	long result = 0;
	uint32_t data = 0;
	const char *op;
	unsigned choice = below(34);
	unsigned variant = below(4);

	/* Keep only operations the stream's mode admits. */
	if (!c->readable && choice < 11) choice += 11;
	if (!c->writable && choice >= 11 && choice < 18) choice = below(11);
	errno = 0;
	switch (choice) {
	case 0: case 1:
		prepare_read(c);
		if (c->standard_in && variant == 0) { op = "getchar"; result = getchar(); }
		else if (c->standard_in && variant == 1) { op = "getchar_unlocked"; result = getchar_unlocked(); }
		else if (variant == 0) { op = "fgetc"; result = fgetc(c->f); }
		else if (variant == 1) { op = "getc_unlocked"; result = getc_unlocked(c->f); }
		else if (variant == 2) { op = "_IO_getc"; result = _IO_getc(c->f); }
		else { op = choice ? "_IO_getc_unlocked" : "fgetc_unlocked";
			result = choice ? _IO_getc_unlocked(c->f) : fgetc_unlocked(c->f); }
		c->direction = READING; c->can_unget = result != EOF; break;
	case 2: case 3: {
		size_t size = below(4) == 0 ? below(1400) : below(40);
		prepare_read(c);
		if (variant & 1) { op = "fread_unlocked"; result = (long)fread_unlocked(buffer, 1, size, c->f); }
		else { op = "fread"; result = (long)fread(buffer, variant ? 3 : 1, size / (variant ? 3 : 1), c->f); }
		data = fnv(buffer, (size_t)result * (variant == 2 ? 3 : 1));
		c->direction = READING; c->can_unget = result > 0; break;
	}
	case 4: {
		int size = 1 + (int)below(below(4) == 0 ? 500 : 30);
		char *got;
		prepare_read(c);
		if (c->standard_in && variant == 0) { op = "gets"; got = gets((char *)buffer); }
		else if (variant == 1) { op = "fgets_unlocked"; got = fgets_unlocked((char *)buffer, size, c->f); }
		else { op = "fgets"; got = fgets((char *)buffer, size, c->f); }
		result = got ? (long)strlen((char *)buffer) : -1;
		data = got ? fnv(buffer, (size_t)result) : 0;
		c->direction = READING; c->can_unget = got != NULL; break;
	}
	case 5: case 6: {
		char *text = NULL;
		size_t capacity = variant == 3 ? 4 : 0;
		if (capacity) CHECK((text = malloc(capacity)));
		prepare_read(c);
		if (choice == 5) { op = "getline"; result = (long)getline(&text, &capacity, c->f); }
		else if (variant & 1) { op = "__getdelim"; result = (long)__getdelim(&text, &capacity, ';', c->f); }
		else { op = "getdelim"; result = (long)getdelim(&text, &capacity, ';', c->f); }
		data = result > 0 ? fnv(text, (size_t)result) : 0;
		free(text);
		c->direction = READING; c->can_unget = result > 0; break;
	}
	case 7:
		/* Pushing back before the first byte leaves the position
		 * indeterminate (C 7.21.7.10), so only unget after one. */
		if (!c->can_unget || (seekable(c) && ftell(c->f) <= 0)) {
			op = variant ? "feof_unlocked" : "_IO_feof_unlocked";
			result = variant ? feof_unlocked(c->f) : _IO_feof_unlocked(c->f); break;
		}
		op = "ungetc"; result = ungetc('A' + (int)below(26), c->f);
		c->can_unget = 0; break;
	case 8: {
		int count = 0;
		char word[32];
		prepare_read(c);
		if (c->standard_in && variant == 0) { op = "scanf"; result = scanf("%31[a-z]%n", word, &count); }
		else if (variant == 1) { op = "__isoc99_fscanf"; result = __isoc99_fscanf(c->f, "%31[a-z]%n", word, &count); }
		else { op = "fscanf"; result = fscanf(c->f, " %31[a-z]%n", word, &count); }
		data = result == 1 ? fnv(word, strlen(word)) ^ (uint32_t)count : 0;
		c->direction = READING; c->can_unget = 0; break;
	}
	case 9: {
		size_t length = 0;
		prepare_read(c);
		if (variant & 1) {
			op = "fgetln";
			char *got = fgetln(c->f, &length);
			result = got ? (long)length : -1;
			data = got ? fnv(got, length) : 0;
		} else {
			op = "getw"; result = getw(c->f);
		}
		c->direction = READING; c->can_unget = 0; break;
	}
	case 10: {
		size_t ahead = __freadahead(c->f);
		if (c->direction == READING && ahead != 0) {
			size_t length = 0;
			const char *pointer = __freadptr(c->f, &length);
			size_t advance = 1 + below((unsigned)(length < 64 ? length : 64));
			op = "__freadptrinc";
			CHECK(pointer && length == ahead);
			data = fnv(pointer, advance);
			__freadptrinc(c->f, advance);
			result = (long)advance;
			c->can_unget = 0;
		} else {
			op = "ferror_unlocked"; result = variant ? ferror_unlocked(c->f) : _IO_ferror_unlocked(c->f);
		}
		break;
	}
	case 11: case 12: {
		size_t size = below(4) == 0 ? below(1400) : below(40);
		fill(buffer, size);
		op = variant & 1 ? "fwrite_unlocked" : "fwrite";
		if (!prepare_write(c)) { op = "fwrite-skipped"; break; }
		result = (long)(variant & 1 ? fwrite_unlocked(buffer, 1, size, c->f) : fwrite(buffer, 1, size, c->f));
		data = fnv(buffer, size);
		c->direction = WRITING; break;
	}
	case 13: {
		int byte = below(3) == 0 ? '\n' : 'a' + (int)below(26);
		if (!prepare_write(c)) { op = "fputc-skipped"; break; }
		if (c->standard_out && variant == 0) { op = "putchar"; result = putchar(byte); }
		else if (c->standard_out && variant == 1) { op = "putchar_unlocked"; result = putchar_unlocked(byte); }
		else if (variant == 0) { op = "fputc"; result = fputc(byte, c->f); }
		else if (variant == 1) { op = "putc_unlocked"; result = putc_unlocked(byte, c->f); }
		else if (variant == 2) { op = "_IO_putc"; result = _IO_putc(byte, c->f); }
		else { op = "fputc_unlocked"; result = below(2) ? fputc_unlocked(byte, c->f) : _IO_putc_unlocked(byte, c->f); }
		c->direction = WRITING; break;
	}
	case 14: {
		size_t size = below(60);
		fill((unsigned char *)line, size);
		for (size_t at = 0; at < size; at++) if (!line[at]) line[at] = '0';
		line[size] = 0;
		if (!prepare_write(c)) { op = "fputs-skipped"; break; }
		if (c->standard_out && variant == 0) { op = "puts"; result = puts(line) >= 0; }
		else if (variant == 1) { op = "fputs_unlocked"; result = fputs_unlocked(line, c->f) >= 0; }
		else { op = "fputs"; result = fputs(line, c->f) >= 0; }
		data = fnv(line, size);
		c->direction = WRITING; break;
	}
	case 15:
		if (!prepare_write(c)) { op = "fprintf-skipped"; break; }
		if (c->standard_out && variant == 0) {
			op = "printf"; result = printf("<%u:%x:%s>", index, (unsigned)next(), below(2) ? "\n" : "");
		} else {
			op = "fprintf"; result = fprintf(c->f, "<%u:%x:%s>", index, (unsigned)next(), below(2) ? "\n" : "");
		}
		c->direction = WRITING; break;
	case 16:
		if (!prepare_write(c)) { op = "putw-skipped"; break; }
		op = "putw"; result = putw((int)next(), c->f);
		c->direction = WRITING; break;
	case 17:
		/* __fpurge discards buffered input and output alike. */
		op = variant & 1 ? "fpurge" : "__fpurge";
		result = variant & 1 ? fpurge(c->f) : (__fpurge(c->f), 0);
		c->can_unget = 0; break;
	case 18: case 19: case 20: {
		static const int whence[] = { SEEK_SET, SEEK_CUR, SEEK_END };
		int w = whence[below(3)];
		long offset = (long)below(2600) - (w == SEEK_SET ? 0 : 1300);
		if (variant & 1) { op = "fseeko"; result = fseeko(c->f, (off_t)offset, w); }
		else { op = "fseek"; result = fseek(c->f, offset, w); }
		data = (uint32_t)offset ^ (uint32_t)w << 24;
		/* A rejected seek leaves the stream in its previous direction:
		 * whether it separates input from output is the recorded
		 * input-then-output difference, not an engine property. */
		if (result == 0) c->direction = IDLE;
		c->can_unget = 0; break;
	}
	case 21:
		op = variant & 1 ? "fflush_unlocked" : "fflush";
		if (c->direction == READING) {
			if (c->backing != BACKING_FILE) { op = "ftello"; result = (long)ftello(c->f); break; }
			/* fflush of a seekable input stream is defined by POSIX: it
			 * discards read-ahead and seeks the descriptor. It is still an
			 * input stream for the direction rule. */
			result = variant & 1 ? fflush_unlocked(c->f) : fflush(c->f);
			c->can_unget = 0; break;
		}
		result = variant & 1 ? fflush_unlocked(c->f) : fflush(c->f);
		c->direction = IDLE; break;
	case 22: {
		fpos_t saved;
		op = "fgetpos+fsetpos";
		result = fgetpos(c->f, &saved);
		if (result == 0) result = fsetpos(c->f, &saved);
		if (result == 0) c->direction = IDLE;
		c->can_unget = 0; break;
	}
	case 23:
		/* rewind returns nothing; a failed seek (a pipe, or a cookie
		 * without a seek callback) reports only through errno, which is
		 * zero here, and does not separate input from output. */
		op = "rewind"; rewind(c->f); result = 0;
		if (errno == 0) c->direction = IDLE;
		c->can_unget = 0; break;
	case 24:
		op = variant & 1 ? "clearerr_unlocked" : "clearerr";
		if (variant & 1) clearerr_unlocked(c->f); else clearerr(c->f);
		break;
	case 25:
		op = "buffer-state";
		result = (long)__fbufsize(c->f) * 4 + (__flbf(c->f) != 0) * 2 + (__freadable(c->f) != 0);
		data = (uint32_t)__fwritable(c->f) | (uint32_t)__fsetlocking(c->f, FSETLOCKING_QUERY) << 4;
		break;
	case 26:
		op = variant & 1 ? "fileno_unlocked" : "fileno";
		result = (variant & 1 ? fileno_unlocked(c->f) : fileno(c->f)) >= 0; break;
	case 27:
		op = variant & 1 ? "ftello" : "ftell";
		result = variant & 1 ? (long)ftello(c->f) : ftell(c->f); break;
	case 28: {
		/* The lock is recursive: a held lock admits ftrylockfile. */
		op = "flockfile";
		flockfile(c->f);
		result = ftrylockfile(c->f);
		if (result == 0) funlockfile(c->f);
		funlockfile(c->f);
		break;
	}
	case 29:
		op = "_flushlbf";
		if (c->direction == READING && c->backing != BACKING_FILE) { result = feof(c->f); break; }
		_flushlbf(); result = 0; break;
	case 30:
		op = "__fseterr"; __fseterr(c->f); result = ferror(c->f); break;
	default:
		op = variant & 1 ? "ferror" : "feof";
		result = variant & 1 ? ferror(c->f) : feof(c->f);
		break;
	}
	observe(scenario, index, op, result, data, errno, c);
}

/* Returns the chosen buffering for the scenario header. */
static const char *configure_buffer(struct stream_case *c, char **own)
{
	static char description[32];
	*own = NULL;
	switch (below(9)) {
	case 0: CHECK(setvbuf(c->f, NULL, _IONBF, 0) == 0); return "unbuffered";
	case 1: CHECK(setvbuf(c->f, NULL, _IOLBF, 0) == 0); return "line";
	case 2: case 3: {
		size_t size = 1 + below(200);
		int line = below(2) == 0;
		*own = malloc(size);
		CHECK(*own && setvbuf(c->f, *own, line ? _IOLBF : _IOFBF, size) == 0);
		snprintf(description, sizeof description, "%s:%zu", line ? "line" : "full", size);
		return description;
	}
	case 4: setbuf(c->f, NULL); return "setbuf-null";
	case 5:
		*own = malloc(BUFSIZ);
		CHECK(*own);
		setbuf(c->f, *own);
		return "setbuf";
	case 6: {
		size_t size = 1 + below(300);
		*own = malloc(size);
		CHECK(*own);
		setbuffer(c->f, *own, size);
		snprintf(description, sizeof description, "setbuffer:%zu", size);
		return description;
	}
	case 7: setlinebuf(c->f); return "setlinebuf";
	default: return "default";
	}
}

static void run_steps(unsigned scenario, struct stream_case *c, unsigned minimum, unsigned spread)
{
	unsigned steps = minimum + below(spread);
	for (unsigned index = 0; index < steps; index++)
		byte_step(scenario, index, c);
}

static const char *const file_modes[] = { "r", "r+", "w", "w+", "a", "a+" };

static void set_mode(struct stream_case *c, const char *mode)
{
	c->readable = mode[0] == 'r' || mode[1] == '+';
	c->writable = mode[0] != 'r' || mode[1] == '+';
}

static size_t seed_file(const char *path)
{
	unsigned char initial[3000];
	size_t initial_size = below(3) == 0 ? 0 : below(sizeof initial);
	fill(initial, initial_size);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0 && write(fd, initial, initial_size) == (ssize_t)initial_size && !close(fd));
	return initial_size;
}

static void report_file(unsigned scenario, const char *path)
{
	int fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	ssize_t size = read(fd, big, sizeof big);
	CHECK(size >= 0 && !close(fd));
	report("final %u size=%zd hash=%08x\n", scenario, size, fnv(big, (size_t)size));
}

static void run_file_scenario(unsigned scenario, const char *path)
{
	size_t initial_size = seed_file(path);
	struct stream_case c = {0};
	const char *mode = file_modes[below(6)];
	unsigned origin = below(8);
	set_mode(&c, mode);
	if (origin == 0) {
		int flags = (c.readable && c.writable ? O_RDWR : c.writable ? O_WRONLY : O_RDONLY) |
			(mode[0] == 'a' ? O_APPEND : 0) | (mode[0] == 'w' ? O_TRUNC : 0);
		int fd = open(path, flags);
		CHECK(fd >= 0);
		if (below(2)) CHECK(lseek(fd, (off_t)below((unsigned)initial_size + 1), SEEK_SET) >= 0);
		c.f = fdopen(fd, mode);
	} else if (origin == 1) {
		c.f = tmpfile();
		CHECK(c.f);
		set_mode(&c, "w+");
		mode = "w+";
	} else {
		c.f = fopen(path, mode);
	}
	CHECK(c.f);
	c.fd = fileno(c.f);
	c.backing = BACKING_FILE;
	char *own;
	const char *buffering = configure_buffer(&c, &own);
	report("scenario %u %s %s %s initial=%zu\n", scenario,
		origin == 0 ? "fdopen" : origin == 1 ? "tmpfile" : "fopen", mode, buffering, initial_size);
	run_steps(scenario, &c, 10, 40);
	if (origin >= 2 && below(2)) {
		/* freopen the same stream, onto the same path or (with a null
		 * path) onto the same open file with a mode its access admits. */
		const char *again = file_modes[below(6)];
		int same = below(2);
		if (same) again = c.readable && c.writable ? (below(2) ? "r+" : "a+") : c.readable ? "r" : "a";
		errno = 0;
		FILE *reopened = freopen(same ? NULL : path, again, c.f);
		report("freopen %u %s %s r=%d e=%d\n", scenario, same ? "null" : "path", again,
			reopened == c.f, errno);
		if (!reopened) { free(own); report_file(scenario, path); return; }
		set_mode(&c, again);
		c.fd = fileno(c.f);
		c.direction = IDLE;
		c.can_unget = 0;
		run_steps(scenario, &c, 10, 30);
	}
	CHECK(fclose(c.f) == 0 || errno);
	free(own);
	if (origin != 1) report_file(scenario, path);
	else report("final %u tmpfile\n", scenario);
}

static void run_standard_scenario(unsigned scenario, const char *path, const char *input_path)
{
	struct stream_case c = {0};
	if (below(2)) {
		size_t initial = seed_file(input_path);
		CHECK(freopen(input_path, "r", stdin) == stdin);
		c.f = stdin;
		c.standard_in = 1;
		set_mode(&c, "r");
		report("scenario %u stdin initial=%zu\n", scenario, initial);
	} else {
		const char *mode = file_modes[2 + below(4)];
		seed_file(path);
		CHECK(freopen(path, mode, stdout) == stdout);
		c.f = stdout;
		c.standard_out = 1;
		set_mode(&c, mode);
		report("scenario %u stdout %s\n", scenario, mode);
	}
	c.fd = fileno(c.f);
	c.backing = BACKING_FILE;
	run_steps(scenario, &c, 20, 40);
	/* Leave the standard stream open on its file: the next reopen, or
	 * process exit, flushes it. */
	if (c.standard_out) {
		CHECK(fflush(stdout) == 0 || ferror(stdout));
		report_file(scenario, path);
	}
}

static void run_memory_scenario(unsigned scenario)
{
	struct stream_case c = {0};
	unsigned kind = below(3);
	char *own = NULL;
	if (kind == 0) {
		c.f = open_memstream(&c.memory, &c.memory_size);
		CHECK(c.f);
		c.writable = 1;
		c.backing = BACKING_MEMORY;
		report("scenario %u open_memstream\n", scenario);
	} else if (kind == 1) {
		const char *mode = file_modes[below(6)];
		c.fmem_size = 1 + below(3000);
		int owned = below(4) == 0;
		if (!owned) {
			CHECK((c.fmem = calloc(c.fmem_size + 1, 1)));
			fill(c.fmem, c.fmem_size);
		}
		c.f = fmemopen(c.fmem, c.fmem_size, mode);
		CHECK(c.f);
		set_mode(&c, mode);
		c.backing = BACKING_FMEM;
		const char *buffering = configure_buffer(&c, &own);
		report("scenario %u fmemopen %s size=%zu%s %s\n", scenario, mode, c.fmem_size,
			owned ? " null" : "", buffering);
	} else {
		static const char *const modes[] = { "r", "r+", "w", "w+", "a+" };
		const char *mode = modes[below(5)];
		CHECK((c.cookie = calloc(1, sizeof *c.cookie)));
		c.cookie->length = mode[0] == 'w' ? 0 : below(4000);
		fill(c.cookie->data, c.cookie->length);
		c.cookie->read_limit = 1 + below(below(2) ? 7 : 3000);
		c.cookie->write_limit = 1 + below(below(2) ? 7 : 3000);
		if (below(3) == 0) c.cookie->read_budget = 1 + below(8);
		if (below(3) == 0) c.cookie->write_budget = 1 + below(8);
		if (mode[0] == 'a') c.cookie->position = c.cookie->length;
		/* A missing callback makes that transfer or seek fail. */
		unsigned missing = below(8);
		cookie_io_functions_t functions = {
			missing == 0 ? NULL : cookie_read, missing == 1 ? NULL : cookie_write,
			missing == 2 ? NULL : cookie_seek, NULL,
		};
		c.f = fopencookie(c.cookie, mode, functions);
		CHECK(c.f);
		set_mode(&c, mode);
		c.backing = BACKING_COOKIE;
		const char *buffering = configure_buffer(&c, &own);
		report("scenario %u fopencookie %s read=%u/%u write=%u/%u missing=%u %s\n", scenario, mode,
			c.cookie->read_limit, c.cookie->read_budget, c.cookie->write_limit,
			c.cookie->write_budget, missing, buffering);
	}
	c.fd = -1;
	run_steps(scenario, &c, 20, 60);
	errno = 0;
	int closed = fclose(c.f);
	int close_error = errno;
	free(own);
	switch (c.backing) {
	case BACKING_MEMORY:
		report("final %u close=%d size=%zu hash=%08x\n", scenario, closed, c.memory_size,
			fnv(c.memory, c.memory_size));
		free(c.memory);
		break;
	case BACKING_FMEM:
		report("final %u close=%d/%d hash=%08x\n", scenario, closed, closed ? close_error : 0,
			c.fmem ? fnv(c.fmem, c.fmem_size + 1) : 0);
		free(c.fmem);
		break;
	default:
		report("final %u close=%d/%d length=%zu hash=%08x\n", scenario, closed,
			closed ? close_error : 0, c.cookie->length, fnv(c.cookie->data, c.cookie->length));
		free(c.cookie);
		break;
	}
}

static void run_pipe_scenario(unsigned scenario)
{
	int ends[2];
	struct stream_case c = {0};
	CHECK(!pipe(ends));
	c.peer = -1;
	if (below(2)) {
		/* A closed-writer pipe holding a fixed byte sequence. */
		size_t size = below(16384);
		fill(big, size);
		CHECK(write(ends[1], big, size) == (ssize_t)size && !close(ends[1]));
		c.f = fdopen(ends[0], "r");
		c.readable = 1;
		c.backing = BACKING_PIPE_READ;
		report("scenario %u pipe-read initial=%zu\n", scenario, size);
	} else {
		int broken = below(3) == 0;
		c.f = fdopen(ends[1], "w");
		c.writable = 1;
		c.backing = BACKING_PIPE_WRITE;
		if (broken) CHECK(!close(ends[0]));
		else c.peer = ends[0];
		report("scenario %u pipe-write%s\n", scenario, broken ? " broken" : "");
	}
	CHECK(c.f);
	c.fd = fileno(c.f);
	char *own;
	const char *buffering = configure_buffer(&c, &own);
	report("buffering %u %s\n", scenario, buffering);
	run_steps(scenario, &c, 20, 60);
	errno = 0;
	int closed = fclose(c.f);
	int close_error = errno;
	free(own);
	if (c.peer >= 0) {
		ssize_t got;
		while ((got = read(c.peer, big, sizeof big)) > 0) {
			c.drained_hash ^= fnv(big, (size_t)got) + (uint32_t)c.drained;
			c.drained += got;
		}
		CHECK(got == 0 && !close(c.peer));
	}
	report("final %u close=%d/%d drained=%ld hash=%08x\n", scenario, closed,
		closed ? close_error : 0, c.drained, c.drained_hash);
}

/*
 * A file whose writes fail part way: a lowered RLIMIT_FSIZE soft limit makes
 * a write that reaches it short and every later one fail with EFBIG
 * (SIGXFSZ is ignored). The limit is restored before the next scenario.
 */
static void run_limited_scenario(unsigned scenario, const char *path)
{
	struct stream_case c = {0};
	size_t initial = seed_file(path);
	struct rlimit saved, limited;
	CHECK(!getrlimit(RLIMIT_FSIZE, &saved));
	limited = saved;
	limited.rlim_cur = below(3200);
	const char *mode = file_modes[2 + below(4)];
	c.f = fopen(path, mode);
	CHECK(c.f);
	set_mode(&c, mode);
	c.fd = fileno(c.f);
	c.backing = BACKING_FILE;
	char *own;
	const char *buffering = configure_buffer(&c, &own);
	report("scenario %u limited %s %s initial=%zu limit=%lu\n", scenario, mode, buffering, initial,
		(unsigned long)limited.rlim_cur);
	CHECK(!setrlimit(RLIMIT_FSIZE, &limited));
	run_steps(scenario, &c, 10, 30);
	errno = 0;
	int closed = fclose(c.f);
	int close_error = errno;
	CHECK(!setrlimit(RLIMIT_FSIZE, &saved));
	report("final %u close=%d/%d\n", scenario, closed, closed ? close_error : 0);
	free(own);
	report_file(scenario, path);
}

static const wchar_t wide_samples[] = {
	L'a', L'z', L'\n', 0xe9, 0x20ac, 0x1f600, 0xdf80, 0xd800, 0x110000,
};
#define WIDE_SAMPLE_COUNT (sizeof wide_samples / sizeof wide_samples[0])

/* Wide streams: only wide operations after the first, and positioning only
 * to the start, the end, or a saved fpos_t. */
static void wide_step(unsigned scenario, unsigned index, struct stream_case *c, fpos_t *mark, int *marked)
{
	wchar_t text[256];
	long result = 0;
	uint32_t data = 0;
	const char *op;
	unsigned choice = below(16);
	unsigned variant = below(4);

	if (!c->readable && choice < 5) choice += 5;
	if (!c->writable && choice >= 5 && choice < 9) choice = below(5);
	errno = 0;
	switch (choice) {
	case 0: case 1:
		prepare_read(c);
		if (variant == 0) { op = "fgetwc"; result = (long)fgetwc(c->f); }
		else if (variant == 1) { op = "getwc"; result = (long)getwc(c->f); }
		else if (variant == 2) { op = "fgetwc_unlocked"; result = (long)fgetwc_unlocked(c->f); }
		else { op = "__fgetwc_unlocked"; result = (long)__fgetwc_unlocked(c->f); }
		c->direction = READING; c->can_unget = result != (long)WEOF; break;
	case 2: {
		int size = 1 + (int)below(40);
		prepare_read(c);
		op = "fgetws";
		wchar_t *got = fgetws(text, size, c->f);
		result = got ? (long)wcslen(text) : -1;
		data = got ? fnv(text, (size_t)result * sizeof *text) : 0;
		c->direction = READING; c->can_unget = got != NULL; break;
	}
	case 3:
		if (!c->can_unget) { op = "fwide"; result = fwide(c->f, 0); break; }
		op = "ungetwc"; result = (long)ungetwc(wide_samples[below(6)], c->f);
		c->can_unget = 0; break;
	case 4: {
		prepare_read(c);
		op = "fwscanf";
		wchar_t word[32];
		int count = 0;
		result = fwscanf(c->f, L"%31l[a-z]%n", word, &count);
		data = result == 1 ? fnv(word, wcslen(word) * sizeof *word) ^ (uint32_t)count : 0;
		c->direction = READING; c->can_unget = 0; break;
	}
	case 5: case 6: {
		wchar_t character = wide_samples[below(WIDE_SAMPLE_COUNT)];
		if (!prepare_write(c)) { op = "fputwc-skipped"; break; }
		if (variant == 0) { op = "fputwc"; result = (long)fputwc(character, c->f); }
		else if (variant == 1) { op = "putwc"; result = (long)putwc(character, c->f); }
		else if (variant == 2) { op = "fputwc_unlocked"; result = (long)fputwc_unlocked(character, c->f); }
		else { op = "__fputwc_unlocked"; result = (long)__fputwc_unlocked(character, c->f); }
		data = (uint32_t)character;
		c->direction = WRITING; break;
	}
	case 7: {
		size_t size = below(40);
		for (size_t at = 0; at < size; at++) text[at] = wide_samples[below(6)];
		text[size] = 0;
		if (!prepare_write(c)) { op = "fputws-skipped"; break; }
		op = "fputws"; result = fputws(text, c->f);
		data = fnv(text, size * sizeof *text);
		c->direction = WRITING; break;
	}
	case 8:
		if (!prepare_write(c)) { op = "fwprintf-skipped"; break; }
		op = "fwprintf"; result = fwprintf(c->f, L"<%u:%lc>", index, (wint_t)wide_samples[below(6)]);
		c->direction = WRITING; break;
	case 9:
		op = "fgetpos";
		result = fgetpos(c->f, mark);
		*marked = result == 0;
		break;
	case 10:
		if (!*marked) {
			op = "rewind"; rewind(c->f); result = 0;
			if (errno == 0) c->direction = IDLE;
			c->can_unget = 0; break;
		}
		op = "fsetpos"; result = fsetpos(c->f, mark);
		if (result == 0) c->direction = IDLE;
		c->can_unget = 0; break;
	case 11:
		op = "fseek-end"; result = fseek(c->f, 0, SEEK_END);
		if (result == 0) c->direction = IDLE;
		c->can_unget = 0; break;
	case 12:
		op = "fflush";
		if (c->direction == READING) { result = fwide(c->f, 0); break; }
		result = fflush(c->f); c->direction = IDLE; break;
	case 13:
		op = "fwide"; result = fwide(c->f, variant ? 1 : -1); break;
	default:
		op = "ftell"; result = ftell(c->f); break;
	}
	observe(scenario, index, op, result, data, errno, c);
}

static void run_wide_scenario(unsigned scenario, const char *path)
{
	struct stream_case c = {0};
	fpos_t mark;
	int marked = 0;
	int utf8 = below(3) != 0;
	CHECK(setlocale(LC_CTYPE, utf8 ? "C.UTF-8" : "C"));
	if (below(5) == 0) {
		c.f = open_wmemstream((wchar_t **)&c.memory, &c.memory_size);
		CHECK(c.f);
		c.writable = 1;
		c.backing = BACKING_MEMORY;
		c.fd = -1;
		report("scenario %u open_wmemstream %s\n", scenario, utf8 ? "C.UTF-8" : "C");
	} else {
		size_t size = fill_utf8(big, 3000);
		int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
		CHECK(fd >= 0 && write(fd, big, size) == (ssize_t)size && !close(fd));
		const char *mode = file_modes[below(6)];
		c.f = fopen(path, mode);
		CHECK(c.f);
		set_mode(&c, mode);
		c.fd = fileno(c.f);
		c.backing = BACKING_FILE;
		report("scenario %u wide %s %s initial=%zu\n", scenario, mode, utf8 ? "C.UTF-8" : "C", size);
	}
	errno = 0;
	int orientation = fwide(c.f, 1);
	report("fwide %u %d\n", scenario, orientation);
	unsigned steps = 20 + below(60);
	for (unsigned index = 0; index < steps; index++)
		wide_step(scenario, index, &c, &mark, &marked);
	CHECK(fclose(c.f) == 0 || errno);
	if (c.backing == BACKING_MEMORY) {
		report("final %u wsize=%zu hash=%08x\n", scenario, c.memory_size,
			fnv(c.memory, c.memory_size * sizeof(wchar_t)));
		free(c.memory);
	} else {
		report_file(scenario, path);
	}
	CHECK(setlocale(LC_CTYPE, "C"));
}

/*
 * Two threads contend for one stream. Every line must arrive whole (each
 * fputs holds the stream lock), and ftrylockfile must fail while another
 * thread holds the lock and succeed once it is released.
 */
struct contention { FILE *f; int id, lines, attempt; };

static void *contend(void *opaque)
{
	struct contention *c = opaque;
	char line[64];
	for (int index = 0; index < c->lines; index++) {
		snprintf(line, sizeof line, "thread %d line %04d %s\n", c->id, index,
			"abcdefghijklmnopqrstuvwxyz" + index % 26);
		if (fputs(line, c->f) < 0) return (void *)1;
	}
	return NULL;
}

static void *try_lock(void *opaque)
{
	struct contention *c = opaque;
	c->attempt = ftrylockfile(c->f) == 0;
	if (c->attempt) funlockfile(c->f);
	return NULL;
}

static void run_thread_scenario(unsigned scenario, const char *path)
{
	FILE *f = fopen(path, "w+");
	CHECK(f);
	if (below(2)) CHECK(!setvbuf(f, NULL, _IOLBF, 0));
	struct contention first = { f, 1, 300 + (int)below(300), 0 };
	struct contention second = { f, 2, 300 + (int)below(300), 0 };
	pthread_t one, two;
	CHECK(!pthread_create(&one, NULL, contend, &first));
	CHECK(!pthread_create(&two, NULL, contend, &second));
	void *first_status, *second_status;
	CHECK(!pthread_join(one, &first_status) && !pthread_join(two, &second_status));
	CHECK(!first_status && !second_status && fflush(f) == 0);

	/* The trying thread runs, and is joined, while this thread holds the
	 * stream lock; then again after it is released. */
	struct contention trier = { f, 3, 0, 0 };
	flockfile(f);
	CHECK(!pthread_create(&one, NULL, try_lock, &trier));
	CHECK(!pthread_join(one, NULL));
	int held_attempt = trier.attempt;
	funlockfile(f);
	CHECK(!pthread_create(&one, NULL, try_lock, &trier));
	CHECK(!pthread_join(one, NULL));
	int free_attempt = trier.attempt;

	rewind(f);
	char line[128];
	int counts[3] = {0}, whole = 1;
	while (fgets(line, sizeof line, f)) {
		int id, number;
		char tail[64];
		if (sscanf(line, "thread %d line %d %63s", &id, &number, tail) != 3 || id < 1 || id > 2 ||
			number != counts[id] || strcmp(tail, "abcdefghijklmnopqrstuvwxyz" + number % 26)) {
			whole = 0;
			break;
		}
		counts[id]++;
	}
	CHECK(!fclose(f));
	report("scenario %u threads lines=%d/%d whole=%d try-held=%d try-free=%d\n", scenario,
		counts[1] == first.lines, counts[2] == second.lines, whole, held_attempt, free_attempt);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2);
	report_fd = dup(1);
	CHECK(report_fd > 2);
	/* Writes to a pipe without readers must fail with EPIPE, and writes
	 * past the file-size limit with EFBIG, rather than kill. */
	CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR && signal(SIGXFSZ, SIG_IGN) != SIG_ERR);
	char input_path[4096];
	CHECK(snprintf(input_path, sizeof input_path, "%s.in", argv[1]) < (int)sizeof input_path);
	state = MODEL_SEED;
	for (unsigned scenario = 0; scenario < MODEL_SCENARIOS; scenario++) {
		switch (scenario % 16) {
		case 3: run_limited_scenario(scenario, argv[1]); break;
		case 5: case 13: run_pipe_scenario(scenario); break;
		case 6: case 14: run_wide_scenario(scenario, argv[1]); break;
		case 7: case 15: run_memory_scenario(scenario); break;
		case 9: run_standard_scenario(scenario, argv[1], input_path); break;
		case 11:
			if (scenario % 64 == 11) { run_thread_scenario(scenario, argv[1]); break; }
			run_file_scenario(scenario, argv[1]); break;
		default: run_file_scenario(scenario, argv[1]); break;
		}
#ifdef MODEL_TRACE
		emit(trace, (int)trace_length);
		trace_length = 0;
#endif
		announce("scenario %u lines=%u digest=%08x\n", scenario, digest_lines, digest);
		digest = UINT32_C(2166136261);
		digest_lines = 0;
	}
	/* stdout may still name the scratch file, if a scenario reopened it;
	 * exit then flushes it into the unlinked file. */
	CHECK(unlink(argv[1]) == 0);
	unlink(input_path);
	return 0;
}
