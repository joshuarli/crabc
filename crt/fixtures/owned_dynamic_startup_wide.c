/* One source for every image of the installed dynamic startup "wide" graph.
 *
 * The graph is deliberately larger than any small fixed loader table: the
 * executable names WIDE_FANOUT direct libraries plus a hub, the hub names
 * WIDE_FANOUT more, and a runtime plugin names WIDE_FANOUT of its own, so
 * the initial graph holds 43 images. The executable, the hub and the plugin
 * each carry WIDE_CALLBACKS constructors and destructors. Pinned musl 1.2.6
 * has no such bound, so the candidate must reproduce its exact construction
 * order, finalization order, symbol binding and exit status.
 *
 * Roles: WIDE_LEAF with WIDE_ID and the WIDE_GROUP token (w: executable
 * dependency, d: hub dependency, p: plugin dependency); WIDE_HUB;
 * WIDE_PLUGIN; otherwise the executable.
 * Every marker is written unbuffered so stdio finalization cannot reorder it.
 */
#include <unistd.h>

#define WIDE_FANOUT 20
#define WIDE_CALLBACKS 24

static void mark(char role, char value)
{
	char text[2] = { role, value };
	(void)write(1, text, 2);
}

#define WIDE_CALLBACK_PAIR(role, index) \
	__attribute__((constructor)) static void construct_##index(void) { mark(role, 'A' + index); } \
	__attribute__((destructor)) static void destruct_##index(void) { mark(role, 'a' + index); }
#define WIDE_CALLBACK_ARRAYS(role) \
	WIDE_CALLBACK_PAIR(role, 0) WIDE_CALLBACK_PAIR(role, 1) WIDE_CALLBACK_PAIR(role, 2) \
	WIDE_CALLBACK_PAIR(role, 3) WIDE_CALLBACK_PAIR(role, 4) WIDE_CALLBACK_PAIR(role, 5) \
	WIDE_CALLBACK_PAIR(role, 6) WIDE_CALLBACK_PAIR(role, 7) WIDE_CALLBACK_PAIR(role, 8) \
	WIDE_CALLBACK_PAIR(role, 9) WIDE_CALLBACK_PAIR(role, 10) WIDE_CALLBACK_PAIR(role, 11) \
	WIDE_CALLBACK_PAIR(role, 12) WIDE_CALLBACK_PAIR(role, 13) WIDE_CALLBACK_PAIR(role, 14) \
	WIDE_CALLBACK_PAIR(role, 15) WIDE_CALLBACK_PAIR(role, 16) WIDE_CALLBACK_PAIR(role, 17) \
	WIDE_CALLBACK_PAIR(role, 18) WIDE_CALLBACK_PAIR(role, 19) WIDE_CALLBACK_PAIR(role, 20) \
	WIDE_CALLBACK_PAIR(role, 21) WIDE_CALLBACK_PAIR(role, 22) WIDE_CALLBACK_PAIR(role, 23)

#define WIDE_NAME_(group, id) wide_##group##_##id##_value
#define WIDE_NAME(group, id) WIDE_NAME_(group, id)
#define WIDE_TEXT_(token) #token
#define WIDE_TEXT(token) WIDE_TEXT_(token)
#define WIDE_EACH(apply) \
	apply(1) apply(2) apply(3) apply(4) apply(5) apply(6) apply(7) apply(8) apply(9) apply(10) \
	apply(11) apply(12) apply(13) apply(14) apply(15) apply(16) apply(17) apply(18) apply(19) apply(20)

#if defined(WIDE_LEAF)
/* A leaf reports its own construction and finalization once. Its value is a
 * dynamic TLS variable, so the initial graph carries more than 32 initial
 * TLS modules and the plugin's leaves add runtime modules. */
static __thread volatile int value = WIDE_ID;
__attribute__((constructor)) static void construct(void) { mark(WIDE_TEXT(WIDE_GROUP)[0], 'A' + WIDE_ID); }
__attribute__((destructor)) static void destruct(void) { mark(WIDE_TEXT(WIDE_GROUP)[0], 'a' + WIDE_ID); }
int WIDE_NAME(WIDE_GROUP, WIDE_ID)(void) { return value; }

#elif defined(WIDE_HUB)
#define WIDE_DECLARE(id) int wide_d_##id##_value(void);
#define WIDE_SUM(id) + wide_d_##id##_value()
WIDE_EACH(WIDE_DECLARE)
WIDE_CALLBACK_ARRAYS('H')
int wide_hub_value(void) { return 1000 WIDE_EACH(WIDE_SUM); }

#elif defined(WIDE_PLUGIN)
#define WIDE_DECLARE(id) int wide_p_##id##_value(void);
#define WIDE_SUM(id) + wide_p_##id##_value()
WIDE_EACH(WIDE_DECLARE)
WIDE_CALLBACK_ARRAYS('Q')
int wide_plugin_value(void) { return 2000 WIDE_EACH(WIDE_SUM); }

#else
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

#define WIDE_DECLARE(id) int wide_w_##id##_value(void);
#define WIDE_SUM(id) + wide_w_##id##_value()
WIDE_EACH(WIDE_DECLARE)
int wide_hub_value(void);
WIDE_CALLBACK_ARRAYS('M')

static int (*plugin_value)(void);

/* A worker gets its own copy of every initial and runtime TLS module. */
static void *worker(void *unused)
{
	(void)unused;
	return (void *)(long)(wide_hub_value() WIDE_EACH(WIDE_SUM) + plugin_value());
}

int main(void)
{
	int initial = wide_hub_value() WIDE_EACH(WIDE_SUM);
	void *plugin = dlopen("libowned-startup-wide-plugin.so", RTLD_NOW);
	if (!plugin) return 40;
	plugin_value = (int (*)(void))dlsym(plugin, "wide_plugin_value");
	if (!plugin_value) return 41;
	pthread_t thread;
	void *result;
	if (pthread_create(&thread, 0, worker, 0) || pthread_join(thread, &result)) return 42;
	char text[48];
	int length = snprintf(text, sizeof text, "|%d,%d,%ld|", initial, plugin_value(), (long)result);
	(void)write(1, text, (size_t)length);
	return 7;
}
#endif
