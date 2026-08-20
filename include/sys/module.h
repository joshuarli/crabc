#ifndef _SYS_MODULE_H
#define _SYS_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

int init_module(void *, unsigned long, const char *);
int delete_module(const char *, unsigned int);

#ifdef __cplusplus
}
#endif

#endif
