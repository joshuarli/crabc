#ifndef _NET_IF_H
#define _NET_IF_H

#define IF_NAMESIZE 16

struct if_nameindex {
    unsigned if_index;
    char *if_name;
};

void if_freenameindex(struct if_nameindex *);
char *if_indextoname(unsigned, char *);
struct if_nameindex *if_nameindex(void);
unsigned if_nametoindex(const char *);

#endif
