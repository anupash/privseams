#ifndef HIP_AGENT_TOOLS_H
#define HIP_AGENT_TOOLS_H
/*
 *  HIP Agent
 *
 *  License: GNU/GPL
 *  Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#include <netinet/in.h>

void agent_exit(void);

void print_hit_to_buffer(char *, struct in6_addr *);
int read_hit_from_buffer(struct in6_addr *, char *);

int config_read(const char *);

#endif
