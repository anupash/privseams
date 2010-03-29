#ifndef _INET_FNS_H
#define _INET_FNS_H

/* Get address of local machine */
uint32_t get_local_addr_eth(void);
uint32_t name_to_addr(const char *);
uint32_t get_local_addr_uname(void);
uint32_t get_local_addr(void);

#endif
