#ifndef HIP_FIREWALL_CACHE_H
#define HIP_FIREWALL_CACHE_H

#include "lib/core/icomm.h"

int hip_firewall_cache_db_match(const struct in6_addr *, const struct in6_addr *,
                                hip_lsi_t *, hip_lsi_t *,
                                struct in6_addr *, struct in6_addr *, int *);

//Initializes the firewall cache database
void hip_firewall_cache_init_hldb(void);

firewall_cache_hl_t *hip_cache_create_hl_entry(void);

//unsigned long hip_firewall_cache_hash_ip_peer(const void *ptr);

//int hip_firewall_cache_match_ip_peer(const void *ptr1, const void *ptr2);

void hip_firewall_cache_delete_hldb(void);



#endif /* HIP_FIREWALL_CACHE_H */
