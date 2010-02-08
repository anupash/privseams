/** @file
 * oppipdb.h: A header file for oppipdb.c
 *
 * @author  Antti Partanen
 * @author  Alberto Garcia
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#ifndef HIP_OPPIPDB_H
#define HIP_OPPIPDB_H

#include "lib/core/debug.h"
#include "hidb.h"
#include "lib/core/hashtable.h"

typedef struct in6_addr hip_oppip_t;

int hip_for_each_oppip(void (*func)(hip_oppip_t *entry, void *opaq), void *opaque);
void hip_oppipdb_del_entry_by_entry(hip_oppip_t *entry);
int hip_oppipdb_add_entry(const struct in6_addr *ip_peer);
int hip_init_oppip_db(void);
hip_oppip_t *hip_oppipdb_find_byip(const struct in6_addr *ip_peer);
void hip_oppipdb_delentry(const struct in6_addr *ip_peer);
void hip_oppipdb_uninit(void);

#endif /* HIP_OPPIPDB_H */



