/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_CACHE_H
#define HIP_FIREWALL_CACHE_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"
#include "lib/core/icomm.h"

typedef struct hip_hadb_user_info_state fw_cache_hl_t;

typedef enum { FW_CACHE_HIT, FW_CACHE_LSI, FW_CACHE_IP } fw_cache_query_type_t;

fw_cache_hl_t *hip_firewall_cache_db_match(const void *local,
                                           const void *peer,
                                           fw_cache_query_type_t type,
                                           int query_daemon);

void hip_firewall_cache_db_del_entry(const void *local, const void *peer,
                                     fw_cache_query_type_t type);

void hip_firewall_cache_init_hldb(void);

fw_cache_hl_t *hip_cache_create_hl_entry(void);

void hip_firewall_cache_delete_hldb(int);

int hip_firewall_cache_set_bex_state(const struct in6_addr *hit_s,
                                     const struct in6_addr *hit_r,
                                     int state);

int hip_firewall_cache_update_entry(const struct in6_addr *ip_our,
                                    const struct in6_addr *ip_peer,
                                    const struct in6_addr *hit_our,
                                    const struct in6_addr *hit_peer,
                                    int state);

#endif /* HIP_FIREWALL_CACHE_H */
