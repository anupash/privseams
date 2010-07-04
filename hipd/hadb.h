/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIP_HIPD_HADB_H
#define HIP_HIPD_HADB_H

#include "config.h"
#include "keymat.h"
#include "lib/tool/pk.h"
#include "lib/core/debug.h"

#include "hidb.h"
#include "lib/core/hashtable.h"
#include "lib/core/state.h"
#include "lib/core/builder.h"
#include "lib/core/straddr.h"
#include "input.h"      // required for declaration of receive functions
#include "user_ipsec_sadb_api.h"
#include "lib/tool/xfrmapi.h"
#include "nat.h"
#include "hadb_legacy.h"

#define HIP_LOCK_INIT(ha)
#define HIP_LOCK_HA(ha)
#define HIP_UNLOCK_HA(ha)

#define do_gettimeofday(x) gettimeofday(x, NULL)

/* For switch userspace / kernel IPsec */
extern int hip_use_userspace_ipsec;

extern hip_xmit_func_set_t nat_xmit_func_set;

void hip_hadb_hold_entry(void *entry);

/*************** BASE FUNCTIONS *******************/

/* Matching */
static inline int hip_hadb_match_spi(const void *key_1, const void *key_2)
{
    return *(const uint32_t *) key_1 == *(const uint32_t *) key_2;
}

int hip_ha_compare(const hip_ha_t *ha1, const hip_ha_t *ha2);

void hip_init_hadb(void);
void hip_uninit_hadb(void);

void hip_delete_all_sp(void);

/* Initialization functions */

/* Accessors */
hip_ha_t *hip_hadb_find_byhits(const hip_hit_t *hit, const hip_hit_t *hit2);
hip_ha_t *hip_hadb_try_to_find_by_peer_hit(const hip_hit_t *hit);

/* insert/create/delete */
int hip_hadb_insert_state(hip_ha_t *ha);
void hip_delete_security_associations_and_sp(struct hip_hadb_state *ha);
int hip_init_peer(hip_ha_t *entry, struct hip_host_id *peer);
int hip_init_us(hip_ha_t *entry, hip_hit_t *hit_our);


/*************** CONSTRUCTS ********************/
int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr);

int hip_hadb_add_peer_addr(hip_ha_t *entry, const struct in6_addr *new_addr,
                           uint32_t interface_id, uint32_t lifetime,
                           int state, in_port_t port);

int hip_add_peer_map(const struct hip_common *input);

int hip_hadb_add_peer_info(hip_hit_t *hit,
                           struct in6_addr *addr,
                           hip_lsi_t *peer_lsi,
                           const char *peer_hostname);

int hip_hadb_add_peer_info_complete(const hip_hit_t *local_hit,
                                    const hip_hit_t *peer_hit,
                                    const hip_lsi_t *peer_lsi,
                                    const struct in6_addr *local_addr,
                                    const struct in6_addr *peer_addr,
                                    const char *peer_hostname);

int hip_del_peer_info_entry(hip_ha_t *ha);
int hip_del_peer_info(hip_hit_t *, hip_hit_t *);


/* Utilities */

hip_ha_t *hip_hadb_create_state(void);

int hip_for_each_ha(int(func) (hip_ha_t * entry, void *opaq), void *opaque);

/* next 2 functions are not called from outside but make sense and are
 * 'proposed' in libhipcore/state.h
 */

void hip_hadb_set_local_controls(hip_ha_t *entry, hip_controls_t mask);
void hip_hadb_set_peer_controls(hip_ha_t *entry, hip_controls_t mask);
void hip_hadb_cancel_local_controls(hip_ha_t *entry, hip_controls_t mask);

int hip_count_open_connections(void);

hip_ha_t *hip_hadb_find_rvs_candidate_entry(hip_hit_t *, hip_hit_t *);

int hip_handle_get_ha_info(hip_ha_t *entry, void *);

/*lsi support functions*/
int hip_generate_peer_lsi(hip_lsi_t *lsi);
hip_ha_t *hip_hadb_try_to_find_by_peer_lsi(hip_lsi_t *lsi);
hip_ha_t *hip_hadb_try_to_find_by_pair_lsi(hip_lsi_t *lsi_src, hip_lsi_t *lsi_dst);

int hip_recreate_security_associations_and_sp(struct hip_hadb_state *ha,
                                              in6_addr_t *src_addr,
                                              in6_addr_t *dst_addr);

#endif /* HIP_HIPD_HADB_H */
