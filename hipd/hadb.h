/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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

#include <stdint.h>

#include "lib/core/hashtable.h"
#include "lib/core/protodefs.h"
#include "lib/core/state.h"


/* For switch userspace / kernel IPsec */
extern int hip_use_userspace_ipsec;

extern HIP_HASHTABLE *hadb_hit;

void hip_hadb_hold_entry(void *entry);

/*************** BASE FUNCTIONS *******************/

/* Matching */
static inline int hip_hadb_match_spi(const void *key_1, const void *key_2)
{
    return *(const uint32_t *) key_1 == *(const uint32_t *) key_2;
}

int hip_ha_compare(const struct hip_hadb_state *ha1,
                   const struct hip_hadb_state *ha2);

void hip_init_hadb(void);
void hip_uninit_hadb(void);

void hip_delete_all_sp(void);

/* Initialization functions */

/* Accessors */
struct hip_hadb_state *hip_hadb_find_byhits(const hip_hit_t *hit,
                                            const hip_hit_t *hit2);
struct hip_hadb_state *hip_hadb_try_to_find_by_peer_hit(const hip_hit_t *hit);

/* insert/create/delete */
int hip_hadb_insert_state(struct hip_hadb_state *ha);
void hip_delete_security_associations_and_sp(struct hip_hadb_state *ha);
int hip_init_peer(struct hip_hadb_state *entry, const struct hip_host_id *peer);
int hip_init_us(struct hip_hadb_state *entry, hip_hit_t *hit_our);


/*************** CONSTRUCTS ********************/
int hip_hadb_get_peer_addr(struct hip_hadb_state *entry, struct in6_addr *addr);

int hip_hadb_add_peer_addr(struct hip_hadb_state *entry,
                           const struct in6_addr *new_addr,
                           uint32_t interface_id, uint32_t lifetime,
                           int state, in_port_t port);

int hip_add_peer_map(const struct hip_common *input);

int hip_hadb_add_peer_info(const hip_hit_t *peer_hit,
                           const struct in6_addr *peer_addr,
                           const hip_lsi_t *peer_lsi,
                           const char *peer_hostname);

int hip_hadb_add_peer_info_complete(const hip_hit_t *local_hit,
                                    const hip_hit_t *peer_hit,
                                    const hip_lsi_t *peer_lsi,
                                    const struct in6_addr *local_addr,
                                    const struct in6_addr *peer_addr,
                                    const char *peer_hostname);

int hip_del_peer_info_entry(struct hip_hadb_state *ha);
int hip_del_peer_info(hip_hit_t *, hip_hit_t *);


/* Utilities */

struct hip_hadb_state *hip_hadb_create_state(void);

int hip_for_each_ha(int(func) (struct hip_hadb_state *entry, void *opaq),
                    void *opaque);

/* next 2 functions are not called from outside but make sense and are
 * 'proposed' in libhipcore/state.h
 */

void hip_hadb_set_local_controls(struct hip_hadb_state *entry,
                                 hip_controls mask);
void hip_hadb_set_peer_controls(struct hip_hadb_state *entry,
                                hip_controls mask);
void hip_hadb_cancel_local_controls(struct hip_hadb_state *entry,
                                    hip_controls mask);

int hip_count_open_connections(void);

struct hip_hadb_state *hip_hadb_find_rvs_candidate_entry(const hip_hit_t *,
                                                         const hip_hit_t *);

int hip_handle_get_ha_info(struct hip_hadb_state *entry, void *);

/*lsi support functions*/
int hip_generate_peer_lsi(hip_lsi_t *lsi);
struct hip_hadb_state *hip_hadb_try_to_find_by_peer_lsi(const hip_lsi_t *lsi);
struct hip_hadb_state *hip_hadb_try_to_find_by_pair_lsi(hip_lsi_t *lsi_src,
                                                        hip_lsi_t *lsi_dst);

int hip_recreate_security_associations_and_sp(struct hip_hadb_state *ha,
                                              struct in6_addr *src_addr,
                                              struct in6_addr *dst_addr);

#endif /* HIP_HIPD_HADB_H */
