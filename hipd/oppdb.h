/*
 * hipd oppdb.h
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */

#ifndef HIP_OPPDB_H
#define HIP_OPPDB_H

#include "debug.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"
#include "builder.h"

#define HIP_LOCK_OPP_INIT(entry)
#define HIP_UNLOCK_OPP_INIT(entry)
#define HIP_LOCK_OPP(entry)  
#define HIP_UNLOCK_OPP(entry)
#define HIP_OPPDB_SIZE 533

typedef struct hip_opp_blocking_request_entry hip_opp_block_t;

void hip_init_opp_db();
//void hip_uninit_opp_db();
hip_opp_block_t *hip_create_opp_block_entry();
void hip_oppdb_dump();
hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *hit_peer, const hip_hit_t *hit_our);
int hip_oppdb_add_entry(const hip_hit_t *hit_peer, const hip_hit_t *hit_our,
			const struct sockaddr_un *caller);
int hip_oppdb_del_entry(const hip_hit_t *hit_peer, const hip_hit_t *hit_our);
void hip_oppdb_del_entry_by_entry(hip_opp_block_t *entry);

#endif /* HIP_HADB_H */
