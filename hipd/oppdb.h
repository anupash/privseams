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

#include <sys/socket.h>
#include <sys/un.h>
#include "libhipcore/debug.h"
#include "libhipcore/misc.h"
#include "hidb.h"
#include "libhipcore/hashtable.h"
#include "libhipcore/builder.h"
#include "libhiptool/lutil.h"
#include "libhipcore/utils.h"
#include "oppipdb.h"

struct hip_opp_blocking_request_entry
{
	hip_hit_t             peer_phit;
	struct sockaddr_in6   caller;
	hip_hit_t             our_real_hit;
	//hip_hit_t             peer_real_hit;
	//spinlock_t           	lock;
	//atomic_t             	refcnt;
	
	time_t                creation_time;
    struct in6_addr       peer_ip;
    struct in6_addr       our_ip;  
    uint8_t               proxy_flag; //0: normal connection, 1: connection through proxy
  
};

typedef struct hip_opp_blocking_request_entry hip_opp_block_t;

void hip_init_opp_db(void);
//void hip_uninit_opp_db();
int hip_opptcp_send_tcp_packet(struct hip_common *msg, const struct sockaddr_in6 *src);
int hip_opptcp_unblock_and_blacklist(struct hip_common *msg, const struct sockaddr_in6 *src);
int hip_handle_opp_fallback(hip_opp_block_t *entry,
			    void *current_time);
hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *phit, struct sockaddr_in6 *src);
hip_opp_block_t *hip_oppdb_find_by_ip(const struct in6_addr *ip_peer);
hip_ha_t *hip_get_opp_hadb_entry(hip_hit_t *resp_hit,
				 struct in6_addr *resp_addr);
int hip_oppdb_del_entry(const hip_hit_t *phit, const struct sockaddr_in6 *src);
void hip_oppdb_uninit(void);
int hip_oppdb_entry_clean_up(hip_opp_block_t *opp_entry);

int hip_opp_get_peer_hit(struct hip_common *msg,
			 const struct sockaddr_in6 *src);
hip_ha_t * hip_opp_add_map(const struct in6_addr *dst_ip,
			   const struct in6_addr *hit_our,
			   const struct sockaddr_in6 *caller);

hip_ha_t *hip_oppdb_get_hadb_entry_i1_r1(struct hip_common *msg,
					 struct in6_addr *src_addr,
					 struct in6_addr *dst_addr,
					 hip_portpair_t *msg_info);
int hip_for_each_opp(int (*func)(hip_opp_block_t *entry, void *opaq),
		     void *opaque);

int hip_handle_opp_reject(hip_opp_block_t *entry, void *ips);
#endif /* HIP_HADB_H */
