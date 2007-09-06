/*
 * hipd oppdb.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */

#ifdef CONFIG_HIP_OPPORTUNISTIC

#include "oppdb.h"

HIP_HASHTABLE *oppdb;
//static hip_list_t oppdb_list[HIP_OPPDB_SIZE]= { 0 };
extern unsigned int opportunistic_mode;

unsigned long hip_oppdb_hash_hit(const void *ptr)
{
	hip_opp_block_t *entry = (hip_opp_block_t *)ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, &entry->our_real_hit, sizeof(hip_hit_t) * 2, hash);

	return *((unsigned long *)hash);
}

int hip_oppdb_match_hit(const void *ptr1, const void *ptr2)
{
	return (hip_hash_hit(ptr1) != hip_hash_hit(ptr2));
}

int hip_oppdb_entry_clean_up(hip_opp_block_t *opp_entry)
{
	hip_ha_t *hadb_entry;
	int err = 0;

	/* XX FIXME: this does not support multiple multiple opp
	   connections: a better solution might be trash collection  */

	HIP_ASSERT(opp_entry);
	err = hip_del_peer_info(&opp_entry->peer_real_hit,
				&opp_entry->our_real_hit,
				&opp_entry->peer_ip);
	HIP_DEBUG("Del peer info returned %d\n", err);
	hip_oppdb_del_entry_by_entry(opp_entry);
	return err;
}

int hip_for_each_opp(int (*func)(hip_opp_block_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_opp_block_t *this;
	hip_list_t *item, *tmp;
	
	if (!func) return -EINVAL;
	
	HIP_LOCK_HT(&opp_db);
	list_for_each_safe(item, tmp, oppdb, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("List_for_each_entry_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		//hip_db_put_ha(this, hip_oppdb_del_entry_by_entry);
		if (fail) break;
	}
	HIP_UNLOCK_HT(&opp_db);
	return fail;
}

#if 0
inline void hip_oppdb_hold_entry(void *entry)
{
  	HIP_DB_HOLD_ENTRY(entry, struct hip_opp_blocking_request_entry);
}

inline void hip_oppdb_put_entry(void *entry)
{  	
	HIP_DB_PUT_ENTRY(entry, struct hip_opp_blocking_request_entry,
			 hip_oppdb_del_entry_by_entry);
}

inline void *hip_oppdb_get_key(void *entry)
{
	return &(((hip_opp_block_t *)entry)->hash_key);
}
#endif

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_oppdb_del_entry_by_entry(hip_opp_block_t *entry)
{
	HIP_DEBUG_HIT("peer_real_hit", &entry->peer_real_hit);
	_HIP_HEXDUMP("caller", &entry->caller, sizeof(struct sockaddr_un));
	
	HIP_LOCK_OPP(entry);
	hip_ht_delete(oppdb, entry);
	HIP_UNLOCK_OPP(entry);
	//HIP_FREE(entry);
}

int hip_oppdb_uninit_wrap(hip_opp_block_t *entry, void *unused)
{
	hip_oppdb_del_entry_by_entry(entry);
	return 0;
}

void hip_oppdb_uninit()
{
	hip_for_each_opp(hip_oppdb_uninit_wrap, NULL);
}

hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *hit_peer, const hip_hit_t *hit_our)
{
	hip_opp_block_t entry;
	ipv6_addr_copy(&entry.peer_real_hit, hit_peer);
	ipv6_addr_copy(&entry.our_real_hit, hit_our);
	HIP_HEXDUMP("hit_peer is: ", hit_peer, sizeof(hip_hit_t));
	HIP_HEXDUMP("hit_our is: ", hit_our, sizeof(hip_hit_t));
	return (hip_opp_block_t *)hip_ht_find(oppdb, (void *)&entry);
}

hip_opp_block_t *hip_create_opp_block_entry() 
{
	hip_opp_block_t * entry = NULL;

	entry = (hip_opp_block_t *)malloc(sizeof(hip_opp_block_t));
	if (!entry){
		HIP_ERROR("hip_opp_block_t memory allocation failed.\n");
		return NULL;
	}
  
	memset(entry, 0, sizeof(*entry));
  
//	INIT_LIST_HEAD(&entry->next_entry);
  
	HIP_LOCK_OPP_INIT(entry);
	atomic_set(&entry->refcnt,0);
	time(&entry->creation_time);
	HIP_UNLOCK_OPP_INIT(entry);
 out_err:
        return entry;
}

//int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
int hip_oppdb_add_entry(const hip_hit_t *hit_peer, 
			const hip_hit_t *hit_our,
			const struct in6_addr *ip_peer,
			const struct in6_addr *ip_our,
			const struct sockaddr_in6 *caller)
{
	int err = 0;
	hip_opp_block_t *tmp = NULL;
	hip_opp_block_t *new_item = NULL;
	
	new_item = hip_create_opp_block_entry();
	if (!new_item) {
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}

//	hip_xor_hits(&new_item->hash_key, hit_peer, hit_our);

	ipv6_addr_copy(&new_item->peer_real_hit, hit_peer);
	ipv6_addr_copy(&new_item->our_real_hit, hit_our);
	if (ip_peer)
		ipv6_addr_copy(&new_item->peer_ip, ip_peer);
	if (ip_our)
		ipv6_addr_copy(&new_item->our_ip, ip_our);
	memcpy(&new_item->caller, caller, sizeof(struct sockaddr_in6));
	
	err = hip_ht_add(oppdb, new_item);
	hip_oppdb_dump();
	
	return err;
}

int hip_oppdb_del_entry(const hip_hit_t *hit_peer, const hip_hit_t *hit_our)
{
	hip_opp_block_t *entry = NULL;
	
	entry = hip_oppdb_find_byhits(hit_peer, hit_our);
	if (!entry) {
		return -ENOENT;
	}
	hip_oppdb_del_entry_by_entry(entry);
	return 0;
}

void hip_init_opp_db()
{
#if 0
	memset(&oppdb,0,sizeof(oppdb));
	
	oppdb.head =      oppdb_list;
	oppdb.hashsize =  HIP_OPPDB_SIZE;
	oppdb.offset =    offsetof(hip_opp_block_t, next_entry);
	oppdb.hash =      hip_hash_hit;
	oppdb.compare =   hip_match_hit;
	oppdb.hold =      hip_oppdb_hold_entry;
	oppdb.put =       hip_oppdb_put_entry;
	oppdb.get_key =   hip_oppdb_get_key;
	
	strncpy(oppdb.name,"OPPDB_BY_HIT", 12);
	oppdb.name[12] = 0;
	
	hip_ht_init(&oppdb);
#endif
	oppdb = hip_ht_init(hip_oppdb_hash_hit, hip_oppdb_match_hit);
}

void hip_oppdb_dump()
{
	int i;
	//  char peer_real_hit[INET6_ADDRSTRLEN] = "\0";
	hip_opp_block_t *this;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("start oppdb dump\n");
	HIP_LOCK_HT(&oppdb);

	list_for_each_safe(item, tmp, oppdb, i)
	{
		this = list_entry(item);

		//hip_in6_ntop(&this->peer_real_hit, peer_real_hit);
//		HIP_DEBUG("hash_key=%d  lock=%d refcnt=%d\n", this->hash_key, this->lock, this->refcnt);
		HIP_DEBUG_HIT("this->peer_real_hit",
					&this->peer_real_hit);
	}

	HIP_UNLOCK_HT(&oppdb);
	HIP_DEBUG("end oppdb dump\n");
}

int hip_opp_unblock_app(const struct sockaddr_in6 *app_id, hip_hit_t *hit,
			int reject) {
	struct hip_common *message = NULL;
	int err = 0, n;

	HIP_IFE(!(message = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(message, SO_HIP_SET_PEER_HIT, 0), -1,
		 "build user header failed\n");
	if (hit) {
		HIP_IFEL(hip_build_param_contents(message, hit,
		                                  HIP_PARAM_HIT,
		                                  sizeof(struct in6_addr)), -1,
		         "build param HIP_PARAM_HIT  failed\n");
	}
	
	if (reject) {
		n = 1;
		HIP_DEBUG("message len: %d\n", hip_get_msg_total_len(message));
		HIP_IFEL(hip_build_param_contents(message, &n,
		                                  HIP_PARAM_AGENT_REJECT,
		                                  sizeof(n)), -1,
		         "build param HIP_PARAM_HIT  failed\n");
		HIP_DEBUG("message len: %d\n", hip_get_msg_total_len(message));
	}

	n = hip_sendto(message, app_id);
	if(n < 0){
		HIP_ERROR("hip_sendto() failed.\n");
		err = -1;
		goto out_err;
	}
 out_err:
	if (message)
		HIP_FREE(message);
	return err;
}

hip_ha_t *hip_oppdb_get_hadb_entry(hip_hit_t *init_hit,
				   struct in6_addr *resp_addr)
{
	hip_ha_t *entry_tmp = NULL;
	hip_hit_t phit;
	int err = 0;

	HIP_DEBUG_HIT("resp_addr=", resp_addr);
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(resp_addr, &phit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "hip_opportunistic_ipv6_to_hit failed\n");

	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit));
	
	entry_tmp = hip_hadb_find_byhits(init_hit, &phit);

 out_err:
	return entry_tmp;
}

hip_ha_t *hip_oppdb_get_hadb_entry_i1_r1(struct hip_common *msg,
					struct in6_addr *src_addr,
					struct in6_addr *dst_addr,
					hip_portpair_t *msg_info)
{
	hip_hdr_type_t type = hip_get_msg_type(msg);
	hip_ha_t *entry = NULL;

	if (type == HIP_I1) {
		if(!hit_is_opportunistic_null(&msg->hitr)){
			goto out_err;
		}

		hip_get_any_localhost_hit(&msg->hitr, HIP_HI_DEFAULT_ALGO, 0);
	} else if (type == HIP_R1) {
		entry = hip_oppdb_get_hadb_entry(&msg->hitr, src_addr);
	} else {
		HIP_ASSERT(0);
	}

 out_err:
	return entry;
}

int hip_receive_opp_r1(struct hip_common *msg,
		       struct in6_addr *src_addr,
		       struct in6_addr *dst_addr,
		       hip_ha_t *opp_entry,
		       hip_portpair_t *msg_info)
{
	hip_opp_block_t *block_entry = NULL;
	hip_ha_t *entry_tmp = NULL, *entry;
	hip_hit_t phit;
	int n = 0, err = 0;
	
	entry_tmp = hip_oppdb_get_hadb_entry(&msg->hitr, src_addr);
	if (!entry_tmp){
		HIP_ERROR("Cannot find HA entry after receive r1\n");
		err = -1;
		goto out_err;
	}

	// add new HA with real hit
	//err = hip_hadb_add_peer_info(&msg->hits, src_addr);
	
	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_IN6ADDR("!!!! peer addr=", src_addr);
	HIP_DEBUG_IN6ADDR("!!!! local addr=", dst_addr);
	
	HIP_IFEL(hip_hadb_add_peer_info_complete(&msg->hitr, &msg->hits,
						 dst_addr, src_addr), -1,
		 "Failed to insert peer map\n");
	
	HIP_IFEL(!(entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr)), -1,
		 "Did not find opp entry\n");

	HIP_IFEL(hip_init_us(entry, &msg->hitr), -1,
		 "hip_init_us failed\n");
	/* old HA has state 2, new HA has state 1, so copy it */
	entry->state = opp_entry->state;

	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_HIT("!!!! peer addr=", src_addr);
	HIP_DEBUG_HIT("!!!! local addr=", dst_addr);

	HIP_IFEL(hip_opportunistic_ipv6_to_hit(src_addr, &phit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "pseudo hit conversion failed\n");
	
	HIP_IFEL(!(block_entry = hip_oppdb_find_byhits(&phit, &msg->hitr)), -1,
		 "Failed to find opp entry by hit\n");

	//memcpy(&block_entry->peer_real_hit, &msg->hits, sizeof(hip_hit_t));
	HIP_IFEL(hip_opp_unblock_app(&block_entry->caller, &msg->hits, 0), -1,
		 "unblock failed\n");
	// we should still get entry after delete old phit HA
	entry_tmp = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	HIP_ASSERT(entry_tmp);

	/* why is the receive entry still pointing to hip_receive_opp_r1 ? */
	entry->hadb_rcv_func->hip_receive_r1 = hip_receive_r1;
	HIP_IFCS(entry,
		 err = entry->hadb_rcv_func->hip_receive_r1(msg,
							    src_addr,
							    dst_addr,
							    entry,
							    msg_info))
 out_err:
	if (block_entry && err) {
		HIP_DEBUG("Error %d occurred, cleaning up\n", err);
		hip_oppdb_entry_clean_up(block_entry);
	}
	return err;
}


/**
 * Receive opportunistic R1 when entry is in established mode already.
 * This is because we need to send right HIT to client app and not
 * empty packet. If this is not done, client app will fallback to normal
 * tcp connection without HIP after one connection to host has already
 * been made earlier.
 */
int hip_receive_opp_r1_in_established(struct hip_common *msg,
		       struct in6_addr *src_addr,
		       struct in6_addr *dst_addr,
		       hip_ha_t *opp_entry,
		       hip_portpair_t *msg_info)
{
	hip_opp_block_t *block_entry = NULL;
	hip_hit_t phit;
	int err = 0;

	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_HIT("!!!! peer addr=", src_addr);
	HIP_DEBUG_HIT("!!!! local addr=", dst_addr);

	HIP_IFEL(hip_opportunistic_ipv6_to_hit(src_addr, &phit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "pseudo hit conversion failed\n");
	
	HIP_IFEL(!(block_entry = hip_oppdb_find_byhits(&phit, &msg->hitr)), -1,
		 "Failed to find opp entry by hit\n");

	HIP_IFEL(hip_opp_unblock_app(&block_entry->caller, &msg->hits, 0), -1,
		 "unblock failed\n");
 
out_err:
	if (block_entry && err) {
		HIP_DEBUG("Error %d occurred, cleaning up\n", err);
		hip_oppdb_entry_clean_up(block_entry);
	}
	return err;
}


/**
 * No description.
 */
int hip_opp_get_peer_hit(struct hip_common *msg, const struct sockaddr_in6 *src)
{
	int n = 0, err = 0, alen = 0;
	struct in6_addr phit, dst_ip, hit_our;
	struct in6_addr *ptr = NULL;
	hip_opp_block_t *entry = NULL;
	hip_ha_t *ha = NULL;
	
	if(!opportunistic_mode) {
		hip_msg_init(msg);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1, 
			 "Building of user header failed\n");
		err = -11; /* Force immediately to send message to app */
		goto out_err;
	}

	/* Create an opportunistic HIT from the peer's IP  */
	
	memset(&hit_our, 0, sizeof(struct in6_addr));
	ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_HIT);
	HIP_IFEL(!ptr, -1, "No hit in msg\n");
	memcpy(&hit_our, ptr, sizeof(hit_our));
	HIP_DEBUG_HIT("hit_our=", &hit_our);
	
	ptr = (struct in6_addr *)
		hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
	HIP_IFEL(!ptr, -1, "No ip in msg\n");
	memcpy(&dst_ip, ptr, sizeof(dst_ip));
	HIP_DEBUG_HIT("dst_ip=", &dst_ip);
	
	hip_msg_init(msg);

	if (hip_ipdb_check((struct in6_addr *)&dst_ip))
	{
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1, 
		         "Building of user header failed\n");
		err = -11; /* Force immediately to send message to app */
		
		goto out_err;
	}
	
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(&dst_ip, &phit,
					       HIP_HIT_TYPE_HASH100),
		 -1, "Opp HIT conversion failed\n");
	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit)); 
	HIP_DEBUG_HIT("phit", &phit);
	
	err = hip_hadb_add_peer_info(&phit, &dst_ip);
	HIP_IFEL(!(ha = hip_hadb_find_byhits(&hit_our, &phit)), -1,
		 "Did not find entry\n")

	/* Override the receiving function */
	ha->hadb_rcv_func->hip_receive_r1 = hip_receive_opp_r1;
	
	entry = hip_oppdb_find_byhits(&phit, &hit_our);
	if(!entry) {
		HIP_IFEL(hip_oppdb_add_entry(&phit, &hit_our, &dst_ip, NULL,
					     src), -1,
			 "Add db failed\n");
	       	HIP_IFEL(hip_send_i1(&hit_our, &phit, ha), -1,
			 "sending of I1 failed\n");
		
	} else if (ipv6_addr_any(&entry->peer_real_hit)) {
		/* Two simultaneously connecting applications */
		HIP_DEBUG("Peer HIT still undefined, doing nothing\n");
		goto out_err;
	} else {
		/* Two applications connecting consequtively: let's just return
		   the real HIT instead of sending I1 */
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&entry->peer_real_hit),
					       HIP_PARAM_HIT,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1,
			 "Building of msg header failed\n");
	}
	
 send_i1:
	/*	HIP_IFEL(hip_send_i1(&hit_our, &phit, ha), -1,
		 "sending of I1 failed\n");
	*/
 out_err:
	return err;
}

int hip_handle_opp_fallback(hip_opp_block_t *entry,
			    void *current_time) {
	int err = 0, disable_fallback = 0;
	time_t *now = (time_t*) current_time;
	struct in6_addr *addr;
	//HIP_DEBUG("now=%d e=%d\n", *now, entry->creation_time);

#if defined(CONFIG_HIP_AGENT) && defined(CONFIG_HIP_OPPORTUNISTIC)
	/* If agent is prompting user, let's make sure that
	   the death counter in maintenance does not expire */
	if (hip_agent_is_alive()) {
		hip_ha_t *ha = NULL;
		ha = hip_oppdb_get_hadb_entry(&entry->our_real_hit,
					      &entry->peer_ip);
		if (ha)
			disable_fallback = ha->hip_opp_fallback_disable;
		HIP_DEBUG("disable_fallback: %d\n",disable_fallback);

	}
#endif
	HIP_DEBUG("disable_fallback: %d\n",disable_fallback);
	if(!disable_fallback && (*now - HIP_OPP_WAIT > entry->creation_time)) {
		addr = (struct in6_addr *) &entry->peer_ip;
		hip_ipdb_add(addr);
		HIP_DEBUG("Timeout for opp entry, falling back to\n");
		err = hip_opp_unblock_app(&entry->caller, NULL, 0);
		HIP_DEBUG("Unblock returned %d\n", err);
		err = hip_oppdb_entry_clean_up(entry);
		memset(&now,0,sizeof(now));
		
	}
	
 out_err:
	return err;
}



int hip_handle_opp_reject(hip_opp_block_t *entry, void *data)
{
	int err = 0;
	struct in6_addr *resp_ip = data;
	
	if (ipv6_addr_cmp(&entry->peer_ip, resp_ip)) goto out_err;

	HIP_DEBUG_HIT("entry initiator hit:", &entry->our_real_hit);
	HIP_DEBUG_HIT("entry responder ip:", &entry->peer_ip);
	HIP_DEBUG("Rejecting blocked opp entry\n");
	err = hip_opp_unblock_app(&entry->caller, NULL, 1);
	HIP_DEBUG("Unblock returned %d\n", err);
	err = hip_oppdb_entry_clean_up(entry);
	
out_err:
	return err;
}

#endif /* CONFIG_HIP_OPPORTUNISTIC */
