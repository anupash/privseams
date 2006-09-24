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

HIP_HASHTABLE oppdb;
static struct list_head oppdb_list[HIP_OPPDB_SIZE]= { 0 };
extern unsigned int opportunistic_mode;

int hip_oppdb_entry_clean_up(hip_opp_block_t *opp_entry) {
	hip_ha_t *hadb_entry;
	int err = 0;

	/* XX FIXME: this does not support multiple multiple opp
	   connections: a better solution might be trash collection  */

	HIP_ASSERT(opp_entry);
	hip_oppdb_del_entry_by_entry(opp_entry);
	err = hip_del_peer_info(&opp_entry->peer_real_hit,
				&opp_entry->our_real_hit,
				&opp_entry->peer_ip);
	return err;
}

int hip_handle_opp_fallback(hip_opp_block_t *entry,
			    void *current_time) {
	int err = 0;
	time_t *now = (time_t*) current_time;	
	
	if(*now - HIP_OPP_WAIT > entry->creation_time) {
		HIP_DEBUG("Timeout for opp entry, falling back to\n");
		err = hip_opp_unblock_app(&entry->caller,
					  &entry->peer_real_hit);
		HIP_DEBUG("Unblock returned %d\n", err);
		err = hip_oppdb_entry_clean_up(entry);
	}
	
 out_err:
	return err;
}

int hip_for_each_opp(int (*func)(hip_opp_block_t *entry, void *opaq),
		     void *opaque)
{
	int i = 0, fail = 0;
	hip_opp_block_t *this, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&opp_db);
	for(i = 0; i < HIP_OPPDB_SIZE; i++) {
		_HIP_DEBUG("The %d list is empty? %d\n", i,
			   list_empty(&oppdb_list[i]));
		list_for_each_entry_safe(this, tmp, &oppdb_list[i],next_entry)
		{
			_HIP_DEBUG("List_for_each_entry_safe\n");
			hip_hold_ha(this);
			fail = func(this, opaque);
			hip_db_put_ha(this, hip_oppdb_del_entry_by_entry);
			if (fail)
				break;
		}
		if (fail)
			break;
	}
	HIP_UNLOCK_HT(&opp_db);
	return fail;
}

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

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_oppdb_del_entry_by_entry(hip_opp_block_t *entry)
{
	HIP_DEBUG_HIT("peer_real_hit", &entry->peer_real_hit);
	HIP_HEXDUMP("caller", &entry->caller, sizeof(struct sockaddr_un));
	
	HIP_LOCK_OPP(entry);
	hip_ht_delete(&oppdb, entry);
	HIP_UNLOCK_OPP(entry);
	HIP_FREE(entry);
}

int hip_oppdb_uninit_wrap(hip_opp_block_t *entry, void *unused) {
	hip_oppdb_del_entry_by_entry(entry);
	return 0;
}

void hip_oppdb_uninit() {
	hip_for_each_opp(hip_oppdb_uninit_wrap, NULL);
}

hip_opp_block_t *hip_create_opp_block_entry() 
{
	hip_opp_block_t * entry = NULL;
	time_t current_time;
	time(&current_time);
	
	entry = (hip_opp_block_t *)malloc(sizeof(hip_opp_block_t));
	if (!entry){
		HIP_ERROR("hip_opp_block_t memory allocation failed.\n");
		return NULL;
	}
	
	memset(entry, 0, sizeof(*entry));
	
	entry->creation_time = current_time;
	
	INIT_LIST_HEAD(&entry->next_entry);
	
	HIP_LOCK_OPP_INIT(entry);
	atomic_set(&entry->refcnt,0);
	HIP_UNLOCK_OPP_INIT(entry);
 out_err:
	return entry;
}

hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *hit_peer, const hip_hit_t *hit_our)
{
	hip_hit_t key;
	hip_xor_hits(&key, hit_peer, hit_our);
	HIP_HEXDUMP("hit_peer is: ", hit_peer, sizeof(hip_hit_t));
	HIP_HEXDUMP("hit_our is: ", hit_our, sizeof(hip_hit_t));
	HIP_HEXDUMP("the computed key is: ", &key, sizeof(hip_hit_t));
	return (hip_opp_block_t *)hip_ht_find(&oppdb, (void *)&key);
}


//int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
int hip_oppdb_add_entry(const hip_hit_t *hit_peer, 
			const hip_hit_t *hit_our,
			const struct in6_addr *ip_peer,
			const struct in6_addr *ip_our,
			const struct sockaddr_un *caller)
{
	int err = 0;
	hip_opp_block_t *tmp = NULL;
	hip_opp_block_t *new_item = NULL;
	
	new_item = (hip_opp_block_t *)malloc(sizeof(hip_opp_block_t));   
	if (!new_item) {
		HIP_ERROR("new_item malloc failed\n");                   
		err = -ENOMEM;                                               
		return err;
	}                                    
	
	hip_xor_hits(&new_item->hash_key, hit_peer, hit_our);

	ipv6_addr_copy(&new_item->peer_real_hit, hit_peer);
	ipv6_addr_copy(&new_item->our_real_hit, hit_our);
	if (ip_peer)
		ipv6_addr_copy(&new_item->peer_ip, ip_peer);
	if (ip_our)
		ipv6_addr_copy(&new_item->our_ip, ip_our);
	memcpy(&new_item->caller, caller, sizeof(struct sockaddr_un));
	
	err = hip_ht_add(&oppdb, new_item);
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
}

void hip_oppdb_dump()
{
	int i;
	//  char peer_real_hit[INET6_ADDRSTRLEN] = "\0";
	hip_opp_block_t *item = NULL;
	hip_opp_block_t *tmp = NULL;
	
	HIP_DEBUG("start oppdb dump\n");
	HIP_LOCK_HT(&oppdb);
	
	for(i = 0; i < HIP_OPPDB_SIZE; i++) {
		if (list_empty(&oppdb_list[i]))
			continue;

		HIP_DEBUG("HT[%d]\n", i);
		list_for_each_entry_safe(item, tmp,
					 &(oppdb_list[i]),
					 next_entry) {
			
			//hip_in6_ntop(&item->peer_real_hit, peer_real_hit);
			HIP_DEBUG("hash_key=%d  lock=%d refcnt=%d\n",
				  item->hash_key, item->lock, item->refcnt);
			HIP_DEBUG_HIT("item->peer_real_hit",
				      &item->peer_real_hit);
			HIP_HEXDUMP("caller", &item->caller,
				    sizeof(struct sockaddr_un));
		}
	}
	HIP_UNLOCK_HT(&oppdb);
	HIP_DEBUG("end oppdb dump\n");
}

int hip_opp_unblock_app(const struct sockaddr_un *app_id, hip_hit_t *hit) {
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


hip_ha_t *hip_oppdb_get_hadb_entry(hip_hit_t *resp_hit,
				   struct in6_addr *resp_addr)
{
	hip_ha_t *entry_tmp = NULL;
	hip_hit_t nullhit;
	int err = 0;

	HIP_DEBUG_HIT("resp_addr=", resp_addr);
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(resp_addr, &nullhit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "hip_opportunistic_ipv6_to_hit failed\n");

	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&nullhit));
	
	entry_tmp = hip_hadb_find_byhits(&nullhit, resp_hit);
	HIP_ASSERT(entry_tmp);

 out_err:
	return entry_tmp;
}

hip_ha_t *hip_oppdb_get_hadb_entry_i1_r1(struct hip_common *msg,
					struct in6_addr *src_addr,
					struct in6_addr *dst_addr,
					struct hip_stateless_info *msg_info)
{
	hip_hdr_type_t type = hip_get_msg_type(msg);
	hip_ha_t *entry = NULL;

	if (type == HIP_I1) {
		struct gaih_addrtuple *at = NULL;
		struct gaih_addrtuple **pat = &at;

		if(!hit_is_opportunistic_null(&msg->hitr)){
			goto out_err;
		}
			
		/* Rewrite responder HIT of i1  */
		get_local_hits(NULL, pat);
		HIP_DEBUG_HIT("The local HIT =", &at->addr);
		HIP_DEBUG_HIT("msg->hitr =", &msg->hitr);
		
		memcpy(&msg->hitr, &at->addr, sizeof(at->addr));
		HIP_DEBUG_HIT("msg->hitr =", &msg->hitr);    
	} else if (type == HIP_R1) {
		entry = hip_oppdb_get_hadb_entry(&msg->hits, src_addr);
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
		       struct hip_stateless_info *msg_info)
{
	hip_opp_block_t *block_entry = NULL;
	hip_ha_t *entry_tmp = NULL, *entry;
	hip_hit_t nullhit;
	int n = 0;
	int err = 0;
	
	entry_tmp = hip_oppdb_get_hadb_entry(src_addr, &msg->hitr);
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
	
	// we should get entry by both real hits
	//	  entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	HIP_ASSERT(entry);

	// Bing, we need entry->our_pub and our_priv, so init_us
	HIP_IFEL(hip_init_us(entry, &msg->hitr), -1,
		 "hip_init_us failed\n");
	// old HA has state 2, new HA has state 1, so copy it
	entry->state = opp_entry->state;

	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_HIT("!!!! peer addr=", src_addr);
	HIP_DEBUG_HIT("!!!! local addr=", dst_addr);

	HIP_IFEL(hip_opportunistic_ipv6_to_hit(src_addr, &nullhit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "pseudo hit conversion failed\n");
	
	block_entry = hip_oppdb_find_byhits(&nullhit, &msg->hitr);
	//HIP_ASSERT(entry);
	memcpy(&block_entry->peer_real_hit, &msg->hits, sizeof(hip_hit_t));
	HIP_IFEL(hip_opp_unblock_app(&block_entry->caller, &msg->hits), -1,
		 "unblock failed\n");
	// we should still get entry after delete old nullhit HA
        entry_tmp = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	HIP_ASSERT(entry_tmp);

	HIP_IFCS(entry,
		 err = entry->hadb_rcv_func->hip_receive_r1(msg,
							    src_addr,
							    dst_addr,
							    entry,
							    msg_info))
 out_err:
	if (block_entry) {
		HIP_DEBUG("Error %d occurred, cleaning up\n", err);
		hip_oppdb_entry_clean_up(block_entry);
	}
	return err;
}

/**
 * No description.
 */
int hip_opp_get_peer_hit(struct hip_common *msg, const struct sockaddr_un *src)
{
	int n = 0;
	int err = 0;
	int alen = 0;
	struct in6_addr phit, dst_ip, hit_our;
	struct in6_addr *ptr = NULL;
	hip_opp_block_t *entry = NULL;
	hip_ha_t *ha = NULL;
	
	if(!opportunistic_mode) {
		hip_msg_init(msg);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1, 
			 "Building of user header failed\n");
		n = hip_sendto(msg, src);
		if(n < 0){
			HIP_ERROR("hip_sendto() failed.\n");
			err = -1;
		}
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
	
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(&dst_ip, &phit,
					       HIP_HIT_TYPE_HASH100),
		 -1, "Opp HIT conversion failed\n");
	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit)); 
	HIP_DEBUG_HIT("phit", &phit);
	
	err = hip_hadb_add_peer_info(&phit, &dst_ip);
	ha = hip_hadb_find_byhits(&hit_our, &phit);
	HIP_ASSERT(ha);

	/* Override the receiving function */
	ha->hadb_rcv_func->hip_receive_r1 = hip_receive_opp_r1;
	
	entry = hip_oppdb_find_byhits(&phit, &hit_our);
	if(!entry) {
		HIP_IFEL(hip_oppdb_add_entry(&phit, &hit_our, &dst_ip, NULL,
					     src), -1,
			 "Add db failed\n");
	} else if (ipv6_addr_any(&entry->peer_real_hit)) {
		/* Two simultaneously connecting applications */
		HIP_DEBUG("Peer HIT still undefined, doing nothing\n");
		goto out_err;
	} else {
		hip_msg_init(msg);
		/* Two applications connecting consequtively: let's just return
		   the real HIT instead of sending I1 */
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&entry->peer_real_hit),
					       HIP_PARAM_HIT,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_PEER_HIT, 0), -1,
			 "Building of msg header failed\n");
		n = hip_sendto(msg, src);
		if(n < 0){
			HIP_ERROR("hip_sendto() failed.\n");
			err = -1;
		}
		goto out_err;
	}
	
 send_i1:
	HIP_IFEL(hip_send_i1(&hit_our, &phit, ha), -1,
		 "sending of I1 failed\n");
	
 out_err:
	return err;
}

#endif /* CONFIG_HIP_OPPORTUNISTIC */
