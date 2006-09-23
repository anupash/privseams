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

int hip_handle_opp_fallback(hip_opp_block_t *entry, void *current_time) {
  int err = 0;
  time_t *now = (time_t*) current_time;	

  if(*now - HIP_OPP_WAIT > entry->creation_time) {
    // send IP to the application and unblock it
    // hip_oppdb_del_entry_by_entry()
    // hip_del_peer_info()
    XX_FIXME;
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
	for(i = 0; i < HIP_HADB_SIZE; i++) {
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
  HIP_DB_PUT_ENTRY(entry, struct hip_opp_blocking_request_entry, hip_oppdb_del_entry_by_entry);
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
    if (!list_empty(&oppdb_list[i])) {
      HIP_DEBUG("HT[%d]\n", i);
      list_for_each_entry_safe(item, tmp, &(oppdb_list[i]), next_entry) {
	
	//hip_in6_ntop(&item->peer_real_hit, peer_real_hit);
	HIP_DEBUG("hash_key=%d  lock=%d refcnt=%d\n",
		  item->hash_key, item->lock, item->refcnt);
	HIP_DEBUG_HIT("item->peer_real_hit", &item->peer_real_hit);
	HIP_HEXDUMP("caller", &item->caller, sizeof(struct sockaddr_un));
      }
    }
  }
  HIP_UNLOCK_HT(&oppdb);
  HIP_DEBUG("end oppdb dump\n");
}

int hip_opp_unblock_app(const struct sockaddr_un *app_id, hit_hit_t *resp_id) {
	struct hip_common *message = NULL;
	int err = 0;

	HIP_IFE(!(message = HIP_MSG_ALLOC(HIP_MAX_PACKET)), -1);
	HIP_IFEL(hip_build_user_hdr(message, SO_HIP_SET_PEER_HIT, 0), -1,
		 "build user header failed\n");
	HIP_IFEL(hip_build_param_contents(message, resp_id,
					  HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	n = hip_sendto(message, app_id);
	message = NULL;
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

int hip_check_hip_r1_opportunistic_mode(struct hip_common *msg,
					struct in6_addr *src_addr,
					struct in6_addr *dst_addr,
					struct hip_stateless_info *msg_info,
					hip_ha_t *entry){
  
	hip_hit_t nullhit;
	hip_opp_block_t *block_entry = NULL;
	//hip_hit_t *peer_hit = NULL;
	hip_ha_t *entry_tmp = NULL;
	hip_ha_t *pEntry;
	int n = 0;
	int err = 0;
	
	HIP_DEBUG_HIT("src_addr=", src_addr);
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(src_addr, &nullhit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "hip_opportunistic_ipv6_to_hit failed\n");

	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&nullhit));
	
	entry_tmp = hip_hadb_find_byhits(&nullhit, &msg->hitr);
	HIP_ASSERT(entry_tmp);
	if (!entry_tmp){
	  HIP_ERROR("Cannot find HA entry after receive r1\n");
	  err = -1;
	  goto out_err;
	}

	// add new HA with real hit
	//err = hip_hadb_add_peer_info(&msg->hits, src_addr);
	
	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_HIT("!!!! peer addr=", src_addr);
	HIP_DEBUG_HIT("!!!! local addr=", dst_addr);
	
	HIP_IFEL(hip_hadb_add_peer_info_complete(&msg->hitr, &msg->hits,
						 dst_addr, src_addr), -1,
		 "Failed to insert peer map\n");
	
	// we should get entry by both real hits
	//	  entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	pEntry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	HIP_ASSERT(pEntry);
	if(pEntry)
	  memcpy(entry, pEntry, sizeof(hip_ha_t));
	
	if (!entry) {
		HIP_ERROR("Cannot find the added HA entry\n");
		err = -1;
		goto out_err;
	}

	// Bing, we need entry->our_pub and our_priv, so init_us
	HIP_IFEL(hip_init_us(entry, &entry->hit_our), -1,
		 "hip_init_us failed\n");
	// old HA has state 2, new HA has state 1, so copy it
	entry->state = entry_tmp->state;

	// delete nullhit HA
	entry_tmp = NULL;
	HIP_IFEL(hip_del_peer_info(&msg->hitr, &nullhit, src_addr), -1,
		 "Failed to delete mapping\n");
	
	// hashtable=hip_opp_blocking_request_entry
	// ent = find_opp_entry_from_hashtable(SRC_HIT, DST_PHIT)
	// msg = REAL_DST_HIT
	// memcpy(ent->real_peer_hit, real_dst_hit);
	// sendto(entry->caller, msg);
	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_HIT("!!!! peer addr=", src_addr);
	HIP_DEBUG_HIT("!!!! local addr=", dst_addr);
	
	block_entry = hip_oppdb_find_byhits(&nullhit, &msg->hitr);
	//HIP_ASSERT(entry);
	memcpy(&block_entry->peer_real_hit, &msg->hits, sizeof(hip_hit_t));
	HIP_IFEL(hip_opp_unblock_app(&block_entry->caller, &msg->hits), -1,
		 "unblock failed\n");
	// we should still get entry after delete old nullhit HA
	pEntry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	HIP_ASSERT(pEntry);
	memcpy(entry, pEntry, sizeof(hip_ha_t));

	if (!entry)
		goto out_err;
	
	err = ((hip_input_filter_func_set_t *)hip_get_input_filter_default_func_set())->hip_input_filter(msg);
	if (err == -ENOENT) {
		HIP_DEBUG("No agent running, continuing\n");
		err = 0;
	} else if (err == 0) {
		HIP_DEBUG("Agent accepted packet\n");
	} else if (err) {
		HIP_ERROR("Agent reject packet\n");
	}

	// XX FIXME: DEALLOC OPP ENTRY AND OPP HASHED HADB
	
 out_err:
	if (message)
		HIP_FREE(message);
	return err;
}

#endif /* CONFIG_HIP_OPPORTUNISTIC */
