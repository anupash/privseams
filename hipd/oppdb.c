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

  entry = (hip_opp_block_t *)malloc(sizeof(hip_opp_block_t));
  if (!entry){
    HIP_ERROR("hip_opp_block_t memory allocation failed.\n");
    return NULL;
  }
  
  memset(entry, 0, sizeof(*entry));
  
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

#endif /* CONFIG_HIP_OPPORTUNISTIC */
