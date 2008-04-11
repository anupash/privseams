#include "firewalldb.h"
/**
 * firewall_hit_lsi_db_match:
 * Search in the database the given lsi
 *
 * @param lsi_peer: entrance that we are searching in the db
 * @return NULL if not found and otherwise the firewall_hl_t structure
 */
firewall_hl_t *firewall_hit_lsi_db_match(hip_lsi_t *lsi_peer){
  //hip_firewall_hldb_dump();
  return (firewall_hl_t *)hip_ht_find(firewall_lsi_hit_db, (void *)lsi_peer);
  
}

firewall_hl_t *hip_create_hl_entry(void){
	firewall_hl_t *entry = NULL;
	int err = 0;
	HIP_IFEL(!(entry = (firewall_hl_t *) HIP_MALLOC(sizeof(firewall_hl_t),0)),
		 -ENOMEM, "No memory available for firewall database entry\n");
  	memset(entry, 0, sizeof(entry));
out_err:
	return entry;
}


void hip_firewall_hldb_dump(void)
{
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	HIP_DEBUG("/////////////////////////////\n");
	HIP_DEBUG("//////  Firewall db  ///////\n");
	HIP_DEBUG("/////////////////////////////\n")
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_lsi_hit_db, i)
	{
		this = list_entry(item);
		HIP_DEBUG_HIT("Dump >>> hit_our", &this->hit_our);
		HIP_DEBUG_HIT("Dump >>> hit_peer", &this->hit_peer);
		HIP_DEBUG_LSI("Dump >>> lsi", &this->lsi);
		HIP_DEBUG("Dump >>> bex_state %d \n", this->bex_state);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("end hldbdb dump\n");
}

int firewall_add_hit_lsi(struct in6_addr *hit_our, struct in6_addr *hit_peer, hip_lsi_t *lsi){
	int err = 0;
	firewall_hl_t *new_entry = NULL;

	HIP_ASSERT(hit_our != NULL && hit_peer != NULL && lsi != NULL);
	HIP_DEBUG("Start firewall_add_hit_lsi\n");
	
	new_entry = hip_create_hl_entry();
	ipv6_addr_copy(&new_entry->hit_our, hit_our);
	ipv6_addr_copy(&new_entry->hit_peer, hit_peer);
	ipv4_addr_copy(&new_entry->lsi, lsi);
	new_entry->bex_state = 0;
	HIP_DEBUG_HIT("1. entry to add to firewall_db hit_our ", &new_entry->hit_our);
	HIP_DEBUG_HIT("1. entry to add to firewall_db hit_peer ", &new_entry->hit_peer);
	HIP_DEBUG_LSI("1. entry to add to firewall_db lsi ", &new_entry->lsi);
	hip_ht_add(firewall_lsi_hit_db, new_entry);

out_err:
	//	hip_firewall_hldb_dump();
	HIP_DEBUG("End firewall_add_hit_lsi\n");
	return err;
}


/**
 * hip_firewall_hash_lsi:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the lsi used to make the hash
 *
 * @return hash information
 */
unsigned long hip_firewall_hash_lsi(const void *ptr){
        hip_lsi_t *lsi = &((firewall_hl_t *)ptr)->lsi;
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, lsi, sizeof(*lsi), hash);     
	return *((unsigned long *)hash);
}

/**
 * hip_firewall_match_lsi:
 * Compares two LSIs
 *
 * @param ptr1: pointer to lsi
 * @param ptr2: pointer to lsi
 *
 * @return 0 if hashes identical, otherwise 1
 */
int hip_firewall_match_lsi(const void *ptr1, const void *ptr2){
	return (hip_firewall_hash_lsi(ptr1) != hip_firewall_hash_lsi(ptr2));
}

void firewall_init_hldb(void){
	firewall_lsi_hit_db = hip_ht_init(hip_firewall_hash_lsi, hip_firewall_match_lsi);
}

int firewall_set_bex_state(struct in6_addr *hit_s, struct in6_addr *hit_r, int state){
	int err = 0;
	hip_lsi_t *lsi_peer = NULL;
	firewall_hl_t *entry_update = NULL;

	lsi_peer = hip_get_lsi_peer_by_hits(hit_s, hit_r);

	if (lsi_peer){
	        entry_update = firewall_hit_lsi_db_match(lsi_peer);
		entry_update->bex_state = state;
		hip_ht_add(firewall_lsi_hit_db, entry_update);
	}
	else
		err = -1;
	return err;
}

void hip_firewall_delete_hldb(void){
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start hldb delete\n");
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_lsi_hit_db, i)
	{
		this = list_entry(item);
		hip_ht_delete(firewall_lsi_hit_db, this);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("End hldbdb delete\n");
}
