/*
 * Key escrow functionality for HIP.
 *
 * Authors:
 * - Anu Markkola
 *
 * Licence: GNU/GPL
 */

#include "escrow.h"

HIP_HASHTABLE kea_table;

static struct list_head keadb[HIP_KEA_SIZE];


static void *hip_keadb_get_key(void *entry)
{
	// TODO: return hashkey	
	return (void *)&(((HIP_KEA *)entry)->hash_key);
}

/** 
 * TODO: Add other method to access data (< dst_IP, SPI> ?)
 * Initializes the database 
 */
void hip_init_keadb(void)
{ 
	memset(&kea_table, 0, sizeof(kea_table));

	kea_table.head = keadb;
	kea_table.hashsize = HIP_KEA_SIZE;
	kea_table.offset = offsetof(HIP_KEA, list_hit);
	kea_table.hash = hip_hash_hit;
	kea_table.compare = hip_match_hit;
	kea_table.hold = hip_keadb_hold_entry;
	kea_table.put = hip_keadb_put_entry;
	kea_table.get_key = hip_keadb_get_key;

	strncpy(kea_table.name, "KEA TABLE", 15);
	kea_table.name[15] = 0;

	hip_ht_init(&kea_table);
}


void hip_keadb_hold_entry(void *entry) //TODO: remove?
{
	HIP_KEA *kea = entry;

	HIP_ASSERT(entry);
	atomic_inc(&kea->refcnt);
	HIP_DEBUG("KEA: %p, refcnt incremented to: %d\n", kea, 
		atomic_read(&kea->refcnt));
}

void hip_keadb_put_entry(void *entry) //TODO: remove?
{
	HIP_KEA *kea = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&kea->refcnt)) {
    	HIP_DEBUG("KEA: %p, refcnt reached zero. Deleting...\n",kea);
		hip_keadb_delete_entry(kea);
	} else {
    	HIP_DEBUG("KEA: %p, refcnt decremented to: %d\n", kea, 
    		atomic_read(&kea->refcnt));
	}
}

void hip_uninit_keadb(void)
{
	//TODO
}

HIP_KEA *hip_kea_allocate(int gfpmask)
{
	HIP_KEA *kea;

	kea = HIP_MALLOC(sizeof(*kea), gfpmask);
	
	if (!kea)
		return NULL;

	atomic_set(&kea->refcnt, 0);
	HIP_LOCK_INIT(kea);
	kea->keastate = HIP_KEASTATE_INVALID;

	return kea;
}



/**
 * Creates a new key escrow association with the given values.
 */
HIP_KEA *hip_kea_create(struct in6_addr *hit1, struct in6_addr *hit2, 
						int esp_transform, uint32_t spi, uint16_t key_len, 
						struct hip_crypto_key *key, int gfpmask)
{
	HIP_KEA *kea;
	kea = hip_kea_allocate(gfpmask);
	if (!kea)
		return NULL;
	
	hip_hold_kea(kea); // Add reference
	
	ipv6_addr_copy(&kea->hit1, hit1);
	ipv6_addr_copy(&kea->hit2, hit2);
	kea->esp_transform = esp_transform;
	kea->key_len = key_len;
	kea->spi = spi;
	
	memcpy(&kea->esp_key, key, sizeof(kea->esp_key));
	kea->keastate = HIP_KEASTATE_VALID;
	
	return kea;	
}


int hip_keadb_add_entry(HIP_KEA *kea)
{
	int err = 0;
	HIP_KEA * temp;

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&kea->refcnt) <= 1); 

	HIP_IFEL(ipv6_addr_any(&kea->hit1), -EINVAL,
		 "Cannot insert KEA entry with NULL hit1\n");
	HIP_IFEL(ipv6_addr_any(&kea->hit2), -EINVAL,
		 "Cannot insert KEA entry with NULL hit2\n");
		 
	hip_xor_hits(&kea->hash_key, &kea->hit1, &kea->hit2);
	// Do we allow duplicates?	 
	temp = hip_ht_find(&kea_table, &kea->hash_key); // Adds reference
	
	if (temp) {
		hip_put_kea(temp); // remove reference
		HIP_ERROR("Failed to add kea hash table entry\n");
	} else {
		hip_ht_add(&kea_table, kea);
		kea->keastate |= HIP_KEASTATE_VALID;
	}
	
 out_err:
	return err;
}


void hip_keadb_remove_entry(HIP_KEA *kea)
{
	HIP_ASSERT(kea);

	HIP_LOCK_HA(kea); // refcnt should be more than 1
	if (!(kea->keastate & HIP_KEASTATE_VALID)) {
		HIP_DEBUG("KEA not in kea hashtable or state corrupted\n");
		return;
	}
	
	hip_ht_delete(&kea_table, kea); // refcnt decremented
	HIP_UNLOCK_HA(kea); 

}


void hip_keadb_delete_entry(HIP_KEA *kea)
{
	HIP_FREE(kea);
}

HIP_KEA *hip_kea_find_byhits(struct in6_addr *hit1, struct in6_addr *hit2)
{
	// XOR the HITs to get the key
	hip_hit_t key;
   	hip_xor_hits(&key, hit1, hit2);
	//HIP_HEXDUMP("hit is: ", hit, 16);
	//HIP_HEXDUMP("hit2 is: ", hit2, 16);
	//HIP_HEXDUMP("the computed key is: ", &key, 16);
	
	return hip_ht_find(&kea_table, &key);
}

