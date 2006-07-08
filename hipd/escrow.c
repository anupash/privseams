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

HIP_HASHTABLE kea_endpoints;

static struct list_head keadb[HIP_KEA_SIZE];
static struct list_head kea_endpointdb[HIP_KEA_EP_SIZE];

static void *hip_keadb_get_key(void *entry)
{
	return (void *)&(((HIP_KEA *)entry)->hit);
}

/** 
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
HIP_KEA *hip_kea_create(struct in6_addr *hit, int gfpmask)
{
	HIP_KEA *kea;
	_HIP_DEBUG("Creating kea entry");
	kea = hip_kea_allocate(gfpmask);
	if (!kea)
		return NULL;
	
	hip_hold_kea(kea); // Add reference
	
	ipv6_addr_copy(&kea->hit, hit);
	kea->keastate = HIP_KEASTATE_VALID;
	
	return kea;	
}


int hip_keadb_add_entry(HIP_KEA *kea)
{
	int err = 0;
	HIP_KEA * temp;

	_HIP_DEBUG("Adding kea entry");

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&kea->refcnt) <= 1); 

	HIP_IFEL(ipv6_addr_any(&kea->hit), -EINVAL,
		 "Cannot insert KEA entry with NULL hit\n");
		 
	// Do we allow duplicates?	 
	temp = hip_ht_find(&kea_table, &kea->hit); // Adds reference
	
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

HIP_KEA *hip_kea_find(struct in6_addr *hit)
{
	return hip_ht_find(&kea_table, hit);
}

void hip_kea_set_state_registering(HIP_KEA *kea)
{
	kea->keastate = HIP_KEASTATE_REGISTERING;

}

/**********************************************/



void hip_kea_hold_ep(void *entry) //TODO: remove?
{
	HIP_KEA_EP *kea_ep = entry;

	HIP_ASSERT(entry);
	atomic_inc(&kea_ep->refcnt);
	HIP_DEBUG("KEA EP: %p, refcnt incremented to: %d\n", kea_ep, 
		atomic_read(&kea_ep->refcnt));
}

void hip_kea_put_ep(void *entry) //TODO: remove?
{
	HIP_KEA_EP *kea_ep = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&kea_ep->refcnt)) {
    	HIP_DEBUG("KEA EP: %p, refcnt reached zero. Deleting...\n",kea_ep);
		hip_kea_delete_endpoint(kea_ep);
	} else {
    	HIP_DEBUG("KEA EP: %p, refcnt decremented to: %d\n", kea_ep, 
    		atomic_read(&kea_ep->refcnt));
	}
}


static void *hip_kea_endpoints_get_key(void *entry)
{
	return (void *)&(((HIP_KEA_EP *)entry)->ep_id);
}

void hip_init_kea_endpoints(void)
{
	memset(&kea_endpoints, 0, sizeof(kea_endpoints));

	kea_endpoints.head = kea_endpointdb;
	kea_endpoints.hashsize = HIP_KEA_EP_SIZE;
	kea_endpoints.offset = offsetof(HIP_KEA_EP, list_hit);
	kea_endpoints.hash = hip_kea_ep_hash;
	kea_endpoints.compare = hip_kea_ep_match;
	kea_endpoints.hold = hip_kea_hold_ep;
	kea_endpoints.put = hip_kea_put_ep;
	kea_endpoints.get_key = hip_kea_endpoints_get_key;

	strncpy(kea_endpoints.name, "KEA ENDPOINTS", 15);
	kea_endpoints.name[15] = 0;

	hip_ht_init(&kea_endpoints);
}


void hip_uninit_kea_endpoints(void)
{
	//TODO:
}

int hip_kea_ep_hash(const void * key, int range)
{
	HIP_KEA_EP_ID * id = (HIP_KEA_EP_ID *) key; 
	// TODO: Is the key random enough?
	return (id->value[2] ^ id->value[3] ^ id->value[4]) % range;
}


int hip_kea_ep_match(const void * ep1, const void * ep2)
{	
	return !memcmp((const void *) ep1, (const void *) ep2, 18);
}

HIP_KEA_EP *hip_kea_ep_allocate(int gfpmask)
{
	HIP_KEA_EP *kea_ep;

	kea_ep = HIP_MALLOC(sizeof(*kea_ep), gfpmask);
	
	if (!kea_ep)
		return NULL;

	atomic_set(&kea_ep->refcnt, 0);
	HIP_LOCK_INIT(kea_ep);

	return kea_ep;

}

HIP_KEA_EP *hip_kea_ep_create(struct in6_addr *hit, int esp_transform, 
									uint32_t spi, uint16_t key_len, 
									struct hip_crypto_key * key, int gfpmask)
{
	HIP_KEA_EP *kea_ep;
	kea_ep = hip_kea_ep_allocate(gfpmask);
	if (!kea_ep)
		return NULL;
	
	hip_hold_kea(kea_ep); // Add reference
	
	ipv6_addr_copy(&kea_ep->hit, hit);
	kea_ep->esp_transform = esp_transform;
	kea_ep->key_len = key_len;
	kea_ep->spi = spi;
	
	memcpy(&kea_ep->esp_key, key, sizeof(kea_ep->esp_key));
	
	return kea_ep;	
}

int hip_kea_add_endpoint(HIP_KEA_EP *kea_ep)
{
	int err = 0;
	HIP_KEA_EP * temp;

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&kea_ep->refcnt) <= 1); 

	HIP_IFEL(ipv6_addr_any(&kea_ep->hit), -EINVAL,
		 "Cannot insert KEA_EP entry with NULL hit\n");
		 
	// Create key
	memcpy(&kea_ep->ep_id.value, &kea_ep->hit.in6_u.u6_addr32, 
		   sizeof(struct in6_addr));
	memcpy(&kea_ep->ep_id.value[4], &kea_ep->spi, sizeof(int));
	
	HIP_HEXDUMP("KEA endpoint hit:", &kea_ep->hit, 16);
	HIP_HEXDUMP("KEA endpoint spi:", &kea_ep->spi, 2);
	HIP_HEXDUMP("KEA endpoint id:", &kea_ep->ep_id, 18);
	
	temp = hip_ht_find(&kea_endpoints, &kea_ep->ep_id); // Adds reference
	
	if (temp) {
		hip_put_kea_ep(temp); // remove reference
		HIP_ERROR("Failed to add kea endpoint hash table entry\n");
	} else {
		hip_ht_add(&kea_endpoints, kea_ep);
		// set state if needed
	}
	
 out_err:
	return err;
}


void hip_kea_remove_endpoint(HIP_KEA_EP *kea_ep)
{
	HIP_ASSERT(kea_ep);

	HIP_LOCK_HA(kea_ep); // refcnt should be more than 1
	//if (!(kea_ep->keastate & HIP_EP_KEASTATE_VALID)) { //check state
	//	HIP_DEBUG("KEA not in kea hashtable or state corrupted\n");
	//	return;
	//}
	
	hip_ht_delete(&kea_endpoints, kea_ep); // refcnt decremented
	HIP_UNLOCK_HA(kea_ep); 
	
}


void hip_kea_delete_endpoint(HIP_KEA_EP *kea_ep)
{
	HIP_FREE(kea_ep);
}


HIP_KEA_EP *hip_kea_ep_find(struct in6_addr *hit, uint32_t spi)
{

	HIP_KEA_EP_ID *key;
	
	key = HIP_MALLOC(sizeof(struct hip_kea_ep_id), GFP_KERNEL);
	
	memcpy(&key->value, &hit->in6_u.u6_addr32, sizeof(struct in6_addr));
	memcpy(&key->value[4], &spi, sizeof(int));

	HIP_HEXDUMP("Searching KEA endpoint with key:", key, 18);
		
	return hip_ht_find(&kea_endpoints, key);
}



