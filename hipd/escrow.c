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

// ?
HIP_KEA *hip_kea_get_base_entry(void)
{
	/*HIP_KEA *kea = &kea_base;
	if (kea_base == NULL)
		return 0;
	return 1;*/
	return NULL;
}

// hit_our is not really needed now
int hip_kea_create_base_entry(struct hip_host_id_entry *entry, 
	void *server_hit_void)
{
	int err = 0;
	HIP_KEA *kea;
	struct in6_addr *server_hit = server_hit_void; 	
	kea = hip_kea_create(&entry->lhi.hit, GFP_KERNEL);
	if (!kea) 
		return -1;	
	ipv6_addr_copy(&kea->server_hit, server_hit);	
	err = hip_keadb_add_entry(kea);
	HIP_DEBUG_HIT("Created kea base entry with hit: ", &entry->lhi.hit);
	return err;
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

HIP_KEA_EP *hip_kea_ep_create(struct in6_addr *hit, struct in6_addr *ip, 
							  int esp_transform, uint32_t spi, uint16_t key_len, 
							  struct hip_crypto_key * key, int gfpmask)
{
	HIP_KEA_EP *kea_ep;
	kea_ep = hip_kea_ep_allocate(gfpmask);
	if (!kea_ep)
		return NULL;
	
	HIP_DEBUG("Creating kea endpoint");
	HIP_DEBUG_HIT("ep hit:", hit);
	HIP_DEBUG("ep spi: %d", spi);
	
	hip_hold_kea(kea_ep); // Add reference
	
	ipv6_addr_copy(&kea_ep->hit, hit);
	ipv6_addr_copy(&kea_ep->ip, ip);
	kea_ep->esp_transform = esp_transform;
	kea_ep->key_len = key_len;
	kea_ep->spi = spi;
	
	memcpy(&kea_ep->esp_key, key, sizeof(kea_ep->esp_key));
	
	return kea_ep;	
}

int hip_kea_add_endpoint(HIP_KEA_EP *kea_ep)
{
	HIP_DEBUG("Adding kea endpoint");
	
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
	HIP_DEBUG("Removing kea endpoint");
	
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


/******************************/


int hip_send_escrow_update(hip_ha_t *entry, int operation, 
	struct in6_addr *addr, struct in6_addr *hit, uint32_t spi, uint32_t old_spi,
	int ealg, uint16_t key_len, struct hip_crypto_key * enc)
{

	int err = 0;
	//, make_new_sa = 0, /*add_esp_info = 0,*/ add_locator;
	uint32_t update_id_out = 0;
	//uint32_t mapped_spi = 0; /* SPI of the SA mapped to the ifindex */
	//uint32_t new_spi_in = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr saddr = { 0 }, daddr = { 0 };
	//uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	//struct hip_own_addr_list_item *own_address_item, *tmp;
	
	
	hip_hadb_get_peer_addr(entry, &daddr);
	
	/* Start building UPDATE packet */
	
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory.\n");
	HIP_DEBUG_HIT("sending UPDATE to", &entry->hit_peer);

	HIP_DEBUG_HIT("escrow data hit:", hit);
	HIP_DEBUG("escrow data spi: %d", spi);
	HIP_DEBUG("escrow data old spi: %d", old_spi);
	HIP_DEBUG("escrow data ealg: %d", ealg);
	HIP_DEBUG("escrow data key length: %d",key_len);

	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, &entry->hit_our,
						     &entry->hit_peer);
			
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	_HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	/* todo: handle this case */
	HIP_IFEL(!update_id_out, -EINVAL,
		 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ param failed\n");

	
	/* Add hip_keys */
	HIP_DEBUG("Adding hip_keys parameter (escrow data)");
	
	HIP_IFEL(hip_build_param_keys(update_packet, (uint16_t)operation, 
		(uint16_t)ealg, addr, hit, spi, old_spi, key_len, enc), -1, 
		 "Building of hip_keys param (escrow data) failed\n");
	
	HIP_DEBUG("Built escrow data");
	
	
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv, update_packet), -EINVAL,
	 	 "Could not sign UPDATE. Failing\n");

	/* Send UPDATE */
	//hip_set_spi_update_status(entry, esp_info_old_spi, 1);


	memcpy(&saddr, &entry->local_address, sizeof(saddr));
        HIP_DEBUG("Sending UPDATE packet with escrow data\n");
	HIP_IFEL(entry->hadb_xmit_func->hip_csum_send(&saddr, &daddr,0,0,
						      update_packet, entry, 1),
		 -1, "csum_send failed\n");

	
	goto out;

 out_err:
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("fallbacked to state ESTABLISHED (ok ?)\n");
	
 out:

	HIP_UNLOCK_HA(entry);
	if (update_packet)
		HIP_FREE(update_packet);
	return err;
	
}

/******************************/

int hip_get_service_types(uint8_t * list)
{
	// Check for services that we are offering (at this point only escrow)
	// TODO
}

int hip_select_service_types(struct hip_reg_request *rreq, int *type_list, int len)
{
	/*HIP_IFEL(!(reg_info = hip_get_param(r1, HIP_PARAM_REG_INFO)), -ENOENT,
		 "No REG_INFO found in R1: no services available \n");
		uint8_t *types = (uint8_t *)(hip_get_param_contents(r1, HIP_PARAM_REG_INFO));
		int typecnt = hip_get_param_contents_len(reg_info);
		int accept = 0;
		int i;
		if (typecnt >= 2) { 
		for (i = 2; i < typecnt; i++) {
			HIP_DEBUG("Service type: %d", types[i]);
			if (types[i] == HIP_ESCROW_SERVICE)
				accept = 1;
		}
		}
	

	uint8_t *types = (uint8_t *)(rreq + 1);
	int typecnt, i, j;

	typecnt = hip_get_param_contents_len(rreq) - sizeof(uint8_t);
	int accept = 0
	int i;
	for(i = 0, j = 0; i < typecnt && j < llen; i++) {
		if (types[i] == HIP_ESCROW_SERVICE) {
			accept = 1; 
		}
	}

 out_of_loop:
	return j;
*/
}
