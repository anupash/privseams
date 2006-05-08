/*
 * Rendezvous Server functionality for HIP.
 *
 * Authors:
 * - Kristian Slavov
 *
 * Licence: GNU/GPL
 */

#include "rvs.h"
HIP_HASHTABLE rva_table;

static struct list_head rvadb[HIP_RVA_SIZE];

/**
 * hip_rva_allocate - Allocate and initialize Rendezvous Association
 * @gfpmask: Mask for HIP_MALLOC() that is used to allocate  the memory.
 *
 * Returns NULL if failure, or a pointer to newly allocated and initialized
 * RVA atructure
 */
HIP_RVA *hip_rva_allocate(int gfpmask)
{
	HIP_RVA *res;

	res = HIP_MALLOC(sizeof(*res), gfpmask);
	if (!res)
		return NULL;

	atomic_set(&res->refcnt, 0);
	HIP_LOCK_INIT(res);
	res->lifetime = 0;
	memset(res->ip_addrs, 0, HIP_RVA_MAX_IPS*sizeof(struct in6_addr));

	return res;
}
/**
 * hip_ha_to_rva - Create a Rendezvous Association from Host Association
  * @ha: HA
  * @gfpmask: Mask for HIP_MALLOC(). Used to allocate memory for the RVA.
  *
  * Returns the newly created RVA, with information from HA copied to it.
  * NULL if there was an error (out of memory).
  */
HIP_RVA *hip_ha_to_rva(hip_ha_t *ha, int gfpmask)
{
	HIP_RVA *rva;
	struct hip_peer_addr_list_item *item;
	int ipcnt = 0;
	struct hip_spi_out_item *spi_out, *spi_tmp;

	rva = hip_rva_allocate(gfpmask);
	if (!rva)
		return NULL;

	hip_hold_rva(rva);

	HIP_LOCK_HA(ha);
	ipv6_addr_copy(&rva->hit, &ha->hit_peer);

	memcpy(&rva->hmac_our, &ha->hip_hmac_in, sizeof(rva->hmac_our));
 	memcpy(&rva->hmac_peer, &ha->hip_hmac_out, sizeof(rva->hmac_peer));

	if (!ipv6_addr_any(&ha->preferred_address)) {
		HIP_DEBUG("copying bex address\n");
		ipv6_addr_copy(&rva->ip_addrs[ipcnt], &ha->preferred_address);
		ipcnt++;
		if (ipcnt >= HIP_RVA_MAX_IPS)
			goto out;
	}

	list_for_each_entry_safe(spi_out, spi_tmp, &ha->spis_out, list) {
		list_for_each_entry(item, &spi_out->peer_addr_list, list) {
			if (item->address_state != PEER_ADDR_STATE_ACTIVE)
				continue;

			ipv6_addr_copy(&rva->ip_addrs[ipcnt], &item->address);
			ipcnt++;
			if (ipcnt >= HIP_RVA_MAX_IPS)
				break;
		}
		if (ipcnt >= HIP_RVA_MAX_IPS)
			break;
	}
 out:
	HIP_UNLOCK_HA(ha);

	return rva;

}

/**
 * hip_rva_find - Get RVA entry corresponding to the argument hit.
 * @hit: Key
 * 
 * If a RVA is found, it is automatically holded (refcnt incremented).
 *
 * Returns the RVA or NULL if RVA was not found.
 */
HIP_RVA *hip_rva_find(struct in6_addr *hit)
{
 	return hip_ht_find(&rva_table, hit);
}

HIP_RVA *hip_rva_find_valid(struct in6_addr *hit)
{
	HIP_RVA *rva;

 	rva = hip_ht_find(&rva_table, hit);
 	if (rva) {
 		if ((rva->rvastate & HIP_RVASTATE_VALID) == 0) {
			HIP_ERROR("RVA state not valid\n");
 			hip_put_rva(rva);
 			rva = NULL;
 		}
 	}
	return rva;
}

/**
 * hip_rva_insert_ip_n - Insert/update/overwrite one IP in the RVA.
 * @rva: RVA
 * @ip: IP address to be written to the RVA's IP-list.
 * @n: Repalce n:th element in the IP-list. 0 <= n < HIP_RVA_MAX_IPS
 *
 * The IP that is overwritten is the n:th in the list.
 *
 */
void hip_rva_insert_ip_n(HIP_RVA *rva, struct in6_addr *ip, unsigned int n)
{
 	HIP_ASSERT(n < HIP_RVA_MAX_IPS);

 	HIP_LOCK_HA(rva);
 	ipv6_addr_copy(&rva->ip_addrs[n], ip);
 	HIP_UNLOCK_HA(rva);
}

/**
 * hip_rva_insert_ip - Insert/update/overwrite one IP in the RVA.
 * @rva: RVA
 * @ip: IP address to be written to the RVA's IP-list.
 *
 * The IP that is overwritten is the first in the list. This can, and probably
 * will change as we create better algorithms to decide which address to
 * replace (LRU/MRU/etc).
 *
 */
void hip_rva_insert_ip(HIP_RVA *rva, struct in6_addr *ip)
{
	hip_rva_insert_ip_n(rva, ip, 0);
}

/**
 * hip_rva_fetch_ip_n - Fetch Nth IP-address from the RVA to the destination buffer
 * @rva: Rendezvous Association
 * @dst: Target buffer (must be preallocated)
 * @n: The IP-address to fetch (0 <= n < HIP_RVA_MAX_IPS)
 *
 */
void hip_rva_fetch_ip_n(HIP_RVA *rva, struct in6_addr *dst, unsigned int n)
{
	HIP_ASSERT(dst);
	HIP_ASSERT(n < HIP_RVA_MAX_IPS);

	HIP_LOCK_HA(rva);
	ipv6_addr_copy(dst, &rva->ip_addrs[n]);
	HIP_UNLOCK_HA(rva);
}

/**
 * hip_rva_fetch_ip - Fetch first IP-address from the RVA to the destination buffer
 * @rva: Rendezvous Association
 * @dst: Target buffer (must be preallocated)
 *
 */
void hip_rva_fetch_ip(HIP_RVA *rva, struct in6_addr *dst)
{
	hip_rva_fetch_ip_n(rva, dst, 0);
}

/**
 * hip_rva_get_ip - Allocate memory and copy one IP from RVA's list.
 * @rva: RVA
 * @gfpmask: gfpmask
 *
 * Memory is allocated and the IP to copy is selected to be the first one
 * in to RVA's list. Later we might have a better algorithm selecting
 * a better IP. 
 *
 * Returns pointer to an IPv6 address that MUST be freed after use.
 */
struct in6_addr *hip_rva_get_ip(HIP_RVA *rva,int gfpmask)
{
	return hip_rva_get_ip_n(rva,gfpmask,0);
}

/**
 * hip_rva_get_ip - Allocate memory and copy one IP from RVA's list.
 * @rva: RVA
 * @gfpmask: gfpmask
 * @n: Element ot get from the RVA's IP-list.
 *
 * Memory is allocated and the IP to copy is selected to be the first one
 * in to RVA's list. Later we might have a better algorithm selecting
 * a better IP. 
 *
 * Returns pointer to an IPv6 address that MUST be freed after use.
 * Or %NULL if failed.
 */
struct in6_addr *hip_rva_get_ip_n(HIP_RVA *rva, int gfpmask, unsigned int n)
{
	struct in6_addr *hit;

	HIP_ASSERT(n < HIP_RVA_MAX_IPS);

	hit = HIP_MALLOC(sizeof(struct in6_addr), gfpmask);
	if (!hit)
		return NULL;

	hip_rva_fetch_ip_n(rva, hit, n);
	return hit;
}

/**
 * hip_rva_insert - Insert Rendezvous Association into the RVA hashtable
 * @rva: The RVA to be added to the hashtable.
 *
 * The RVA is automatically holded (refcnt incremented) as a side effect of
 * inserting it to the hashtable.
 *
 * Returns errno, or 0 if ok.
 */
int hip_rva_insert(HIP_RVA *rva)
{
	int err;

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&rva->refcnt) <= 1); 

	HIP_DEBUG_HIT("rva->hit", &rva->hit);

	HIP_IFEL(ipv6_addr_any(&rva->hit), -EINVAL,
		 "Cannot insert RVA entry with NULL hit\n");
	HIP_IFEL(hip_ht_find(&rva_table, &rva->hit), -EEXIST,
		 "Duplicate RVA entry. Not adding to RVA table\n");
	
	err = hip_ht_add(&rva_table, rva);
	if (err) {
		HIP_ERROR("Failed to add rva hash table entry\n");
	} else {
		rva->rvastate |= HIP_RVASTATE_VALID;
	}
 out_err:
	return err;
}


static void hip_rva_hold_entry(void *entry)
{
	HIP_RVA *rva = entry;

	HIP_ASSERT(entry);
	atomic_inc(&rva->refcnt);
	HIP_DEBUG("RVA: %p, refcnt incremented to: %d\n", rva, atomic_read(&rva->refcnt));
}

static void hip_rva_put_entry(void *entry)
{
	HIP_RVA *rva = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&rva->refcnt)) {
                HIP_DEBUG("RVA: %p, refcnt reached zero. Deleting...\n",rva);
		hip_rva_delete(rva);
	} else {
                HIP_DEBUG("RVA: %p, refcnt decremented to: %d\n", rva, atomic_read(&rva->refcnt));
	}
}

static void *hip_rva_get_key(void *entry)
{
	return (void *)&(((HIP_RVA *)entry)->hit);
}

void hip_init_rvadb()
{
	memset(&rva_table,0,sizeof(rva_table));

	rva_table.head = rvadb;
	rva_table.hashsize = HIP_RVA_SIZE;
	rva_table.offset = offsetof(HIP_RVA, list_hit);
	rva_table.hash = hip_hash_hit;
	rva_table.compare = hip_match_hit;
	rva_table.hold = hip_rva_hold_entry;
	rva_table.put = hip_rva_put_entry;
	rva_table.get_key = hip_rva_get_key;

	strncpy(rva_table.name, "RVA TABLE", 15);
	rva_table.name[15] = 0;

	hip_ht_init(&rva_table);
}

void hip_uninit_rvadb()
{
	/* do something... */
}

void hip_rva_delete(HIP_RVA *rva)
{
	/* last reference has been deleted by now */
	HIP_FREE(rva);
}

void hip_rva_remove(HIP_RVA *rva)
{
	HIP_ASSERT(rva);

	HIP_LOCK_HA(rva);
	if (!(rva->rvastate & HIP_RVASTATE_VALID)) {
		HIP_DEBUG("RVA not in rva hashtable or state corrupted\n");
		return;
	}

	hip_ht_delete(&rva_table, rva);
	HIP_UNLOCK_HA(rva);

	/* the refcnt should now be at least 1, since we must have
	   at least two references when calling this function: One in the
	   hashtable, one in the calling function.
	   After the delete operation we should have one less, but still over
	   0 and thus the HIP_UNLOCK_HA should not cause problems (accessing
	   deleted memory).
	*/
}

/**
 * hip_select_rva_types - Select RVA types that we accept
 * @rreq: The original request
 * @type_list: List that holds place for @llen 16-bit integers.
 * @llen: length of @type_list.
 *
 * Returns the amount of types that were accepted.
 */
int hip_select_rva_types(struct hip_rva_request *rreq, int *type_list, int llen)
{
	uint16_t *types = (uint16_t *)(rreq + 1);
	int typecnt, i, j;

	typecnt = hip_get_param_contents_len(rreq) - sizeof(uint32_t) / 2;
	/* due to padding, the actual amount of types is either types or types-1 */

	for(i=0,j=0;i<typecnt && j<llen; i++) {
		switch(types[i]) {
		case 0:
			/* padding */
			goto out_of_loop;
			break;
		case HIP_RVA_RELAY_I1:
			type_list[j++] = types[i];
			break;
		case HIP_RVA_RELAY_I1R1:
		case HIP_RVA_RELAY_I1R1I2:
		case HIP_RVA_RELAY_I1R1I2R2:
		case HIP_RVA_RELAY_ESP_I1:
		case HIP_RVA_REDIRECT_I1:
			break;
		default:
			/* was? */
			HIP_ERROR("Don't come here, please\n");
			return 0;
		}
	}

 out_of_loop:
	return j;
}

int hip_relay_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		 struct in6_addr *i1_daddr, HIP_RVA *rva)
{
	struct in6_addr *final_dst = NULL, *original_src;
	struct hip_common *old_i1, *new_i1;
	struct hip_tlv_common *tmp;
	int err, from_added = 0;
	char ipv6dst[128] = {0};

	HIP_IFEL(!(final_dst = hip_rva_get_ip(rva, GFP_KERNEL)), -ENOENT,
		 "Did not find forwarding address\n");
	old_i1 = i1;
	original_src = i1_saddr;
	
	HIP_IFEL(!(new_i1 = hip_msg_alloc()), -ENOMEM,
		 "No memory to copy original I1\n");
	
	/* TODO: TH: hip_build_network_hdr has to be replaced with an appropriate function pointer */
	hip_build_network_hdr(new_i1, HIP_I1, 0,
			      &(old_i1->hits),
			      &(old_i1->hitr));
	/* we need to add FROM field */
	while ((tmp = hip_get_next_param(old_i1, NULL))) {
		if (from_added || ntohs(tmp->type) <= HIP_PARAM_FROM) {
			/* copy */
			hip_build_param(new_i1,tmp);
			continue;
		}

		/* FROM parameter not added AND type > FROM... */
		/* add FROM _AND_ copy the tmp parameter */
		hip_build_param_from(new_i1, original_src, 0);
		hip_build_param(new_i1, tmp);
		from_added = 1;
	}

	if (!from_added) {
		hip_build_param_from(new_i1, original_src, 0);
	}

	err = hip_csum_send(NULL, final_dst, 0, 0, new_i1, NULL, 0); //Currenlty NULLing the stateless info --Abi
	if (err)
		HIP_ERROR("Sending the modified I1 (RVS) failed: %d\n",err);
	else {
		hip_in6_ntop(final_dst, ipv6dst);
		HIP_INFO("Relayed I1 to %s\n", ipv6dst);
	}
		
 out_err:
	if (final_dst)
		HIP_FREE(final_dst);
	return err;
}

int hip_rvs_set_request_flag(hip_hit_t *src_hit,
			      hip_hit_t *dst_hit)
{
	int err = 0;
	hip_ha_t *entry;


	HIP_IFEL(!(entry = hip_hadb_find_byhits(src_hit, dst_hit)),
		 -1, "Could not set RVS request bit\n");

	entry->local_controls |= HIP_PSEUDO_CONTROL_REQ_RVS;
	hip_put_ha(entry);

 out_err:
	return err;
}
