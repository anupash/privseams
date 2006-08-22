/**
 * This file defines a rendezvous extension for the Host Identity Protocol
 * (HIP). The rendezvous extension extends HIP and the HIP registration
 * extension for initiating communication between HIP nodes via HIP
 * rendezvous servers. The rendezvous server (RVS) serves as an initial contact
 * point ("rendezvous point") for its clients.  The clients of an RVS are HIP
 * nodes that use the HIP Registration Protocol [draft-ietf-hip-registration-02]
 * to register their HIT->IP address mappings with the RVS. After this
 * registration, other HIP nodes can initiate a base exchange using the IP
 * address of the RVS instead of the current IP address of the node they attempt
 * to contact.
 * 
 * A rendezvous server stores the HIT->IP address mappings of its clients into
 * a hashtable as a rendezvous association data structure. A client can have
 * a maximum number of HIP_RVA_MAX_IPS IP addresses mapped to a single HIT,
 * and a RVS can have a maximum of HIP_RVA_SIZE clients.
 * 
 * author:  (version 1.0) Kristian Slavov 
 * author:  (version 2.0) Lauri Silvennoinen 
 * date:    22.08.2006
 * draft:   draft-ietf-hip-rvs-05
 * licence: GNU/GPL
 */ 
#include "rvs.h"

HIP_HASHTABLE rva_table;
static struct list_head rvadb[HIP_RVA_SIZE];

/**
 * hip_rva_allocate - Allocate and initialize a rendezvous association.
 * @param gfpmask Mask for HIP_MALLOC() that is used to allocate the memory.
 *
 * @return a pointer to a newly allocated and initialized rendezvous 
 *          association structure or NULL if failed to allocate memory.
 */
HIP_RVA *hip_rva_allocate(int gfpmask)
{
	HIP_RVA *res;

	if((res = HIP_MALLOC(sizeof(*res), gfpmask)) == NULL) {
		HIP_ERROR("Error allocating memory for rendezvous association.\n");
		return NULL;
	}

	atomic_set(&res->refcnt, 0);
	HIP_LOCK_INIT(res);
	res->lifetime = 0;
	memset(res->ip_addrs, 0, HIP_RVA_MAX_IPS*sizeof(struct in6_addr));

	return res;
}

/**
<<<<<<< TREE
 * hip_rva_ha2rva - create a rendezvous association from a host association
 * @param ha      a host association from where from to copy. 
 * @param gfpmask: memory allocation mask.
 * 
 * Allocates memory for a new rendezvous association and copies information
 * from the parameter host association into it.
 * 
 * @Returns a pointer to a newly allocated rendezvous association or NULL if
 *          failed to allocate memory.
 */
HIP_RVA *hip_rva_ha2rva(hip_ha_t *ha, int gfpmask)
{
	HIP_RVA *rva;
	struct hip_peer_addr_list_item *item;
	int ipcnt = 0;
	struct hip_spi_out_item *spi_out, *spi_tmp;

	if((rva = hip_rva_allocate(gfpmask)) == NULL) {
		HIP_ERROR("Error allocating memory for rendezvous association.\n");
		return NULL;
	}

	hip_hold_rva(rva);

	HIP_LOCK_HA(ha);
	ipv6_addr_copy(&rva->hit, &ha->hit_peer);

	memcpy(&rva->hmac_our, &ha->hip_hmac_in, sizeof(rva->hmac_our));
 	memcpy(&rva->hmac_peer, &ha->hip_hmac_out, sizeof(rva->hmac_peer));
	
	if (!ipv6_addr_any(&ha->preferred_address)) {
		HIP_DEBUG("Copying bex address.\n");
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
 * hip_rva_get - get a rendezvous association matching the argument hit.
 * @param hit The HIT of the rendezvous association to get.
 * 
 * If a rendezvous association is found, it is automatically holded
 * (refcnt incremented).
 *
 * @Returns a pointer to a matching rendezvous association or NULL if
 *          a matching rendezvous association was not found.
 */
HIP_RVA *hip_rva_get(struct in6_addr *hit)
{
 	return (HIP_RVA*)hip_ht_find(&rva_table, hit);
}

/**
 * hip_rva_get_valid - get a valid rendezvous association matching the argument hit.
 * @hit: The HIT of the rendezvous association to get.
 * 
 * Finds a rendezvous association matching the argument hit and whose state is
 * HIP_RVASTATE_VALID. If a valid rendezvous association is found, it is
 * automatically holded (refcnt incremented).
 *
 * @return a pointer to a matching valid rendezvous association or NULL if
 *          a matching valid rendezvous association was not found.
 */
HIP_RVA *hip_rva_get_valid(struct in6_addr *hit)
{
	HIP_RVA *rva;

 	rva = hip_ht_find(&rva_table, hit);
 	if (rva) {
 		if ((rva->rvastate & HIP_RVASTATE_VALID) == 0) {
			HIP_ERROR("A matching rendezvous association was found, "\
				  "but the state is not valid.\n");
 			hip_put_rva(rva);
 			rva = NULL;
 		}
 	}
	return rva;
}

/**
 * hip_rva_put_ip - inserts or updates a rendezvous association IP address.
 * @param rva   the rendezvous association whose IP address is to be modified. 
 * @param ip    the IP address to insert.
 * @param index the index of the IP address to be modified.
 * 
 * A rendezvous server client can register more than one of its IP addresses
 * to a rendezvous server. In this case the rendezvous association has a maximum
 * number of HIP_RVA_MAX_IPS IP addresses mapped to a single HIT. This function
 * inserts one IP address to a rendezvous association. The index of the IP
 * address to insert must be smaller than HIP_RVA_MAX_IPS. The existing IP at
 * "index" is overwritten.
 */
void hip_rva_put_ip(HIP_RVA *rva, struct in6_addr *ip, unsigned int index)
{
	HIP_ASSERT(rva);
 	HIP_ASSERT(index < HIP_RVA_MAX_IPS);

 	HIP_LOCK_HA(rva);
 	ipv6_addr_copy(&rva->ip_addrs[index], ip);
 	HIP_UNLOCK_HA(rva);
}

/**
 * hip_rva_get_ip - get an IP address from a rendezvous association.
 * @param rva   the rendezvous association from where to get the IP address.
 * @param dst   a pointer to a buffer where to put the IP address.
 * @param index the index of the IP address to get.
 *
 * Gets an IP address at "index" from a rendezvous association. Destination
 * buffer "dst" must be allocated before calling this function and "index"
 * must be smaller than HIP_RVA_MAX_IPS.
 */
void hip_rva_get_ip(HIP_RVA *rva, struct in6_addr *dst, unsigned int index)
{
	HIP_ASSERT(rva);
	HIP_ASSERT(dst);
	HIP_ASSERT(index < HIP_RVA_MAX_IPS);

	HIP_LOCK_HA(rva);
	ipv6_addr_copy(dst, &rva->ip_addrs[index]);
	HIP_UNLOCK_HA(rva);
}

/**
 * hip_rva_put_rva - insert a new rendezvous association into the hashtable.
 * @param rva the rendezvous association to be added into the hashtable.
 *
 * The rendezvous association is automatically holded (refcnt incremented).
 *
 * @return zero on success, or negative error value on error.
 */
int hip_rva_put_rva(HIP_RVA *rva)
{
	int err;
	HIP_DEBUG_HIT("hip_rva_put_rva(): Inserting rendezvous association "\
		      "with hit", &rva->hit);
	
	/* If assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&rva->refcnt) <= 1); 

	HIP_IFEL(ipv6_addr_any(&rva->hit), -EINVAL,
		 "Trying to insert rva entry with NULL hit.\n");
	HIP_IFEL(hip_ht_find(&rva_table, &rva->hit), -EEXIST,
		 "Duplicate rva entry. Not adding hit to rva table.\n");
	
	err = hip_ht_add(&rva_table, rva);
	if (err) {
		HIP_ERROR("Failed to add rva hash table entry.\n");
	} else {
		rva->rvastate |= HIP_RVASTATE_VALID;
	}
 out_err:
	return err;
}

/**
 * hip_rva_hold_entry - hold a rendezvous association hashtable entry. 
 * @entry: the entry to be held.
 * 
 * A function used as the hold function of the rendezvous association hashtable.
 * 
 * Note: this is a static function and thus can't be used outside this file.
 */
static void hip_rva_hold_entry(void *entry)
{
	HIP_RVA *rva = entry;

	HIP_ASSERT(entry);
	atomic_inc(&rva->refcnt);
	HIP_DEBUG("RVA: %p, refcnt incremented to: %d\n", rva, atomic_read(&rva->refcnt));
}

/**
 * hip_rva_put_entry - put a rendezvous association hashtable entry. 
 * @entry: the entry to be put.
 * 
 * A function used as the put function of the rendezvous association hashtable.
 * 
 * Note: this is a static function and thus can't be used outside this file.
 */
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

/**
 * hip_rva_get_key - get a key from rendezvous association hashtable. 
 * @entry: the entry to be got.
 * 
 * A function used as the get_key function of the rendezvous association
 * hashtable. Rendezvous association hashtable uses client HITs as keys.
 * 
 * Note:    this is a static function and thus can't be used outside this file.
 * Returns: a pointer to the matching key or NULL if no match was found.
 */
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
 * hip_relay_i1 - relay an incoming I1 packet.
 * @param i1        HIP packet common header with source and destination HITs.
 * @param i1_saddr the source address from where the I1 packet was received.
 * @param i1_daddr the destination address where the I1 packet was sent to (own address).
 * @param rva      rendezvous association matching the HIT of next hop.
 * @param i1_info  the source and destination ports (when NAT is in use).
 *
 * This function relays an incoming I1 packet to the next node on path
 * to receiver and inserts a FROM parameter encapsulating the source IP address.
 * Next node on path is typically the responder, but if the message is to travel
 * multiple rendezvous servers en route to responder, next node can also be
 * another rendezvous server. In this case the FROM parameter is appended after
 * the existing ones. Thus current RVS appends the address of previous RVS
 * and the final RVS (n) sends FROM:I, FROM:RVS1, ... , FROM:RVS(n-1).
 * 
 * @return zero on success, or negative error value on error.
 */
int hip_relay_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		 struct in6_addr *i1_daddr, HIP_RVA *rva, struct hip_stateless_info *i1_info)
{
	HIP_DEBUG("Lauri: hip_relay_i1() invoked.\n");
	HIP_DUMP_MSG(i1);
	HIP_DEBUG_IN6ADDR("Lauri:  i1_saddr", i1_saddr);
	HIP_DEBUG_IN6ADDR("Lauri: i1_daddr", i1_daddr);
	HIP_DEBUG("Lauri: rva->rvastate: %s.\n", rva->rvastate ? "HIP_RVASTATE_VALID" : "HIP_RVASTATE_INVALID");
	HIP_DEBUG_HIT("Lauri: rva->hit", &rva->hit);
	int i = 0;
	for(; i < HIP_RVA_MAX_IPS; i++)
		HIP_DEBUG_IN6ADDR("Lauri: rva->ip_addrs", &rva->ip_addrs[i]);
	HIP_DEBUG("Lauri: i1_info->src_port: %u.\n", i1_info->src_port);
	HIP_DEBUG("Lauri: i1_info->dst_port: %u.\n", i1_info->dst_port);
	
	struct in6_addr *final_dst = NULL, *original_src;
	struct hip_common *old_i1, *new_i1;
	struct hip_tlv_common *current_param = NULL;
	int err, from_added = 0;
	char ipv6dst[128] = {0};

	final_dst = HIP_MALLOC(sizeof(*final_dst), gfpmask);
	HIP_IFEL(!final_dst, -ENOENT, "Error allocating memory for destination address.\n");
	hip_rva_get_ip(rva, final_dst, 0);

	old_i1 = i1;
	original_src = i1_saddr;
	
	/* New I1 packet has to be created since the received
	   has wrong network header. */
	HIP_IFEL(!(new_i1 = hip_msg_alloc()), -ENOMEM,
		 "No memory to copy original I1\n");
	
	/*! \todo : TH: hip_build_network_hdr has to be replaced with an appropriate
	   function pointer */
	hip_build_network_hdr(new_i1, HIP_I1, 0,
			      &(old_i1->hits), &(old_i1->hitr));

	/* Adding FROM parameter. Loop through all the parameters in the
	   received I1 packet, and insert a new FROM parameter after the last
	   found FROM parameter. Notice that in most cases the incoming I1 has
	   no paramaters at all, and this "while" loop is skipped. Multiple
	   rvses en route to responder is one (and only?) case when the incoming
	   I1 packet has parameters. */
	while ((current_param = hip_get_next_param(old_i1, current_param)) != NULL)
	{
		HIP_DEBUG("Found parameter in I1.\n");
		/* Copy while type is smaller than or equal to FROM or a 
		   new FROM has already been added. */
		if (from_added || ntohs(current_param->type) <= HIP_PARAM_FROM)
		{
			HIP_DEBUG("Copying existing parameter to I1 packet "\
				  "to be relayed.\n");
			hip_build_param(new_i1,current_param);
			continue;
		}
		/* Parameter under inspections has greater type than FROM
		   parameter: insert a new FROM parameter between the last
		   found FROM parameter and "current_param". */
		else
		{
			HIP_DEBUG("Created new FROM and copied "\
				  "current parameter to relayed I1.\n");
			hip_build_param_from(new_i1, original_src, 0);
			hip_build_param(new_i1, current_param);
			from_added = 1;
		}
	}

	/* If the incoming I1 had no parameters after the existing FROM
	   parameters, new FROM parameter is not added until here. */
	if (!from_added)
	{
		HIP_DEBUG("Adding a new FROM as the last parameter.\n");
		hip_build_param_from(new_i1, original_src, 0);
	}

	err = hip_csum_send(NULL, final_dst, i1_info->src_port, i1_info->dst_port, new_i1, NULL, 0); 
	//Sending the port info from the I1 from initiator behind NAT to the server --Abi
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
