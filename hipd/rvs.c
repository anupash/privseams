/** @file
 * This file defines a rendezvous extension for the Host Identity Protocol
 * (HIP). The rendezvous extension extends HIP and the HIP registration
 * extension for initiating communication between HIP nodes via HIP
 * rendezvous servers. The rendezvous server (RVS) serves as an initial contact
 * point ("rendezvous point") for its clients.  The clients of an RVS are HIP
 * nodes that use the HIP Registration Protocol
 * [<a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-registration-02.txt">
 * draft-ietf-hip-registration-02</a>] to register their HIT->IP address mappings
 * with the RVS. After this registration, other HIP nodes can initiate a base
 * exchange using the IP address of the RVS instead of the current IP address
 * of the node they attempt to contact.
 * 
 * A rendezvous server stores the HIT->IP address mappings of its clients into
 * a hashtable as a rendezvous association data structure. A client can have
 * a maximum number of @c HIP_RVA_MAX_IPS IP addresses mapped to a single HIT,
 * and a RVS can have a maximum of @c HIP_RVA_SIZE clients.
 * 
 * Version 1.1 added function comments, removed many useless functions and
 * renewed the hip_rvs_relay_i1() -function.
 * 
 * @author  (version 1.0) Kristian Slavov
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    24.08.2006
 * @note    Related draft:
 *          <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *          draft-ietf-hip-rvs-05</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @note    Version 1.0 was document scarcely and the comments regarding
 *          version 1.0 that have been added afterwards may be inaccurate.
 */ 
#include "rvs.h"

/** A hashtable for storing rendezvous associations. */
HIP_HASHTABLE rva_table;
/** A linked list head used inside @c rva_table hashtable. */
static struct list_head rvadb[HIP_RVA_SIZE];

/**
 * Allocates and initializes a rendezvous association.
 *
 * @param gfpmask a mask for HIP_MALLOC() that is used to allocate the memory.
 * @return        a pointer to a newly allocated and initialized rendezvous 
 *                association structure or NULL if failed to allocate memory.
 */
HIP_RVA *hip_rvs_allocate(int gfpmask)
{
	HIP_RVA *res;

	if((res = HIP_MALLOC(sizeof(*res), gfpmask)) == NULL) {
		HIP_ERROR("Error allocating memory for rendezvous association.\n");
		return NULL;
	}

	atomic_set(&res->refcnt, 0);
	HIP_LOCK_INIT(res);
	res->lifetime = 0; // HIP_DEFAULT_RVA_LIFETIME
	memset(res->ip_addrs, 0, HIP_RVA_MAX_IPS*sizeof(struct in6_addr));

	return res;
}

/**
 * Creates a rendezvous association from a host association.
 * 
 * Allocates memory for a new rendezvous association and copies information
 * from the parameter host association into it.
 * 
 * @param  ha      a pointer to a host association from where from to copy.
 * @param  gfpmask memory allocation mask.
 * @return         a pointer to a newly allocated rendezvous association or
 *                 NULL if failed to allocate memory.
 */
HIP_RVA *hip_rvs_ha2rva(hip_ha_t *ha, int gfpmask)
{
	HIP_DEBUG("hip_rvs_ha2rva() invoked.\n");
	HIP_DEBUG("ha->peer_udp_port:%d.\n", ha->peer_udp_port);
	HIP_RVA *rva;
	struct hip_peer_addr_list_item *item;
	int ipcnt = 0;
	struct hip_spi_out_item *spi_out, *spi_tmp;

	if((rva = hip_rvs_allocate(gfpmask)) == NULL) {
		HIP_ERROR("Error allocating memory for rendezvous association.\n");
		return NULL;
	}
	
	/* Incremented the refrerence count of the new rendezvous association. */
	hip_hold_rva(rva);
	
	/* Copy the client udp port. */
	if(ha->peer_udp_port != 0) {
		rva->client_udp_port = ha->peer_udp_port;
	}
	else {
		rva->client_udp_port = 0;
	}
	
	/* Lock the host association copying values from it. */
	HIP_LOCK_HA(ha);

	/* Copy peer hit as the client hit. */
	ipv6_addr_copy(&rva->hit, &ha->hit_peer);
	
	/* Copy HMACs. */
	memcpy(&rva->hmac_our, &ha->hip_hmac_in, sizeof(rva->hmac_our));
 	memcpy(&rva->hmac_peer, &ha->hip_hmac_out, sizeof(rva->hmac_peer));
	
	/* If the host association has a preferred address, copy it as the
	   first IP address of the rendezvous association. */
	if (!ipv6_addr_any(&ha->preferred_address)) {
		HIP_DEBUG("Copying bex address.\n");
		ipv6_addr_copy(&rva->ip_addrs[ipcnt], &ha->preferred_address);
		ipcnt++;
		if (ipcnt >= HIP_RVA_MAX_IPS)
			goto out;
	}

	/* Copy rest of the IP addresses. */
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
 * Gets a rendezvous association from the rendezvous association hashtable.
 *
 * Gets a rendezvous association matching the argument @c hit. If
 * a rendezvous association is found, it is automatically holded (refcnt
 * incremented).
 *
 * @param hit the HIT of the rendezvous association to get.
 * @return    a pointer to a matching rendezvous association or NULL if
 *            a matching rendezvous association was not found.
 */
HIP_RVA *hip_rvs_get(struct in6_addr *hit)
{
 	return (HIP_RVA*)hip_ht_find(&rva_table, hit);
}

/**
 * Gets a valid rendezvous association from the rendezvous association
 * hashtable.
 *
 * Gets a valid rendezvous association matching the argument hit. Finds
 * a rendezvous association matching the argument hit and whose state is
 * @c HIP_RVASTATE_VALID. If a valid rendezvous association is found,
 * it is automatically holded (refcnt incremented).
 * 
 * @param hit the HIT of the rendezvous association to get.
 * @return a pointer to a matching valid rendezvous association or NULL if
 *         a matching valid rendezvous association was not found.
 */
HIP_RVA *hip_rvs_get_valid(struct in6_addr *hit)
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
 * Inserts or updates a rendezvous association IP address.
 * 
 * A rendezvous server client can register more than one of its IP addresses to
 * a rendezvous server. In this case the rendezvous association has a maximum
 * number of @c HIP_RVA_MAX_IPS IP addresses mapped to a single HIT.
 * This function inserts one IP address to a rendezvous association. The index
 * of the IP address to insert must be smaller than @c HIP_RVA_MAX_IPS. The
 * existing IP at @c index is overwritten.
 *
 * @param rva   the rendezvous association whose IP address is to be modified. 
 * @param ip    the IP address to insert.
 * @param index the index of the IP address to be modified.
 */
void hip_rvs_put_ip(HIP_RVA *rva, struct in6_addr *ip, unsigned int index)
{
	HIP_ASSERT(rva);
 	HIP_ASSERT(index < HIP_RVA_MAX_IPS);

 	HIP_LOCK_HA(rva);
 	ipv6_addr_copy(&rva->ip_addrs[index], ip);
 	HIP_UNLOCK_HA(rva);
}

/**
 * Gets an IP address from a rendezvous association.
 * 
 * Gets an IP address at @c index from a rendezvous association. Destination
 * buffer @c dst must be allocated before calling this function and @c index
 * must be smaller than @c HIP_RVA_MAX_IPS.
 *
 * @param rva   the rendezvous association from where to get the IP address.
 * @param dst   a pointer to a buffer where to put the IP address.
 * @param index the index of the IP address to get.
 */
void hip_rvs_get_ip(HIP_RVA *rva, struct in6_addr *dst, unsigned int index)
{
	HIP_ASSERT(rva);
	HIP_ASSERT(dst);
	HIP_ASSERT(index < HIP_RVA_MAX_IPS);

	HIP_LOCK_HA(rva);
	ipv6_addr_copy(dst, &rva->ip_addrs[index]);
	HIP_UNLOCK_HA(rva);
}

/**
 * Inserts a new rendezvous association into the rendezvous association
 * hashtable.
 * 
 * Inserts a parameter rendezvous association @c rva into the rendezvous
 * association hashtable. The rendezvous association @c rva is automatically
 * holded (refcnt incremented).
 *
 * @param rva the rendezvous association to be added into the hashtable.
 * @return    zero on success, or negative error value on error.
 */
int hip_rvs_put_rva(HIP_RVA *rva)
{
	int err;
	HIP_DEBUG_HIT("hip_rvs_put_rva(): Inserting rendezvous association "\
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
 * Holds a rendezvous association hashtable entry. 
 * 
 * A function used as the @c hold function of the rendezvous association hashtable.
 *  
 * @param entry the entry to be held.
 * @note        this is a static function and thus can't be used outside this file.
 */
static void hip_rvs_hold_entry(void *entry)
{
	HIP_RVA *rva = entry;

	HIP_ASSERT(entry);
	atomic_inc(&rva->refcnt);
	HIP_DEBUG("RVA: %p, refcnt incremented to: %d\n", rva, atomic_read(&rva->refcnt));
}

/**
 * Puts a rendezvous association hashtable entry. 
 *
 * A function used as the @c put function of the rendezvous association hashtable.
 *
 * @param entry the entry to be put.
 * @note  this is a static function and thus can't be used outside this file.
 */
static void hip_rvs_put_entry(void *entry)
{
	HIP_RVA *rva = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&rva->refcnt)) {
                HIP_DEBUG("Reference count of rendezvous association at %p "\
			  "reached zero. Rendezvous association is freed.\n",
			  rva);
		hip_rvs_free_rva(rva);
	} else {
		HIP_DEBUG("Reference count of rendezvous association at %p "\
			  "decremented to %d.\n.", rva,
			  atomic_read(&rva->refcnt));
	}
}

/**
 * Gets a key from rendezvous association hashtable. 
 * 
 * A function used as the @c get_key function of the rendezvous association
 * hashtable. Rendezvous association hashtable uses client HITs as keys.
 * 
 * @param entry the entry to be got.
 * @return      a pointer to the matching key or NULL if no match was found.
 * @note        this is a static function and thus can't be used outside this file.
 */
static void *hip_rvs_get_key(void *entry)
{
	return (void *)&(((HIP_RVA *)entry)->hit);
}

/**
 * Initializes the rendezvous association hashtable.
 *
 * Initializes the rendezvous association hashtable @c rva_table by
 * <ul>
 * <li>setting the memory area all zeros,
 * <li>setting the hashsize and offset,
 * <li>setting the needed function pointers,
 * <li>naming the table as <code>RVA TABLE</code>.
 * </ul>
 */ 
void hip_rvs_init_rvadb()
{
	memset(&rva_table,0,sizeof(rva_table));

	rva_table.head = rvadb;
	rva_table.hashsize = HIP_RVA_SIZE;
	rva_table.offset = offsetof(HIP_RVA, list_hit);
	rva_table.hash = hip_hash_hit;
	rva_table.compare = hip_match_hit;
	rva_table.hold = hip_rvs_hold_entry;
	rva_table.put = hip_rvs_put_entry;
	rva_table.get_key = hip_rvs_get_key;
	strncpy(rva_table.name, "RVA TABLE", 15);
	rva_table.name[15] = 0;

	hip_ht_init(&rva_table);
}

/**
 * Uninitializes the rendezvous association hashtable.
 * 
 * Uninitializes the rendezvous association hashtable @c rva_table by calling
 * hip_ht_uninit() for @c rva_table. Memory allocated for each rendezvous
 * association is freed.
 */ 
void hip_rvs_uninit_rvadb()
{
	HIP_DEBUG("hip_rvs_uninit_rvadb() invoked.\n");
	hip_ht_uninit(&rva_table);
}

/**
 * Frees the memory allocated for a rendezvous association.
 *
 * Frees the memory allocated for the parameter rendezvous association.
 *
 * @param rva the rendezvous association whose memory to free.
 * @note      this function should be called only after the last reference to
 *            the parameter @c rva is deleted. 
 */ 
void hip_rvs_free_rva(HIP_RVA *rva)
{
	HIP_FREE(rva);
}

/**
 * Removes a rendezvous association from the rendezvous association hashtable.
 *
 * Removes the parameter rendezvous association from the rendezvous
 * association hashtable.
 *
 * @param rva the rendezvous association to remove.
 */ 
void hip_rvs_remove(HIP_RVA *rva)
{
	HIP_ASSERT(rva);

	HIP_LOCK_HA(rva);
	if (!(rva->rvastate & HIP_RVASTATE_VALID)) {
		HIP_DEBUG("RVA not in rva hashtable or state corrupted\n");
		return;
	}

	hip_ht_delete(&rva_table, rva);
	HIP_UNLOCK_HA(rva);

	/* the refcnt should now be at least 1, since we must have at least two
	   references when calling this function: One in the hashtable, one in
	   the calling function. After the delete operation we should have one
	   less, but still over 0 and thus the HIP_UNLOCK_HA should not cause
	   problems (accessing deleted memory). */
}

/**
 * Relays an incoming I1 packet.
 *
 * This function relays an incoming I1 packet to the next node on path
 * to receiver and inserts a @c FROM parameter encapsulating the source IP address.
 * Next node on path is typically the responder, but if the message is to travel
 * multiple rendezvous servers en route to responder, next node can also be
 * another rendezvous server. In this case the @c FROM parameter is appended after
 * the existing ones. Thus current RVS appends the address of previous RVS
 * and the final RVS (n) sends @c FROM:I, @c FROM:RVS1, ... ,
 * <code>FROM:RVS(n-1)</code>.
 * 
 * @param i1       a pointer to the I1 HIP packet common header with source and
 *                 destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where the I1 packet was
 *                 sent to (own address).
 * @param rva      a pointer to a rendezvous association matching the HIT of
 *                 next hop.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 */
int hip_rvs_relay_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		     struct in6_addr *i1_daddr, HIP_RVA *rva, 
		     struct hip_stateless_info *i1_info)
{
	HIP_DEBUG("hip_rvs_relay_i1() invoked.\n");
	HIP_DEBUG_IN6ADDR("hip_rvs_relay_i1():  I1 source address", i1_saddr);
	HIP_DEBUG_IN6ADDR("hip_rvs_relay_i1():  I1 destination address", i1_daddr);
	HIP_DEBUG_HIT("hip_rvs_relay_i1(): Rendezvous association hit", &rva->hit);
	HIP_DEBUG("Rendezvous association port: %d.\n", rva->client_udp_port);
	HIP_DEBUG("I1 source port: %u, destination port: %u\n",
		  i1_info->src_port, i1_info->dst_port);
		
	struct hip_common *i1_to_be_relayed = NULL;
	struct hip_tlv_common *current_param = NULL;
	int err = 0, from_added = 0;
	struct in6_addr final_dst, local_addr;

	/* Get the destination IP address which the client has registered from
	   the rendezvous association. */
	/** @todo How to decide which IP address of rva->ip_addrs the to use? */
	hip_rvs_get_ip(rva, &final_dst, 0);

	HIP_IFEL(!(i1_to_be_relayed = hip_msg_alloc()), -ENOMEM,
		 "No memory to copy original I1\n");	

	/* I1 packet forwarding is achieved by rewriting the source and
	   destination IP addresses. */
	hip_build_network_hdr(i1_to_be_relayed, HIP_I1, 0,
			      &(i1->hits), &(i1->hitr));

	/* Adding FROM parameter. Loop through all the parameters in the
	   received I1 packet, and insert a new FROM parameter after the last
	   found FROM parameter. Notice that in most cases the incoming I1 has
	   no paramaters at all, and this "while" loop is skipped. Multiple
	   rvses en route to responder is one (and only?) case when the incoming
	   I1 packet has parameters. */
	while ((current_param = hip_get_next_param(i1, current_param)) != NULL)
	{
		HIP_DEBUG("Found parameter in I1.\n");
		/* Copy while type is smaller than or equal to FROM or a 
		   new FROM has already been added. */
		/** @todo Could use hip_get_param_type() here. */
		if (from_added || ntohs(current_param->type) <= HIP_PARAM_FROM)
		{
			HIP_DEBUG("Copying existing parameter to I1 packet "\
				  "to be relayed.\n");
			hip_build_param(i1_to_be_relayed,current_param);
			continue;
		}
		/* Parameter under inspections has greater type than FROM
		   parameter: insert a new FROM parameter between the last
		   found FROM parameter and "current_param". */
		else
		{
			HIP_DEBUG("Created new FROM and copied "\
				  "current parameter to relayed I1.\n");
			hip_build_param_from(i1_to_be_relayed, i1_saddr);
			hip_build_param(i1_to_be_relayed, current_param);
			from_added = 1;
		}
	}

	/* If the incoming I1 had no parameters after the existing FROM
	   parameters, new FROM parameter is not added until here. */
	if (!from_added)
	{
		HIP_DEBUG("No parameters found, adding a new FROM.\n");
		hip_build_param_from(i1_to_be_relayed, i1_saddr);
	}

	/* Adding RVS_HMAC parameter as the last parameter of the relayed
	   packet. Notice, that this presumes that there are no parameters
	   whose type value is greater than RVS_HMAC in the incoming I1
	   packet. */
	HIP_DEBUG("Adding a new RVS_HMAC parameter as the last parameter.\n");
	HIP_IFEL(hip_build_param_rvs_hmac_contents(i1_to_be_relayed,
						   &rva->hmac_our), -1,
		 "Building of RVS_HMAC failed.\n");
	
	/* If the client is behind NAT, the I1 packet is relayed on UDP. If
	   there is no NAT, the packet is relayed on raw HIP. Note that we
	   use NULL as source IP address instead of i1_daddr. A source address
	   is selected in the corresponding send function. */
	if(rva->client_udp_port == 0) {
		HIP_IFEL(hip_csum_send(NULL, &final_dst,
				       i1_info->src_port, i1_info->dst_port,
				       i1_to_be_relayed, NULL, 0), -1,
			 "Relaying I1 on raw HIP failed.\n");
		HIP_DEBUG_HIT("hip_rvs_relay_i1(): Relayed I1 on raw HIP to",
			      &final_dst);
	}
	else {
		HIP_IFEL(hip_nat_send_udp(NULL, &final_dst,
					 HIP_NAT_UDP_PORT, rva->client_udp_port,
					  i1_to_be_relayed, NULL, 0), -1,
			 "Relaying I1 on UDP failed.\n");
		HIP_DEBUG_HIT("hip_rvs_relay_i1(): Relayed I1 on UDP to",
			      &final_dst);
	}
		
 out_err:
	if(i1_to_be_relayed)
	{
		HIP_FREE(i1_to_be_relayed);
	}
	return err;
}

/**
 * Set a rendezvous server request flag for a host association.
 *
 * Set a rendezvous server request flag for a host association matching the
 * source/destination -hitpair. Calling this function indicates that the current
 * machine is requesting a rendezvous service for a host association entry. This
 * function is called when a host starts registering procedure to rendezvous
 * service by sending a @b I1 packet to the rendezvous server.
 *
 * @param  src_hit the source hit of a host association.
 * @param  dst_hit the destination hit of a host association.
 * @return zero on success, or negative error value if a matching entry is
 *         not found.
 */ 
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
