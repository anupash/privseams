// FIXME: whenever something that is replicated in beet db is
// modified, the modifications must be written there too.
#include "hadb.h"

HIP_HASHTABLE *hadb_hit;
//HIP_HASHTABLE *hadb_spi_list;

//static hip_list_t hadb_byhit[HIP_HADB_SIZE];

/* default set of miscellaneous function pointers. This has to be in the global
   scope. */

/** A transmission function set for sending raw HIP packets. */
hip_xmit_func_set_t default_xmit_func_set;
/** A transmission function set for NAT traversal. */
hip_xmit_func_set_t nat_xmit_func_set;
static hip_misc_func_set_t ahip_misc_func_set;
static hip_misc_func_set_t default_misc_func_set;
static hip_input_filter_func_set_t default_input_filter_func_set;
static hip_output_filter_func_set_t default_output_filter_func_set;
static hip_rcv_func_set_t default_rcv_func_set;
static hip_rcv_func_set_t ahip_rcv_func_set;
static hip_handle_func_set_t default_handle_func_set;
static hip_handle_func_set_t ahip_handle_func_set;
static hip_update_func_set_t default_update_func_set;
static hip_update_func_set_t ahip_update_func_set;

#if 0
void hip_hadb_delete_hs(struct hip_hit_spi *hs)
{
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	HIP_LOCK_HS(hs);
	hip_ht_delete(hadb_spi_list, hs);
	HIP_UNLOCK_HS(hs);
	HIP_FREE(hs);
}

void hip_hadb_hold_hs(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, struct hip_hit_spi);
}

void hip_hadb_put_hs(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, struct hip_hit_spi, hip_hadb_delete_hs);
}
#endif

unsigned long hip_hash_peer_addr(const void *ptr)
{
	struct in6_addr *addr = &((struct hip_peer_addr_list_item *)ptr)->address;
        uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, addr, sizeof(*addr), hash);

	return *((unsigned long *) hash);
}

int hip_match_peer_addr(const void *ptr1, const void *ptr2)
{
	return (hip_hash_peer_addr(ptr1) != hip_hash_peer_addr(ptr2));
}

void hip_hadb_hold_entry(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry,hip_ha_t);
}

void hip_hadb_put_entry(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, hip_ha_t, hip_hadb_delete_state);
}

#if 0
static void *hip_hadb_get_key_hit(void *entry)
{
	return (void *)&(((hip_ha_t *)entry)->hashkey);
        //return HIP_DB_GET_KEY_HIT(entry, hip_ha_t);
}
#endif

static void *hip_hadb_get_key_spi_list(void *entry)
{
	return (void *)(((struct hip_hit_spi *)entry)->spi);
}

static int hit_match(hip_ha_t *entry, void *our) {
	return ipv6_addr_cmp(our, &entry->hit_our) == 0;
}

//static hip_list_t hadb_byspi_list[HIP_HADB_SIZE];

/**
 * hip_hadb_rem_state_hit - Remove HA from HIT table
 * @param entry HA
 * HA must be locked.
 */
static inline void hip_hadb_rem_state_hit(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;
	HIP_DEBUG("\n");
	ha->hastate &= ~HIP_HASTATE_HITOK;
	hip_ht_delete(hadb_hit, entry);
}

/**
 * hip_hadb_remove_state_hit - Remove HA from HIT hash table.
 * @param ha HA
 */
static void hip_hadb_remove_state_hit(hip_ha_t *ha)
{
	HIP_LOCK_HA(ha);
	if ((ha->hastate & HIP_HASTATE_HITOK) == HIP_HASTATE_HITOK) {
		hip_hadb_rem_state_hit(ha);
	}
	HIP_UNLOCK_HA(ha);
}

/*
  Support for multiple inbound IPsec SAs:

  We need a separate hashtable containing elements HIT and SPI, which
  tells which HIT has the inbound SPI. When an ESP packet is received,
  we first get the SPI from it and perform a lookup on the HIT-SPI
  hashtable to get the mapping. Then we perform another lookup from
  the HIT hashtable using the HIT we got from the previous
  lookup. This way we get the HA beloning to the connection.

  hs = HIT-SPI (struct hip_hit_spi)

  (functions hip_ .. _hs)
*/


/*
 *
 * All the primitive functions up to this point are static, to force
 * some information hiding. The construct functions can access these
 * functions directly.
 *
 *
 */


/* PRIMITIVES */

#if 0
/* find HA by inbound SPI */
hip_ha_t *hip_hadb_find_byspi_list(u32 spi)
{
	struct hip_hit_spi *hs;
	hip_list_t *item, *tmp;
	hip_hit_t hit_our, hit_peer;
	hip_ha_t *ha;
	int i;

	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		//hs = (struct hip_hit_spi *) hip_ht_find(hadb_spi_list, (void *)spi);
		
	}

	if (!hs)
	{
		HIP_DEBUG("HIT-SPI not found for SPI=0x%x\n", spi);
		return NULL;
	}

	ipv6_addr_copy(&hit_our, &hs->hit_our);
	ipv6_addr_copy(&hit_peer, &hs->hit_peer);
	hip_hadb_put_hs(hs);

	ha = hip_hadb_find_byhits(&hit_our, &hit_peer);
	if (!ha) {
		HIP_DEBUG("HA not found for SPI=0x%x\n", spi);
	}

	return ha;
}
#endif

/**
 * This function searches for a hip_ha_t entry from the hip_hadb_hit
 * by a HIT pair (local,peer).
 */
hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
{
	hip_ha_t ha, *ret;
	memcpy(&ha.hit_our, hit, sizeof(hip_hit_t));
	memcpy(&ha.hit_peer, hit2, sizeof(hip_hit_t));
	HIP_DEBUG_HIT("HIT1", hit);
	HIP_DEBUG_HIT("HIT2", hit2);

	ret = hip_ht_find(hadb_hit, &ha);
	if (!ret) {
		memcpy(&ha.hit_peer, hit, sizeof(hip_hit_t));
		memcpy(&ha.hit_our, hit2, sizeof(hip_hit_t));
		ret = hip_ht_find(hadb_hit, &ha);
	}

	return ret;
}

/**
 * This function simply goes through all local HIs and tries
 * to find a HADB entry that matches the current HI and
 * the given peer hit. First matching HADB entry is then returned.
 *
 * @todo Find a better solution, see the text below:
 * This function is needed because we index the HADB now by
 * key values calculated from <peer_hit,local_hit> pairs. Unfortunately, in
 * some functions like the ipv6 stack hooks hip_get_saddr() and
 * hip_handle_output() we just can't know the local_hit so we have to
 * improvise and just try to find some HA entry.
 *
 * @note This way of finding HA entries doesn't work properly if we have 
 * multiple entries with the same peer_hit.
 * @note Don't use this function because it does not deal properly
 * with multiple source hits. Prefer hip_hadb_find_byhits() function.
 */
hip_ha_t *hip_hadb_try_to_find_by_peer_hit(hip_hit_t *hit)
{
	hip_list_t *item, *tmp;
	struct hip_host_id_entry *e;
	hip_ha_t *entry = NULL;
	hip_hit_t our_hit;
	int i;

	list_for_each_safe(item, tmp, hip_local_hostid_db, i)
	{
		e = list_entry(item);
		ipv6_addr_copy(&our_hit,&e->lhi.hit);
		HIP_DEBUG_HIT("try_to_find_by_peer_hit:", &our_hit);
		HIP_DEBUG_HIT("hit:", hit);
		entry = hip_hadb_find_byhits(hit, &our_hit);
		if (!entry) continue;
		else return entry;
	}
	return NULL;
}

/**
 * hip_hadb_insert_state - Insert state to hash tables.
 *
 * @todo SPI STUFF IS DEPRECATED
 *
 * Adds @ha to either SPI or HIT hash table, or _BOTH_.
 * As a side effect updates the hastate of the @ha.
 *
 * Function can be called even if the HA is in either or
 * both hash tables already.
 *
 * PRECONDITIONS: To add to the SPI hash table the @ha->spi_in
 * must be non-zero. To add to the HIT hash table the @ha->hit_peer
 * must be non-zero (tested with ipv6_addr_any).
 *
 * Returns the hastate of the HA:
 * HIP_HASTATE_VALID = HA added to (or is in) both hash tables
 * HIP_HASTATE_SPIOK = HA added to (or is in) SPI hash table
 * HIP_HASTATE_HITOK = HA added to (or is in) HIT hash table
 * HIP_HASTATE_INVALID = HA was not added, nor is in either of the hash tables.
 */
int hip_hadb_insert_state(hip_ha_t *ha)
{
	hip_hastate_t st;
	hip_ha_t *tmp;

	HIP_DEBUG("hip_hadb_insert_state() invoked.\n");

	/* assume already locked ha */

	HIP_ASSERT(!(ipv6_addr_any(&ha->hit_peer)));

	st = ha->hastate;

	if (!ipv6_addr_any(&ha->hit_peer) && !(st & HIP_HASTATE_HITOK))
	{
		HIP_HEXDUMP("ha->hit_our is: ", &ha->hit_our, 16);
		HIP_HEXDUMP("ha->hit_peer is: ", &ha->hit_peer, 16);
		tmp = hip_ht_find(hadb_hit, ha);
		if (!tmp)
		{
			hip_ht_add(hadb_hit, ha);
			st |= HIP_HASTATE_HITOK;
			HIP_DEBUG("New state added\n");
		}
		else
		{
			hip_db_put_ha(tmp, hip_hadb_delete_state);
			HIP_DEBUG("HIT already taken\n");
		}
	}

#ifdef CONFIG_HIP_ESCROW
	{
		HIP_KEA *kea;
		kea = hip_kea_find(&ha->hit_our);
		if (kea) {
			/** @todo Check conditions for escrow associations here 
			    (for now, there are none). */
			HIP_DEBUG("Escrow used for this entry: Initializing "\
				  "ha_state escrow fields.\n");
			ha->escrow_used = 1;
			ipv6_addr_copy(&ha->escrow_server_hit, &kea->server_hit);
			HIP_DEBUG_HIT("server hit saved: ", &kea->server_hit);
			hip_keadb_put_entry(kea);
		}
		else {
			HIP_DEBUG("Escrow not in use.\n");
		}
	}
#endif //CONFIG_HIP_ESCROW

	ha->hastate = st;
	return st;
}

/**
 * .
 *
 * Practically called only by when adding a HIT-IP mapping before base exchange.
 *
 * @param  local_hit  a pointer to... 
 * @param  peer_hit   a pointer to... 
 * @param  local_addr a pointer to... 
 * @param  peer_addr  a pointer to... 
 * @return 
 * @todo   Allow multiple mappings; base exchange should be initiated to allow
 *         of them in order to prevent local DoS.
 * @todo   Create a security policy for triggering base exchange.
 * @todo   Multiple identities support: alternative a) make generic HIT prefix
 *         based policy to work alternative b) add SP pair for all local HITs.
 */ 
int hip_hadb_add_peer_info_complete(hip_hit_t *local_hit,
				    hip_hit_t *peer_hit,
				    struct in6_addr *local_addr,
				    struct in6_addr *peer_addr)
{
	int err = 0;
	hip_ha_t *entry;
	
	HIP_DEBUG("hip_hadb_add_peer_info_complete() invoked.\n");
	HIP_DEBUG_HIT("Our HIT", local_hit);
	HIP_DEBUG_HIT("Peer HIT", peer_hit);
	HIP_DEBUG_IN6ADDR("Our addr", local_addr);
	HIP_DEBUG_IN6ADDR("Peer addr", peer_addr);
	
	entry = hip_hadb_find_byhits(local_hit, peer_hit);
	if (entry) hip_hadb_dump_spis_out(entry);
	HIP_IFEL(entry, 0, "Ignoring new mapping, old one exists\n");
	
	entry = hip_hadb_create_state(GFP_KERNEL);
	HIP_IFEL(!entry, -1, "");
	if (!entry) {
		HIP_ERROR("Unable to create a new entry\n");
		return -1;
	}
	
	_HIP_DEBUG("created a new sdb entry\n");

	ipv6_addr_copy(&entry->hit_peer, peer_hit);
	ipv6_addr_copy(&entry->hit_our, local_hit);
	ipv6_addr_copy(&entry->local_address, local_addr);
	
	/* If global NAT status is on, that is if the current host is behind
	   NAT, the NAT status of the host association is set on and the send
	   function set is set to "nat_xmit_func_set". */
	if(hip_nat_status && IN6_IS_ADDR_V4MAPPED(peer_addr)) {
		entry->nat_mode = 1;
		entry->peer_udp_port = HIP_NAT_UDP_PORT;
		entry->hadb_xmit_func = &nat_xmit_func_set;
	}
	else {
		entry->nat_mode = 0;
		entry->peer_udp_port = 0;
	}

#ifdef CONFIG_HIP_BLIND
	if(hip_blind_status)
		entry->blind = 1;
#endif
	if (hip_hidb_hit_is_our(peer_hit)) {
		HIP_DEBUG("Peer HIT is ours (loopback)\n");
		entry->is_loopback = 1;
	}

	hip_hadb_insert_state(entry);
	/* Released at the end */
	hip_hold_ha(entry);
	
	/* Add initial HIT-IP mapping. */
	err = hip_hadb_add_peer_addr(entry, peer_addr, 0, 0,
				     PEER_ADDR_STATE_ACTIVE);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		err = -2;
		goto out_err;
	}

	HIP_DEBUG_HIT("Peer HIT\n", peer_hit);
	HIP_DEBUG_HIT("Our HIT\n", &entry->hit_our);
	HIP_DEBUG_IN6ADDR("Our IPv6\n", &entry->local_address);
	HIP_DEBUG_IN6ADDR("Peer IPv6\n", peer_addr);
	HIP_IFEL(hip_setup_hit_sp_pair(peer_hit, local_hit,
				       local_addr, peer_addr, 0, 1, 0),
		 -1, "Error in setting the SPs\n");

out_err:
	if (entry)
		hip_db_put_ha(entry, hip_hadb_delete_state);
	return err;
}

/**
 * .
 *
 * @param  entry         a pointer to...
 * @param  peer_map_void a pointer to...
 * @return ...
 */ 
int hip_hadb_add_peer_info_wrapper(struct hip_host_id_entry *entry,
				   void *peer_map_void)
{
	struct hip_peer_map_info *peer_map = peer_map_void;
	int err = 0;

	HIP_DEBUG("hip_hadb_add_peer_info_wrapper() invoked.\n");
	HIP_IFEL(hip_hadb_add_peer_info_complete(&entry->lhi.hit,
						 &peer_map->peer_hit,
						 &peer_map->our_addr,
						 &peer_map->peer_addr), -1,
		 "Failed to add peer info\n");

 out_err:
	return err;
}

int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
{
	int err = 0;
	hip_ha_t *entry;
	struct hip_peer_map_info peer_map;

	HIP_DEBUG("hip_hadb_add_peer_info() invoked.\n");
	HIP_DEBUG_HIT("Peer HIT", peer_hit);
	HIP_DEBUG_IN6ADDR("Peer addr", peer_addr);

	memcpy(&peer_map.peer_addr, peer_addr, sizeof(struct in6_addr));
	memcpy(&peer_map.peer_hit, peer_hit, sizeof(hip_hit_t));

	HIP_IFEL(hip_select_source_address(&peer_map.our_addr,
					   &peer_map.peer_addr), -1,
		 "Cannot find source address\n");

	HIP_DEBUG("Source address found\n");

	HIP_IFEL(hip_for_each_hi(hip_hadb_add_peer_info_wrapper, &peer_map), 0,
	         "for_each_hi err.\n");	
	
 out_err:
	return err;
}

int hip_add_peer_map(const struct hip_common *input)
{
	struct in6_addr *hit, *ip;
	int err = 0;
	_HIP_HEXDUMP("packet", input,  hip_get_msg_total_len(input));
	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out_err;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out_err;
	}
	
	err = hip_hadb_add_peer_info(hit, ip);
	_HIP_DEBUG_HIT("hip_add_map_info peer's real hit=", hit);
	_HIP_ASSERT(hit_is_opportunistic_hashed_hit(hit));
 	if (err) {
 		HIP_ERROR("Failed to insert peer map (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;

}

int hip_hadb_del_peer_info_wrapper(hip_ha_t *entry, void *peer_hit)
{
	hip_hit_t *hit = peer_hit;
	int err = 0;

	if (memcmp(hit, &entry->hit_peer, sizeof(hip_hit_t)) == 0)
	{
		hip_hadb_delete_state(entry);
	}

 out_err:
	return err;
}

int hip_hadb_del_peer_map(hip_hit_t *hit)
{
	int err = 0;

	HIP_IFEL(hip_for_each_ha(hip_hadb_del_peer_info_wrapper, hit), -1,
	         "for_each_hi err.\n");	
	
 out_err:
	return err;
}

#if 0
/**
 * .
 * 
 * @param hit_peer a pointer to ...
 * @param hit_our  a pointer to ...
 * @param hit_spi  ...
 * @ returns       0 if @spi was added to the inbound SPI list of the HA @ha,
 *                  otherwise < 0.
 */
int hip_hadb_insert_state_spi_list(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
				   uint32_t spi)
{
	int err = 0;
	HIP_INSERT_STATE_SPI_LIST(&hadb_spi_list, hip_hadb_put_entry,
				  hit_our, hit_peer, spi);
	return err;
}
#endif

/**
 * Allocates and initializes a new HA structure.
 * 
 * @gfpmask a mask passed directly to HIP_MALLOC().
 * @return NULL if memory allocation failed, otherwise the HA.
 */
hip_ha_t *hip_hadb_create_state(int gfpmask)
{
	hip_ha_t *entry = NULL;
	int err = 0;

	entry = (hip_ha_t *)HIP_MALLOC(sizeof(struct hip_hadb_state), gfpmask);
	if (!entry)
		return NULL;

	memset(entry, 0, sizeof(*entry));

/*	INIT_LIST_HEAD(&entry->next_hit);
	INIT_LIST_HEAD(&entry->spis_in);
	INIT_LIST_HEAD(&entry->spis_out);*/

	entry->spis_in = hip_ht_init(hip_hash_spi, hip_match_spi);
	entry->spis_out = hip_ht_init(hip_hash_spi, hip_match_spi);
	
	HIP_LOCK_INIT(entry);
	//atomic_set(&entry->refcnt,0);

	entry->state = HIP_STATE_UNASSOCIATED;
	entry->hastate = HIP_HASTATE_INVALID;

        /* SYNCH: does it really need to be syncronized to beet-xfrm? -miika
	   No dst hit. */
	
	/* Function pointer sets which define HIP behavior in respect to the
	   hadb_entry. */
	HIP_IFEL(hip_hadb_set_rcv_function_set(entry, &default_rcv_func_set),
		 -1, "Can't set new function pointer set\n");
	HIP_IFEL(hip_hadb_set_handle_function_set(entry,
						  &default_handle_func_set),
		 -1, "Can't set new function pointer set\n");
	HIP_IFEL(hip_hadb_set_update_function_set(entry,
						  &default_update_func_set),
		 -1, "Can't set new function pointer set\n");
		    
	HIP_IFEL(hip_hadb_set_misc_function_set(entry, &default_misc_func_set),
		 -1, "Can't set new function pointer set\n");
	/* Set the xmit function set as function set for sending raw HIP. */
	HIP_IFEL(hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set),
		 -1, "Can't set new function pointer set\n");

	HIP_IFEL(hip_hadb_set_input_filter_function_set(
			 entry, &default_input_filter_func_set),
		 -1, "Can't set new function pointer set\n");

	HIP_IFEL(hip_hadb_set_output_filter_function_set(
			 entry,& default_output_filter_func_set),
		 -1, "Can't set new function pointer set\n");

 out_err:
	
	return entry;
}

/* END OF PRIMITIVE FUNCTIONS */

/* select the preferred address within the addresses of the given SPI */
/* selected address is copied to @addr, it is is non-NULL */
int hip_hadb_select_spi_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out, struct in6_addr *addr)
{
	int err = 0, i;
	struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;
	hip_list_t *item, *tmp;

	list_for_each_safe(item, tmp, spi_out->peer_addr_list, i)
	{
		s = list_entry(item);
		if (s->address_state != PEER_ADDR_STATE_ACTIVE)
		{
			_HIP_DEBUG("skipping non-active address %s\n",addrstr);
			continue;
		}
		
		if (candidate)
		{
			int this_is_later;
			this_is_later = hip_timeval_diff(&s->modified_time, &latest, &dt);
			_HIP_DEBUG("latest=%ld.%06ld\n", latest.tv_sec, latest.tv_usec);
			_HIP_DEBUG("dt=%ld.%06ld\n", dt.tv_sec, dt.tv_usec);
			if (this_is_later)
			{
				_HIP_DEBUG("is later, change\n");
				memcpy(&latest, &s->modified_time, sizeof(struct timeval));
				candidate = s;
			}
		}
		else
		{
			candidate = s;
			memcpy(&latest, &s->modified_time, sizeof(struct timeval));
		}
	}
	
	if (!candidate)
	{
		HIP_ERROR("did not find usable peer address\n");
		HIP_DEBUG("todo: select from other SPIs ?\n");
		/* todo: select other SPI as the default SPI out */
		err = -ENOMSG;
	}
	else ipv6_addr_copy(addr, &candidate->address);

	return err;
}

/**
 * hip_hadb_get_peer_addr - Get some of the peer's usable IPv6 address
 * @param entry corresponding hadb entry of the peer
 * @param addr where the selected IPv6 address of the peer is copied to
 *
 * Current destination address selection algorithm:
 * 1. use preferred address of the HA, if any (should be set)
 *
 * tkoponen: these are useless: ?
 * 2. use preferred address of the default outbound SPI, if any
 * (should be set, suspect bug if we get this far)
 *
 * 3. select among the active addresses of the default outbound SPI
 * (select the address which was added/updated last)
 *
 * @return 0 if some of the addresses was copied successfully, else < 0.
 */
int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr)
{
	int err = 0;
	//	struct hip_spi_out_item *spi_out;

	/* assume already locked entry */

	HIP_DEBUG_HIT("entry def addr", &entry->preferred_address);
	ipv6_addr_copy(addr, &entry->preferred_address);
        return err;
}

/**
 * hip_hadb_get_peer_addr_info - get infomation on the given peer IPv6 address
 * @param entry corresponding hadb entry of the peer
 * @param addr the IPv6 address for which the information is to be retrieved
 * @param spi where the outbound SPI of @c addr is copied to
 * @param lifetime where the lifetime of @c addr is copied to
 * @param modified_time where the time when @c addr was added or updated is copied to
 *
 * @return if @c entry has the address @c addr in its peer address list
 * parameters @c spi, @lifetime, and @c modified_time are
 * assigned if they are non-NULL and 1 is returned, else @c interface_id
 * and @c lifetime are not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *spi, uint32_t *lifetime,
				struct timeval *modified_time)
{
	struct hip_peer_addr_list_item *s;
	int i = 1, ii, iii;
	struct hip_spi_out_item *spi_out;
	hip_list_t *item, *tmp, *a_item, *a_tmp;

	/* assumes already locked entry */
	list_for_each_safe(item, tmp, entry->spis_out, ii)
	{
		spi_out = list_entry(item);
		list_for_each_safe(a_item, a_tmp, spi_out->peer_addr_list, iii)
		{
			s = list_entry(a_item);
			if (!ipv6_addr_cmp(&s->address, addr))
			{
				_HIP_DEBUG("found\n");
				if (lifetime)
					*lifetime = s->lifetime;
				if (modified_time)
				{
					modified_time->tv_sec = s->modified_time.tv_sec;
					modified_time->tv_usec = s->modified_time.tv_usec;
				}
				if (spi)
					*spi = spi_out->spi;
				return 1;
			}
			i++;
		}
	}

	_HIP_DEBUG("not found\n");
	return 0;
}

/**
 * Adds a new peer IPv6 address to the entry's list of peer addresses.
 * @param entry corresponding hadb entry of the peer
 * @param new_addr IPv6 address to be added
 * @param spi outbound SPI to which the @c new_addr is related to
 * @param lifetime address lifetime of the address
 * @param state address state
 *
 * @return if @c new_addr already exists, 0 is returned. If address was
 * added successfully 0 is returned, else < 0.
 */
int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t spi, uint32_t lifetime, int state)
{
	int err = 0, i;
	struct hip_peer_addr_list_item *a_item;
	char addrstr[INET6_ADDRSTRLEN];
	uint32_t prev_spi;
	struct hip_spi_out_item *spi_out;
	int found_spi_list = 0;
	hip_list_t *item, *tmp;

	/* assumes already locked entry */

	/* check if we are adding the peer's address during the base
	 * exchange */
	if (spi == 0) {
		HIP_DEBUG("SPI is 0, set address as the bex address\n");
		if (!ipv6_addr_any(&entry->preferred_address)) {
			hip_in6_ntop(&entry->preferred_address, addrstr);
			HIP_DEBUG("warning, overwriting existing preferred address %s\n",
				  addrstr);
		}
		ipv6_addr_copy(&entry->preferred_address, new_addr);
		goto out_err;
	}

	/** @todo replace following with hip_hadb_get_spi_list */
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_out = list_entry(item);
		if (spi_out->spi == spi)
		{
			found_spi_list = 1;
			break;
		}
	}

	if (!found_spi_list)
	{
		HIP_ERROR("did not find SPI list for SPI 0x%x\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	err = hip_hadb_get_peer_addr_info(entry, new_addr, &prev_spi, NULL, NULL);
	if (err)
	{
		/** @todo validate previous vs. new interface id for 
		    the new_addr ? */
		if (prev_spi != spi)
			HIP_DEBUG("todo: SPI changed: prev=%u new=%u\n", prev_spi,
				  spi);

		HIP_DEBUG("duplicate address not added (todo: update address lifetime ?)\n");
		/** @todo update address lifetime ? */
		err = 0;
		goto out_err;
	}

	a_item = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
	if (!a_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	_HIP_DEBUG("HIP_MALLOCed item=0x%p\n", item);

	a_item->lifetime = lifetime;
	ipv6_addr_copy(&a_item->address, new_addr);
	a_item->address_state = state;
	do_gettimeofday(&a_item->modified_time);

	list_add(a_item, spi_out->peer_addr_list);

out_err:
	return err;
}

/**
 * hip_hadb_delete_peer_address_list_one - delete IPv6 address from the entry's list 
 * of peer addresses
 * @param entry corresponding hadb entry of the peer
 * @param addr IPv6 address to be deleted
 */
void hip_hadb_delete_peer_addrlist_one(hip_ha_t *entry, struct in6_addr *addr) 
{
	struct hip_peer_addr_list_item *a_item;
	int i = 1, ii, iii;
	struct hip_spi_out_item *spi_out;
	hip_list_t *spi_item, *spi_tmp, *item, *tmp;

	/* possibly deprecated function .. */

	HIP_LOCK_HA(entry);
	
	list_for_each_safe(spi_item, spi_tmp, entry->spis_out, ii)
	{
		spi_out = list_entry(spi_item);
		list_for_each_safe(item, tmp, spi_out->peer_addr_list, iii)
		{
			a_item = list_entry(item);
			if (!ipv6_addr_cmp(&a_item->address, addr))
			{
				_HIP_DEBUG("deleting address\n");
				list_del(a_item, spi_out->peer_addr_list);
				HIP_FREE(a_item);
				/* if address is on more than one spi list then do not goto out */
				goto out;
			}
			i++;
		}
	}
 out:
	HIP_UNLOCK_HA(entry);
	return;
}

/**
 * Currently deletes the whole entry...
 */		
int hip_del_peer_info(hip_hit_t *our_hit, hip_hit_t *peer_hit,
		      struct in6_addr *addr)
{
	hip_ha_t *ha;

	ha = hip_hadb_find_byhits(our_hit, peer_hit);
	if (!ha) {
		return -ENOENT;
	}


	if (!ipv6_addr_any(addr)) {
	  	hip_hadb_delete_inbound_spi(ha, 0);
		hip_hadb_delete_outbound_spi(ha, 0);
		hip_hadb_remove_state_hit(ha);
		/* by now, if everything is according to plans, the refcnt
		   should be 1 */
		HIP_DEBUG_HIT("our HIT", &ha->hit_our);
		HIP_DEBUG_HIT("peer HIT", &ha->hit_peer);
		hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our,
				       IPPROTO_ESP, 1);
		/* Not going to "put" the entry because it has been removed
		   from the hashtable already (hip_exit won't find it
		   anymore). */
		hip_hadb_delete_state(ha);
		hip_db_put_ha(ha, hip_hadb_delete_state);
		/* and now zero --> deleted*/
	} else {
		hip_hadb_delete_peer_addrlist_one(ha, addr);
		hip_db_put_ha(ha, hip_hadb_delete_state);
	}


	return 0;
}

/* assume already locked entry */
// SYNC
int hip_hadb_add_inbound_spi(hip_ha_t *entry, struct hip_spi_in_item *data)
{
	int err = 0, i;
	struct hip_spi_in_item *spi_item;
	uint32_t spi_in;
	hip_list_t *item, *tmp;
	spi_in = data->spi;

	/* assumes locked entry */
	_HIP_DEBUG("SPI_in=0x%x\n", spi_in);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi_in)
		{
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_in);
			goto out;
		}
	}
	
	spi_item = (struct hip_spi_in_item *)HIP_MALLOC(sizeof(struct hip_spi_in_item), GFP_ATOMIC);
	if (!spi_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(spi_item, data, sizeof(struct hip_spi_in_item));
	spi_item->timestamp = jiffies;
	list_add(spi_item, entry->spis_in);
	spi_item->addresses = NULL;
	spi_item->addresses_n = 0;
	HIP_DEBUG("added SPI 0x%x to the inbound SPI list\n", spi_in);
	// hip_hold_ha(entry); ?

	/*_HIP_DEBUG("inserting SPI to HIT-SPI hashtable\n");
	err = hip_hadb_insert_state_spi_list(&entry->hit_peer, &entry->hit_our, spi_in);
	if (err == -EEXIST) err = 0;*/

out_err:
out:
	return err;
}

/* assume already locked entry */
// SYNCH
int hip_hadb_add_outbound_spi(hip_ha_t *entry, struct hip_spi_out_item *data)
{
	int err = 0, i;
	struct hip_spi_out_item *spi_item;
	uint32_t spi_out;
	hip_list_t *item, *tmp;

	/* assumes locked entry ? */
	spi_out = data->spi;

	_HIP_DEBUG("SPI_out=0x%x\n", spi_out);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi_out)
		{
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_out);
			goto out;
		}
	}

	spi_item = (struct hip_spi_out_item *)HIP_MALLOC(sizeof(struct hip_spi_out_item), GFP_ATOMIC);
	if (!spi_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(spi_item, data, sizeof(struct hip_spi_out_item));
// 	INIT_LIST_HEAD(&spi_item->peer_addr_list);
	spi_item->peer_addr_list = hip_ht_init(hip_hash_peer_addr, hip_match_peer_addr);
	ipv6_addr_copy(&spi_item->preferred_address, &in6addr_any);
	list_add(spi_item, entry->spis_out);
	HIP_DEBUG("added SPI 0x%x to the outbound SPI list\n", spi_out);

 out_err:
 out:
	return err;
}

/* assume already locked entry */
int hip_hadb_add_spi(hip_ha_t *entry, int direction, void *data)
{
	int err = -EINVAL;

	if (direction == HIP_SPI_DIRECTION_IN)
		err = hip_hadb_add_inbound_spi(entry, (struct hip_spi_in_item *) data);
	else if (direction == HIP_SPI_DIRECTION_OUT)
		err = hip_hadb_add_outbound_spi(entry, (struct hip_spi_out_item *) data);
	else
		HIP_ERROR("bug, invalid direction %d\n", direction);

	return err;
}


/* Set the ifindex of given SPI */
/* assumes locked HA */
void hip_hadb_set_spi_ifindex(hip_ha_t *entry, uint32_t spi, int ifindex)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes that inbound spi already exists in ha's spis_in */
	HIP_DEBUG("SPI=0x%x ifindex=%d\n", spi, ifindex);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("found updated spi-ifindex mapping\n");
			spi_item->ifindex = ifindex;
			return;
		}
	}
	HIP_DEBUG("SPI not found, returning\n");
}

/* Get the ifindex of given SPI, returns 0 if SPI was not found */
int hip_hadb_get_spi_ifindex(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->spi == spi || spi_item->new_spi == spi)
		{
			_HIP_DEBUG("found\n");
			return spi_item->ifindex;
		}
	}
	HIP_DEBUG("ifindex not found for the SPI 0x%x\n", spi);
	return 0;
}

/* Get the SPI of given ifindex, returns 0 if ifindex was not found  */
uint32_t hip_hadb_get_spi(hip_ha_t *entry, int ifindex)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("ifindex=%d\n", ifindex);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->ifindex == ifindex)
		{
			HIP_DEBUG("found SPI 0x%x\n", spi_item->spi);
			return spi_item->spi;
		}
	}

	HIP_DEBUG("SPI not found for the ifindex\n");
	return 0;
}

uint32_t hip_update_get_prev_spi_in(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
				spi_item->ifindex, spi_item->spi, spi_item->nes_spi_out, spi_item->seq_update_id);
		if (spi_item->seq_update_id == peer_update_id) {
			HIP_DEBUG("found SPI 0x%x\n", spi_item->spi);
			return spi_item->spi;
		}
	}
	HIP_DEBUG("SPI not found\n");
	return 0;
}

/* Get the SPI of the SA belonging to the interface through
   which we received the UPDATE */
/* also sets updating flag of SPI to 1 */
uint32_t hip_get_spi_to_update_in_established(hip_ha_t *entry, struct in6_addr *dev_addr)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;
	int ifindex;

	HIP_DEBUG_HIT("dst dev_addr", dev_addr);
	ifindex = hip_devaddr2ifindex(dev_addr);
	HIP_DEBUG("ifindex of dst dev=%d\n", ifindex);
	if (!ifindex)
		return 0;

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->ifindex == ifindex)
		{
			spi_item->updating = 1;
			return spi_item->spi;
		}
	}

	HIP_DEBUG("SPI not found for ifindex\n");
	return 0;
}

void hip_set_spi_update_status(hip_ha_t *entry, uint32_t spi, int set)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("spi=0x%x set=%d\n", spi, set);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x updating=%d\n",
				spi_item->ifindex, spi_item->spi, spi_item->updating);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("setting updating status to %d\n", set);
			spi_item->updating = set;
			break;
		}
	}
}

void hip_update_clear_status(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x\n", spi_item->spi);
		if (spi_item->spi == spi)
		{
			_HIP_DEBUG("clearing SPI status\n");
			spi_item->update_state_flags = 0;
			memset(&spi_item->stored_received_esp_info, 0,
					sizeof(struct hip_esp_info));
			break;
		}
	}
}

/* spi_out is the SPI which was in the received NES Old SPI field */
void hip_update_set_new_spi_in(hip_ha_t *entry, uint32_t spi, uint32_t new_spi,
			       uint32_t spi_out /* test */)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;
	
	_HIP_DEBUG("spi=0x%x new_spi=0x%x spi_out=0x%x\n", spi, new_spi, spi_out);

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
				spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("setting new_spi\n");
			if (!spi_item->updating)
			{
				_HIP_ERROR("SA update not in progress, continuing anyway\n");
			}
			if ((spi_item->spi != spi_item->new_spi) && spi_item->new_spi)
			{
				HIP_ERROR("warning: previous new_spi is not zero: 0x%x\n",
						spi_item->new_spi);
			}
			spi_item->new_spi = new_spi;
			spi_item->esp_info_spi_out = spi_out; /* maybe useless */
			break;
		}
	}
}

/* just sets the new_spi field */
void hip_update_set_new_spi_out(hip_ha_t *entry, uint32_t spi, uint32_t new_spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x new_spi=0x%x\n", spi, new_spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
				spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			_HIP_DEBUG("setting new_spi\n");
			if (spi_item->new_spi)
			{
				HIP_ERROR("previous new_spi is not zero: 0x%x\n", spi_item->new_spi);
				HIP_ERROR("todo: delete previous new_spi\n");
			}
			spi_item->new_spi = new_spi;
			break;
		}
	}
}


uint32_t hip_update_get_new_spi_in(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
			  spi_item->spi, spi_item->new_spi);
		if (spi_item->seq_update_id == peer_update_id)
		{
			if (spi_item->new_spi)
				return spi_item->new_spi;
			return spi_item->spi;
		}
	}
	HIP_DEBUG("New SPI not found\n");
	return 0;
}

/* switch from Old SPI to New SPI (inbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_in(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("old_spi=0x%x\n", old_spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x new_spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
			   spi_item->ifindex, item->spi, spi_item->new_spi,
			   spi_item->nes_spi_out, spi_item->seq_update_id);
		if (spi_item->spi == old_spi)
		{
			_HIP_DEBUG("switching\n");
			spi_item->spi = spi_item->new_spi;
			spi_item->new_spi = 0;
			spi_item->esp_info_spi_out = 0;
			break;
		}
	}
}

/* switch from Old SPI to New SPI (outbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_out(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("old_spi=0x%x\n", old_spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x seq_id=%u\n",
			   spi_item->spi, spi_item->new_spi, spi_item->seq_update_id);
		if (spi_item->spi == old_spi)
		{
			_HIP_DEBUG("switching\n");
			spi_item->spi = spi_item->new_spi;
			spi_item->new_spi = 0;
			break;
		}
	}
}


void hip_update_set_status(hip_ha_t *entry, uint32_t spi, int set_flags,
			   uint32_t update_id, int update_flags_or,
			   struct hip_esp_info *esp_info,
			   uint16_t keymat_index)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x update_id=%u update_flags_or=0x%x keymat_index=%u esp_info=0x%p\n",
		   spi, update_id, update_flags_or, keymat_index, esp_info);
	if (esp_info)
		_HIP_DEBUG("esp_info: old_spi=0x%x new_spi=0x%x keymat_index=%u\n",
			   ntohl(esp_info->old_spi), ntohl(esp_info->new_spi), ntohs(esp_info->keymat_index));

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n", spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			_HIP_DEBUG("setting new values\n");
			if (set_flags & 0x1) spi_item->seq_update_id = update_id;
			if (set_flags & 0x2) spi_item->update_state_flags |= update_flags_or;
			if (esp_info && (set_flags & 0x4))
			{
				spi_item->stored_received_esp_info.old_spi = esp_info->old_spi;
				spi_item->stored_received_esp_info.new_spi = esp_info->new_spi;
				spi_item->stored_received_esp_info.keymat_index = esp_info->keymat_index;
			}
			if (set_flags & 0x8) spi_item->keymat_index = keymat_index;

			return;
		}
	}
	HIP_ERROR("SPI not found\n");
}


/* returns 1 if given SPI belongs to the SA having direction
 * @direction, else 0. If @test_new_spi is 1 then test new_spi instead
 * of spi */
int hip_update_exists_spi(hip_ha_t *entry, uint32_t spi,
			       int direction, int test_new_spi)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	int i;

	/* assumes locked entry  */

	_HIP_DEBUG("spi=0x%x direction=%d test_new_spi=%d\n",
		  spi, direction, test_new_spi);

	if (direction == HIP_SPI_DIRECTION_IN)
	{
		list_for_each_safe(item, tmp, entry->spis_in, i)
		{
			spi_item = list_entry(item);
			_HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n",
				   spi_item->spi, spi_item->new_spi);
			if ( (spi_item->spi == spi && !test_new_spi) ||
			     (spi_item->new_spi == spi && test_new_spi) )
				return 1;
		}
	}
	else
	{
		list_for_each_safe(item, tmp, entry->spis_out, i)
		{
			spi_item = list_entry(item);
			_HIP_DEBUG("test item: spi_out=0x%x new_spi=0x%x\n",
				   spi_item->spi, spi_item->new_spi);
			if ( (spi_item->spi == spi && !test_new_spi) ||
			     (spi_item->new_spi == spi && test_new_spi) )
				return 1;
		}
	}
	HIP_DEBUG("not found\n");
	return 0;
}

/* Get an usable outbound SPI, SPI must contain ACTIVE addresses */
/* todo: return void instead of spi */

/* returns the new default outbound SPI is succesful, or 0 if no
 * usable address was found */
uint32_t hip_hadb_relookup_default_out(hip_ha_t *entry)
{
	uint32_t spi = 0;
	struct hip_spi_out_item *spi_out;
	hip_list_t *item, *tmp;
	int i;

	/* assumes locked entry  */

	HIP_DEBUG("\n");
	/* latest outbound SPIs are usually in the beginning of the list */
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_out = list_entry(item);

		int ret;
		struct in6_addr addr;

		_HIP_DEBUG("checking SPI 0x%x\n", spi_out->spi);
		ret = hip_hadb_select_spi_addr(entry, spi_out, &addr);
		if (ret == 0)
		{
			hip_hadb_set_default_out_addr(entry, spi_out, &addr);
			spi = spi_out->spi;
			goto out;
		}
	}

	if (spi)
		HIP_DEBUG("Set SPI 0x%x as the default outbound SPI\n", spi);
	else
		HIP_DEBUG("Did not find an usable outbound SPI\n");
 out:
	return spi;
}

/* if add is non-NULL, set addr as the default address for both
 * entry's default address and outbound SPI list's default address*/

/* if addr is null, select some address from the SPI list */
void hip_hadb_set_default_out_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out,
				   struct in6_addr *addr)
{
	HIP_DEBUG("\n");

	if (!spi_out)
	{
		HIP_ERROR("NULL spi_out\n");
		return;
	}

	if (addr)
	{
		HIP_DEBUG("testing, setting given address as default out addr\n");
		ipv6_addr_copy(&spi_out->preferred_address, addr);
		ipv6_addr_copy(&entry->preferred_address, addr);
	}
	else
	{
		/* useless ? */
		struct in6_addr a;
		int err = hip_hadb_select_spi_addr(entry, spi_out, &a);
		_HIP_DEBUG("setting address as default out addr\n");
		if (!err)
		{
			ipv6_addr_copy(&spi_out->preferred_address, &a);
			ipv6_addr_copy(&entry->preferred_address, &a);
			HIP_DEBUG("default out addr\n",
				  &entry->preferred_address);
		}
		else HIP_ERROR("couldn't select and set preferred address\n");
	}
	HIP_DEBUG("setting default SPI out to 0x%x\n", spi_out->spi);
	entry->default_spi_out = spi_out->spi;
}

/* have_esp_info is 1, if there is ESP_INFO in the same packet as the ACK was */
void hip_update_handle_ack(hip_ha_t *entry, struct hip_ack *ack, int have_esp_info){
	size_t n, i;
	uint32_t *peer_update_id;

	/* assumes locked entry  */

	HIP_DEBUG("have_esp_info=%d\n", have_esp_info);

	if (!ack)
	{
		HIP_ERROR("NULL ack\n");
		goto out_err;
	}

	if (hip_get_param_contents_len(ack) % sizeof(uint32_t))
	{
		HIP_ERROR("ACK param length not divisible by 4 (%u)\n",
			  hip_get_param_contents_len(ack));
		goto out_err;
	}

	n = hip_get_param_contents_len(ack) / sizeof(uint32_t);
	HIP_DEBUG("%d pUIDs in ACK param\n", n);
	peer_update_id = (uint32_t *) ((void *)ack+sizeof(struct hip_tlv_common));
	for (i = 0; i < n; i++, peer_update_id++)
	{
		hip_list_t *item, *tmp;
		struct hip_spi_in_item *in_item;
		uint32_t puid = ntohl(*peer_update_id);
		int i;

		_HIP_DEBUG("peer Update ID=%u\n", puid);

		/* see if your ESP_INFO is acked and maybe if corresponging ESP_INFO was received */
		list_for_each_safe(item, tmp, entry->spis_in, i)
		{
			in_item = list_entry(item);
			_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
				   in_item->spi, in_item->seq_update_id);
			if (in_item->seq_update_id == puid)
			{
				_HIP_DEBUG("SEQ and ACK match\n");
				in_item->update_state_flags |= 0x1; /* recv'd ACK */
				if (have_esp_info) in_item->update_state_flags |= 0x2; /* recv'd also ESP_INFO */
			}
		}

	}
 out_err:
	return;
}



void hip_update_handle_esp_info(hip_ha_t *entry, uint32_t peer_update_id)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	int i;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
			   spi_item->spi, spi_item->seq_update_id);
		if (spi_item->seq_update_id == peer_update_id)
		{
			_HIP_DEBUG("received peer's ESP_INFO\n");
			spi_item->update_state_flags |= 0x2; /* recv'd ESP_INFO */
		}
	}
}

/* works if update contains only one ESP_INFO */
int hip_update_get_spi_keymat_index(hip_ha_t *entry, uint32_t peer_update_id)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	int i;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi_in=0x%x seq_update_id=%u keymat_index=%u\n",
			   spi_item->spi, item->seq_update_id, item->keymat_index);
		if (spi_item->seq_update_id == peer_update_id)
		{
			return spi_item->keymat_index;
		}
	}
	return 0;
}

int hip_update_send_echo(hip_ha_t *entry,
			 uint32_t spi_out,
			 struct hip_peer_addr_list_item *addr){
	
	int err = 0;
	struct hip_common *update_packet = NULL;

	HIP_DEBUG_HIT("new addr to check", &addr->address);
	
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	HIP_IFEL(hip_build_verification_pkt(entry, update_packet, addr, 
					    &entry->hit_peer, &entry->hit_our),
		 -1, "Building Echo Packet failed\n");

	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(&entry->local_address, &addr->address,
			      HIP_NAT_UDP_PORT, entry->peer_udp_port,
			      update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet with echo data failed.\n");
	
 out_err:
	return err;

}

/* todo: use jiffies instead of timestamp */
uint32_t hip_hadb_get_latest_inbound_spi(hip_ha_t *entry)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;
	int i;

	/* assumes already locked entry */
	
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		if (now - spi_item->timestamp < t)
		{
			spi = spi_item->spi;
			t = now - spi_item->timestamp;
		}
	}
	
	_HIP_DEBUG("newest spi_in is 0x%x\n", spi);
	return spi;
}

/* get pointer to the outbound SPI list or NULL if the outbound SPI
   list does not exist */
struct hip_spi_out_item *hip_hadb_get_spi_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes already locked entry */
	
	_HIP_DEBUG("Search spi list for SPI=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("search: 0x%x ?= 0x%x\n", spi_item->spi, spi);	
		if (spi_item->spi == spi) return spi_item;
	}

	return NULL;
}

/* get pointer to the inbound SPI list or NULL if SPI list does not exist */
struct hip_spi_in_item *hip_hadb_get_spi_in_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes already locked entry */

	HIP_DEBUG("SPI=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi) return spi_item;
	}

	return NULL;
}

/* add an address belonging to the SPI list */
/* or update old values */
int hip_hadb_add_addr_to_spi(hip_ha_t *entry, uint32_t spi,
			     struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr)
{
	int err = 0, new = 1, i;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a;
	hip_list_t *item, *tmp;
	struct in6_addr *preferred_address; 
	/* Assumes already locked entry */
	HIP_DEBUG("spi=0x%x is_preferred_addr=%d\n", spi, is_preferred_addr);

	spi_list = hip_hadb_get_spi_list(entry, spi);
	if (!spi_list)
	{
		HIP_ERROR("SPI list for 0x%x not found\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	/* Check if addr already exists. If yes, then just update values. */
	list_for_each_safe(item, tmp, spi_list->peer_addr_list, i)
	{
		a = list_entry(item);
		if (!ipv6_addr_cmp(&a->address, addr))
		{
			// Do we send a verification if state is unverified?
			// The address should be awaiting verifivation already
			new_addr = a;
			new = 0;
			break;
		}
	}

	if (new)
	{
		HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), 0);
		if (!new_addr)
		{
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	}
	else HIP_DEBUG("update old addr item\n");
	
	new_addr->lifetime = lifetime;
	if (new) ipv6_addr_copy(&new_addr->address, addr);

	/* If the address is already bound, its lifetime is updated.
	   If the status of the address is DEPRECATED, the status is
	   changed to UNVERIFIED.  If the address is not already bound,
	   the address is added, and its status is set to UNVERIFIED. */
	if (!new)
	{
		switch (new_addr->address_state)
		{
		case PEER_ADDR_STATE_DEPRECATED:
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			HIP_DEBUG("updated address state DEPRECATED->UNVERIFIED\n");
			break;
 		case PEER_ADDR_STATE_ACTIVE:
			HIP_DEBUG("address state stays in ACTIVE\n");
			break;
		default:
			// Does this mean that unverified cant be here? Why?
			HIP_ERROR("state is UNVERIFIED, shouldn't even be here ?\n");
			break;
		}
	}
	else
	{
		if (is_bex_address)
		{
			/* workaround for special case */
			HIP_DEBUG("address is base exchange address, setting state to ACTIVE\n");
			new_addr->address_state = PEER_ADDR_STATE_ACTIVE;
			HIP_DEBUG("setting bex addr as preferred address\n");
			ipv6_addr_copy(&entry->preferred_address, addr);
			new_addr->seq_update_id = 0;
		} else {
			HIP_DEBUG("address's state is set in state UNVERIFIED\n");
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			err = entry->hadb_update_func->hip_update_send_echo(entry, spi, new_addr);

			// @todo: check! If not acctually a problem (during Handover). Andrey.
			if( err==-ECOMM ) err = 0;
		}
	}

	do_gettimeofday(&new_addr->modified_time);
	new_addr->is_preferred = is_preferred_addr;
	if(is_preferred_addr){
		HIP_DEBUG("Since the address is preferred, we set the entry preferred_address as such\n");
		ipv6_addr_copy(&entry->preferred_address, &new_addr->address);
	}

	if (new) {
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add(new_addr, spi_list->peer_addr_list);
	}

 out_err:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
}

/**
 * hip_hadb_dump_hits - Dump the contents of the HIT hash table.
 *
 * Should be safe to call from any context. THIS IS FOR DEBUGGING ONLY.
 * DONT USE IT IF YOU DONT UNDERSTAND IT. 
 */
void hip_hadb_dump_hits(void)
{
	int i;
	hip_ha_t *entry;
	char *string;
	int cnt, k;
	hip_list_t *item, *tmp;

	string = (char *)HIP_MALLOC(4096, GFP_ATOMIC);
	if (!string)
	{
		HIP_ERROR("Cannot dump HADB... out of memory\n");
		return;
	}

	HIP_LOCK_HT(&hadb_hit);

	cnt = 0;
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		entry = list_entry(item);
		
		hip_hold_ha(entry);
		if (cnt > 3900)
		{
			string[cnt] = '\0';
			HIP_ERROR("%s\n", string);
			cnt = 0;
		}

		k = hip_in6_ntop2(&entry->hit_peer, string + cnt);
		cnt += k;
		hip_db_put_ha(entry, hip_hadb_delete_state);
	}
	HIP_ERROR("%s\n", string);
	
	HIP_UNLOCK_HT(&hadb_hit);
}


void hip_hadb_dump_spis_in(hip_ha_t *entry)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x esp_info_SPI_out=0x%x ifindex=%d "
			  "ts=%lu updating=%d keymat_index=%u upd_flags=0x%x seq_update_id=%u ESP_INFO=old 0x%x,new 0x%x,km %u\n",
			  spi_item->spi, spi_item->new_spi, spi_item->esp_info_spi_out, spi_item->ifindex,
			  jiffies - spi_item->timestamp, spi_item->updating, spi_item->keymat_index,
			  spi_item->update_state_flags, spi_item->seq_update_id,
			  spi_item->stored_received_esp_info.old_spi,
			  spi_item->stored_received_esp_info.old_spi,
			  spi_item->stored_received_esp_info.keymat_index);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

void hip_hadb_dump_spis_out(hip_ha_t *entry)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x seq_update_id=%u\n",
			  spi_item->spi, spi_item->new_spi, spi_item->seq_update_id);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

/**
 * hip_store_base_exchange_keys - store the keys negotiated in base exchange
 * @param ctx the context inside which the key data will copied around
 * @param is_initiator true if the localhost is the initiator, or false if
 *                   the localhost is the responder
 *
 * @return 0 if everything was stored successfully, otherwise < 0.
 */
int hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				  struct hip_context *ctx, int is_initiator)
{
	int err = 0;
	int hmac_key_len, enc_key_len, auth_key_len, hip_enc_key_len;

	hmac_key_len = hip_hmac_key_length(entry->esp_transform);
	enc_key_len = hip_enc_key_length(entry->esp_transform);
	auth_key_len = hip_auth_key_length_esp(entry->esp_transform);
	hip_enc_key_len = hip_transform_key_length(entry->hip_transform);

	memcpy(&entry->hip_hmac_out, &ctx->hip_hmac_out, hmac_key_len);
	memcpy(&entry->hip_hmac_in, &ctx->hip_hmac_in, hmac_key_len);

	memcpy(&entry->esp_in.key, &ctx->esp_in.key, enc_key_len);
	memcpy(&entry->auth_in.key, &ctx->auth_in.key, auth_key_len);

	memcpy(&entry->esp_out.key, &ctx->esp_out.key, enc_key_len);
	memcpy(&entry->auth_out.key, &ctx->auth_out.key, auth_key_len);

	memcpy(&entry->hip_enc_out.key, &ctx->hip_enc_out.key, hip_enc_key_len);
	memcpy(&entry->hip_enc_in.key, &ctx->hip_enc_in.key, hip_enc_key_len);

	hip_update_entry_keymat(entry, ctx->current_keymat_index,
				ctx->keymat_calc_index, ctx->esp_keymat_index,
				ctx->current_keymat_K);

	if (entry->dh_shared_key)
	{
		HIP_DEBUG("HIP_FREEing old dh_shared_key\n");
		HIP_FREE(entry->dh_shared_key);
	}

	entry->dh_shared_key_len = 0;
	/* todo: reuse pointer, no HIP_MALLOC */
	entry->dh_shared_key = (char *)HIP_MALLOC(ctx->dh_shared_key_len, GFP_ATOMIC);
	if (!entry->dh_shared_key)
	{
		HIP_ERROR("entry dh_shared HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	entry->dh_shared_key_len = ctx->dh_shared_key_len;
	memcpy(entry->dh_shared_key, ctx->dh_shared_key, entry->dh_shared_key_len);
	_HIP_HEXDUMP("Entry DH SHARED", entry->dh_shared_key, entry->dh_shared_key_len);
	_HIP_HEXDUMP("Entry Kn", entry->current_keymat_K, HIP_AH_SHA_LEN);
	return err;

out_err:
	if (entry->dh_shared_key)
		HIP_FREE(entry->dh_shared_key);

	return err;
}

/*
 * @msg for future purposes (KeyNote)
 */
int hip_init_peer(hip_ha_t *entry, struct hip_common *msg, 
		  struct hip_host_id *peer)
{
	int err = 0;
	int len = hip_get_param_total_len(peer); 
	struct in6_addr hit;

	/* public key and verify function might be initialized already in the
	   case of loopback */
	
	if (entry->peer_pub)
	{
		HIP_DEBUG("Not initializing peer host id, old exists\n");
		goto out_err;
	}

	HIP_IFEL(hip_host_id_to_hit(peer,&hit,HIP_HIT_TYPE_HASH100) ||
		 ipv6_addr_cmp(&hit, &entry->hit_peer),
		 -1, "Unable to verify sender's HOST_ID\n");
	
	HIP_IFEL(!(entry->peer_pub = HIP_MALLOC(len, GFP_KERNEL)),
		 -ENOMEM, "Out of memory\n");
	
	memcpy(entry->peer_pub, peer, len);
	entry->verify =
		hip_get_host_id_algo(entry->peer_pub) == HIP_HI_RSA ? 
		hip_rsa_verify : hip_dsa_verify;
	
 out_err:
	HIP_DEBUG_HIT("peer's hit", &hit);
	HIP_DEBUG_HIT("entry's hit", &entry->hit_peer);
	return err;
}

int hip_init_us(hip_ha_t *entry, struct in6_addr *hit_our)
{
	int err = 0, len, alg;

	if (!(entry->our_priv = hip_get_host_id(HIP_DB_LOCAL_HID, hit_our,
						HIP_HI_RSA))) {
		HIP_DEBUG("Could not acquire a local host id with RSA, trying with DSA\n");
		HIP_IFEL(!(entry->our_priv = hip_get_host_id(HIP_DB_LOCAL_HID,
							     hit_our,
						     HIP_HI_DSA)),
		 -1, "Could not acquire a local host id with DSA\n");
	}
	alg = hip_get_host_id_algo(entry->our_priv);
	entry->sign = alg == HIP_HI_RSA ? hip_rsa_sign : hip_dsa_sign;

	len = hip_get_param_total_len(entry->our_priv);
	HIP_IFEL(!(entry->our_pub = HIP_MALLOC(len, GFP_KERNEL)), -1, "Could not allocate a public key\n");
	memcpy(entry->our_pub, entry->our_priv, len);
	entry->our_pub = hip_get_public_key(entry->our_pub);

	err = alg == HIP_HI_DSA ? 
		hip_dsa_host_id_to_hit(entry->our_pub, &entry->hit_our, HIP_HIT_TYPE_HASH100) :
		hip_rsa_host_id_to_hit(entry->our_pub, &entry->hit_our, HIP_HIT_TYPE_HASH100);
	HIP_IFEL(err, err, "Unable to digest the HIT out of public key.");
	
 out_err:
	if (err && entry->our_priv) 
		HIP_FREE(entry->our_priv);
	if (err && entry->our_pub) 
		HIP_FREE(entry->our_pub);

	return err;
}

/* ----------------- */
#if 0
void hip_hadb_dump_hs_ht(void)
{
	int i;
	struct hip_hit_spi *hs, *tmp_hs;
	char str[INET6_ADDRSTRLEN];
	
	HIP_DEBUG("start\n");
	HIP_LOCK_HT(&hadb_spi_list);
	
	list_for_each_entry_safe(hs, tmp_hs, &hadb_byspi_list[i], list)
	{
		hip_hadb_hold_hs(hs);
		hip_in6_ntop(&hs->hit_peer, str);
		_HIP_DEBUG("HIT=%s SPI=0x%x refcnt=%d\n",
					str, hs->spi, atomic_read(&hs->refcnt));
		hip_hadb_put_hs(hs);
	}
	
	HIP_UNLOCK_HT(&hadb_spi_list);
	HIP_DEBUG("end\n");
}
#endif

void hip_init_hadb(void)
{
#if 0
	memset(&hadb_hit,0,sizeof(hadb_hit));
	memset(&hadb_spi_list,0,sizeof(hadb_spi_list));

	hadb_hit.head =      hadb_byhit;
	hadb_hit.hashsize =  HIP_HADB_SIZE;
	hadb_hit.offset =    offsetof(hip_ha_t, next_hit);
	hadb_hit.hash =      hip_hash_hit;
	hadb_hit.compare =   hip_match_hit;
	hadb_hit.hold =      hip_hadb_hold_entry;
	hadb_hit.put =       hip_hadb_put_entry;
	hadb_hit.get_key =   hip_hadb_get_key_hit;

	strncpy(hadb_hit.name,"HADB_BY_HIT", 15);
	hadb_hit.name[15] = 0;

	hadb_spi_list.head =      hadb_byspi_list;
	hadb_spi_list.hashsize =  HIP_HADB_SIZE;
	hadb_spi_list.offset =    offsetof(struct hip_hit_spi, list);
	hadb_spi_list.hash =      hip_hash_spi;
	hadb_spi_list.compare =   hip_hadb_match_spi;
	hadb_spi_list.hold =      hip_hadb_hold_hs;
	hadb_spi_list.put =       hip_hadb_put_hs;
	hadb_spi_list.get_key =   hip_hadb_get_key_spi_list;

	strncpy(hadb_spi_list.name,"HADB_BY_SPI_LIST", 15);
	hadb_spi_list.name[15] = 0;

	hip_ht_init(hadb_hit);
	hip_ht_init(hadb_spi_list);
#endif
	/** @todo Check for errors. */
	hadb_hit = hip_ht_init(hip_hash_hit, hip_match_hit);

	/* initialize default function pointer sets for receiving messages*/
	default_rcv_func_set.hip_receive_i1        = hip_receive_i1;
	default_rcv_func_set.hip_receive_r1        = hip_receive_r1;
	default_rcv_func_set.hip_receive_i2        = hip_receive_i2;
	default_rcv_func_set.hip_receive_r2        = hip_receive_r2;
	default_rcv_func_set.hip_receive_update    = hip_receive_update;
	default_rcv_func_set.hip_receive_notify    = hip_receive_notify;
	default_rcv_func_set.hip_receive_bos       = hip_receive_bos;
	default_rcv_func_set.hip_receive_close     = hip_receive_close;
	default_rcv_func_set.hip_receive_close_ack = hip_receive_close_ack;
	
	/* initialize alternative function pointer sets for receiving messages*/
	/* insert your alternative function sets here!*/ 

	/* initialize default function pointer sets for handling messages*/
	default_handle_func_set.hip_handle_i1  = hip_handle_i1;
	default_handle_func_set.hip_handle_r1  = hip_handle_r1;
	default_handle_func_set.hip_handle_i2  = hip_handle_i2;
	default_handle_func_set.hip_handle_r2  = hip_handle_r2;
	default_handle_func_set.hip_handle_bos = hip_handle_bos;
	default_handle_func_set.hip_handle_close     = hip_handle_close;
	default_handle_func_set.hip_handle_close_ack = hip_handle_close_ack;
	
	/* initialize alternative function pointer sets for handling messages*/
	/* insert your alternative function sets here!*/ 
	
	/* initialize default function pointer sets for misc functions*/
	default_misc_func_set.hip_solve_puzzle  	   = hip_solve_puzzle;
	default_misc_func_set.hip_produce_keying_material  = hip_produce_keying_material;
	default_misc_func_set.hip_create_i2		   = hip_create_i2;
	default_misc_func_set.hip_create_r2		   = hip_create_r2;
	default_misc_func_set.hip_build_network_hdr	   = hip_build_network_hdr;

	/* initialize alternative function pointer sets for misc functions*/
	/* insert your alternative function sets here!*/ 
	
	/* initialize default function pointer sets for update functions*/
	default_update_func_set.hip_handle_update_plain_locator = hip_handle_update_plain_locator;
	default_update_func_set.hip_handle_update_addr_verify = hip_handle_update_addr_verify;
	default_update_func_set.hip_update_handle_ack	      = hip_update_handle_ack;
	default_update_func_set.hip_handle_update_established = hip_handle_update_established;
	default_update_func_set.hip_handle_update_rekeying    = hip_handle_update_rekeying;
	default_update_func_set.hip_update_send_addr_verify   = hip_update_send_addr_verify;
	default_update_func_set.hip_update_send_echo	      = hip_update_send_echo;

	/* xmit function set */
	/** @todo Add support for i3. */
	default_xmit_func_set.hip_send_pkt = hip_send_raw;
	nat_xmit_func_set.hip_send_pkt = hip_send_udp;
	
	/* filter function sets */
	default_input_filter_func_set.hip_input_filter	   = hip_agent_filter;
	default_output_filter_func_set.hip_output_filter   = hip_agent_filter;
}

hip_xmit_func_set_t *hip_get_xmit_default_func_set() {
	return &default_xmit_func_set;
}

hip_misc_func_set_t *hip_get_misc_default_func_set() {
	return &default_misc_func_set;
}

hip_input_filter_func_set_t *hip_get_input_filter_default_func_set() {
	return &default_input_filter_func_set;
}

hip_output_filter_func_set_t *hip_get_output_filter_default_func_set() {
	return &default_output_filter_func_set;
}

hip_rcv_func_set_t *hip_get_rcv_default_func_set() {
	return &default_rcv_func_set;
}

hip_handle_func_set_t *hip_get_handle_default_func_set() {
	return &default_handle_func_set;
}

hip_update_func_set_t *hip_get_update_default_func_set() {
	return &default_update_func_set;
}

/**
 * hip_hadb_set_rcv_function_set - set function pointer set for an hadb record.
 *				   Pointer values will not be copied!
 * @param entry e pointer to the hadb record
 * @param new_func_set pointer to the new function set
 *
 * @return 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_rcv_function_set(hip_ha_t * entry,
				   hip_rcv_func_set_t * new_func_set){
	/*! \todo add check whether all function pointers are set */
	if( entry ){
		entry->hadb_rcv_func = new_func_set;
		return 0;
	}
	//HIP_ERROR("Func pointer set malformed. Func pointer set NOT appied.");
	return -1;
}

/**
 * hip_hadb_set_handle_function_set - set function pointer set for an
 * hadb record. Pointer values will not be copied!
 * @param entry pointer to the hadb record
 * @param new_func_set pointer to the new function set
 *
 * @return 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_handle_function_set(hip_ha_t * entry,
				     hip_handle_func_set_t * new_func_set){
	/** @todo add check whether all function pointers are set. */
	if( entry ){
		entry->hadb_handle_func = new_func_set;
		return 0;
	}
	//HIP_ERROR("Func pointer set malformed. Func pointer set NOT appied.");
	return -1;
}

/**
 * hip_hadb_set_misc_function_set - set function pointer set for an hadb record.
 * Pointer values will not be copied!
 * @param entry pointer to the hadb record
 * @param new_func_set pointer to the new function set
 *
 * @return 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_misc_function_set(hip_ha_t * entry,
				   hip_misc_func_set_t * new_func_set){
	/** @todo add check whether all function pointers are set. */
	if( entry ){
		entry->hadb_misc_func = new_func_set;
		return 0;
	}
	//HIP_ERROR("Func pointer set malformed. Func pointer set NOT appied.");
	return -1;
}

int hip_hadb_set_xmit_function_set(hip_ha_t * entry,
				   hip_xmit_func_set_t * new_func_set){
	if( entry ){
		entry->hadb_xmit_func = new_func_set;
		return 0;
	}
}

int hip_hadb_set_input_filter_function_set(hip_ha_t * entry,
					   hip_input_filter_func_set_t * new_func_set)
{
	if( entry ){
		entry->hadb_input_filter_func = new_func_set;
		return 0;
	}
}

int hip_hadb_set_output_filter_function_set(hip_ha_t * entry,
					   hip_output_filter_func_set_t * new_func_set)
{
	if( entry ){
		entry->hadb_output_filter_func = new_func_set;
		return 0;
	}
}

/**
 * hip_hadb_set_update_function_set - set function pointer set for an hadb record.
 * Pointer values will not be copied!
 * @param entry pointer to the hadb record
 * @param new_func_set pointer to the new function set
 *
 * @return 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_update_function_set(hip_ha_t * entry,
				     hip_update_func_set_t * new_func_set){
	/*! \todo add check whether all function pointers are set */
	if( entry ){
		entry->hadb_update_func = new_func_set;
		return 0;
	}
	//HIP_ERROR("Func pointer set malformed. Func pointer set NOT appied.");
	return -1;
}

void hip_uninit_hadb()
{
	int i;
	hip_ha_t *ha, *tmp;
	//struct hip_hit_spi *hs, *tmp_hs;

	HIP_DEBUG("\n");

	HIP_DEBUG("DEBUG: DUMP SPI LISTS\n");
//	hip_hadb_dump_hs_ht();

	/* I think this is not very safe deallocation.
	 * Locking the hadb_spi and hadb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in 
	 * hip_hadb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
#if 0
	HIP_DEBUG("DELETING HA HT\n");
	list_for_each_entry_safe(ha, tmp, hadb_byhit[i], next_hit)
	{
		if (atomic_read(&ha->refcnt) > 2)
				HIP_ERROR("HA: %p, in use while removing it from HADB\n", ha);
		//hip_hold_ha(ha); // tkoponen: not needed as we do not call remove_state(...)
		hip_hadb_remove_state_hit(ha);
		hip_db_put_ha(ha, hip_hadb_delete_state);
	}
#endif
}

void hip_delete_all_sp()
{
	int i;
	hip_ha_t *ha, *tmp;
	//struct hip_hit_spi *hs, *tmp_hs;
	struct hip_spi_in_item *item, *tmp_spi;
	HIP_DEBUG("\n");

	HIP_DEBUG("DEBUG: DUMP SPI LISTS\n");
	//hip_hadb_dump_hs_ht();

	/* I think this is not very safe deallocation.
	 * Locking the hadb_spi and hadb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in 
	 * hip_hadb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
	HIP_DEBUG("DELETING HA HT\n");

#if 0
	for(i = 0; i < HIP_HADB_SIZE; i++) {
		list_for_each_entry_safe(ha, tmp, &hadb_byhit[i], next_hit) {
			hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our, IPPROTO_ESP, 1);
			hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our, 0, 1);


			list_for_each_entry_safe(item, tmp_spi, &ha->spis_in, list) {
				hip_delete_sa(item->spi, &ha->local_address, &ha->preferred_address, 
					      AF_INET6, ha->peer_udp_port, 0);
			}

			list_for_each_entry_safe(item, tmp_spi, &ha->spis_out, list) {
				hip_delete_sa(item->spi, &ha->preferred_address, &ha->local_address, 
					      AF_INET6, 0, ha->peer_udp_port);
			}
		}
	}
#endif
}


/**
* hip_list_peers_add - private function to add an entry to the peer list
* @addr: IPv6 address
* @entry: peer list entry
* @last: pointer to pointer to end of peer list linked list
*
* Add an IPv6 address (if valid) to the peer list and update the tail
* pointer.
*
* Returns: zero on success, or negative error value on failure
*/

int hip_list_peers_add(struct in6_addr *address,
			      hip_peer_entry_opaque_t *entry,
			      hip_peer_addr_opaque_t **last)
{
	hip_peer_addr_opaque_t *addr;

	HIP_DEBUG_IN6ADDR("## SPI is 0, found bex address:", address);
	
	/* Allocate an entry for the address */
	addr = HIP_MALLOC(sizeof(hip_peer_addr_opaque_t), GFP_ATOMIC);
	if (!addr) {
		HIP_ERROR("No memory to create peer addr entry\n");
		return -ENOMEM;
	}
	addr->next = NULL;
	/* Record the peer addr */
	ipv6_addr_copy(&addr->addr, address);
	
	if (*last == NULL) {  /* First entry? Add to head and tail */
		entry->addr_list = addr;
	} else {             /* Otherwise, add to tail */
		(*last)->next = addr;
	}
	*last = addr;
	entry->count++;   /* Increment count in peer entry */
	return 0;
}

/**
 * hip_hadb_list_peers_func - private function to process a hadb entry
 * @param entry hadb table entry
 * @param opaque private data for the function (contains record keeping structure)
 *
 * Process a hadb entry, extracting the HOST ID, HIT, and IPv6 addresses.
 *
 * @return zero on success, or negative error value on failure
 */
int hip_hadb_list_peers_func(hip_ha_t *entry, void *opaque)
{
	int err = 0;
#if 0
	hip_peer_opaque_t *op = (hip_peer_opaque_t *)opaque;
	hip_peer_entry_opaque_t *peer_entry = NULL;
	hip_peer_addr_opaque_t *last = NULL;
	struct hip_peer_addr_list_item *s;
	struct hip_spi_out_item *spi_out, *tmp;
	char buf[46];
	struct hip_lhi lhi;
	int found_addrs = 0;

	/* Start by locking the entry */
	HIP_LOCK_HA(entry);

	/* Extract HIT */
	hip_in6_ntop(&(entry->hit_peer), buf);
	HIP_DEBUG("## Got an entry for peer HIT: %s\n", buf);
	memset(&lhi, 0, sizeof(struct hip_lhi));
	memcpy(&(lhi.hit),&(entry->hit_peer),sizeof(struct in6_addr));

	/* Create a new peer list entry */
	peer_entry = HIP_MALLOC(sizeof(hip_peer_entry_opaque_t),GFP_ATOMIC);
	if (!peer_entry) {
		HIP_ERROR("No memory to create peer list entry\n");
		err = -ENOMEM;
		goto error;
	}
	peer_entry->count = 0;    /* Initialize the number of addrs to 0 */
	peer_entry->host_id = NULL;
	/* Record the peer hit */
	ipv6_addr_copy(&(peer_entry->hit), &(lhi.hit));
	peer_entry->addr_list = NULL;
	peer_entry->next = NULL; 

	if (!op->head) {          /* Save first list entry as head and tail */
		op->head = peer_entry;
		op->end = peer_entry;
	} else {                  /* Add entry to the end */
		op->end->next = peer_entry;
		op->end = peer_entry;
	}

	/* Record each peer address */
	
	if (entry->default_spi_out == 0) {
		if (!ipv6_addr_any(&entry->preferred_address)) {
			err = hip_list_peers_add(&entry->preferred_address,
						 peer_entry, &last);
			if (err != 0)
				goto error;
			found_addrs = 1;
		}
		goto done;
	}

	list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		list_for_each_entry(s, &spi_out->peer_addr_list, list) {
			err = hip_list_peers_add(&(s->address), peer_entry,
						 &last);
			if (err != 0)
				goto error;
			found_addrs = 1;
		}
	}

 done:

	/* Increment count of entries and connect the address list to
	 * peer entry only if addresses were copied */
	if (!found_addrs) {
		err = -ENOMSG;
		HIP_DEBUG("entry has no usable addresses\n");
	}

	op->count++; /* increment count on error also so err handling works */
		
 error:
	//HIP_DEBUG("*** TODO: on error, HIP_FREE HIP_MALLOCed addresses here ? ***\n");
	_HIP_DEBUG("op->end->next=0x%p\n", op->end->next);
	_HIP_DEBUG("op->end=0x%p\n", op->end);

	HIP_UNLOCK_HA(entry);
#endif
	return err;
}

#if 0
void hip_hadb_remove_hs(uint32_t spi)
{
	struct hip_hit_spi *hs;

	hs = (struct hip_hit_spi *) hip_ht_find(hadb_spi_list, (void *)spi);
	if (!hs) {
		HIP_DEBUG("HS not found for SPI=0x%x\n", spi);
                return;
        }

	HIP_LOCK_HS(hs);
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	//hip_ht_delete(&hadb_spi_list, hs);
	HIP_UNLOCK_HS(hs);
	hip_hadb_put_hs(hs);
	hip_hadb_put_hs(hs); /* verify that put_hs is safe after unlocking */
}
#endif

/* Delete given inbound SPI, and all if spi == 0 */
void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes locked entry */
	HIP_DEBUG("SPI=0x%x\n", spi);
	int counter = 0;

	/* @todo: check that the deletion below actually works (hits and addresses are
	   used inconsistenly) */
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{ 
		spi_item = list_entry(item);
	  	if (!spi || spi_item->spi == spi)
	  	{
		  	HIP_DEBUG("deleting SPI_in=0x%x SPI_in_new=0x%x from "
				  "inbound list, item=0x%p addresses=0x%p\n",
				  spi_item->spi, spi_item->new_spi, item, spi_item->addresses);
		  	HIP_ERROR("remove SPI from HIT-SPI HT\n");
			//hip_hadb_remove_hs(spi_item->spi);
			HIP_DEBUG_IN6ADDR("delete", &entry->local_address);
			hip_delete_sa(spi_item->spi, &entry->local_address, &entry->hit_our,
				      AF_INET6, entry->peer_udp_port, 0);
				      //AF_INET6, 0, 0);
			// XX FIX: should be deleted like this?
			//for(i = 0; i < spi_item->addresses_n; i++)
			//  hip_delete_sa(spi_item->spi,
			//    &spi_item->addresses->address + i, AF_INET6);
 			if (spi_item->spi != spi_item->new_spi)
 				hip_delete_sa(spi_item->new_spi, &entry->hit_our, &entry->local_address,
					      AF_INET6, entry->peer_udp_port, 0);
 			if (spi_item->addresses)
 			{
 				HIP_DEBUG("deleting stored addrlist 0x%p\n", spi_item->addresses);
 				HIP_FREE(spi_item->addresses);
 			}
			list_del(spi_item, entry->spis_in);
			HIP_FREE(spi_item);
			break;
			
		}
	}
}

/* Delete given outbound SPI, and all if spi == 0 */
void hip_hadb_delete_outbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i, ii;

	/* assumes locked entry */
	HIP_DEBUG("entry=0x%p SPI=0x%x\n", entry, spi);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		if (!spi || spi_item->spi == spi)
		{
			struct hip_peer_addr_list_item *addr_item;
			hip_list_t *a_item, *a_tmp;

			HIP_DEBUG("deleting SPI_out=0x%x SPI_out_new=0x%x from outbound list, item=0x%p\n",
				  spi_item->spi, spi_item->new_spi, item);
			hip_delete_sa(spi_item->spi, &entry->preferred_address, &entry->preferred_address,
				      AF_INET6, 0, entry->peer_udp_port);
			hip_delete_sa(spi_item->new_spi, &entry->preferred_address,&entry->preferred_address,
				      AF_INET6, 0, entry->peer_udp_port);
			/* delete peer's addresses */
			list_for_each_safe(a_item, a_tmp, spi_item->peer_addr_list, ii)
			{
				addr_item = list_entry(a_item);
				list_del(addr_item, spi_item->peer_addr_list);
				HIP_FREE(addr_item);
			}
			list_del(spi_item, entry->spis_out);
			HIP_FREE(spi_item);
		}
	}
}

/** 
 * hip_hadb_delete_state - Delete HA state (and deallocate memory)
 * @param ha HA
 *
 * Deletes all associates IPSEC SAs and frees the memory occupied
 * by the HA state.
 *
 * ASSERT: The HA must be unlinked from the global hadb hash tables
 * (SPI and HIT). This function should only be called when absolutely 
 * sure that nobody else has a reference to it.
 */
void hip_hadb_delete_state(hip_ha_t *ha)
{
	HIP_DEBUG("ha=0x%p\n", ha);

	/* Delete SAs */
	
	hip_hadb_delete_inbound_spi(ha, 0);
	hip_hadb_delete_outbound_spi(ha, 0);
	

	if (ha->dh_shared_key)
		HIP_FREE(ha->dh_shared_key);
	if (ha->hip_msg_retrans.buf)
		HIP_FREE(ha->hip_msg_retrans.buf);
	if (ha->peer_pub)
		HIP_FREE(ha->peer_pub);
	if (ha->our_priv)
		HIP_FREE(ha->our_priv);
	if (ha->our_pub)
		HIP_FREE(ha->our_pub);
	if (ha)
		HIP_FREE(ha);


}


/**
 * hip_for_each_ha - Map function @func to every HA in HIT hash table
 * @param func Mapper function
 * @param opaque Opaque data for the mapper function.
 *
 * The hash table is LOCKED while we process all the entries. This means
 * that the mapper function MUST be very short and _NOT_ do any operations
 * that might sleep!
 *
 * Returns negative if an error occurs. If an error occurs during traversal of
 * a the HIT hash table, then the traversal is stopped and function returns.
 * Returns the last return value of applying the mapper function to the last
 * element in the hash table.
 */
int hip_for_each_ha(int (*func)(hip_ha_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_ha_t *this;
	hip_list_t *item, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hadb_hit);
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("list_for_each_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (fail) break;
	}
	
	HIP_UNLOCK_HT(&hadb_hit);
	return fail;
}

/** Enumeration for hip_count_open_connections */
int hip_count_one_entry(hip_ha_t *entry, void *cntr)
{
	int *counter = cntr;
	if (entry->state == HIP_STATE_CLOSING ||
	    entry->state == HIP_STATE_ESTABLISHED ||
	    entry->state == HIP_STATE_FILTERING_I2 ||
	    entry->state == HIP_STATE_FILTERING_R2)
	{
		(*counter)++;
	}
	return 0;
}


/**
 * Return number of open connections by calculating hadb entrys.
 */
int hip_count_open_connections(void)
{
	int n = 0;
	
	hip_for_each_ha(hip_count_one_entry, &n);
	
	return n;
}

int hip_handle_get_ha_info(hip_ha_t *entry, struct hip_common *msg)
{
	
	int err = 0;
    	struct hip_hadb_user_info_state hid;

	memset(&hid, 0, sizeof(hid));
	hid.state = entry->state;
    	hid.hit_our = entry->hit_our;
	hid.hit_peer = entry->hit_peer;
			
	err = hip_build_param_contents(msg, &hid, HIP_PARAM_HA_INFO,
				       sizeof(hid));
	if (err)
		HIP_ERROR("Building ha info failed\n");
  	
    out_err:
	return err;

}

#ifdef CONFIG_HIP_RVS

/**
 * Finds a rendezvous server candidate host association entry.
 *
 * Finds a rendezvous server candidate host association entry matching the
 * parameter @c local_hit and @c rvs_ip. When a relayed I1 packet arrives to the
 * responder, the packet has the initiators HIT as the source HIT, and the
 * responder HIT as the destination HIT. The responder needs the host
 * assosiation having RVS's HIT and the responder's HIT. This function gets that
 * host assosiation without using the RVS's HIT as searching key.
 *
 * @param  local_hit a pointer to rendezvous server HIT used as searching key.
 * @param  rvs_ip    a pointer to rendezvous server IPv6 or IPv4-in-IPv6 format
 *                   IPv4 address  used as searching key.
 * @return           a pointer to a matching host association or NULL if
 *                   a matching host association was not found.
 * @author           Miika Komu
 * @date             31.08.2006
 */ 
hip_ha_t *hip_hadb_find_rvs_candidate_entry(hip_hit_t *local_hit,
					    hip_hit_t *rvs_ip)
{
	int err = 0, i;
	hip_ha_t *this;
	hip_list_t *item, *tmp, *result = NULL;

	HIP_LOCK_HT(&hadb_hit);
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("List_for_each_entry_safe\n");
		hip_hold_ha(this);
		if ((ipv6_addr_cmp(local_hit, &this->hit_our) == 0) &&
			(ipv6_addr_cmp(rvs_ip, &this->preferred_address) == 0)) {
			result = this;
			break;
		}
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (err)
			break;
	}
	HIP_UNLOCK_HT(&hadb_hit);

 out_err:
	if (err)
		result = NULL;

	return result;
}
#endif


#ifdef CONFIG_HIP_BLIND
hip_ha_t *hip_hadb_find_by_blind_hits(hip_hit_t *local_blind_hit,
				      hip_hit_t *peer_blind_hit)
{
	int err = 0, i;
	hip_ha_t *this, *tmp, *result = NULL;

	HIP_LOCK_HT(&hadb_hit);
	for(i = 0; i < HIP_HADB_SIZE; i++) {
	  _HIP_DEBUG("The %d list is empty? %d\n", i,
		     list_empty(&hadb_byhit[i]));
	  list_for_each_entry_safe(this, tmp, &hadb_byhit[i], next_hit)
	    {
	      _HIP_DEBUG("List_for_each_entry_safe\n");
	      hip_hold_ha(this);
	      if ((ipv6_addr_cmp(local_blind_hit, &this->hit_our_blind) == 0) &&
		  (ipv6_addr_cmp(peer_blind_hit, &this->hit_peer_blind) == 0)) {
		result = this;
		break;
	      }
	      hip_db_put_ha(this, hip_hadb_delete_state);
	      if (err)
		break;
	    }
	  if (err)
	    break;
	}
	HIP_UNLOCK_HT(&hadb_hit);
	
 out_err:
	if (err)
	  result = NULL;
	
	return result;
}
#endif
