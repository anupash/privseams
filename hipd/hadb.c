// FIXME: whenever something that is replicated in beet db is
// modified, the modifications must be written there too.
#include "hadb.h"


HIP_HASHTABLE hadb_hit;
HIP_HASHTABLE hadb_spi_list;

static struct list_head hadb_byhit[HIP_HADB_SIZE];

/* default set of miscellaneous function pointers. This has to be in the global scope */
static hip_xmit_func_set_t default_xmit_func_set;
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

void hip_hadb_delete_hs(struct hip_hit_spi *hs)
{
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	HIP_LOCK_HS(hs);
	hip_ht_delete(&hadb_spi_list, hs);
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

void hip_hadb_hold_entry(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, hip_ha_t);
}

void hip_hadb_put_entry(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, hip_ha_t, hip_hadb_delete_state);
}

static void *hip_hadb_get_key_hit(void *entry)
{
	return (void *)&(((hip_ha_t *)entry)->hash_key);
        //return HIP_DB_GET_KEY_HIT(entry, hip_ha_t);
}

static void *hip_hadb_get_key_spi_list(void *entry)
{
	return (void *)(((struct hip_hit_spi *)entry)->spi);
}

static int hit_match(hip_ha_t *entry, void *our) {
	return ipv6_addr_cmp(our, &entry->hit_our) == 0;
}

static struct list_head hadb_byspi_list[HIP_HADB_SIZE];

/**
 * hip_hadb_rem_state_hit - Remove HA from HIT table
 * @entry: HA
 * HA must be locked.
 */
static inline void hip_hadb_rem_state_hit(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;
	HIP_DEBUG("\n");
	ha->hastate &= ~HIP_HASTATE_HITOK;
	hip_ht_delete(&hadb_hit, entry);
}

int hip_hadb_hit_is_our(const hip_hit_t *our) {
	/* FIXME: This full scan is stupid, but we have no hashtables anyway... tkoponen */
	return hip_for_each_ha(hit_match, (void *) our);
}

/**
 * hip_hadb_remove_state_hit - Remove HA from HIT hash table.
 * @ha: HA
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
 **********************************************************************
 * All the primitive functions up to this point are static, to force
 * some information hiding. The construct functions can access these
 * functions directly.
 *
 **********************************************************************
 */


/*********************** PRIMITIVES ***************************/

/* find HA by inbound SPI */
hip_ha_t *hip_hadb_find_byspi_list(u32 spi)
{
	struct hip_hit_spi *hs;
	hip_hit_t hit_our, hit_peer;
	hip_ha_t *ha;

	hs = (struct hip_hit_spi *) hip_ht_find(&hadb_spi_list, (void *)spi);
	if (!hs) {
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

/**
 * This function searches for a hip_ha_t entry from the hip_hadb_hit
 * by a HIT pair (local,peer).
 */
hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
{
        hip_hit_t key;
        hip_xor_hits(&key, hit, hit2);
	HIP_HEXDUMP("hit is: ", hit, 16);
	HIP_HEXDUMP("hit2 is: ", hit2, 16);
	HIP_HEXDUMP("the computed key is: ", &key, 16);
        return (hip_ha_t *)hip_ht_find(&hadb_hit, (void *)&key);
}

/**
 * This function simply goes through all local HIs and tries
 * to find a HADB entry that matches the current HI and
 * the given peer hit. First matching HADB entry is then returned.
 *
 * XX TODO: find a better solution, see the text below:
 * This function is needed because we index the HADB now by
 * key values calculated from <peer_hit,local_hit> pairs. Unfortunately, in
 * some functions like the ipv6 stack hooks hip_get_saddr() and
 * hip_handle_output() we just can't know the local_hit so we have to
 * improvise and just try to find some HA entry.
 *
 * NOTE: This way of finding HA entries doesn't work properly if we have 
 * multiple entries with the same peer_hit.
 */
hip_ha_t *hip_hadb_try_to_find_by_peer_hit(hip_hit_t *hit)
{
        struct hip_host_id_entry *item = NULL, *tmp = NULL;
        hip_ha_t *entry = NULL;
        hip_hit_t our_hit;

        list_for_each_entry_safe(item,tmp,&hip_local_hostid_db.db_head, next) {
                ipv6_addr_copy(&our_hit,&item->lhi.hit);
		
		HIP_DEBUG_HIT("try_to_find_by_peer_hit:", &our_hit);
		HIP_DEBUG_HIT("hit:", hit);
		entry = hip_hadb_find_byhits(hit, &our_hit);
                if (!entry) {
                        continue;
                } else {
                        return entry;
                }
        }
        return NULL;
}


/**
 * hip_hadb_insert_state - Insert state to hash tables.
 *
 * *** TODO: SPI STUFF IS DEPRECATED ***
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

	/* assume already locked ha */

	HIP_ASSERT(!(ipv6_addr_any(&ha->hit_peer)));

	st = ha->hastate;

	if (!ipv6_addr_any(&ha->hit_peer) && !(st & HIP_HASTATE_HITOK)) {
		hip_xor_hits(&ha->hash_key, &ha->hit_our, &ha->hit_peer);
		HIP_HEXDUMP("ha->hit_our is: ", &ha->hit_our, 16);
		HIP_HEXDUMP("ha->hit_peer is: ", &ha->hit_peer, 16);
		HIP_HEXDUMP("the hash key is: ", &ha->hash_key, 16);
		tmp = hip_ht_find(&hadb_hit, (void *)&(ha->hash_key));
		if (!tmp) {
			hip_ht_add(&hadb_hit, ha);
			st |= HIP_HASTATE_HITOK;
			HIP_DEBUG("New state added\n");
		} else {
			hip_db_put_ha(tmp, hip_hadb_delete_state);
			HIP_DEBUG("HIT already taken\n");
		}
	}

	ha->hastate = st;
	return st;
}

/* Practically called only by when adding a HIT-IP mapping before bex */
int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
{
	int err = 0;
	hip_ha_t *entry;

	/* XX FIXME: allow multiple mappings; base exchange should be
	   initiated to allow of them in order to prevent local DoS */

	HIP_DEBUG("CALLED hip_hadb_add_peer_info\n\n\n");
	HIP_DEBUG_HIT("HIT", peer_hit);
	HIP_DEBUG_IN6ADDR("addr", peer_addr);

	/* XX TODO: should we search by (hit, our_default_hit) pair ? */
	entry = hip_hadb_try_to_find_by_peer_hit(peer_hit);
	HIP_IFEL(entry, 0, "Ignoring new mapping, old one exists\n");

	entry = hip_hadb_create_state(GFP_KERNEL);
	HIP_IFEL(!entry, -1, "");
	if (!entry) {
		HIP_ERROR("Unable to create a new entry\n");
		return -1;
	}
		    
	_HIP_DEBUG("created a new sdb entry\n");
	ipv6_addr_copy(&entry->hit_peer, peer_hit);

	/* XXX: This is wrong. As soon as we have native socket API, we
	 * should enter here the correct sender... (currently unknown).
	 */
	if (!hip_init_us(entry, NULL))
		HIP_DEBUG_HIT("our hit seems to be", &entry->hit_our);
	else
		HIP_INFO("Could not assign local hit, continuing\n");
	
	hip_hadb_insert_state(entry);
	hip_hold_ha(entry); /* released at the end */

	/* add initial HIT-IP mapping */
	err = hip_hadb_add_peer_addr(entry, peer_addr, 0, 0,
				     PEER_ADDR_STATE_ACTIVE);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		err = -2;
		goto out_err;
	}

	HIP_IFEL(hip_select_source_address(&entry->local_address,
					   peer_addr), -1,
		 "Cannot find source address\n");
	
	HIP_DEBUG("Source address found\n");
	
	/*
	 * Create a security policy for triggering base exchange.
	 *
	 * XX FIX: multiple identities support
	 * alternative a) make generic HIT prefix based policy to work
	 * alternative b) add SP pair for all local HITs
	 *
	 */
	HIP_IFEL(hip_setup_hit_sp_pair(peer_hit, &entry->hit_our,
				       &entry->local_address,
				       peer_addr, 0, 1, 0), -1,
		 "Error in setting the SPs\n");

out_err:
	if (entry)
		hip_db_put_ha(entry, hip_hadb_delete_state);
	return err;
}

int hip_add_peer_map(const struct hip_common *input)
{
	struct in6_addr *hit, *ip;
	int err = 0;
	//HIP_HEXDUMP("packet", input,  hip_get_msg_total_len(input));
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
 	if (err) {
 		HIP_ERROR("Failed to insert peer map work order (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;

}

int hip_del_peer_map(const struct hip_common *input)
{
	struct in6_addr *hit, *ip;
	int err = 0;

	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out;
	}

	HIP_DEBUG_HIT("hit", hit);
	HIP_DEBUG_IN6ADDR("ip", ip);

	err = hip_del_peer_info(hit, ip);
	if (err) {
		HIP_ERROR("Failed to delete mapping\n");
		goto out;
	}
	  
 out:

	return err;
}

/*
 * XXXXXX Returns: 0 if @spi was added to the inbound SPI list of the HA @ha, otherwise < 0.
 */
int hip_hadb_insert_state_spi_list(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
				   uint32_t spi)
{
	int err = 0;
	HIP_INSERT_STATE_SPI_LIST(&hadb_spi_list, hip_hadb_put_entry,
				  hit_our, hit_peer, spi);
	return err;
}



/**
 * hip_hadb_create_state - Allocates and initializes a new HA structure
 * @gfpmask - passed directly to HIP_MALLOC().
 *
 * Return NULL if memory allocation failed, otherwise the HA.
 */
hip_ha_t *hip_hadb_create_state(int gfpmask)
{
	hip_ha_t *entry = NULL;
	int err = 0;

	entry = (hip_ha_t *)HIP_MALLOC(sizeof(struct hip_hadb_state), gfpmask);
	if (!entry)
		return NULL;

	memset(entry, 0, sizeof(*entry));

	INIT_LIST_HEAD(&entry->next_hit);
	INIT_LIST_HEAD(&entry->spis_in);
	INIT_LIST_HEAD(&entry->spis_out);

	HIP_LOCK_INIT(entry);
	atomic_set(&entry->refcnt,0);

	entry->state = HIP_STATE_UNASSOCIATED;
	entry->hastate = HIP_HASTATE_INVALID;

        // SYNCH: does it really need to be syncronized to beet-xfrm? -miika
	// No dst hit.
	
	/* Function pointer sets which define HIP behavior in respect to the hadb_entry */

	/* choose the set of processing function for the hadb_entry*/
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

	HIP_IFEL(hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set),
		 -1, "Can't set new function pointer set\n");

	HIP_IFEL(hip_hadb_set_input_filter_function_set(entry, &default_input_filter_func_set),
		 -1, "Can't set new function pointer set\n");

	HIP_IFEL(hip_hadb_set_output_filter_function_set(entry, &default_output_filter_func_set),
		 -1, "Can't set new function pointer set\n");

 out_err:
	
	return entry;
}

/************** END OF PRIMITIVE FUNCTIONS **************/

/* select the preferred address within the addresses of the given SPI */
/* selected address is copied to @addr, it is is non-NULL */
int hip_hadb_select_spi_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out, struct in6_addr *addr)
{
	int err = 0;
        struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;

        list_for_each_entry(s, &spi_out->peer_addr_list, list) {
		if (s->address_state != PEER_ADDR_STATE_ACTIVE) {
			_HIP_DEBUG("skipping non-active address %s\n",addrstr);
			continue;
		}

		if (candidate) {
			int this_is_later;
			this_is_later = hip_timeval_diff(&s->modified_time, &latest, &dt);
			_HIP_DEBUG("latest=%ld.%06ld\n", latest.tv_sec, latest.tv_usec);
			_HIP_DEBUG("dt=%ld.%06ld\n", dt.tv_sec, dt.tv_usec);
			if (this_is_later) {
				_HIP_DEBUG("is later, change\n");
				memcpy(&latest, &s->modified_time, sizeof(struct timeval));
				candidate = s;
			}
		} else {
			candidate = s;
			memcpy(&latest, &s->modified_time, sizeof(struct timeval));
		}
        }

        if (!candidate) {
		HIP_ERROR("did not find usable peer address\n");
		HIP_DEBUG("todo: select from other SPIs ?\n");
		/* todo: select other SPI as the default SPI out */
		err = -ENOMSG;
	} else {
		ipv6_addr_copy(addr, &candidate->address);
	}

	return err;
}

/**
 * hip_hadb_get_peer_addr - Get some of the peer's usable IPv6 address
 * @entry: corresponding hadb entry of the peer
 * @addr: where the selected IPv6 address of the peer is copied to
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
 * Returns: 0 if some of the addresses was copied successfully, else < 0.
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
 * @entry: corresponding hadb entry of the peer
 * @addr: the IPv6 address for which the information is to be retrieved
 * @spi: where the outbound SPI of @addr is copied to
 * @lifetime: where the lifetime of @addr is copied to
 * @modified_time: where the time when @addr was added or updated is copied to
 *
 * Returns: if @entry has the address @addr in its peer address list
 * parameters @spi, @lifetime, and @modified_time are
 * assigned if they are non-NULL and 1 is returned, else @interface_id
 * and @lifetime are not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *spi, uint32_t *lifetime,
				struct timeval *modified_time)
{
	struct hip_peer_addr_list_item *s;
	int i = 1;
	struct hip_spi_out_item *spi_out, *tmp;

	/* assumes already locked entry */

        list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		list_for_each_entry(s, &spi_out->peer_addr_list, list) {
			if (!ipv6_addr_cmp(&s->address, addr)) {
				_HIP_DEBUG("found\n");
				if (lifetime)
					*lifetime = s->lifetime;
				if (modified_time) {
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
 * hip_hadb_add_peer_addr - add a new peer IPv6 address to the entry's list of peer addresses
 * @entry: corresponding hadb entry of the peer
 * @new_addr: IPv6 address to be added
 * @spi: outbound SPI to which the @new_addr is related to
 * @lifetime: address lifetime of the address
 * @state: address state
 *
 * Returns: if @new_addr already exists, 0 is returned. If address was
 * added successfully 0 is returned, else < 0.
 *
*/
int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t spi, uint32_t lifetime, int state)
{
	int err = 0;
	struct hip_peer_addr_list_item *item;
	char addrstr[INET6_ADDRSTRLEN];
	uint32_t prev_spi;
	struct hip_spi_out_item *spi_out, *tmp;
	int found_spi_list = 0;

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

	/* todo: replace following with hip_hadb_get_spi_list */
        list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		if (spi_out->spi == spi) {
			found_spi_list = 1;
			break;
		}
        }

	if (!found_spi_list) {
		HIP_ERROR("did not find SPI list for SPI 0x%x\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	err = hip_hadb_get_peer_addr_info(entry, new_addr, &prev_spi, NULL, NULL);
	if (err) {
		/* todo: validate previous vs. new interface id for 
		 * the new_addr ? */
		if (prev_spi != spi)
			HIP_DEBUG("todo: SPI changed: prev=%u new=%u\n", prev_spi,
				  spi);

		HIP_DEBUG("duplicate address not added (todo: update address lifetime ?)\n");
		/* todo: update address lifetime ? */
		err = 0;
		goto out_err;
	}

	item = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
	if (!item) {
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	_HIP_DEBUG("HIP_MALLOCed item=0x%p\n", item);

	item->lifetime = lifetime;
	ipv6_addr_copy(&item->address, new_addr);
	item->address_state = state;
	do_gettimeofday(&item->modified_time);

	list_add_tail(&item->list, &spi_out->peer_addr_list);

 out_err:
	return err;
}

/**
 * hip_hadb_delete_peer_address_list_one - delete IPv6 address from the entry's list 
 * of peer addresses
 * @entry: corresponding hadb entry of the peer
 * @addr: IPv6 address to be deleted
 */
void hip_hadb_delete_peer_addrlist_one(hip_ha_t *entry, struct in6_addr *addr) 
{
	struct hip_peer_addr_list_item *item, *tmp;
	int i = 1;
	struct hip_spi_out_item *spi_out, *spi_tmp;

	/* possibly deprecated function .. */

	HIP_LOCK_HA(entry);

        list_for_each_entry_safe(spi_out, spi_tmp, &entry->spis_out, list) {
		list_for_each_entry_safe(item, tmp, &spi_out->peer_addr_list, list) {
			if (!ipv6_addr_cmp(&item->address, addr)) {
				_HIP_DEBUG("deleting address\n");
				list_del(&item->list);
				HIP_FREE(item);
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
int hip_del_peer_info(struct in6_addr *hit, struct in6_addr *addr)
{
	hip_ha_t *ha;

	/* XX TODO: delete all ha entries that contain a matching peer hi? */
	ha = hip_hadb_try_to_find_by_peer_hit(hit);
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
static int hip_hadb_add_inbound_spi(hip_ha_t *entry, struct hip_spi_in_item *data)
{
	int err = 0;
	struct hip_spi_in_item *item, *tmp;
	uint32_t spi_in;

	spi_in = data->spi;

	/* assumes locked entry */
	_HIP_DEBUG("SPI_in=0x%x\n", spi_in);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (item->spi == spi_in) {
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_in);
			goto out;
		}
        }

	item = (struct hip_spi_in_item *)HIP_MALLOC(sizeof(struct hip_spi_in_item), GFP_ATOMIC);
	if (!item) {
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(item, data, sizeof(struct hip_spi_in_item));
	item->timestamp = jiffies;
	list_add(&item->list, &entry->spis_in);
	item->addresses = NULL;
	item->addresses_n = 0;
	HIP_DEBUG("added SPI 0x%x to the inbound SPI list\n", spi_in);
	// hip_hold_ha(entry); ?

	_HIP_DEBUG("inserting SPI to HIT-SPI hashtable\n");
	err = hip_hadb_insert_state_spi_list(&entry->hit_peer, &entry->hit_our,
					     spi_in);
	if (err == -EEXIST)
		err = 0;
 out_err:
 out:
	return err;
}

/* assume already locked entry */
// SYNCH
int hip_hadb_add_outbound_spi(hip_ha_t *entry, struct hip_spi_out_item *data)
{
	int err = 0;
	struct hip_spi_out_item *item, *tmp;
	uint32_t spi_out;

	/* assumes locked entry ? */

	spi_out = data->spi;

	_HIP_DEBUG("SPI_out=0x%x\n", spi_out);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		if (item->spi == spi_out) {
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_out);
			goto out;
		}
        }

	item = (struct hip_spi_out_item *)HIP_MALLOC(sizeof(struct hip_spi_out_item), GFP_ATOMIC);
	if (!item) {
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(item, data, sizeof(struct hip_spi_out_item));
	INIT_LIST_HEAD(&item->peer_addr_list);
	ipv6_addr_copy(&item->preferred_address, &in6addr_any);
	list_add(&item->list, &entry->spis_out);
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
	struct hip_spi_in_item *item, *tmp;
	/* assumes that inbound spi already exists in ha's spis_in */
	HIP_DEBUG("SPI=0x%x ifindex=%d\n", spi, ifindex);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
		if (item->spi == spi) {
			HIP_DEBUG("found updated spi-ifindex mapping\n");
			item->ifindex = ifindex;
			return;
		}
        }
	HIP_DEBUG("SPI not found, returning\n");
}

/* Get the ifindex of given SPI, returns 0 if SPI was not found */
int hip_hadb_get_spi_ifindex(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("spi=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
		if (item->spi == spi || item->new_spi == spi) {
			_HIP_DEBUG("found\n");
			return item->ifindex;
		}
        }
	HIP_DEBUG("ifindex not found for the SPI 0x%x\n", spi);
	return 0;
}

/* Get the SPI of given ifindex, returns 0 if ifindex was not found  */
uint32_t hip_hadb_get_spi(hip_ha_t *entry, int ifindex)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("ifindex=%d\n", ifindex);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
		if (item->ifindex == ifindex) {
			HIP_DEBUG("found SPI 0x%x\n", item->spi);
			return item->spi;
		}
        }
	HIP_DEBUG("SPI not found for the ifindex\n");
	return 0;
}

uint32_t hip_update_get_prev_spi_in(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
			  item->ifindex, item->spi, item->nes_spi_out, item->seq_update_id);
		if (item->seq_update_id == peer_update_id) {
			HIP_DEBUG("found SPI 0x%x\n", item->spi);
			return item->spi;
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
	struct hip_spi_in_item *item, *tmp;
	int ifindex;

	HIP_DEBUG_HIT("dst dev_addr", dev_addr);
	ifindex = hip_devaddr2ifindex(dev_addr);
	HIP_DEBUG("ifindex of dst dev=%d\n", ifindex);
	if (!ifindex)
		return 0;

        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
		if (item->ifindex == ifindex) {
			item->updating = 1;
			return item->spi;
		}
        }

	HIP_DEBUG("SPI not found for ifindex\n");
	return 0;
}

void hip_set_spi_update_status(hip_ha_t *entry, uint32_t spi, int set)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("spi=0x%x set=%d\n", spi, set);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x updating=%d\n",
			   item->ifindex, item->spi, item->updating);
		if (item->spi == spi) {
			HIP_DEBUG("setting updating status to %d\n", set);
			item->updating = set;
			break;
		}
        }
}

void hip_update_clear_status(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("spi=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: spi=0x%x\n", item->spi);
		if (item->spi == spi) {
			_HIP_DEBUG("clearing SPI status\n");
			item->update_state_flags = 0;
			memset(&item->stored_received_nes, 0, sizeof(struct hip_nes));
			break;
		}
        }
}

/* spi_out is the SPI which was in the received NES Old SPI field */
void hip_update_set_new_spi_in(hip_ha_t *entry, uint32_t spi, uint32_t new_spi,
			       uint32_t spi_out /* test */)
{
	struct hip_spi_in_item *item, *tmp;
	_HIP_DEBUG("spi=0x%x new_spi=0x%x spi_out=0x%x\n", spi, new_spi, spi_out);

	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
			   item->spi, item->new_spi);
		if (item->spi == spi) {
			HIP_DEBUG("setting new_spi\n");
			if (!item->updating) {
				_HIP_ERROR("SA update not in progress, continuing anyway\n");
			}
			if ((item->spi != item->new_spi) && item->new_spi) {
				HIP_ERROR("warning: previous new_spi is not zero: 0x%x\n",
					  item->new_spi);
			}
			item->new_spi = new_spi;
			item->nes_spi_out = spi_out; /* maybe useless */
			break;
		}
        }
}

/* just sets the new_spi field */
void hip_update_set_new_spi_out(hip_ha_t *entry, uint32_t spi, uint32_t new_spi)
{
	struct hip_spi_out_item *item, *tmp;

	_HIP_DEBUG("spi=0x%x new_spi=0x%x\n", spi, new_spi);
	list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
			  item->spi, item->new_spi);
		if (item->spi == spi) {
			_HIP_DEBUG("setting new_spi\n");
			if (item->new_spi) {
				HIP_ERROR("previous new_spi is not zero: 0x%x\n", item->new_spi);
				HIP_ERROR("todo: delete previous new_spi\n");
			}
			item->new_spi = new_spi;
			break;
		}
        }
}


uint32_t hip_update_get_new_spi_in(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
			  item->spi, item->new_spi);
		if (item->seq_update_id == peer_update_id) {
			if (item->new_spi)
				return item->new_spi;
			return item->spi;
		}
        }
	HIP_DEBUG("New SPI not found\n");
	return 0;
}

/* switch from Old SPI to New SPI (inbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_in(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("old_spi=0x%x\n", old_spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x new_spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
			   item->ifindex, item->spi, item->new_spi,
			   item->nes_spi_out, item->seq_update_id);
		if (item->spi == old_spi) {
			_HIP_DEBUG("switching\n");
			item->spi = item->new_spi;
			item->new_spi = 0;
			item->nes_spi_out = 0;
			break;
		}
        }
}

/* switch from Old SPI to New SPI (outbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_out(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_out_item *item, *tmp;

	_HIP_DEBUG("old_spi=0x%x\n", old_spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x seq_id=%u\n",
			   item->spi, item->new_spi, item->seq_update_id);
		if (item->spi == old_spi) {
			_HIP_DEBUG("switching\n");
			item->spi = item->new_spi;
			item->new_spi = 0;
			break;
		}
        }
}


void hip_update_set_status(hip_ha_t *entry, uint32_t spi, int set_flags,
			   uint32_t update_id, int update_flags_or,
			   struct hip_nes *nes, uint16_t keymat_index)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("spi=0x%x update_id=%u update_flags_or=0x%x keymat_index=%u nes=0x%p\n",
		   spi, update_id, update_flags_or, keymat_index, nes);
	if (nes)
		_HIP_DEBUG("NES: old_spi=0x%x new_spi=0x%x keymat_index=%u\n",
			   ntohl(nes->old_spi), ntohl(nes->new_spi), ntohs(nes->keymat_index));

	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n",
			   item->spi, item->new_spi);
		if (item->spi == spi) {
			_HIP_DEBUG("setting new values\n");
			if (set_flags & 0x1)
				item->seq_update_id = update_id;
			if (set_flags & 0x2)
				item->update_state_flags |= update_flags_or;
			if (nes && (set_flags & 0x4)) {
				item->stored_received_nes.old_spi = ntohl(nes->old_spi);
				item->stored_received_nes.new_spi = ntohl(nes->new_spi);
				item->stored_received_nes.keymat_index = ntohs(nes->keymat_index);
			}
			if (set_flags & 0x8)
				item->keymat_index = keymat_index;

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
	/* assumes locked entry  */

	_HIP_DEBUG("spi=0x%x direction=%d test_new_spi=%d\n",
		  spi, direction, test_new_spi);

	if (direction == HIP_SPI_DIRECTION_IN) {
		struct hip_spi_in_item *item, *tmp;
		list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
			_HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n",
				   item->spi, item->new_spi);
			if ( (item->spi == spi && !test_new_spi) ||
			     (item->new_spi == spi && test_new_spi) )
				return 1;
		}
        } else {
		struct hip_spi_out_item *item, *tmp;
		list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
			_HIP_DEBUG("test item: spi_out=0x%x new_spi=0x%x\n",
				   item->spi, item->new_spi);
			if ( (item->spi == spi && !test_new_spi) ||
			     (item->new_spi == spi && test_new_spi) )
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
	struct hip_spi_out_item *spi_out, *spi_out_tmp;

	/* assumes locked entry  */

	HIP_DEBUG("\n");
	/* latest outbound SPIs are usually in the beginning of the list */
	list_for_each_entry_safe(spi_out, spi_out_tmp, &entry->spis_out, list) {
		int ret;
		struct in6_addr addr;

		_HIP_DEBUG("checking SPI 0x%x\n", spi_out->spi);
		ret = hip_hadb_select_spi_addr(entry, spi_out, &addr);
		if (ret == 0) {
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
	if (!spi_out) {
		HIP_ERROR("NULL spi_out\n");
		return;
	}

	if (addr) {
		HIP_DEBUG("testing, setting given address as default out addr\n");
		ipv6_addr_copy(&spi_out->preferred_address, addr);
		ipv6_addr_copy(&entry->preferred_address, addr);
	} else {
		/* useless ? */
		struct in6_addr a;
		int err = hip_hadb_select_spi_addr(entry, spi_out, &a);
		_HIP_DEBUG("setting address as default out addr\n");
		if (!err) {
			ipv6_addr_copy(&spi_out->preferred_address, &a);
			ipv6_addr_copy(&entry->preferred_address, &a);
		} else
			HIP_ERROR("couldn't select and set preferred address\n");
	}
	HIP_DEBUG("setting default SPI out to 0x%x\n", spi_out->spi);
	entry->default_spi_out = spi_out->spi;
}

/* have_nes is 1, if there is NES in the same packet as the ACK was */
void hip_update_handle_ack(hip_ha_t *entry, struct hip_ack *ack, int have_nes,
			   struct hip_echo_response *echo_resp)
{
	size_t n, i;
	uint32_t *peer_update_id;

	/* assumes locked entry  */

	HIP_DEBUG("have_nes=%d\n", have_nes);

	if (!ack) {
		HIP_ERROR("NULL ack\n");
		goto out_err;
	}

	if (hip_get_param_contents_len(ack) % sizeof(uint32_t)) {
		HIP_ERROR("ACK param length not divisible by 4 (%u)\n",
			  hip_get_param_contents_len(ack));
		goto out_err;
	}

	n = hip_get_param_contents_len(ack) / sizeof(uint32_t);
	HIP_DEBUG("%d pUIDs in ACK param\n", n);
	peer_update_id = (uint32_t *) ((void *)ack+sizeof(struct hip_tlv_common));
	for (i = 0; i < n; i++, peer_update_id++) {
		struct hip_spi_in_item *in_item, *in_tmp;
		struct hip_spi_out_item *out_item, *out_tmp;
		uint32_t puid = ntohl(*peer_update_id);

		_HIP_DEBUG("peer Update ID=%u\n", puid);

		/* see if your NES is acked and maybe if corresponging NES was received */
		list_for_each_entry_safe(in_item, in_tmp, &entry->spis_in, list) {
			_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
				   in_item->spi, in_item->seq_update_id);
			if (in_item->seq_update_id == puid) {
				_HIP_DEBUG("SEQ and ACK match\n");
				in_item->update_state_flags |= 0x1; /* recv'd ACK */
				if (have_nes)
					in_item->update_state_flags |= 0x2; /* recv'd also NES */
			}
		}

		/* see if the ACK was response to address verification */
		if (echo_resp) {
			list_for_each_entry_safe(out_item, out_tmp, &entry->spis_out, list) {
				struct hip_peer_addr_list_item *addr, *addr_tmp;

				list_for_each_entry_safe(addr, addr_tmp, &out_item->peer_addr_list, list) {
					_HIP_DEBUG("checking address, seq=%u\n", addr->seq_update_id);
					if (addr->seq_update_id == puid) {
						if (hip_get_param_contents_len(echo_resp) != sizeof(addr->echo_data)) {
							HIP_ERROR("echo data len mismatch\n");
							continue;
						}
						if (memcmp(addr->echo_data,
							   (void *)echo_resp+sizeof(struct hip_tlv_common),
							   sizeof(addr->echo_data)) != 0) {
							HIP_ERROR("ECHO_RESPONSE differs from ECHO_REQUEST\n");
							continue;
						}
						_HIP_DEBUG("address verified successfully, setting state to ACTIVE\n");
						addr->address_state = PEER_ADDR_STATE_ACTIVE;
						do_gettimeofday(&addr->modified_time);

						if (addr->is_preferred) {
							/* maybe we should do this default address selection
							   after handling the REA .. */
							hip_hadb_set_default_out_addr(entry, out_item, &addr->address);
						} else
							HIP_DEBUG("address was not set as preferred address in REA\n");
					}
				}
			}
			//entry->skbtest = 1;
			_HIP_DEBUG("set skbtest to 1\n");
		} else {
			HIP_DEBUG("no ECHO_RESPONSE in same packet with ACK\n");
		}
	}
 out_err:
	return;
}

void hip_update_handle_nes(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
			   item->spi, item->seq_update_id);
		if (item->seq_update_id == peer_update_id) {
			_HIP_DEBUG("received peer's NES\n");
			item->update_state_flags |= 0x2; /* recv'd NES */
		}
	}
}

/* works if update contains only one NES */
int hip_update_get_spi_keymat_index(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *item, *tmp;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		_HIP_DEBUG("test item: spi_in=0x%x seq_update_id=%u keymat_index=%u\n",
			   item->spi, item->seq_update_id, item->keymat_index);
		if (item->seq_update_id == peer_update_id) {
			return item->keymat_index;
		}
	}
	return 0;
}

/* todo: use jiffies instead of timestamp */
uint32_t hip_hadb_get_latest_inbound_spi(hip_ha_t *entry)
{
	struct hip_spi_in_item *item, *tmp;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;

	/* assumes already locked entry */

        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (now - item->timestamp < t) {
			spi = item->spi;
			t = now - item->timestamp;
		}
        }

	_HIP_DEBUG("newest spi_in is 0x%x\n", spi);
	return spi;
}

/* get pointer to the outbound SPI list or NULL if the outbound SPI
   list does not exist */
struct hip_spi_out_item *hip_hadb_get_spi_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *item, *tmp;

	/* assumes already locked entry */

	_HIP_DEBUG("SPI=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		if (item->spi == spi)
			return item;
        }
	return NULL;
}

/* get pointer to the inbound SPI list or NULL if SPI list does not exist */
struct hip_spi_in_item *hip_hadb_get_spi_in_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *item, *tmp;

	/* assumes already locked entry */

	HIP_DEBUG("SPI=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (item->spi == spi)
			return item;
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
	int err = 0, new = 1;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a, *tmp;

	/* Assumes already locked entry */
	HIP_DEBUG("spi=0x%x is_preferred_addr=%d\n", spi, is_preferred_addr);

	spi_list = hip_hadb_get_spi_list(entry, spi);
	if (!spi_list) {
		HIP_ERROR("SPI list for 0x%x not found\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	/* Check if addr already exists. If yes, then just update values. */
	list_for_each_entry_safe(a, tmp, &spi_list->peer_addr_list, list) {
		if (!ipv6_addr_cmp(&a->address, addr)) {
			new_addr = a;
			new = 0;
			break;
		}
	}

	if (new) {
		HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
		if (!new_addr) {
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	} else {
		HIP_DEBUG("update old addr item\n");
	}
	
	new_addr->lifetime = lifetime;
	if (new)
		ipv6_addr_copy(&new_addr->address, addr);

	/* If the address is already bound, its lifetime is updated.
	   If the status of the address is DEPRECATED, the status is
	   changed to UNVERIFIED.  If the address is not already bound,
	   the address is added, and its status is set to UNVERIFIED. */
	if (!new) {
		switch (new_addr->address_state) {
		case PEER_ADDR_STATE_DEPRECATED:
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			HIP_DEBUG("updated address state DEPRECATED->UNVERIFIED\n");
			break;
 		case PEER_ADDR_STATE_ACTIVE:
			HIP_DEBUG("address state stays in ACTIVE\n");
			break;
		default:
			HIP_ERROR("state is UNVERIFIED, shouldn't even be here ?\n");
			break;
		}
	} else {
		if (is_bex_address) {
			/* workaround for special case */
			HIP_DEBUG("address is base exchange address, setting state to ACTIVE\n");
			new_addr->address_state = PEER_ADDR_STATE_ACTIVE;
			HIP_DEBUG("setting bex addr as preferred address\n");
			ipv6_addr_copy(&entry->preferred_address, addr);
			new_addr->seq_update_id = 0;
		} else {
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			_HIP_DEBUG("set initial address state UNVERIFIED\n");
		}
	}

	do_gettimeofday(&new_addr->modified_time);
	new_addr->is_preferred = is_preferred_addr;

	if (new) {
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add_tail(&new_addr->list, &spi_list->peer_addr_list);
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

	string = (char *)HIP_MALLOC(4096,GFP_ATOMIC);
	if (!string) {
		HIP_ERROR("Cannot dump HADB... out of memory\n");
		return;
	}

	HIP_LOCK_HT(&hadb_hit);

	for(i = 0; i <HIP_HADB_SIZE; i++) {
		if (!list_empty(&hadb_byhit[i])) {
			cnt = sprintf(string, "[%d]: ", i);

			list_for_each_entry(entry, &hadb_byhit[i], next_hit) {
				hip_hold_ha(entry);
				if (cnt > 3900) {
					string[cnt] = '\0';
					HIP_ERROR("%s\n", string);
					cnt = 0;
				}

				k = hip_in6_ntop2(&entry->hit_peer, string+cnt);
				cnt+=k;
				hip_db_put_ha(entry, hip_hadb_delete_state);
			}
			string[cnt] = '\0';
			HIP_ERROR("%s\n", string);
		}
	}

	HIP_UNLOCK_HT(&hadb_hit);
	HIP_FREE(string);
}


void hip_hadb_dump_spis_in(hip_ha_t *entry)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x nes_SPI_out=0x%x ifindex=%d "
			  "ts=%lu updating=%d keymat_index=%u upd_flags=0x%x seq_update_id=%u NES=old 0x%x,new 0x%x,km %u\n",
			  item->spi, item->new_spi, item->nes_spi_out, item->ifindex,
			  jiffies - item->timestamp, item->updating, item->keymat_index,
			  item->update_state_flags, item->seq_update_id,
			  item->stored_received_nes.old_spi,
			  item->stored_received_nes.old_spi,
			  item->stored_received_nes.keymat_index);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

void hip_hadb_dump_spis_out(hip_ha_t *entry)
{
	struct hip_spi_out_item *item, *tmp;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x seq_update_id=%u\n",
			  item->spi, item->new_spi, item->seq_update_id);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

/**
 * hip_store_base_exchange_keys - store the keys negotiated in base exchange
 * @ctx:             the context inside which the key data will copied around
 * @is_initiator:    true if the localhost is the initiator, or false if
 *                   the localhost is the responder
 *
 * Returns: 0 if everything was stored successfully, otherwise < 0.
 */
int hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				  struct hip_context *ctx, int is_initiator)
{
	int err = 0;
	int hmac_key_len, enc_key_len, auth_key_len;

	hmac_key_len = hip_hmac_key_length(entry->esp_transform);
	enc_key_len = hip_enc_key_length(entry->esp_transform);
	auth_key_len = hip_auth_key_length_esp(entry->esp_transform);

	memcpy(&entry->hip_hmac_out, &ctx->hip_hmac_out, hmac_key_len);
	memcpy(&entry->hip_hmac_in, &ctx->hip_hmac_in, hmac_key_len);

	memcpy(&entry->esp_in.key, &ctx->esp_in.key, enc_key_len);
	memcpy(&entry->auth_in.key, &ctx->auth_in.key, auth_key_len);

	memcpy(&entry->esp_out.key, &ctx->esp_out.key, enc_key_len);
	memcpy(&entry->auth_out.key, &ctx->auth_out.key, auth_key_len);

	hip_update_entry_keymat(entry, ctx->current_keymat_index,
				ctx->keymat_calc_index, ctx->current_keymat_K);

	if (entry->dh_shared_key) {
		HIP_DEBUG("HIP_FREEing old dh_shared_key\n");
		HIP_FREE(entry->dh_shared_key);
	}

	entry->dh_shared_key_len = 0;
	/* todo: reuse pointer, no HIP_MALLOC */
	entry->dh_shared_key = (char *)HIP_MALLOC(ctx->dh_shared_key_len, GFP_ATOMIC);
	if (!entry->dh_shared_key) {
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
		  struct hip_host_id *peer) {
	int err = 0;
	int len = hip_get_param_total_len(peer); 
	struct in6_addr hit;

	/* Verify sender HIT */
 	HIP_IFEL(hip_host_id_to_hit(peer, &hit, HIP_HIT_TYPE_HASH120) ||
		 ipv6_addr_cmp(&hit, &entry->hit_peer),
		 -1, "Unable to verify sender's HOST_ID\n");
	//	HIP_IFEL(!(peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID)), -ENOENT,
	//	 "No HOST_ID found in R1\n");
	HIP_IFEL(!(entry->peer_pub = HIP_MALLOC(len, GFP_KERNEL)), -ENOMEM, "Out of memory\n");
	memcpy(entry->peer_pub, peer, len);
	entry->verify = hip_get_host_id_algo(entry->peer_pub) == HIP_HI_RSA ? 
		hip_rsa_verify : hip_dsa_verify;

 out_err:
	return err;
}

int hip_init_us(hip_ha_t *entry, struct in6_addr *hit_our) {
	int err = 0, len, alg;
	if (!(entry->our_priv = hip_get_host_id(HIP_DB_LOCAL_HID, hit_our,HIP_HI_RSA)))
	{
		HIP_DEBUG("Could not acquire a local host id with RSA, trying with DSA\n");
		HIP_IFEL(!(entry->our_priv = hip_get_host_id(HIP_DB_LOCAL_HID, hit_our,
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
		hip_dsa_host_id_to_hit(entry->our_pub, &entry->hit_our, HIP_HIT_TYPE_HASH120) :
		hip_rsa_host_id_to_hit(entry->our_pub, &entry->hit_our, HIP_HIT_TYPE_HASH120);
	HIP_IFEL(err, err, "Unable to digest the HIT out of public key.");
	
 out_err:
	if (err && entry->our_priv) 
		HIP_FREE(entry->our_priv);
	if (err && entry->our_pub) 
		HIP_FREE(entry->our_pub);

	return err;
}

/******************************************************************************************************/

void hip_hadb_dump_hs_ht(void)
{
        int i;
        struct hip_hit_spi *hs, *tmp_hs;
        char str[INET6_ADDRSTRLEN];

        HIP_DEBUG("start\n");
        HIP_LOCK_HT(&hadb_spi_list);

        for(i = 0; i < HIP_HADB_SIZE; i++) {
                if (!list_empty(&hadb_byspi_list[i])) {
                        _HIP_DEBUG("HT[%d]\n", i);
                        list_for_each_entry_safe(hs, tmp_hs, &hadb_byspi_list[i]
, list) {
                                hip_hadb_hold_hs(hs);
                                hip_in6_ntop(&hs->hit_peer, str);
                                HIP_DEBUG("HIT=%s SPI=0x%x refcnt=%d\n",
                                          str, hs->spi, atomic_read(&hs->refcnt)
);
                                hip_hadb_put_hs(hs);
                        }
                }
        }

        HIP_UNLOCK_HT(&hadb_spi_list);
        HIP_DEBUG("end\n");
}

void hip_init_hadb(void)
{
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

	hip_ht_init(&hadb_hit);
	hip_ht_init(&hadb_spi_list);
	
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
	default_update_func_set.hip_handle_update_plain_rea   = hip_handle_update_plain_rea;
	default_update_func_set.hip_handle_update_addr_verify = hip_handle_update_addr_verify;
	default_update_func_set.hip_update_handle_ack	      = hip_update_handle_ack;
	default_update_func_set.hip_handle_update_established = hip_handle_update_established;
	default_update_func_set.hip_handle_update_rekeying    = hip_handle_update_rekeying;
	default_update_func_set.hip_update_send_addr_verify   = hip_update_send_addr_verify;
	
	/* xmit function set */
	default_xmit_func_set.hip_csum_send	           = hip_csum_send;

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
 * @entry:          e pointer to the hadb record
 * @new_func_set:    pointer to the new function set
 *
 * Returns: 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_rcv_function_set(hip_ha_t * entry,
				   hip_rcv_func_set_t * new_func_set){
	/* TODO: add check whether all function pointers are set */
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
 * @entry:           pointer to the hadb record
 * @new_func_set:    pointer to the new function set
 *
 * Returns: 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_handle_function_set(hip_ha_t * entry,
				     hip_handle_func_set_t * new_func_set){
	/* TODO: add check whether all function pointers are set */
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
 * @entry:           pointer to the hadb record
 * @new_func_set:    pointer to the new function set
 *
 * Returns: 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_misc_function_set(hip_ha_t * entry,
				   hip_misc_func_set_t * new_func_set){
	/* TODO: add check whether all function pointers are set */
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
 * @entry:           pointer to the hadb record
 * @new_func_set:    pointer to the new function set
 *
 * Returns: 0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_update_function_set(hip_ha_t * entry,
				     hip_update_func_set_t * new_func_set){
	/* TODO: add check whether all function pointers are set */
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
	hip_hadb_dump_hs_ht();

	/* I think this is not very safe deallocation.
	 * Locking the hadb_spi and hadb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in 
	 * hip_hadb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
	HIP_DEBUG("DELETING HA HT\n");
	for(i = 0; i < HIP_HADB_SIZE; i++) {
		list_for_each_entry_safe(ha, tmp, &hadb_byhit[i], next_hit) {
			if (atomic_read(&ha->refcnt) > 2)
				HIP_ERROR("HA: %p, in use while removing it from HADB\n", ha);
			//hip_hold_ha(ha); // tkoponen: not needed as we do not call remove_state(...)
			hip_hadb_remove_state_hit(ha);
			hip_db_put_ha(ha, hip_hadb_delete_state);
		}
	}
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

	for(i = 0; i < HIP_HADB_SIZE; i++) {
		list_for_each_entry_safe(ha, tmp, &hadb_byhit[i], next_hit) {
			hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our, IPPROTO_ESP, 1);


			list_for_each_entry_safe(item, tmp_spi, &ha->spis_in, list) {
				hip_delete_sa(item->spi, &ha->local_address, AF_INET6);
			}

			list_for_each_entry_safe(item, tmp_spi, &ha->spis_out, list) {
				hip_delete_sa(item->spi, &ha->preferred_address, AF_INET6);
			}
		}
	}
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
 * @entry: hadb table entry
 * @opaque: private data for the function (contains record keeping structure)
 *
 * Process a hadb entry, extracting the HOST ID, HIT, and IPv6 addresses.
 *
 * Returns: zero on success, or negative error value on failure
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


void hip_hadb_remove_hs(uint32_t spi)
{
	struct hip_hit_spi *hs;

	hs = (struct hip_hit_spi *) hip_ht_find(&hadb_spi_list, (void *)spi);
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

/* Delete given inbound SPI, and all if spi == 0 */
void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *item, *tmp;

	/* assumes locked entry */
	HIP_DEBUG("SPI=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (!spi || item->spi == spi) {
			HIP_DEBUG("deleting SPI_in=0x%x SPI_in_new=0x%x from "
 				  "inbound list, item=0x%p addresses=0x%p\n",
 				  item->spi, item->new_spi, item, item->addresses);
			HIP_ERROR("remove SPI from HIT-SPI HT\n");
			hip_hadb_remove_hs(item->spi);
			HIP_DEBUG_IN6ADDR("cheng", &entry->local_address);
			hip_delete_sa(item->spi, &entry->local_address,
				      AF_INET6);
			// XX FIX: should be deleted like this?
			//for(i = 0; i < item->addresses_n; i++)
			//  hip_delete_sa(item->spi,
			//    &item->addresses->address + i, AF_INET6);
 			if (item->spi != item->new_spi)
 				hip_delete_sa(item->new_spi, &entry->hit_our, AF_INET6);
 			if (item->addresses) {
 				HIP_DEBUG("deleting stored addrlist 0x%p\n",
 					  item->addresses);
 				HIP_FREE(item->addresses);
 			}
			list_del(&item->list);
			HIP_FREE(item);
			break;
		}
        }
}

/* Delete given outbound SPI, and all if spi == 0 */
void hip_hadb_delete_outbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *item, *tmp;

	/* assumes locked entry */
	HIP_DEBUG("entry=0x%p SPI=0x%x\n", entry, spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		if (!spi || item->spi == spi) {
			struct hip_peer_addr_list_item *addr_item, *addr_tmp;

			HIP_DEBUG("deleting SPI_out=0x%x SPI_out_new=0x%x from outbound list, item=0x%p\n",
				  item->spi, item->new_spi, item);
			hip_delete_sa(item->spi, &entry->preferred_address,
				      AF_INET6);
			hip_delete_sa(item->new_spi, &entry->preferred_address,
				      AF_INET6);
			/* delete peer's addresses */
			list_for_each_entry_safe(addr_item, addr_tmp, &item->peer_addr_list, list) {
				list_del(&addr_item->list);
				HIP_FREE(addr_item);
			}
			list_del(&item->list);
			HIP_FREE(item);
		}
        }
}

/** 
 * hip_hadb_delete_state - Delete HA state (and deallocate memory)
 * @ha: HA
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
	HIP_FREE(ha);
}


/**
 * hip_for_each_ha - Map function @func to every HA in HIT hash table
 * @func: Mapper function
 * @opaque: Opaque data for the mapper function.
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
	hip_ha_t *this, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hadb_hit);
	for(i = 0; i < HIP_HADB_SIZE; i++) {
		//HIP_DEBUG("The %d list is empty? %d\n", i, list_empty(&hadb_byhit[i]));
		list_for_each_entry_safe(this, tmp, &hadb_byhit[i], next_hit)
		{
			_HIP_DEBUG("List_for_each_entry_safe\n");
			hip_hold_ha(this);
			fail = func(this, opaque);
			hip_db_put_ha(this, hip_hadb_delete_state);
			if (fail)
				break;
		}
		if (fail)
			break;
	}
	HIP_UNLOCK_HT(&hadb_hit);
	return fail;
}
