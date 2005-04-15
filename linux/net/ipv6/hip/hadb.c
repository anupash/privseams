// FIXME: whenever something that is replicated in beet db is
// modified, the modifications must be written there too.
#include "hadb.h"

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
#ifdef __KERNEL__
#  include <net/ipv6.h>
#endif /* __KERNEL__ */

HIP_HASHTABLE hadb_hit;
HIP_HASHTABLE hadb_spi_list;

static struct list_head hadb_byhit[HIP_HADB_SIZE];
static struct list_head hadb_byspi_list[HIP_HADB_SIZE];

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

static void hip_hadb_hold_entry(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, hip_ha_t);
}

static void hip_hadb_put_entry(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, hip_ha_t, hip_hadb_delete_state);
}

void hip_hadb_delete_hs(struct hip_hit_spi *hs)
{
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	HIP_LOCK_HS(hs);
	hip_ht_delete(&hadb_spi_list, hs);
	HIP_UNLOCK_HS(hs);
	HIP_FREE(hs);
}

static void hip_hadb_put_hs(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, struct hip_hit_spi, hip_hadb_delete_hs);
}

static void hip_hadb_hold_hs(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, struct hip_hit_spi);
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
	hip_ht_delete(&hadb_spi_list, hs);
	HIP_UNLOCK_HS(hs);
	hip_hadb_put_hs(hs); /* verify that put_hs is safe after unlocking */
}

static void *hip_hadb_get_key_hit(void *entry)
{
	return HIP_DB_GET_KEY_HIT(entry, hip_ha_t);
}

static void *hip_hadb_get_key_spi_list(void *entry)
{
	return (void *)(((struct hip_hit_spi *)entry)->spi);
}

/**
 * hip_hadb_rem_state_hit - Remove HA from HIT table
 * @entry: HA
 * HA must be locked.
 */
static inline void hip_hadb_rem_state_hit(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;

	ha->hastate &= ~HIP_HASTATE_HITOK;
	hip_ht_delete(&hadb_hit, entry);
}


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
	hip_hit_t hit;
	hip_ha_t *ha;

	hs = (struct hip_hit_spi *) hip_ht_find(&hadb_spi_list, (void *)spi);
	if (!hs) {
		HIP_DEBUG("HIT-SPI not found for SPI=0x%x\n", spi);
		return NULL;
	}

	ipv6_addr_copy(&hit, &hs->hit);
	hip_hadb_put_hs(hs);

	ha = hip_hadb_find_byhit(&hit);
	if (!ha) {
		HIP_DEBUG("HA not found for SPI=0x%x\n", spi);
	}

	return ha;
}

hip_ha_t *hip_hadb_find_byhit(hip_hit_t *hit)
{
	return (hip_ha_t *)hip_ht_find(&hadb_hit, (void *)hit);
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
		tmp = hip_ht_find(&hadb_hit, (void *)&(ha->hit_peer));
		if (!tmp) {
			hip_ht_add(&hadb_hit, ha);
			st |= HIP_HASTATE_HITOK;
		} else {
			hip_db_put_ha(tmp, hip_hadb_delete_state);
			HIP_DEBUG("HIT already taken\n");
		}
	}

	ha->hastate = st;
	return st;
}

/*
 * XXXXXX Returns: 0 if @spi was added to the inbound SPI list of the HA @ha, otherwise < 0.
 */
int hip_hadb_insert_state_spi_list(hip_ha_t *entry, uint32_t spi)
{
	int err = 0;
	struct hip_hit_spi *tmp;
	hip_hit_t hit;
	struct hip_hit_spi *new_item;

	/* assume already locked entry */

	_HIP_DEBUG("SPI LIST HT_ADD HA=0x%p SPI=0x%x\n", entry, spi);
	ipv6_addr_copy(&hit, &entry->hit_peer);

	tmp = hip_ht_find(&hadb_spi_list, (void *)spi);
	if (tmp) {
		hip_hadb_put_hs(tmp);
		HIP_ERROR("BUG, SPI already inserted\n");
		err = -EEXIST;
		goto out_err;
	}

	new_item = (struct hip_hit_spi *)HIP_MALLOC(sizeof(struct hip_hit_spi), GFP_ATOMIC);
	if (!new_item) {
		HIP_ERROR("new_item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	atomic_set(&new_item->refcnt, 0);
	HIP_LOCK_INIT(new_item);
	new_item->spi = spi;
	ipv6_addr_copy(&new_item->hit, &hit);

	hip_ht_add(&hadb_spi_list, new_item);
	_HIP_DEBUG("SPI 0x%x added to HT spi_list, HS=%p\n", spi, new_item);
	_HIP_DEBUG("HS TABLE:\n");
	//hip_hadb_dump_hs_ht();
 out_err:
	return err;
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
 * hip_hadb_create_state - Allocates and initializes a new HA structure
 * @gfpmask - passed directly to HIP_MALLOC().
 *
 * Return NULL if memory allocation failed, otherwise the HA.
 */
hip_ha_t *hip_hadb_create_state(int gfpmask)
{
	hip_ha_t *entry = NULL;

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

	return entry;
}

/**
 * hip_hadb_remove_state - Removes the HA from either or both hash tables.
 * @ha: HA
 *
 * The caller should have one reference (as he is calling us). That
 * prevents deletion of HA structure from happening under spin locks.
 */
#if 0 // tkoponen, this is functionally equivalent to hip_hadb_remove_state_hit
static void hip_hadb_remove_state(hip_ha_t *ha)
{
	int r;

	HIP_ASSERT(atomic_read(&ha->refcnt) >= 1);
	HIP_LOCK_HA(ha);

	r = atomic_read(&ha->refcnt);

	if ((ha->hastate & HIP_HASTATE_HITOK) && !ipv6_addr_any(&ha->hit_peer))
		hip_hadb_rem_state_hit(ha);

	HIP_DEBUG("Removed HA: %p from HADB hash tables. " \
		  "References remaining before removing: %d\n",
		  ha, r);
	HIP_UNLOCK_HA(ha);
}
#endif
/************** END OF PRIMITIVE FUNCTIONS **************/

/* select the preferred address within the addresses of the given SPI */
/* selected address is copied to @addr, it is is non-NULL */
int hip_hadb_select_spi_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out, struct in6_addr *addr)
{
	int err = 0;
        struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif

        list_for_each_entry(s, &spi_out->peer_addr_list, list) {
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(&s->address, addrstr);
		_HIP_DEBUG("%s modified_time=%ld.%06ld\n", addrstr,
			  s->modified_time.tv_sec, s->modified_time.tv_usec);
#endif
		if (s->address_state != PEER_ADDR_STATE_ACTIVE) {
			HIP_DEBUG("skipping non-active address %s\n", addrstr);
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
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(addr, addrstr);
		_HIP_DEBUG("select %s from if=0x%x\n", addrstr, s->interface_id);
#endif
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
	struct hip_spi_out_item *spi_out;

	/* assume already locked entry */

	HIP_DEBUG_HIT("entry def addr", &entry->preferred_address);
	if (ipv6_addr_any(&entry->preferred_address)) {
		/* possibly ongoing bex */
		_HIP_DEBUG("no preferred address set\n");
	} else {
		ipv6_addr_copy(addr, &entry->preferred_address);
		_HIP_DEBUG("found preferred address\n");
		goto out;
	}

	if (entry->default_spi_out == 0) {
		HIP_DEBUG("default SPI out is 0, try to use the bex address\n");
		if (ipv6_addr_any(&entry->bex_address)) {
			HIP_DEBUG("no bex address\n");
			err = -EINVAL;
		} else
			ipv6_addr_copy(addr, &entry->bex_address);
		goto out;
	}

	/* try to select a peer address among the ones belonging to
	 * the default outgoing SPI */
	spi_out = hip_hadb_get_spi_list(entry, entry->default_spi_out);
	if (!spi_out) {
		HIP_ERROR("did not find SPI list for default_spi_out 0x%x\n",
			  entry->default_spi_out);
		err = -EEXIST;
		goto out;
	}
#if 1
	/* not tested well yet */
	if (!ipv6_addr_any(&spi_out->preferred_address)) {
		HIP_DEBUG("TEST CODE\n");
		HIP_DEBUG("found preferred address for SPI 0x%x\n",
			  spi_out->spi);
		ipv6_addr_copy(addr, &spi_out->preferred_address);
		goto out;		
	}
	err = -EINVAL; /* usable address not found */
	HIP_ERROR("Did not find an usable peer address\n");
#endif
 out:
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
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif
	int i = 1;
	struct hip_spi_out_item *spi_out, *tmp;

	/* assumes already locked entry */

        list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		list_for_each_entry(s, &spi_out->peer_addr_list, list) {
#ifdef CONFIG_HIP_DEBUG
			hip_in6_ntop(&s->address, addrstr);
			_HIP_DEBUG("address %d: %s, lifetime 0x%x (%u)\n",
				   i, addrstr, s->lifetime, s->lifetime);
#endif
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
 * hip_hadb_set_peer_address_info - set entry's peer address address lifetime
 * @entry: corresponding hadb entry of the peer
 * @addr: the IPv6 address for which the information is to be set
 * @lifetime: address lifetime
 *
 * Set @entry's peer address @addr address lifetime to given
 * values. If @lifetime is non-NULL @addr's lifetime is changed to
 * value pointed to by @lifetime.
 *
 * Returns: if @entry has the address @addr in its peer address list
 * parameters @interface_id and @lifetime were assigned and 1 is
 * returned. Else no values were assigned and 0 is returned.
 */
int hip_hadb_set_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *lifetime)
{
	/* XX: Called with sdb lock held ? */

	/* add parameter uint32_t spi */

	struct hip_peer_addr_list_item *s;
	int i = 1;
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif
	struct hip_spi_out_item *spi_out, *tmp;

	HIP_ERROR("USELESS/DEPRECATED ?\n");

	HIP_LOCK_HA(entry);

        list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		list_for_each_entry(s, &spi_out->peer_addr_list, list) {

			/* todo: update s->modified_time ? if yes, when and where ?
			 * when SPI/lifetime is changed ?
			 */
#ifdef CONFIG_HIP_DEBUG
			hip_in6_ntop(&s->address, addrstr);
			_HIP_DEBUG("address %d: %s,  lifetime 0x%x (%u)\n",
				   i, addrstr, s->lifetime, s->lifetime);
#endif
			if (!ipv6_addr_cmp(&s->address, addr)) {
				if (lifetime) {
					HIP_DEBUG("updating lifetime 0x%x -> 0x%x\n",
						  s->lifetime, *lifetime);
					s->lifetime = *lifetime;
				}
				HIP_UNLOCK_HA(entry);
				return 1;
			}
			i++;
		}
	}
	HIP_UNLOCK_HA(entry);

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
		if (!ipv6_addr_any(&entry->bex_address)) {
			hip_in6_ntop(&entry->bex_address, addrstr);
			HIP_DEBUG("warning, overwriting existing bex address %s\n",
				  addrstr);
		}
		ipv6_addr_copy(&entry->bex_address, new_addr);
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

#ifdef CONFIG_HIP_DEBUG
	hip_in6_ntop(new_addr, addrstr);
	HIP_DEBUG("new_addr %s, spi 0x%x, lifetime 0x%x (%u)\n",
		  addrstr, spi, lifetime, lifetime);
#endif

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
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif
	struct hip_spi_out_item *spi_out, *spi_tmp;

	/* possibly deprecated function .. */

	HIP_LOCK_HA(entry);

        list_for_each_entry_safe(spi_out, spi_tmp, &entry->spis_out, list) {
		list_for_each_entry_safe(item, tmp, &spi_out->peer_addr_list, list) {
#ifdef CONFIG_HIP_DEBUG
			hip_in6_ntop(&item->address, addrstr);
			_HIP_DEBUG("%p: address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
				   item, i, addrstr,  item->interface_id, item->interface_id, item->lifetime, item->lifetime);
#endif
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

	ha = hip_hadb_find_byhit(hit);
	if (!ha) {
		return -ENOENT;
	}

	if (ipv6_addr_any(addr)) {
		hip_hadb_delete_inbound_spi(ha, 0);
		hip_hadb_delete_outbound_spi(ha, 0);
		hip_hadb_remove_state_hit(ha);
		/* by now, if everything is according to plans, the refcnt
		   should be 1 */
		hip_db_put_ha(ha, hip_hadb_delete_state);
		/* and now zero --> deleted*/
	} else {
		hip_hadb_delete_peer_addrlist_one(ha, addr);
		hip_db_put_ha(ha, hip_hadb_delete_state);
	}

	return 0;
}

/* Practically called only by when adding a HIT-IP mapping before bex */
int hip_hadb_add_peer_info(hip_hit_t *hit, struct in6_addr *addr)
{
	int err = 0;
	hip_ha_t *entry;
	char str[INET6_ADDRSTRLEN];

	/* old comment ? note: can't lock here or else
	 * hip_sdb_add_peer_address will block
	 *
	 * unsigned long flags = 0;
	 * spin_lock_irqsave(&hip_sdb_lock, flags);
	 */

	hip_in6_ntop(hit, str);
	HIP_DEBUG("called: HIT %s\n", str);

	entry = hip_hadb_find_byhit(hit);
	if (!entry) {
		entry = hip_hadb_create_state(GFP_KERNEL);
		if (!entry) {
			HIP_ERROR("Unable to create a new entry\n");
			return -1;
		}
		_HIP_DEBUG("created a new sdb entry\n");
		ipv6_addr_copy(&entry->hit_peer, hit);

		/* XXX: This is wrong. As soon as we have native socket API, we
		 * should enter here the correct sender... (currently unknown).
		 */
		if (hip_get_any_localhost_hit(&entry->hit_our,
					      HIP_HI_DEFAULT_ALGO) == 0)
			_HIP_DEBUG_HIT("our hit seems to be", &entry->hit_our);
		else 
			HIP_INFO("Could not assign local hit, continuing\n");
		hip_hadb_insert_state(entry);
		hip_hold_ha(entry); /* released at the end */
	}

	/* add initial HIT-IP mapping */
	if (entry && entry->state == HIP_STATE_UNASSOCIATED) {
		err = hip_hadb_add_peer_addr(entry, addr, 0, 0,
					     PEER_ADDR_STATE_ACTIVE);
		if (err) {
			HIP_ERROR("error while adding a new peer address\n");
			err = -2;
			goto out;
		}
	} else
		HIP_DEBUG("Not adding HIT-IP mapping in state %s\n",
			  hip_state_str(entry->state));

 out:
	if (entry)
		hip_db_put_ha(entry, hip_hadb_delete_state);
	return err;
}

/* assume already locked entry */
int hip_hadb_add_inbound_spi(hip_ha_t *entry, struct hip_spi_in_item *data)
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
	HIP_DEBUG("added SPI 0x%x to the inbound SPI list\n", spi_in);
	// hip_hold_ha(entry); ?

	_HIP_DEBUG("inserting SPI to HIT-SPI hashtable\n");
	err = hip_hadb_insert_state_spi_list(entry, spi_in);
	if (err == -EEXIST)
		err = 0;
 out_err:
 out:
	return err;
}

/* assume already locked entry */
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


/* Delete given inbound SPI, and all if spi == 0 */
void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *item, *tmp;

	/* assumes locked entry */
	HIP_DEBUG("SPI=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (!spi || item->spi == spi) {
			HIP_DEBUG("deleting SPI_in=0x%x SPI_in_new=0x%x from inbound list, item=0x%p\n",
				  item->spi, item->new_spi, item);
			HIP_ERROR("remove SPI from HIT-SPI HT\n");
			hip_hadb_remove_hs(item->spi);
			hip_delete_sa(item->spi, &entry->hit_our);
			hip_delete_sa(item->new_spi, &entry->hit_our);
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
			hip_delete_sa(item->spi, &entry->hit_peer);
			hip_delete_sa(item->new_spi, &entry->hit_peer);
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
	ifindex = hip_ipv6_devaddr2ifindex(dev_addr);
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
				HIP_ERROR("SA update not in progress, continuing anyway\n");
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
			return item->new_spi;
			
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
	_HIP_DEBUG("returning\n");
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
	_HIP_DEBUG("returning\n");
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
			entry->skbtest = 1;
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

/* get pointer to the SPI list or NULL if SPI list does not exist */
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

/* add an address belonging to the SPI list */
/* or update old values */
int hip_hadb_add_addr_to_spi(hip_ha_t *entry, uint32_t spi, struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr)
{
	int err = 0;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a, *tmp;
	int new = 1;

	/* assumes already locked entry */

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
		_HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
		if (!new_addr) {
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	} else
		_HIP_DEBUG("update old addr item\n");

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

#if 0
	if (is_preferred_addr) {
		ipv6_addr_copy(&spi_list->preferred_address, addr);
		ipv6_addr_copy(&entry->preferred_address, addr); // test
	}
#endif
	if (new) {
		_HIP_DEBUG("adding new addr to SPI list\n");
		list_add_tail(&new_addr->list, &spi_list->peer_addr_list);
	}

 out_err:
	_HIP_DEBUG("returning, err=%d\n", err);
	return err;
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
	int i, fail = 0;
	hip_ha_t *this, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hadb_hit);
	for(i = 0; i < HIP_HADB_SIZE; i++) {
		list_for_each_entry_safe(this, tmp, &hadb_byhit[i], next_hit) {
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
                                hip_in6_ntop(&hs->hit, str);
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

void hip_hadb_dump_spis_in(hip_ha_t *entry)
{
	struct hip_spi_in_item *item, *tmp;
#ifdef CONFIG_HIP_DEBUG
	unsigned long now = jiffies;
#endif

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x nes_SPI_out=0x%x ifindex=%d "
			  "ts=%lu updating=%d keymat_index=%u upd_flags=0x%x seq_update_id=%u NES=old 0x%x,new 0x%x,km %u\n",
			  item->spi, item->new_spi, item->nes_spi_out, item->ifindex,
			  now - item->timestamp, item->updating, item->keymat_index,
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
}

void hip_uninit_hadb()
{
	int i;
	hip_ha_t *ha, *tmp;
	struct hip_hit_spi *hs, *tmp_hs;

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

	/* HIT-SPI mappings should be already deleted by now, but check anyway */
	HIP_DEBUG("DELETING HS HT\n");
	for(i = 0; i < HIP_HADB_SIZE; i++) {
		_HIP_DEBUG("HS HT [%d]\n", i);
		list_for_each_entry_safe(hs, tmp_hs, &hadb_byspi_list[i], list) {
			HIP_ERROR("BUG: HS NOT ALREADY DELETED, DELETING HS %p, HS SPI=0x%x\n",
				  hs, hs->spi);
			if (atomic_read(&hs->refcnt) > 1)
				HIP_ERROR("HS: %p, in use while removing it from HADB\n", hs);
			hip_hadb_hold_hs(hs);
			hip_hadb_delete_hs(hs);
			//HIP_LOCK_HS(hs);
			//HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
			//hip_ht_delete(&hadb_spi_list, hs);
			//HIP_ERROR("TODO: CALL HS_PUT ?\n");
			//HIP_UNLOCK_HS(hs);
			hip_hadb_put_hs(hs);
		}
	}
	HIP_DEBUG("DONE DELETING HS HT\n");
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


#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
