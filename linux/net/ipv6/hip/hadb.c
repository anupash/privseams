#include "hadb.h"
#include "debug.h"
#include "misc.h"
#include "db.h"
#include "security.h"
#include "hashtable.h"

#include <net/ipv6.h>


HIP_HASHTABLE hadb_hit;
HIP_HASHTABLE hadb_spi;

static struct list_head hadb_byhit[HIP_HADB_SIZE];
static struct list_head hadb_byspi[HIP_HADB_SIZE];


static int hip_hadb_match_hit(void *key_1, void *key_2)
{
	hip_hit_t *key1, *key2;

	key1 = (hip_hit_t *)key_1;
	key2 = (hip_hit_t *)key_2;

	return !ipv6_addr_cmp(key_1, key_2);
	/* true when keys are equal */
}

static int hip_hadb_match_spi(void *key_1, void *key_2)
{
	uint32_t spi1,spi2;

	spi1 = (uint32_t)key_1;
	spi2 = (uint32_t)key_2;

	return (spi1 == spi2);
}

static void hip_hadb_hold_entry(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;
	
	if (!entry)
		return;

	atomic_inc(&ha->refcnt);
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n",ha, atomic_read(&ha->refcnt));
}

static void hip_hadb_put_entry(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;
	
	if (!entry)
		return;

	if (atomic_dec_and_test(&ha->refcnt)) {
		hip_hadb_delete_state(ha);
                HIP_DEBUG("HA: %p deleted.\n", ha);
	} else {
                _HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha, atomic_read(&ha->refcnt));
        }
}

static void *hip_hadb_get_key_hit(void *entry)
{
	return (void *)&(((hip_ha_t *)entry)->hit_peer);
}

static void *hip_hadb_get_key_spi(void *entry)
{
	return (void *)(((hip_ha_t *)entry)->spi_in);
}


/**
 * hip_hadb_rem_state_spi - Remove HA from SPI table
 * @entry: HA
 *
 * HA must be locked.
 */
static inline void hip_hadb_rem_state_spi(void *entry)

{
	hip_ha_t *ha = (hip_ha_t *)entry;

	ha->hastate &= ~HIP_HASTATE_SPIOK;
	hip_ht_delete(&hadb_spi, entry);
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


hip_ha_t *hip_hadb_find_byspi(u32 spi)
{
	return (hip_ha_t *)hip_ht_find(&hadb_spi, (void *)spi);
}


hip_ha_t *hip_hadb_find_byhit(hip_hit_t *hit)
{
	return (hip_ha_t *)hip_ht_find(&hadb_hit, (void *)hit);
}

/**
 * hip_hadb_remove_state_spi - Remove HA from SPI hash table.
 * @ha: HA
 */
void hip_hadb_remove_state_spi(hip_ha_t *ha)
{
	HIP_LOCK_HA(ha);
	if ((ha->hastate & HIP_HASTATE_SPIOK) == HIP_HASTATE_SPIOK) {
		hip_hadb_rem_state_spi(ha);
	} 
	HIP_UNLOCK_HA(ha);
}

/**
 * hip_hadb_remove_state_hit - Remove HA from HIT hash table.
 * @ha: HA
 */
void hip_hadb_remove_state_hit(hip_ha_t *ha)
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
 
	HIP_ASSERT(!(ipv6_addr_any(&ha->hit_peer) &&
		     (ha->spi_in == 0)));

	HIP_LOCK_HA(ha);

	st = ha->hastate;

	if (ha->spi_in != 0 && !(st & HIP_HASTATE_SPIOK)) {
		
		tmp = hip_ht_find(&hadb_spi, (void *)ha->spi_in);
		if (!tmp) {
			hip_ht_add(&hadb_spi, ha);
			st |= HIP_HASTATE_SPIOK;
		} else {
			hip_put_ha(tmp);
			HIP_DEBUG("SPI already taken\n");
		}
	}

	if (!ipv6_addr_any(&ha->hit_peer) && !(st & HIP_HASTATE_HITOK)) {

		tmp = hip_ht_find(&hadb_hit, (void *)&(ha->hit_peer));
		if (!tmp) {
			hip_ht_add(&hadb_hit, ha);
			st |= HIP_HASTATE_HITOK;
		} else {
			hip_put_ha(tmp);
			HIP_DEBUG("HIT already taken\n");
		}
	}

	ha->hastate = st;

	HIP_UNLOCK_HA(ha);

	return st;
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
	/* Delete SAs */
	hip_delete_sa(ha->spi_out, &ha->hit_peer);
	hip_delete_sa(ha->spi_in, &ha->hit_our);
	hip_delete_sa(ha->new_spi_out, &ha->hit_peer);
	hip_delete_sa(ha->new_spi_in, &ha->hit_our);

	/* peer addr list */
	hip_hadb_delete_peer_addrlist(ha);

	/* keymat & mm-01 stuff */
	if (ha->dh_shared_key)
		kfree(ha->dh_shared_key);

	kfree(ha);
}

/**
 * hip_hadb_create_state - Allocates and initializes a new HA structure
 * @gfpmask - passed directly to kmalloc().
 *
 * Return NULL if memory allocation failed, otherwise the HA.
 */
hip_ha_t *hip_hadb_create_state(int gfpmask)
{
	hip_ha_t *entry = NULL;

	entry = kmalloc(sizeof(struct hip_hadb_state), gfpmask);
	if (!entry)
		return NULL;

	memset(entry,0,sizeof(*entry));

	INIT_LIST_HEAD(&entry->next_spi);
	INIT_LIST_HEAD(&entry->next_hit);
	INIT_LIST_HEAD(&entry->peer_addr_list);

	spin_lock_init(&entry->lock);
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
void hip_hadb_remove_state(hip_ha_t *ha)
{
	HIP_ASSERT(atomic_read(&ha->refcnt) >= 1);
	HIP_LOCK_HA(ha);

	if ((ha->hastate & HIP_HASTATE_SPIOK) && ha->spi_in > 0)
		hip_hadb_rem_state_spi(ha);
	
	if ((ha->hastate & HIP_HASTATE_HITOK) && !ipv6_addr_any(&ha->hit_peer))
		hip_hadb_rem_state_hit(ha);

	HIP_UNLOCK_HA(ha);

	HIP_DEBUG("Removed HA: %p from HADB hash tables. References remaining: %d\n",
		  ha, atomic_read(&ha->refcnt));
}


/**
 * hip_hadb_exists_entry - Check if a certain HA exists in HADB hash table
 * @arg: Key to HA (depending on the @type)
 * @type: Type of the key
 *
 * Valid values for @type: HIP_ARG_HIT and HIP_ARG_SPI
 *
 * Returns 1 if the entry exists _AND_ its state is VALID.
 *         0 if the previous conditions are not true.
 */
int hip_hadb_exists_entry(void *arg, int type)
{
	int ok = 0;
	void *ha;

	if (type == HIP_ARG_HIT)
		ha = hip_ht_find(&hadb_hit, arg);
	else
		ha = hip_ht_find(&hadb_spi, arg);

	if (ha) {
		hip_hadb_put_entry(ha);
		if (((hip_ha_t *)ha)->hastate == HIP_HASTATE_VALID)
			ok = 1;
	}
	return ok;
}


/************** END OF PRIMITIVE FUNCTIONS **************/



/**
 * hip_hadb_get_peer_address - Get some of the peer's usable IPv6 address
 * @entry: corresponding hadb entry of the peer
 * @addr: where the selected IPv6 address of the peer is copied to
 *
 * Current destination address selection algorithm:
 * select the address which was added/updated last
 *
 * Returns: 0 if some of the addresses was copied successfully, else < 0.
 */
int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr)
{
	int err = 0;
        struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;

#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif

	HIP_LOCK_HA(entry);

	/* todo: this is ineffecient, optimize (e.g. insert addresses
	 * always in sorted order so we can break out of the loop earlier) */
        list_for_each_entry(s, &entry->peer_addr_list, list) {
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(&s->address, addrstr);
		_HIP_DEBUG("%s modified_time=%ld.%06ld\n", addrstr,
			  s->modified_time.tv_sec, s->modified_time.tv_usec);
#endif
		if (s->address_state != PEER_ADDR_STATE_REACHABLE) {
			HIP_DEBUG("skipping unreachable address %s\n", addrstr);
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
			/* this way we get always some address to use
			 * if peer address list contains at least one
			 * reachable address */
			candidate = s;
			memcpy(&latest, &s->modified_time, sizeof(struct timeval));
		}
        }

	HIP_UNLOCK_HA(entry);

        if (!candidate)
		err = -ENOMSG;
	else {
		ipv6_addr_copy(addr, &candidate->address);
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(addr, addrstr);
		_HIP_DEBUG("select %s from if=0x%x\n", addrstr, s->interface_id);
#endif
	}

        return err;
}

/**
 * hip_hadb_get_peer_addr_info - get infomation on the given peer IPv6 address
 * @entry: corresponding hadb entry of the peer
 * @addr: the IPv6 address for which the information is to be retrieved
 * @interface_id: where the Interface ID of @addr is copied to
 * @lifetime: where the lifetime of @addr is copied to
 * @modified_time: where the time when @addr was added or updated is copied to
 *
 * Returns: if @entry has the address @addr in its peer address list
 * parameters @interface_id, @lifetime, and @modified_time are
 * assigned if they are non-NULL and 1 is returned, else @interface_id
 * and @lifetime are not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_addr_info(hip_ha_t *entry,
				struct in6_addr *addr, uint32_t *interface_id,
				uint32_t *lifetime, struct timeval *modified_time)
{
	struct hip_peer_addr_list_item *s;
	char addrstr[INET6_ADDRSTRLEN];
	int i = 1;

	HIP_LOCK_HA(entry);

	list_for_each_entry(s, &entry->peer_addr_list, list) {
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(&s->address, addrstr);
		_HIP_DEBUG("address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			  i, addrstr,  s->interface_id, s->interface_id, s->lifetime, s->lifetime);
#endif
		if (!ipv6_addr_cmp(&s->address, addr)) {
			_HIP_DEBUG("found\n");
			if (interface_id)
				*interface_id = s->interface_id;
			if (lifetime)
				*lifetime = s->lifetime;
			if (modified_time) {
				modified_time->tv_sec = s->modified_time.tv_sec;
				modified_time->tv_usec = s->modified_time.tv_usec;
			}
			return 1;
		}
		i++;
	}
	HIP_UNLOCK_HA(entry);
	_HIP_DEBUG("not found\n");
	
	return 0;
}

/**
 * hip_hadb_set_peer_address_info - set entry's peer address Interface ID and/or address lifetime
 * @entry: corresponding hadb entry of the peer
 * @addr: the IPv6 address for which the information is to be set
 * @interface_id: Interface ID
 * @lifetime: address lifetime
 *
 * Set @entry's peer address @addr Interface ID and address
 * lifetime to given values. If @interface_id is non-NULL
 * @addr's Interface Id is changed to value pointed to by
 * @interface_id, similarly for parameter @lifetime.
 *
 * Returns: if @entry has the address @addr in its peer address list
 * parameters @interface_id and @lifetime were assigned and 1 is
 * returned. Else no values were assigned and 0 is returned.
 */
int hip_hadb_set_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *interface_id, uint32_t *lifetime)
{
	/* XX: Called with sdb lock held ? */

	struct hip_peer_addr_list_item *s;
	int i = 1;
	char addrstr[INET6_ADDRSTRLEN];


	HIP_LOCK_HA(entry);
	list_for_each_entry(s, &entry->peer_addr_list, list) {

		/* todo: update s->modified_time ? if yes, when and where ?
		 * when interface/lifetime is changed ?
		 */
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(&s->address, addrstr);
		_HIP_DEBUG("address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			  i, addrstr,  s->interface_id, s->interface_id, s->lifetime, s->lifetime);
#endif
		if (!ipv6_addr_cmp(&s->address, addr)) {
			if (interface_id) {
				HIP_DEBUG("updating interface_id 0x%x -> 0x%x\n",
					  s->interface_id, *interface_id);
				s->interface_id = *interface_id;
			}
			if (lifetime) {
				HIP_DEBUG("updating lifetime 0x%x -> 0x%x\n", s->lifetime, *lifetime);
				s->lifetime = *lifetime;
			}
			return 1;
		}
		i++;
	}
	HIP_UNLOCK_HA(entry);

	_HIP_DEBUG("not found\n");
	return 0;
}



/**
 * hip_hadb_add_peer_address - add a new peer IPv6 address to the entry's list of peer addresses
 * @entry: corresponding hadb entry of the peer
 * @new_addr: IPv6 address to be added
 * @interface_id: Interface ID of the address
 * @lifetime: address lifetime of the address
 *
 * Returns: íf @new_Addr already exists, 0 is returned. If address was
 * added successfully 0 is returned, else < 0.
 *
*/
int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t interface_id, uint32_t lifetime)
{
	/* TODO: add a function parameter struct
	 * hip_peer_addr_list_item *address_parameters (e.g. RTT from
	 * REA->AC->ACR) */

	int err = 0;
	struct hip_peer_addr_list_item *item;
	char addrstr[INET6_ADDRSTRLEN];
	uint32_t prev_if;

#ifdef CONFIG_HIP_DEBUG
	hip_in6_ntop(new_addr, addrstr);
	HIP_DEBUG("new_addr %s, interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
		  addrstr, interface_id, interface_id, lifetime, lifetime);
#endif

	err = hip_hadb_get_peer_addr_info(entry, new_addr, &prev_if, NULL, NULL);
	if (err) {
		/* todo: validate previous vs. new interface id for 
		 * the new_addr ? */
		if (prev_if != interface_id)
			HIP_DEBUG("todo: address interface changed: prev=%u new=%u\n", prev_if, 
				  interface_id);

		HIP_DEBUG("duplicate address not added (todo: update address lifetime ?)\n");
		/* todo: update address lifetime ? */
		err = 0;
		goto out_err;
	}

	item = kmalloc(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
	if (!item) {
		HIP_ERROR("item kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	_HIP_DEBUG("kmalloced item=0x%p\n", item);

	item->interface_id = interface_id;
	item->lifetime = lifetime;
	ipv6_addr_copy(&item->address, new_addr);
	item->address_state = PEER_ADDR_STATE_REACHABLE;
	do_gettimeofday(&item->modified_time);

	HIP_LOCK_HA(entry);
	list_add_tail(&item->list, &entry->peer_addr_list);
	HIP_UNLOCK_HA(entry);

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
	char addrstr[INET6_ADDRSTRLEN];

	HIP_LOCK_HA(entry);
	list_for_each_entry_safe(item, tmp, &entry->peer_addr_list, list) {
#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(&item->address, addrstr);
		_HIP_DEBUG("%p: address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			   item, i, addrstr,  item->interface_id, item->interface_id, item->lifetime, item->lifetime);
#endif
		if (!ipv6_addr_cmp(&item->address, addr)) {
			_HIP_DEBUG("deleting address\n");
			list_del(&item->list);
			kfree(item);
			break;
		}
		i++;
	}
	HIP_UNLOCK_HA(entry);
	return;
}


/**
 * hip_hadb_delete_peer_addr_iface - delete peer's addresses belonging to an interface
 * @entry: corresponding hadb entry of the peer
 * @interface_id: Interface ID to which all deleted addresses belong to
 */
void hip_hadb_delete_peer_addr_if(hip_ha_t *entry, uint32_t interface_id)
{
	/* XX: Called with sdb lock held ? currently caller must have the lock */
	struct hip_peer_addr_list_item *item, *tmp;
	char addrstr[INET6_ADDRSTRLEN];

	HIP_DEBUG("entry=%p interface_id=0x%x\n", entry, interface_id);

	HIP_LOCK_HA(entry);
	list_for_each_entry_safe(item, tmp, &entry->peer_addr_list, list) {
		HIP_DEBUG("item=0x%p &item->address=0x%p if=%u\n", item, item ? &item->address : NULL, item->interface_id);
		if (item->interface_id == interface_id) {
#ifdef CONFIG_HIP_DEBUG
			hip_in6_ntop(&item->address, addrstr);
			HIP_DEBUG("delete address %s itemlist=0x%p in=%p ip=%p\n", addrstr, &item->list, item->list.next, item->list.prev);
#endif
			list_del(&item->list);
			kfree(item);
		}
	}
	HIP_UNLOCK_HA(entry);
	return;
}

/**
 * hip_hadb_delete_peer_addr_not_in_list
 * @entry: corresponding hadb entry of the peer
 * @addrlist: list of addresses in format struct hip_rea_info_addr_item
 * @n_addrs: number of addresses listed in @addrlist
 * @iface: Interface ID in which all @addrlist addresses are
 *
 * Delete all @entry's peer addresses which are not contained in address
 * list given in parameter @addrlist which has @n_addrs
 * addresses. addrlist addresses belong to Interface ID @iface.
 */
void hip_hadb_delete_peer_addr_not_in_list(hip_ha_t *entry, 
					      void *addrlist, int n_addrs,
					      uint32_t iface) 
{
	/* THIS IS STILL A TEST FUNCTION .. fix */

	struct hip_peer_addr_list_item *item, *tmp;
	int i = 1;
	int j;
	void *p;
	int found = 0;
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
	char addrstr2[INET6_ADDRSTRLEN];
#endif

	HIP_DEBUG("entry=%p n_addrs=%d iface=0x%x\n", entry, n_addrs, iface);

	if (list_empty(&entry->peer_addr_list)) {
		HIP_DEBUG("AIEEEEEEEE\n");
		return;
	}

	HIP_LOCK_HA(entry);
	list_for_each_entry_safe(item, tmp, &entry->peer_addr_list, list) {

#ifdef CONFIG_HIP_DEBUG
		hip_in6_ntop(&item->address, addrstr);
		_HIP_DEBUG("test address %d: %s if=0x%x\n", i, addrstr, item->interface_id);
#endif
		for (j = 0, p = addrlist; j < n_addrs;
		     j++, p += sizeof(struct hip_rea_info_addr_item)) {
			struct hip_rea_info_addr_item *addr = (struct hip_rea_info_addr_item *) p;
#ifdef CONFIG_HIP_DEBUG
			hip_in6_ntop(&addr->address, addrstr2);
			_HIP_DEBUG(" against address: %s\n", addrstr2);
#endif
			if (!ipv6_addr_cmp(&item->address, &addr->address)) {
				/* address is still valid */
				found = 1;	
				if (item->interface_id == iface) {
					_HIP_DEBUG("match, same iface, still valid, not deleting\n");
				} else {
					/* possibly an erroneous case, two interfaces
					   have the same address simultaneously */

					/* is this a special case ? */
					_HIP_DEBUG("same address but different iface 0x%x, not deleting (?)\n",
						  item->interface_id);
					/* no delete, but just update iface info ? */

				}
				goto aaa;
			}
		}

		if (!found) {
			_HIP_DEBUG("not found, check iface too\n");
			if (item->interface_id == iface) {
				_HIP_DEBUG("same iface -> deleting the address\n");
				list_del(&item->list);
				kfree(item);
			}
		}
	aaa:
		i++;
	}
	HIP_UNLOCK_HA(entry);

	return;
}

/**
 * hip_hadb_delete_peer_address_list - delete all @entry's peer addresses
 * @entry: corresponding hadb entry of the peer
 */
void hip_hadb_delete_peer_addrlist(hip_ha_t *entry) {
        struct hip_peer_addr_list_item *item, *iter;
        char addrstr[INET6_ADDRSTRLEN];

        HIP_DEBUG("\n");

	if (list_empty(&entry->peer_addr_list))
		return;

	HIP_LOCK_HA(entry);
        list_for_each_entry_safe(item, iter, &entry->peer_addr_list, list) {
                hip_in6_ntop(&item->address, addrstr);
                _HIP_DEBUG("%p: address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			   item, i++, addrstr,  item->interface_id, item->interface_id, 
			   item->lifetime, item->lifetime);
		list_del(&item->list);
                kfree(item);
        }
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
		hip_delete_esp(ha);
		hip_hadb_remove_state_hit(ha);
		/* by now, if everything is according to plans, the refcnt should be 1 */
		hip_put_ha(ha);
		/* and now zero --> deleted*/
	} else {
		hip_hadb_delete_peer_addrlist_one(ha, addr);
		hip_put_ha(ha);
	}

	return 0;
}

int hip_hadb_add_peer_info(hip_hit_t *hit, struct in6_addr *addr)
{
	int err;
	hip_ha_t *entry;
	char str[INET6_ADDRSTRLEN];

	/* note: can't lock here or else hip_sdb_add_peer_address will block
	 * unsigned long flags = 0;
	 * spin_lock_irqsave(&hip_sdb_lock, flags); */

	hip_in6_ntop(hit, str);
	HIP_DEBUG("called: HIT %s\n", str);

	entry = hip_hadb_find_byhit(hit);
	if (!entry) {
		entry = hip_hadb_create_state(GFP_KERNEL);
		if (!entry) {
			HIP_ERROR("Unable to create a new entry\n");
			return -1;
		}
		HIP_DEBUG("created a new sdb entry\n");

		ipv6_addr_copy(&entry->hit_peer, hit);

		/* XXX: This is wrong. As soon as we have native socket API, we
		 * should enter here the correct sender... (currently unknown).
		 */
		if (hip_get_any_local_hit(&entry->hit_our) == 0)
			HIP_DEBUG_HIT("our hit seems to be", &entry->hit_our);
		else 
			HIP_INFO("Could not assign local hit... continuing\n");
		hip_hadb_insert_state(entry);
		hip_hold_ha(entry); /* released at the end */
	}

	err = hip_hadb_add_peer_addr(entry, addr, 0, 0);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		err = -2;
		goto out;
	}
	HIP_DEBUG("peer address add ok\n");

 out:
	if (entry)
		hip_put_ha(entry);
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
	int i, fail;
	hip_ha_t *this, *tmp;

	if (!func)
		return -EINVAL;

	fail = 0;

	HIP_LOCK_HT(&hadb_hit);
	for(i=0; i<HIP_HADB_SIZE; i++) {
		list_for_each_entry_safe(this, tmp, &hadb_byhit[i], next_hit) {
			hip_hold_ha(this);

			fail = func(this, opaque);

			hip_put_ha(this);

			if (fail)
				break;
		}
		if (fail)
			break;
	}
	HIP_UNLOCK_HT(&hadb_hit);
	return fail;
}


#ifdef CONFIG_PROC_FS

typedef struct {
	char *page;
	int count;
	int len;
	int i; /* counter */
} hip_proc_opaque_t;


static int hip_proc_hadb_state_func(hip_ha_t *entry, void *opaque)
{
	hip_proc_opaque_t *op = (hip_proc_opaque_t *)opaque;
	char *esp_transforms[] = { "none/reserved", "aes-sha1", "3des-sha1", "3des-md5",
				   "blowfish-sha1", "null-sha1", "null-md5" };
	char addr_str[INET6_ADDRSTRLEN];
	char *page = op->page;
	int len = op->len;
	int count = op->count;
	int i = op->i;

	HIP_LOCK_HA(entry);

	if ( (len += snprintf(page+len, count-len, "%s 0x%x %d 0x%x",
			      hip_state_str(entry->state), entry->hastate, 
			      atomic_read(&entry->refcnt), 
			      entry->peer_controls)) >= count)
		goto error;

	hip_in6_ntop(&entry->hit_our, addr_str);
	if ( (len += snprintf(page+len, count-len, " %s", addr_str)) >= count)
		goto error;

	hip_in6_ntop(&entry->hit_peer, addr_str);
	if ( (len += snprintf(page+len, count-len, " %s", addr_str)) >= count)
		goto error;

	if ( (len += snprintf(page+len, count-len,
			      " 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x %s",
			      entry->spi_in, entry->spi_out, entry->new_spi_in,
			      entry->new_spi_out, entry->lsi_our, entry->lsi_peer,
			      entry->esp_transform <=
			      (sizeof(esp_transforms)/sizeof(esp_transforms[0])) ?
			      esp_transforms[entry->esp_transform] : "UNKNOWN")) >= count)
		goto error;

	if ( (len += snprintf(page+len, count-len,
			      " 0x%llx %u %u %u %u %u\n",
			      entry->birthday, 
			      entry->current_keymat_index,
			      entry->keymat_calc_index, entry->update_id_in,
			      entry->update_id_out, entry->dh_shared_key_len )) >= count)
		goto error;
	
#if 0
	list_for_each_entry(s, &entry->peer_addr_list, list) {
		hip_in6_ntop(&s->address, addr_str);
		if ( (len += snprintf(page+len, count-len,
				      i>0 ? ",%d=%s" : " %d=%s", i+1, addr_str)) >= count)
			goto error;
		i++;
	}

	if (hip_hadb_get_peer_addr(entry, &addr) == 0) {
		hip_in6_ntop(&addr, addr_str);
		len += snprintf(page+len, count-len, " %s", addr_str);
	} else
		len += snprintf(page+len, count-len, " (no addr)");
#endif

	HIP_UNLOCK_HA(entry);

	if (len >= count)
		goto error;

	op->len = len;
	op->count = count;
	op->i = i;
	return 0;

 error:
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("PROC read max len exceeded\n");
	return -1;
}


static int hip_proc_read_hadb_peer_addrs_func(hip_ha_t *entry, void *opaque)
{
	hip_proc_opaque_t *op = (hip_proc_opaque_t *)opaque;
	struct timeval now, addr_age;
	char addr_str[INET6_ADDRSTRLEN];
	struct hip_peer_addr_list_item *s;
	int i = op->i;
	char *page = op->page;
	int len = op->len;
	int count = op->count;
	
	do_gettimeofday(&now);

	HIP_LOCK_HA(entry);

	hip_in6_ntop(&entry->hit_peer, addr_str);
	if ( (len += snprintf(page+len, count-len, "HIT %s", addr_str)) >= count)
		goto error;

	list_for_each_entry(s, &entry->peer_addr_list, list) {
		hip_in6_ntop(&s->address, addr_str);
		hip_timeval_diff(&now, &s->modified_time, &addr_age);
		if ( (len += snprintf(page+len, count-len,
				      "\n %s state=0x%x if=0x%x lifetime=0x%x "
				      "age=%ld.%01ld",
				      addr_str, s->address_state, s->interface_id,
				      s->lifetime, addr_age.tv_sec,
				      addr_age.tv_usec / 100000 /* show 1/10th sec */)
			     ) >= count)
			goto error;
		i++;
	}

	HIP_UNLOCK_HA(entry);

	if (i == 0 && (len += snprintf(page+len, count-len, "\n no addresses")) >= count)
		goto error;

	if ( (len += snprintf(page+len, count-len, "\n")) >= count)
		goto error;

	op->len = len;
	op->count = count;
	op->i = i;
	return 0;
 error:
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("PROC read peer addresses buffer exceeded\n");
	return -1;
}

/**
 * hip_proc_read_hadb_state - debug function for dumping hip_sdb_state
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * hip_hadb_state can be dumped from file /proc/net/hip/sdb_state
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_hadb_state(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
	hip_proc_opaque_t ps;
	int fail;

	ps.page = page;
	ps.count = count;

	ps.len = snprintf(page, count,
		       "state hastate refcnt peer_controls hit_our hit_peer "
		       "spi_in spi_out new_spi_in new_spi_out lsi_our lsi_peer esp_transform "
		       "birthday keymat_index keymat_calc_index "
		       "update_id_in update_id_out dh_len\n");

	/* "update_id_in update_id_out dh_len [list_of_peer_addrs curr_dst_addr]\n"); */

	if (ps.len >= count) {
		fail = 1;
		goto err;
	}

	*eof = 1;

	fail = hip_for_each_ha(hip_proc_hadb_state_func, &ps);

 err:
	if (fail) {
		page[ps.count-1] = '\0';
		ps.len = ps.count;
	} else
		page[ps.len] = '\0';

	return ps.len;
}



/**
 * hip_proc_read_hadb_peer_addrs - dump properties of IPv6 addresses of every peer
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * This debug function lists every IPv6 address and their properties
 * for every peer. The list can be dumped from from file
 * /proc/net/hip/sdb_peer_addrs
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	hip_proc_opaque_t ps;
	int fail;

	ps.page = page;
	ps.count = count;
	ps.len = 0;
	*eof = 1;

	fail = hip_for_each_ha(hip_proc_read_hadb_peer_addrs_func, &ps);
	if (fail) {
		page[ps.count-1] = '\0';
		ps.len = ps.count;
	} else
		page[ps.len] = '\0';

	return ps.len;
}

#endif

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

	string = kmalloc(4096,GFP_ATOMIC);
	if (!string) {
		HIP_ERROR("Cannot dump HADB... out of memory\n");
		return;
	}

	HIP_LOCK_HT(&hadb_hit);

	for(i=0;i<HIP_HADB_SIZE;i++) {
		if (!list_empty(&hadb_byhit[i])) {
			cnt = sprintf(string, "[%d]: ", i);
		
			list_for_each_entry(entry, &hadb_byhit[i], next_hit) {
				hip_hold_ha(entry);
				if (cnt > 3900) {
					string[cnt] = '\0';
					printk(KERN_ALERT "%s\n", string);
					cnt = 0;
				}

				k = hip_in6_ntop2(&entry->hit_peer, string+cnt);
				cnt+=k;
				hip_put_ha(entry);
			}
			string[cnt] = '\0';
			printk(KERN_ALERT "%s\n", string);
		}
	}
	
	HIP_UNLOCK_HT(&hadb_hit);
	kfree(string);
}


void hip_init_hadb(void)
{
	memset(&hadb_hit,0,sizeof(hadb_hit));
	memset(&hadb_spi,0,sizeof(hadb_spi));

	hadb_hit.head =      hadb_byhit;
	hadb_hit.hashsize =  HIP_HADB_SIZE;
	hadb_hit.offset =    offsetof(hip_ha_t, next_hit);
	hadb_hit.hash =      hip_hash_hit;
	hadb_hit.compare =   hip_hadb_match_hit;
	hadb_hit.hold =      hip_hadb_hold_entry;
	hadb_hit.put =       hip_hadb_put_entry;
	hadb_hit.get_key =   hip_hadb_get_key_hit;

	strncpy(hadb_hit.name,"HADB_BY_HIT", 15);
	hadb_hit.name[15] = 0;

	hadb_spi.head =      hadb_byspi;
	hadb_spi.hashsize =  HIP_HADB_SIZE;
	hadb_spi.offset =    offsetof(hip_ha_t, next_spi);
	hadb_spi.hash =      hip_hash_spi;
	hadb_spi.compare =   hip_hadb_match_spi;
	hadb_spi.hold =      hip_hadb_hold_entry;
	hadb_spi.put =       hip_hadb_put_entry;
	hadb_spi.get_key =   hip_hadb_get_key_spi;

	strncpy(hadb_spi.name,"HADB_BY_SPI", 15);
	hadb_spi.name[15] = 0;

	hip_ht_init(&hadb_hit);
	hip_ht_init(&hadb_spi);
}

void hip_uninit_hadb()
{
	int i;
	hip_ha_t *ha, *tmp;

	/* I think this is not very safe deallocation.
	 * Locking the hadb_spi and hadb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in 
	 * hip_hadb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
	for(i=0;i<HIP_HADB_SIZE;i++) {
		list_for_each_entry_safe(ha, tmp, &hadb_byhit[i], next_hit) {
			if (atomic_read(&ha->refcnt) > 2)
				HIP_ERROR("HA: %p, in use while removing it from HADB\n", ha);
			hip_hold_ha(ha);
			hip_hadb_remove_state(ha);
			hip_put_ha(ha);
		}

		list_for_each_entry_safe(ha, tmp, &hadb_byspi[i], next_spi) {
			if (atomic_read(&ha->refcnt) > 1)
				HIP_ERROR("HA: %p, in use while removing it from HADB\n", ha);
			
			hip_hold_ha(ha);
			hip_hadb_remove_state(ha);
			hip_put_ha(ha);
		}
	}
}

