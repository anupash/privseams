#include "hadb.h"
#include "debug.h"
#include "misc.h"
#include "db.h"
#include "security.h"
#include "hashtable.h"
#include "builder.h"

#include <net/ipv6.h>


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
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n", ha, atomic_read(&ha->refcnt));
}

static void hip_hadb_put_entry(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;

	if (!entry)
		return;

	if (atomic_dec_and_test(&ha->refcnt)) {
                HIP_DEBUG("HA: refcnt decremented to 0, deleting %p\n", ha);
		hip_hadb_delete_state(ha);
                HIP_DEBUG("HA: %p deleted\n", ha);
	} else {
                _HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha, atomic_read(&ha->refcnt));
        }
}

void hip_hadb_delete_hs(struct hip_hit_spi *hs)
{
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	kfree(hs);
}

static void hip_hadb_put_hs(void *entry)
{
	struct hip_hit_spi *hs = (struct hip_hit_spi *) entry;
       	if (!hs)
		return;

	if (atomic_dec_and_test(&hs->refcnt)) {
                HIP_DEBUG("HS: refcnt decremented to 0, deleting %p\n", hs);
		hip_hadb_delete_hs(hs);
                HIP_DEBUG("HS: %p deleted\n", hs);
	} else {
		_HIP_DEBUG("HS: %p, refcnt decremented to: %d\n", hs, atomic_read(&hs->refcnt));
        }
}

static void hip_hadb_hold_hs(void *entry)
{
	struct hip_hit_spi *hs = (struct hip_hit_spi *) entry;
      	if (!hs)
		return;

	atomic_inc(&hs->refcnt);
	_HIP_DEBUG("HS: %p, refcnt incremented to: %d\n", hs, atomic_read(&hs->refcnt));
}

//void hip_hadb_remove_hs(struct hip_hit_spi *hs)
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
	hip_hadb_put_hs(hs);
	HIP_UNLOCK_HS(hs);
}

/* test */
void hip_hadb_remove_hs2(struct hip_hit_spi *hs)
{
	if (!hs) {
		HIP_ERROR("NULL HS\n");
                return;
	}

	HIP_LOCK_HS(hs);
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	hip_ht_delete(&hadb_spi_list, hs);
	HIP_ERROR("TODO: CALL HS_PUT ?\n");
	HIP_UNLOCK_HS(hs);
}

static void *hip_hadb_get_key_hit(void *entry)
{
	return (void *)&(((hip_ha_t *)entry)->hit_peer);
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

	HIP_ASSERT(!(ipv6_addr_any(&ha->hit_peer)));

	HIP_LOCK_HA(ha);
	st = ha->hastate;

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

/*
 * XXXXXX Returns: 0 if @spi was added to the inbound SPI list of the HA @ha, otherwise < 0.
 */
int hip_hadb_insert_state_spi_list(hip_ha_t *ha, uint32_t spi)
{
	int err = 0;
	struct hip_hit_spi *tmp;
	hip_hit_t hit;
	struct hip_hit_spi *new_item;

	HIP_DEBUG("SPI LIST HT_ADD HA=0x%p SPI=0x%x\n", ha, spi);
	HIP_LOCK_HA(ha);
	ipv6_addr_copy(&hit, &ha->hit_peer);
	HIP_UNLOCK_HA(ha);

	tmp = hip_ht_find(&hadb_spi_list, (void *)spi);
	if (tmp) {
		hip_hadb_put_hs(tmp);
		HIP_ERROR("BUG, SPI already inserted\n");
		err = -EEXIST;
		goto out_err;
	}

	new_item = kmalloc(sizeof(struct hip_hit_spi), GFP_ATOMIC);
	if (!new_item) {
		HIP_ERROR("new_item kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	atomic_set(&new_item->refcnt, 0);
	spin_lock_init(&new_item->lock);
	new_item->spi = spi;
	ipv6_addr_copy(&new_item->hit, &hit);

	hip_ht_add(&hadb_spi_list, new_item);
	HIP_DEBUG("SPI 0x%x added to HT spi_list, HS=%p\n", spi, new_item);
	HIP_DEBUG("HS TABLE:\n");
	hip_hadb_dump_hs_ht();
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
	hip_hadb_delete_inbound_spis(ha);
	hip_hadb_delete_outbound_spis(ha);
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

	memset(entry, 0, sizeof(*entry));

	INIT_LIST_HEAD(&entry->next_hit);
	INIT_LIST_HEAD(&entry->spis_in);
	INIT_LIST_HEAD(&entry->spis_out);

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

/************** END OF PRIMITIVE FUNCTIONS **************/

#if 1
/* select the preferred address within the addresses of the given SPI */
/* selected address is copied to @addr, it is is non-NULL */
int hip_hadb_select_spi_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out, struct in6_addr *addr)
{
	int err = 0;
        struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;
//	struct hip_spi_out_item *spi_out;//, *tmp;
	char addrstr[INET6_ADDRSTRLEN];

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
#endif

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
        struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;
	struct hip_spi_out_item *spi_out;//, *tmp;
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif

	HIP_LOCK_HA(entry);

	//hip_print_hit("entry def addr", &entry->preferred_address);
	if (ipv6_addr_any(&entry->preferred_address)) {
		HIP_DEBUG("no preferred address\n");
	} else {
		ipv6_addr_copy(addr, &entry->preferred_address);
		_HIP_DEBUG("found preferred address\n");
		goto out;
	}

	if (entry->default_spi_out == 0) {
		HIP_DEBUG("default SPI out is 0, use the bex address\n");
		if (ipv6_addr_any(&entry->bex_address)) {
			HIP_DEBUG("no bex address\n");
			err = -EINVAL;
		} else
			ipv6_addr_copy(addr, &entry->bex_address);
		goto out;
	}

	/* try to select a peer address among the ones belonging to
	 * the default outgoing SPI */
//	err = hip_hadb_select_spi_addr(entry, entry->default_spi_out, addr);

#if 1
	spi_out = hip_hadb_get_spi_list(entry, entry->default_spi_out);
	if (!spi_out) {
		HIP_ERROR("did not find SPI list for default_spi_out 0x%x\n",
			  entry->default_spi_out);
		err = -EEXIST;
		goto out;
	}
#if 0
        list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		if (spi_out->spi == entry->default_spi_out) {
			found_spi_list = 1;
			break;
		}
        }

	if (!found_spi_list) {
		HIP_ERROR("did not find SPI list for default_spi_out 0x%x\n",
			  entry->default_spi_out);
		err = -EEXIST;
		goto out;
	}

	/* not tested yet */
	if (!ipv6_addr_any(&spi_out->preferred_address)) {
		HIP_DEBUG("TEST CODE\n");
		HIP_DEBUG("found preferred address for SPI 0x%x\n",
			  spi_out->spi);
		ipv6_addr_copy(addr, &spi_out->preferred_address);
		goto out;		
	}
#endif

#endif


 out:
	HIP_UNLOCK_HA(entry);
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
	char addrstr[INET6_ADDRSTRLEN];
	int i = 1;
	struct hip_spi_out_item *spi_out, *tmp;

	HIP_LOCK_HA(entry);

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
	char addrstr[INET6_ADDRSTRLEN];
	struct hip_spi_out_item *spi_out, *tmp;

	HIP_ERROR("USELESS ?\n");

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
 * Returns: íf @new_addr already exists, 0 is returned. If address was
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

	HIP_LOCK_HA(entry);

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

	item = kmalloc(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
	if (!item) {
		HIP_ERROR("item kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	_HIP_DEBUG("kmalloced item=0x%p\n", item);

	item->lifetime = lifetime;
	ipv6_addr_copy(&item->address, new_addr);
	item->address_state = state;
	do_gettimeofday(&item->modified_time);

	list_add_tail(&item->list, &spi_out->peer_addr_list);

 out_err:
	HIP_UNLOCK_HA(entry);
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
	struct hip_spi_out_item *spi_out, *spi_tmp;

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
				kfree(item);
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

	/* old comment ? note: can't lock here or else hip_sdb_add_peer_address will block
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

	err = hip_hadb_add_peer_addr(entry, addr, 0, 0, PEER_ADDR_STATE_ACTIVE);
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

int hip_hadb_add_inbound_spi(hip_ha_t *entry, struct hip_spi_in_item *data)
{
	int err = 0;
	struct hip_spi_in_item *item, *tmp;
	uint32_t spi_in;

	spi_in = data->spi;

	/* assumes locked entry */
	HIP_DEBUG("SPI_in=0x%x\n", spi_in);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (item->spi == spi_in) {
			HIP_DEBUG("not adding duplicate SPI\n");
			goto out;
		}
        }

	item = kmalloc(sizeof(struct hip_spi_in_item), GFP_ATOMIC);
	if (!item) {
		HIP_ERROR("item kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(item, data, sizeof(struct hip_spi_in_item));
	item->timestamp = jiffies;
	list_add(&item->list, &entry->spis_in);
	HIP_DEBUG("added SPI 0x%x to the inbound SPI list, item=0x%p\n", spi_in, item);
	// hip_hold_ha(entry); ?

	HIP_DEBUG("inserting SPI to HIT-SPI hashtable\n");
	err = hip_hadb_insert_state_spi_list(entry, spi_in);
	if (err == -EEXIST)
		err = 0;
 out_err:
 out:
	return err;
}

int hip_hadb_add_outbound_spi(hip_ha_t *entry, struct hip_spi_out_item *data)
{
	int err = 0;
	struct hip_spi_out_item *item, *tmp;
	uint32_t spi_out;

	/* assumes locked entry ? */

	spi_out = data->spi;

	HIP_LOCK_HA(entry);
	HIP_DEBUG("SPI_out=0x%x\n", spi_out);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		if (item->spi == spi_out) {
			HIP_DEBUG("not adding duplicate SPI\n");
			goto out;
		}
        }

	item = kmalloc(sizeof(struct hip_spi_out_item), GFP_ATOMIC);
	if (!item) {
		HIP_ERROR("item kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(item, data, sizeof(struct hip_spi_out_item));
	INIT_LIST_HEAD(&item->peer_addr_list);
	ipv6_addr_copy(&item->preferred_address, &in6addr_any);
	list_add(&item->list, &entry->spis_out);
	HIP_DEBUG("added SPI 0x%x to the outbound SPI list, item=0x%p\n", spi_out, item);

 out_err:
 out:
	HIP_UNLOCK_HA(entry);
	return err;
}


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


void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *item, *tmp;

	/* assumes locked entry */
	HIP_DEBUG("entry=0x%p SPI=0x%x\n", entry, spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (item->spi == spi) {
			HIP_DEBUG("deleting SPI_in=0x%x SPI_in_new=0x%x from inbound list, item=0x%p\n",
				  item->spi, item->new_spi, item);
			HIP_ERROR("remove SPI from HIT-SPI HT\n");
			hip_hadb_remove_hs(item->spi);
			hip_delete_sa(item->spi, &entry->hit_our);
			hip_delete_sa(item->new_spi, &entry->hit_our);
			list_del(&item->list);
			kfree(item);
			break;
		}
        }
}

/* delete all entry's inbound SAs */
void hip_hadb_delete_inbound_spis(hip_ha_t *entry)
{
	struct hip_spi_in_item *item, *tmp;

	/* assumes locked entry */
	HIP_DEBUG("entry=0x%p\n", entry);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("deleting SPI_in=0x%x SPI_in_new=0x%x from inbound list, item=0x%p\n",
			  item->spi, item->new_spi, item);
		HIP_DEBUG("remove SPI from HIT-SPI HT\n");
		hip_hadb_remove_hs(item->spi);
		hip_delete_sa(item->spi, &entry->hit_our);
		hip_delete_sa(item->new_spi, &entry->hit_our);
		list_del(&item->list);
		kfree(item);
        }
}

void hip_hadb_delete_outbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *item, *tmp;

	/* assumes locked entry */
	HIP_DEBUG("entry=0x%p SPI=0x%x\n", entry, spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		if (item->spi == spi) {
			struct hip_peer_addr_list_item *addr_item, *addr_tmp;

			HIP_DEBUG("deleting SPI_out=0x%x SPI_out_new=0x%x from outbound list, item=0x%p\n",
				  item->spi, item->new_spi, item);
			hip_delete_sa(item->spi, &entry->hit_peer);
			hip_delete_sa(item->new_spi, &entry->hit_peer);
			/* delete peer's addresses */
			list_for_each_entry_safe(addr_item, addr_tmp, &item->peer_addr_list, list) {
				list_del(&addr_item->list);
				kfree(addr_item);
			}
			list_del(&item->list);
			kfree(item);
		}
        }
}


/* delete all entry's outbound SAs */
void hip_hadb_delete_outbound_spis(hip_ha_t *entry)
{
	struct hip_spi_out_item *spi_out, *spi_tmp;

	/* assumes locked entry */

	HIP_DEBUG("entry=0x%p\n", entry);
        list_for_each_entry_safe(spi_out, spi_tmp, &entry->spis_out, list) {
		struct hip_peer_addr_list_item *addr_item, *addr_tmp;

		HIP_DEBUG("deleting SPI_out=0x%x SPI_out_new=0x%x from outbound list, spi_out=0x%p\n",
			  spi_out->spi, spi_out->new_spi, spi_out);
		hip_delete_sa(spi_out->spi, &entry->hit_peer);
		hip_delete_sa(spi_out->new_spi, &entry->hit_peer);
		/* delete peer's addresses */
		list_for_each_entry_safe(addr_item, addr_tmp, &spi_out->peer_addr_list, list) {
			list_del(&addr_item->list);
			kfree(addr_item);
		}
		list_del(&spi_out->list);
		kfree(spi_out);
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
		HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
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

	HIP_DEBUG("spi=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
		if (item->spi == spi || item->new_spi == spi) {
			HIP_DEBUG("found\n");
			return item->ifindex;
		}
        }
	HIP_DEBUG("ifindex not found for the SPI\n");
	return 0;
}

/* Get the SPI of given ifindex, returns 0 if ifindex was not found  */
uint32_t hip_hadb_get_spi(hip_ha_t *entry, int ifindex)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("ifindex=%d\n", ifindex);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
		if (item->ifindex == ifindex) {
			HIP_DEBUG("found\n");
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
		HIP_DEBUG("test item: ifindex=%d spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
			  item->ifindex, item->spi, item->nes_spi_out, item->seq_update_id);
		if (item->seq_update_id == peer_update_id) {
			HIP_DEBUG("found\n");
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

	hip_print_hit("dst dev_addr", dev_addr);
	ifindex = hip_ipv6_devaddr2ifindex(dev_addr);
	HIP_DEBUG("ifindex of dst dev=%d\n", ifindex);
	if (!ifindex)
		return 0;

        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", item->ifindex, item->spi);
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
		HIP_DEBUG("test item: ifindex=%d spi=0x%x updating=%d\n",
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

	HIP_DEBUG("spi=0x%x\n", spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: spi=0x%x\n", item->spi);
		if (item->spi == spi) {
			HIP_DEBUG("clearing SPI status\n");
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
	HIP_DEBUG("spi=0x%x new_spi=0x%x spi_out=0x%x\n", spi, new_spi, spi_out);

	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
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

	HIP_DEBUG("spi=0x%x new_spi=0x%x\n", spi, new_spi);
	list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
			  item->spi, item->new_spi);
		if (item->spi == spi) {
			HIP_DEBUG("setting new_spi\n");
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

	HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
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

	HIP_DEBUG("old_spi=0x%x\n", old_spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: ifindex=%d spi=0x%x new_spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
			  item->ifindex, item->spi, item->new_spi,
			  item->nes_spi_out, item->seq_update_id);
		if (item->spi == old_spi) {
			HIP_DEBUG("switching\n");
			item->spi = item->new_spi;
			item->new_spi = 0;
			item->nes_spi_out = 0;
			break;
		}
        }
	HIP_DEBUG("returning\n");
}

/* switch from Old SPI to New SPI (outbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_out(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_out_item *item, *tmp;

	HIP_DEBUG("old_spi=0x%x\n", old_spi);
        list_for_each_entry_safe(item, tmp, &entry->spis_out, list) {
		HIP_DEBUG("test item: spi=0x%x new_spi=0x%x seq_id=%u\n",
			  item->spi, item->new_spi, item->seq_update_id);
		if (item->spi == old_spi) {
			HIP_DEBUG("switching\n");
			item->spi = item->new_spi;
			item->new_spi = 0;
			break;
		}
        }
	HIP_DEBUG("returning\n");
}


void hip_update_set_status(hip_ha_t *entry, uint32_t spi, int set_flags,
			   uint32_t update_id, int update_flags_or,
			   struct hip_nes *nes, uint16_t keymat_index)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("spi=0x%x update_id=%u update_flags_or=0x%x keymat_index=%u nes=0x%p\n",
		  spi, update_id, update_flags_or, keymat_index, nes);
	if (nes)
		HIP_DEBUG("NES: old_spi=0x%x new_spi=0x%x keymat_index=%u\n",
			  ntohl(nes->old_spi), ntohl(nes->new_spi), ntohs(nes->keymat_index));

	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n",
			  item->spi, item->new_spi);
		if (item->spi == spi) {
			HIP_DEBUG("setting new values\n");
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
	_HIP_DEBUG("spi=0x%x direction=%d test_new_spi=%d\n",
		  spi, direction, test_new_spi);
	/* assumes locked entry  */
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

void hip_hadb_set_default_out_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out,
				   struct hip_peer_addr_list_item *addr)
{
	if (!spi_out) {
		HIP_ERROR("NULL spi_out\n");
		return;
	}

	if (addr) {
		HIP_DEBUG("testing kludge, setting given address as default out addr\n");
		ipv6_addr_copy(&spi_out->preferred_address, &addr->address);
		ipv6_addr_copy(&entry->preferred_address, &addr->address);
	} else {
		struct in6_addr a;
		int err = hip_hadb_select_spi_addr(entry, spi_out, &a);
		HIP_DEBUG("selected setting address as default out addr\n");
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

		HIP_DEBUG("peer Update ID=%u\n", puid);

		/* see if your NES is acked and maybe if corresponging NES was received */
		list_for_each_entry_safe(in_item, in_tmp, &entry->spis_in, list) {
			HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
				  in_item->spi, in_item->seq_update_id);
			if (in_item->seq_update_id == puid) {
				HIP_DEBUG("SEQ and ACK match\n");
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
					HIP_DEBUG("checking address, seq=%u\n", addr->seq_update_id);
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
						HIP_DEBUG("address verified successfully, setting state to ACTIVE\n");
						addr->address_state = PEER_ADDR_STATE_ACTIVE;
						do_gettimeofday(&addr->modified_time);

						if (addr->is_preferred) {
							hip_hadb_set_default_out_addr(entry, out_item, addr);
						} else
							HIP_DEBUG("address was not set as preferred address in REA\n");
					}
				}
			}
			entry->skbtest = 1;
			HIP_DEBUG("set skbtest to 1\n");
		} else {
			HIP_DEBUG("no ECHO_RESPONSE in same packet with ACK\n");
		}
	}
 out_err:
}

void hip_update_handle_nes(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
			  item->spi, item->seq_update_id);
		if (item->seq_update_id == peer_update_id) {
			HIP_DEBUG("received peer's NES\n");
			item->update_state_flags |= 0x2; /* recv'd NES */
		}
	}
}

/* works if update contains only one NES */
int hip_update_get_spi_keymat_index(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *item, *tmp;

	HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		HIP_DEBUG("test item: spi_in=0x%x seq_update_id=%u keymat_index=%u\n",
			  item->spi, item->seq_update_id, item->keymat_index);
		if (item->seq_update_id == peer_update_id) {
			return item->keymat_index;
		}
	}
	return 0;
}

/* kludge for removing old entry->spi_in code to the new code */
uint32_t hip_hadb_get_latest_inbound_spi(hip_ha_t *entry)
{
	struct hip_spi_in_item *item, *tmp;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;

	HIP_LOCK_HA(entry);
        list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
		if (now - item->timestamp < t) {
			spi = item->spi;
			t = now - item->timestamp;
		}
        }

	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("newest spi_in is 0x%x\n", spi);
	return spi;
}

/* get pointer to the SPI list or NULL if SPI list does not exist */
struct hip_spi_out_item *hip_hadb_get_spi_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *item, *tmp;
	/* no locking */
	HIP_DEBUG("SPI=0x%x\n", spi);
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
	/* no locking */
	int err = 0;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a, *tmp;
	int new = 1;

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
		new_addr = kmalloc(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
		if (!new_addr) {
			HIP_ERROR("item kmalloc failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	} else
		HIP_DEBUG("update old addr item\n");

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
			HIP_DEBUG("set initial address state UNVERIFIED\n");
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
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add_tail(&new_addr->list, &spi_list->peer_addr_list);
	}

 out_err:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
}

/** hip_get_default_spi_out - Get the SPI to use in the outbound ESP packet
 * @hit: peer HIT
 * @state_ok: status of SPI lookup
 *
 * On successful return state_ok is 1, on error it is 0.
 *
 * Returns: the SPI value to use in the packet, or 0 on error.
*/
uint32_t hip_get_default_spi_out(struct in6_addr *hit, int *state_ok)
{
	uint32_t spi;
	hip_ha_t *entry;

	_HIP_DEBUG("\n");

	entry = hip_hadb_find_byhit(hit);
	if (!entry) {
		HIP_DEBUG("entry not found\n");
		*state_ok = 0;
		return 0;
	}

	HIP_LOCK_HA(entry);
	spi = entry->default_spi_out;
	HIP_UNLOCK_HA(entry);
	hip_put_ha(entry);
	*state_ok = spi ? 1 : 0;
	return spi;
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
	for(i = 0; i < HIP_HADB_SIZE; i++) {
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
			      " 0x%08x 0x%08x 0x%08x %s",
			      entry->default_spi_out, entry->lsi_our, entry->lsi_peer,
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

	if (len >= count)
		goto error;

	HIP_UNLOCK_HA(entry);

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
	struct hip_spi_out_item *spi_out, *spi_tmp;
	const char *state_name[] = { "NONE", "UNVERIFIED", "ACTIVE", "DEPRECATED" };

	do_gettimeofday(&now);

	HIP_LOCK_HA(entry);

	hip_in6_ntop(&entry->hit_peer, addr_str);
	if ( (len += snprintf(page+len, count-len, "HIT %s", addr_str)) >= count)
		goto error;

	list_for_each_entry_safe(spi_out, spi_tmp, &entry->spis_out, list) {
		int n_addrs = 0;

		if ( (len += snprintf(page+len, count-len,
				      "\n SPI 0x%x", spi_out->spi)) >= count)
			goto error;

		if (spi_out->spi == entry->default_spi_out &&
		    (len += snprintf(page+len, count-len, " preferred")) >= count)
			goto error;

		list_for_each_entry(s, &spi_out->peer_addr_list, list) {
			n_addrs++;
			hip_in6_ntop(&s->address, addr_str);
			hip_timeval_diff(&now, &s->modified_time, &addr_age);
			if ( (len += snprintf(page+len, count-len,
					      "\n  %s state=%s lifetime=0x%x "
					      "age=%ld.%01ld seq=%u REA_preferred=%d",
					      addr_str, state_name[s->address_state],
					      s->lifetime, addr_age.tv_sec,
					      addr_age.tv_usec / 100000 /* show 1/10th sec */,
					      s->seq_update_id, s->is_preferred)
				     ) >= count)
				goto error;

		if (!ipv6_addr_cmp(&s->address, &spi_out->preferred_address) &&
		    (len += snprintf(page+len, count-len, " preferred")) >= count)
			goto error;

			i++;
		}

		if (n_addrs == 0 && (len += snprintf(page+len, count-len, "\n  no addresses")) >= count)
			goto error;
	}

	if ( (len += snprintf(page+len, count-len, "\n")) >= count)
		goto error;

	HIP_UNLOCK_HA(entry);

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
		       "default_spi_out lsi_our lsi_peer esp_transform "
		       "birthday keymat_index keymat_calc_index "
		       "update_id_in update_id_out dh_len\n");

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

#endif /* CONFIG_PROC_FS */


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

	for(i = 0; i <HIP_HADB_SIZE; i++) {
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


void hip_hadb_dump_hs_ht(void)
{
	int i;
	struct hip_hit_spi *hs, *tmp_hs;
	char str[INET6_ADDRSTRLEN];

	HIP_DEBUG("start\n");
	HIP_LOCK_HT(&hadb_spi_list);

	for(i = 0; i < HIP_HADB_SIZE; i++) {
		if (!list_empty(&hadb_byspi_list[i])) {
			HIP_DEBUG("HT[%d]\n", i);
			list_for_each_entry_safe(hs, tmp_hs, &hadb_byspi_list[i], list) {
				hip_hadb_hold_hs(hs);
				hip_in6_ntop(&hs->hit, str);
				HIP_DEBUG("HIT=%s SPI=0x%x refcnt=%d\n",
					  str, hs->spi, atomic_read(&hs->refcnt));
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
	unsigned long now = jiffies;

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
			hip_hold_ha(ha);
			hip_hadb_remove_state(ha);
			hip_put_ha(ha);
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
			//hip_hadb_delete_hs(hs);
			hip_hadb_remove_hs2(hs);
			hip_hadb_put_hs(hs);
			//} else
			//	HIP_DEBUG("HS refcnt < 1, BUG ?\n");
		}
	}
	HIP_DEBUG("DONE DELETING HS HT\n");
}
