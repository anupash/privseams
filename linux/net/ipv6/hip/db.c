/*
 * HIP database handling functions.
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 * TODO:
 * - change all of these functions to static
 * - sdb accessors and locking
 *   - all accessors should use get_first and get_next functions
 *   - each sdb state can have its own lock and the get_first/get_next
 *     functions use that lock
 * - host id accessors and locking
 *   - use the lock macro!
 *   - use the get_first and get_next accessors, not directly!
 * - cookie functions to support draft -07
 *
 * BUGS:
 * - hip_built_r1 has no acquire_lock
 */

#include "db.h"

/*
 * Do not access these databases directly: use the accessors in this file.
 */

HIP_INIT_DB(hip_peer_hostid_db, "peer_hid");
HIP_INIT_DB(hip_local_hostid_db, "local_hid");
HIP_INIT_DB(hip_hadb, "hadb");
HIP_INIT_DB(hip_local_eid_db, "local_eid");
HIP_INIT_DB(hip_peer_eid_db, "peer_eid");

/*
 *
 *
 * Static functions follow. These functions _MUST_ only be used in conjunction
 * with adequate locking. If the operation only fetches data, then READ lock is
 * enough. All contexts except the hip thread _SHOULD_ use READ locks.
 * The hip thread(s) is/are allowed to write to the databases. For this purpose
 * it/they will acquire the WRITE lock.
 *
 *
 */



/* Declare entry structure and lf integer for storing the flags */
#define HIP_HADB_WRAP_BEGIN_VOID struct hip_hadb_state *entry; unsigned long lf

/* The same as above, but declare also res variable, that is used
 * later by other macros to return value from function */
#define HIP_HADB_WRAP_BEGIN(restype) HIP_HADB_WRAP_BEGIN_VOID; restype res

/* unlock the read-locked HADB and return */
#define HIP_HADB_WRAP_R_END_VOID HIP_READ_UNLOCK_DB(&hip_hadb); return

/* unlock the read-locked HADB and return res (res must be set before
 * using this macro */
#define HIP_HADB_WRAP_R_END HIP_HADB_WRAP_R_END_VOID res

/* The same as the two above, but for write-locked HADB */
#define HIP_HADB_WRAP_W_END_VOID HIP_WRITE_UNLOCK_DB(&hip_hadb); return

/* The same as above */
#define HIP_HADB_WRAP_W_END HIP_HADB_WRAP_W_END_VOID res

/* Acquire read access to HADB, get the entry (based on the arg and type
 * variables, that must be found. If entry is not found then we release the
 * lock and return. */
#define HIP_HADB_WRAP_R_ACCESS_VOID do { \
        HIP_READ_LOCK_DB(&hip_hadb); \
        entry = hip_hadb_access_db(arg,type); \
        if (!entry) { \
                HIP_HADB_WRAP_R_END_VOID; \
	} \
  } while(0)


/* Same as above, but for write access */
#define HIP_HADB_WRAP_W_ACCESS_VOID do { \
        HIP_WRITE_LOCK_DB(&hip_hadb); \
        entry = hip_hadb_access_db(arg,type); \
        if (!entry) { \
                HIP_HADB_WRAP_W_END_VOID; \
	} \
  } while(0)

/* same as above, but for read access. If the entry is not found then,
 * return the errval (and release the lock).
*/
#define HIP_HADB_WRAP_R_ACCESS(errval) do { \
        HIP_READ_LOCK_DB(&hip_hadb); \
        entry = hip_hadb_access_db(arg,type); \
        if (!entry) { \
                res = errval; \
                HIP_HADB_WRAP_R_END; \
	} \
  } while(0)


/* Same as above, but for write access */
#define HIP_HADB_WRAP_W_ACCESS(errval) do { \
        HIP_WRITE_LOCK_DB(&hip_hadb); \
        entry = hip_hadb_access_db(arg,type); \
        if (!entry) { \
                res = errval; \
                HIP_HADB_WRAP_W_END; \
	} \
  } while(0)


/* simple */
#define HIP_HADB_WRAP_R_CALL_FUNC_VOID(func) \
        HIP_HADB_WRAP_R_ACCESS_VOID; \
        func; \
	HIP_HADB_WRAP_R_END_VOID

#define HIP_HADB_WRAP_W_CALL_FUNC_VOID(func) \
        HIP_HADB_WRAP_W_ACCESS_VOID; \
        func; \
        HIP_HADB_WRAP_W_END_VOID
      
#define HIP_HADB_WRAP_R_CALL_FUNC(errval,func) \
        HIP_HADB_WRAP_R_ACCESS(errval); \
        res = func; \
        HIP_HADB_WRAP_R_END

#define HIP_HADB_WRAP_W_CALL_FUNC(errval,func) \
        HIP_HADB_WRAP_W_ACCESS(errval); \
        res = func; \
        HIP_HADB_WRAP_W_END

static void hip_hadb_delete_entry_nolock(struct hip_hadb_state *entry);

/**
 * hip_uninit_hostid_db - uninitialize local/peer Host Id table
 * @db: Database structure to delete. 
 *
 * All elements of the @db are deleted. Since local and peer host id databases
 * include dynamically allocated host_id element, it is also freed.
 */
void hip_uninit_hostid_db(struct hip_db_struct *db)
{
	struct list_head *curr, *iter;
	struct hip_host_id_entry *tmp;
	unsigned long lf;

	HIP_WRITE_LOCK_DB(db);

	list_for_each_safe(curr,iter,&db->db_head) {
		tmp = list_entry(curr,struct hip_host_id_entry,next);
		if (tmp->host_id)
			kfree(tmp->host_id);
		kfree(tmp);
	}

	HIP_WRITE_UNLOCK_DB(db);
}

/**
 * hip_uninit_eid_db - uninitialize local/peer eid db
 * @db: Database structure to delete. 
 *
 * All elements of the @db are deleted.
 */
void hip_uninit_eid_db(struct hip_db_struct *db)
{
	struct list_head *curr, *iter;
	struct hip_host_id_entry *tmp;
	unsigned long lf;
	
	HIP_WRITE_LOCK_DB(db);
	
	list_for_each_safe(curr,iter,&db->db_head) {
		tmp = list_entry(curr, struct hip_host_id_entry, next);
		kfree(tmp);
	}
	
	HIP_WRITE_UNLOCK_DB(db);
}

void hip_uninit_all_eid_db(void)
{
	hip_uninit_eid_db(&hip_peer_eid_db);
	hip_uninit_eid_db(&hip_local_eid_db);
}

/**
 * hip_hadb_find_by_hit - find the entry having HIT @hit as the peer's destination HIT
 * @hit: HIT to be looked for from the host association database
 *
 * Returns: pointer to the entry which has @hit as the peer's HIT, else
 * %NULL if @hit was not found.
 */
static struct hip_hadb_state *hip_hadb_find_by_hit(struct in6_addr *hit)
{
	struct hip_hadb_state *tmp;

	/* XXX: is this necessary? 
	   I think we should fall through the list_for_each_entry() if the list
	   is actually empty
	*/
	if (list_empty(&hip_hadb.db_head))
		return NULL;

	list_for_each_entry(tmp,&hip_hadb.db_head,next) {
		if (!ipv6_addr_cmp(&tmp->hit_peer, hit))
			return tmp;
	}
	
	return NULL;

}

static int hip_hadb_delete_by_hit(struct in6_addr *hit)
{
	struct hip_hadb_state *entry;

	if (list_empty(&hip_hadb.db_head))
		return -EINVAL;

	entry = hip_hadb_access_db(hit, HIP_ARG_HIT);
	if (!entry)
		return -EINVAL;

	hip_hadb_delete_entry_nolock(entry);
	return 0;
}

/**
 * hip_sdb_find_by_spi - find the entry having SPI @spi as the peer's SPI
 * @spi: The SPI value used as a key for the host association state record.
 *
 * Returns: pointer to the entry which has @spi as the peer's SPI or
 * %NULL if @spi was not found.
 */
static struct hip_hadb_state *hip_hadb_find_by_spi(u32 spi)
{
	struct hip_hadb_state *tmp;

	/* XXX: same as above */
	if (list_empty(&hip_hadb.db_head))
		return NULL;

	list_for_each_entry(tmp,&hip_hadb.db_head,next) {
		if (tmp->spi_our == spi)
			return tmp;
	}
	
	return NULL;
}

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
static int hip_hadb_get_peer_addr(struct hip_hadb_state *entry,
				  struct in6_addr *addr)
{
	int err = 0;
        struct list_head *pos;
        struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;

#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif

	/* todo: this is ineffecient, optimize (e.g. insert addresses
	 * always in sorted order so we can break out of the loop earlier) */
        list_for_each(pos, &entry->peer_addr_list) {
                s = list_entry(pos, struct hip_peer_addr_list_item, list);
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
static int 
hip_hadb_get_peer_addr_info(struct hip_hadb_state *entry,
			    struct in6_addr *addr, uint32_t *interface_id,
			    uint32_t *lifetime, struct timeval *modified_time)
{
	struct list_head *pos;
	struct hip_peer_addr_list_item *s;
	char addrstr[INET6_ADDRSTRLEN];
	int i = 1;

	HIP_DEBUG("\n");
	list_for_each(pos, &entry->peer_addr_list) {
		s = list_entry(pos, struct hip_peer_addr_list_item, list);
		hip_in6_ntop(&s->address, addrstr);
		_HIP_DEBUG("address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			  i, addrstr,  s->interface_id, s->interface_id, s->lifetime, s->lifetime);
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
static int 
hip_hadb_set_peer_addr_info(struct hip_hadb_state *entry, struct in6_addr *addr,
			      uint32_t *interface_id, uint32_t *lifetime)
{
	/* XX: Called with sdb lock held ? */

	struct list_head *pos;
	struct hip_peer_addr_list_item *s;
	char addrstr[INET6_ADDRSTRLEN];
	int i = 1;

	/* called with locks held -> no locking ? */
	HIP_DEBUG("\n");
	list_for_each(pos, &entry->peer_addr_list) {
		s = list_entry(pos, struct hip_peer_addr_list_item, list);

		/* todo: update s->modified_time ? if yes, when and where ?
		 * when interface/lifetime is changed ?
		 */

		hip_in6_ntop(&s->address, addrstr);
		_HIP_DEBUG("address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			  i, addrstr,  s->interface_id, s->interface_id, s->lifetime, s->lifetime);
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
static int 

hip_hadb_add_peer_addr(struct hip_hadb_state *entry, struct in6_addr *new_addr,
		       uint32_t interface_id, uint32_t lifetime)
{
	/* TODO: add a function parameter struct
	 * hip_peer_addr_list_item *address_parameters (e.g. RTT from
	 * REA->AC->ACR) */

	int err = 0;
	struct hip_peer_addr_list_item *item;
	char addrstr[INET6_ADDRSTRLEN];
	uint32_t prev_if;

	HIP_DEBUG("\n");
	hip_in6_ntop(new_addr, addrstr);
	HIP_DEBUG("new_addr %s, interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
		  addrstr, interface_id, interface_id, lifetime, lifetime);

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
	list_add_tail(&item->list, &entry->peer_addr_list);

 out_err:
	return err;
}

/**
 * hip_hadb_delete_peer_address_list_one - delete IPv6 address from the entry's list of peer addresses
 * @entry: corresponding hadb entry of the peer
 * @addr: IPv6 address to be deleted
 */
static void 
hip_hadb_delete_peer_addrlist_one(struct hip_hadb_state *entry, struct in6_addr *addr) {
	/* XX: Called with sdb lock held ? currently this function tries to get lock */

	struct list_head *pos, *tmp;
	struct hip_peer_addr_list_item *item;
	int i = 1;
	char addrstr[INET6_ADDRSTRLEN];


	HIP_DEBUG("\n");

	list_for_each_safe(pos, tmp, &entry->peer_addr_list) {
		item = list_entry(pos, struct hip_peer_addr_list_item, list);
		hip_in6_ntop(&item->address, addrstr);
		_HIP_DEBUG("%p: address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			   item, i, addrstr,  item->interface_id, item->interface_id, item->lifetime, item->lifetime);
		if (!ipv6_addr_cmp(&item->address, addr)) {
			_HIP_DEBUG("deleting address\n");
			list_del(&item->list);
			kfree(item);
			break;
		}
		i++;
	}
	return;
}


/**
 * hip_hadb_delete_peer_addr_iface - delete peer's addresses belonging to an interface
 * @entry: corresponding hadb entry of the peer
 * @interface_id: Interface ID to which all deleted addresses belong to
 */
static void
hip_hadb_delete_peer_addr_if(struct hip_hadb_state *entry, uint32_t interface_id)
{
	/* XX: Called with sdb lock held ? currently caller must have the lock */
	struct list_head *pos, *tmp;
	struct hip_peer_addr_list_item *item;
	char addrstr[INET6_ADDRSTRLEN];

	HIP_DEBUG("entry=%p interface_id=0x%x\n", entry, interface_id);

	list_for_each_safe(pos, tmp, &entry->peer_addr_list) {
		item = list_entry(pos, struct hip_peer_addr_list_item, list);
		HIP_DEBUG("item=0x%p &item->address=0x%p if=%u\n", item, item ? &item->address : NULL, item->interface_id);
		if (item->interface_id == interface_id) {
			hip_in6_ntop(&item->address, addrstr);
			HIP_DEBUG("delete address %s itemlist=0x%p in=%p ip=%p\n", addrstr, &item->list, item->list.next, item->list.prev);
			list_del(&item->list);
			kfree(item);
		}
	}
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
static void 
hip_hadb_delete_peer_address_not_in_list(struct hip_hadb_state *entry, 
					 void *addrlist, int n_addrs,
					 uint32_t iface) 
{
	/* XX: Called with sdb lock held ? currently this function tries to get lock */

	/* THIS IS STILL A TEST FUNCTION .. fix */

	struct list_head *pos, *tmp;
	struct hip_peer_addr_list_item *item;
	int i = 1;
	int j;
	char addrstr[INET6_ADDRSTRLEN];
	char addrstr2[INET6_ADDRSTRLEN];
	void *p;

	HIP_DEBUG("entry=%p n_addrs=%d iface=0x%x\n", entry, n_addrs, iface);

	if (list_empty(&entry->peer_addr_list)) {
		HIP_DEBUG("AIEEEEEEEE\n");
		return;
	}

	list_for_each_safe(pos, tmp, &entry->peer_addr_list) {
		int found = 0;
		item = list_entry(pos, struct hip_peer_addr_list_item, list);
		hip_in6_ntop(&item->address, addrstr);
		_HIP_DEBUG("test address %d: %s if=0x%x\n", i, addrstr, item->interface_id);
		for (j = 0, p = addrlist; j < n_addrs;
		     j++, p += sizeof(struct hip_rea_info_addr_item)) {
			struct hip_rea_info_addr_item *addr = (struct hip_rea_info_addr_item *) p;
			hip_in6_ntop(&addr->address, addrstr2);
			_HIP_DEBUG(" against address: %s\n", addrstr2);
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
	return;
}


/**
 * hip_hadb_delete_peer_address_list - delete all @entry's peer addresses
 * @entry: corresponding hadb entry of the peer
 */
static void hip_hadb_delete_peer_addrlist(struct hip_hadb_state *entry) {
        struct list_head *pos,*iter;
        struct hip_peer_addr_list_item *item;
        char addrstr[INET6_ADDRSTRLEN];

        HIP_DEBUG("\n");

	if (list_empty(&entry->peer_addr_list))
		return;

        list_for_each_safe(pos, iter, &entry->peer_addr_list) {
                item = list_entry(pos, struct hip_peer_addr_list_item, list);
                hip_in6_ntop(&item->address, addrstr);
                _HIP_DEBUG("%p: address %d: %s interface_id 0x%x (%u), lifetime 0x%x (%u)\n",
			   item, i++, addrstr,  item->interface_id, item->interface_id, 
			   item->lifetime, item->lifetime);
		list_del(pos);
                kfree(item);
        }
        return;
}

/**
 * hip_hadb_entry_init - Initialize the given hadb entry
 * @entry: entry to be initialized
 *
 * NOTE: No locks required for this function, as long as the entry
 * is not publicly accessible, before its addition to the HADB.
 */
static void hip_hadb_entry_init(struct hip_hadb_state *entry)
{
	memset(entry,0,sizeof(*entry));

	INIT_LIST_HEAD(&entry->next);
	INIT_LIST_HEAD(&entry->peer_addr_list);
	INIT_LIST_HEAD(&entry->kg.socklist);
	entry->kg.sk = NULL;

	entry->state = HIP_STATE_UNASSOCIATED;
	return;
}

static void hip_hadb_free_socks_nolock(struct hip_hadb_state *entry, int error)
{
	struct hip_kludge *kg, *kg_iter;

	/* TCP sockets */
	list_for_each_entry_safe(kg, kg_iter, &entry->kg.socklist, socklist) {
		/* XXX: What should we do with sleeping socks? 
		 * Now: call error_report callback.. is this ok? 
		 * Locking problems?
		 */
		if (kg->sk) {
			if (error) 
				kg->sk->sk_error_report(kg->sk);
			sock_put(kg->sk);
		}
		list_del(&kg->socklist);
		kfree(kg);
	}

}

/**
 * hip_hadb_entry_free - free entry's allocated resources including IPsec associations
 * @entry: the entry whose resources are to be freed
 *
 * Does not free memory used by the structure itself.
 */
static void hip_hadb_entry_free(struct hip_hadb_state *entry)
{
	/* IPsec */
	if (likely(entry->spi_peer)) {
		hip_delete_sa(entry->spi_peer, &entry->hit_our);
	}
	if (likely(entry->spi_our)) {
		hip_delete_sa(entry->spi_our, &entry->hit_peer);
	}
	if (unlikely(entry->new_spi_peer))
		hip_delete_sa(entry->new_spi_peer, &entry->hit_our);
	if (unlikely(entry->new_spi_our))
		hip_delete_sa(entry->new_spi_our, &entry->hit_peer);

	entry->spi_peer = 0;
	entry->spi_our = 0;
	entry->new_spi_peer = 0;
	entry->new_spi_our = 0;

	/* peer addr list */
	hip_hadb_delete_peer_addrlist(entry);

	/* TCP sockets */
	hip_hadb_free_socks_nolock(entry,1);

	/* keymat & mm-01 stuff */
	if (entry->keymat.keymatdst)
		kfree(entry->keymat.keymatdst);
	if (entry->dh_shared_key)
		kfree(entry->dh_shared_key);

	return;
}


/**
 * hip_hadb_insert_entry_nolock - Insert an entry into the HADB without locking.
 * @entry: Entry to be inserted.
 *
 * NOTE: Assuming that the WRITE lock is held by the caller!
 *
 */
void hip_hadb_insert_entry_nolock(struct hip_hadb_state *entry)
{

	hip_hadb.db_cnt++;
	list_add(&entry->next,&hip_hadb.db_head);
}



/**
 * hip_get_hostid_entry_by_lhi - finds the host id corresponding to the given @lhi
 * @db: Database to be searched. Usually either %HIP_DB_PEER_HID or %HIP_DB_LOCAL_HID
 * @lhi: the local host id to be searched 
 *
 * If lhi is null, finds the first used host id. 
 *
 * Returns: %NULL, if failed or non-NULL if succeeded.
 */
static 
struct hip_host_id_entry *hip_get_hostid_entry_by_lhi(struct hip_db_struct *db,
						      const struct hip_lhi *lhi)
{
	struct hip_host_id_entry *id_entry;

	/* should (id->used == used) test be binaric? */

	list_for_each_entry(id_entry,&db->db_head,next) {
		if ((lhi == NULL || hip_lhi_are_equal(&id_entry->lhi, lhi)))
			return id_entry;
	}

	return NULL;
}

static int hip_hadb_reinit_state(struct hip_hadb_state *entry)
{
	HIP_ERROR("Don't call this function!\n");
	HIP_ASSERT(0);
/* we need to define what "reinitialization" means in this
 * context.
 *
 	HIP_DEBUG("** TODO: call hip_hadb_entry_free ? **\n");
	entry->state = HIP_STATE_UNASSOCIATED;
	entry->peer_controls = 0;
	entry->spi_peer = 0;
	entry->spi_our = 0;
	entry->lsi_peer = 0;
	entry->lsi_our = 0;
	entry->esp_transform = 0;
	entry->birthday = 0;
	entry->kg.sk = NULL;

	memset(&entry->hit_our,0,sizeof(struct in6_addr));
*/
	return 0;
}


/*
 *
 *
 * Interface functions to access databases.
 *
 *
 *
 */

/***
 * ARG/TYPE arguments in following functions.
 *
 * arg is used as a database key. It is _REQUIRED_ to be of type
 * struct in6_addr *, _OR_ uint32. The first type is used IF AND ONLY IF,
 * the type argument equals to HIP_ARG_HIT. For all other values of
 * type, arg is assumed to be uint32 and the database is searched for
 * a corresponding own_spi.
 * In HIP_ARG_HIT case, the database is searched for corresponding
 * hit_peer field.
 ***
 */


/*
 * returns 0 if error, positive (2) if ok
 */
int hip_hadb_save_sk(struct in6_addr *arg, struct sock *sk)
{
	HIP_HADB_WRAP_BEGIN(int);
	struct hip_kludge *kg;
	int state;
	int type = HIP_ARG_HIT;
	struct ipv6hdr ip = {0};

	HIP_HADB_WRAP_W_ACCESS(-EINVAL);

	if (entry->state == HIP_STATE_ESTABLISHED) {
		HIP_DEBUG("Already connected\n");
		res = -EISCONN;
		HIP_HADB_WRAP_W_END;
	}

	kg = kmalloc(sizeof(*kg), GFP_KERNEL);
	if (!kg) {
		HIP_ERROR("No memory for kludge\n");
		return -ENOMEM;
	}

	kg->sk = sk;

	sock_hold(kg->sk);
	list_add(&kg->socklist, &entry->kg.socklist);

	state = entry->state;

	HIP_WRITE_UNLOCK_DB(&hip_hadb);

	if (state == HIP_STATE_UNASSOCIATED) {
		ipv6_addr_copy(&ip.daddr, arg);
		hip_handle_output(&ip, NULL); // trigger I1
	}

	return 0;
}


/**
 * hip_hadb_access_db - Find a host association entry using @type key
 * @arg: a pointer to a HIT or an SPI
 * @type: Defines the type of @arg. Either HIP_ARG_HIT or HIP_ARG_SPI
 *
 * NOTE: A lock for the HADB must be acquired prior to calling this function.
 *
 * Returns: Pointer to the hip_hadb_state record, or %NULL if the record
 * was not found
 */
struct hip_hadb_state *hip_hadb_access_db(void *arg, int type)
{
	struct hip_hadb_state *entry;

	if (likely(type == HIP_ARG_HIT)) 
		entry = hip_hadb_find_by_hit((struct in6_addr *)arg);
	else 
		entry = hip_hadb_find_by_spi((u32)arg);

	return entry;
}


/**
 * hip_hadb_create_entry - Create a new HADB entry and initialize it.
 *
 * Returns the new entry. The entry is not added to the HADB automatically.
 * The entry may be used without locking (until it is in the HADB).
 * If an error occurs, %NULL is returned.
 */
struct hip_hadb_state *hip_hadb_create_entry(void)
{
	struct hip_hadb_state *new_entry = NULL;

	new_entry = kmalloc(sizeof(struct hip_hadb_state), GFP_KERNEL);
	if (!new_entry)
		goto out_err1;

	hip_hadb_entry_init(new_entry);
 out_err1:
	return new_entry;
}


static void hip_hadb_delete_entry_nolock(struct hip_hadb_state *entry)
{
	if ((--hip_hadb.db_cnt) < 0)
		HIP_ERROR("Database corrupted!\n");
	list_del(&entry->next);
	/* XXX: Should we free the memory, also? */
	hip_hadb_entry_free(entry);

	kfree(entry);
}


/**
 * hip_uninit_hadb - uninit the Host Association database
 *
 * Called in module unload.
 */
void hip_uninit_hadb(void)
{
	struct hip_hadb_state *this, *iter;
	unsigned long lf; // lock flags

	HIP_WRITE_LOCK_DB(&hip_hadb);

	list_for_each_entry_safe(this,iter,&hip_hadb.db_head, next) {
		hip_hadb_delete_entry_nolock(this);
	}

	HIP_WRITE_UNLOCK_DB(&hip_hadb);
	return;
}


/**
 * hip_hadb_for_each_entry - Do reading action for all entries in HADB
 * @filter: Function that returns TRUE of FALSE, depending on whether it
 *          would like the entry in question to be further processed by
 *          the @accessor function.
 * @accessor: Function that does some action. WRITING INTO THE ENTRY IS
 *            *STRICTLY* FORBIDDEN. This function is allowed only to copy
 *            the relevant data into the %hip_entry_list and later further
 *            process it.
 * @head: Pointer to a list head. All entries that are processed by the
 *        @accessor, will be linked to this list. The list *must* be
 *        initially empty.
 *
 * typedef int (*FILTER_FUNC)(struct hip_hadb_state *);
 * typedef void (*ACCESS_FUNC)(struct hip_hadb_state *, struct hip_entry_list *);
 *
 * Default behaviour, when both @filter and @accessor are NULLs, is to
 * fill the @head list with the *hit_peers* of all the entries found in 
 * the HADB.
 *
 * Return number of entries that were processed. The filtered ones, are
 * not included in the count. A negative value is returned upon an error.
 * In this case, all the elements in the @head will be released, so there
 * is not a possibility to get a half-done result.
 */
int hip_hadb_for_each_entry(FILTER_FUNC filter, ACCESS_FUNC accessor, 
			    struct list_head *head)
{
	unsigned long lf;
	struct hip_hadb_state *entry;
	struct hip_entry_list *elist, *iter;
	int num = 0;

	if (!list_empty(head)) {
		return -ENOTEMPTY;
	}

	HIP_READ_LOCK_DB(&hip_hadb);

	list_for_each_entry(entry, &hip_hadb.db_head, next) {
		if (filter) {
			if (!filter(entry))
				continue;
		}

		elist = kmalloc(sizeof(struct hip_entry_list),GFP_ATOMIC);
		if (!elist) {
			HIP_READ_UNLOCK_DB(&hip_hadb);
			num = -ENOMEM;
			goto free_on_error;
		}
		
		if (accessor) {
			accessor(entry,elist);
		} else {
			ipv6_addr_copy(&elist->peer_hit, &entry->hit_peer);
		}

		list_add(&elist->list,head);
		num++;
	}

	HIP_READ_UNLOCK_DB(&hip_hadb);
	return num;

 free_on_error:
/* clear the argument list */
	if (elist)
		kfree(elist);

	list_for_each_entry_safe(elist, iter, head, list) {
		list_del(&elist->list);
		kfree(elist);
	}

	if (!list_empty(head)) {
		HIP_ERROR("List removal failed\n");
	}

	return num;
}


int hip_hadb_flush_states(struct in6_addr *hit)
{
	int num;
	unsigned long lf; // lf = lock flags
	struct list_head mylist = LIST_HEAD_INIT(mylist);
	struct hip_entry_list *hiplist;
	struct hip_hadb_state *entry;

	if (ipv6_addr_any(hit)) {
		num = hip_hadb_for_each_entry(NULL, NULL, &mylist);
		if (num <= 0)
			return -EINVAL;

		HIP_WRITE_LOCK_DB(&hip_hadb);
		list_for_each_entry(hiplist,&mylist,list) {
			entry = hip_hadb_find_by_hit(&hiplist->peer_hit);
			if (!entry)
				continue;
			hip_hadb_reinit_state(entry);
		}
		HIP_WRITE_UNLOCK_DB(&hip_hadb);

		while(!list_empty(&mylist)) {
			hiplist = list_entry(mylist.next,struct hip_entry_list, list);
			list_del(mylist.next);
			kfree(hiplist);
		}
		return 0;
	}

	/* flush only one map */

	HIP_WRITE_LOCK_DB(&hip_hadb);
	entry = hip_hadb_find_by_hit(hit);
	if (!entry) {
		HIP_WRITE_UNLOCK_DB(&hip_hadb);
		return -ENOENT;
	}
	hip_hadb_reinit_state(entry);
	HIP_WRITE_UNLOCK_DB(&hip_hadb);
	return 0;
}


/**
 * hip_hadb_insert_entry - Inserts an HADB entry into the database.
 * @entry: to be inserted
 *
 */
void hip_hadb_insert_entry(struct hip_hadb_state *entry) 
{
	unsigned long lf;
	HIP_WRITE_LOCK_DB(&hip_hadb);
	hip_hadb_insert_entry_nolock(entry);
	HIP_WRITE_UNLOCK_DB(&hip_hadb);
}



/**
 * hip_uninit_host_id_dbs - Delete both host id databases
 *
 */
void hip_uninit_host_id_dbs(void)
{
	hip_uninit_hostid_db(&hip_local_hostid_db);
	hip_uninit_hostid_db(&hip_peer_hostid_db);
}


/**
 * hip_add_host_id - add the given HI into the database 
 * @db: Database structure
 * @lhi: HIT
 * @host_id: HI
 *
 * Checks for duplicates. If one is found, the current HI is _NOT_
 * stored.
 *
 * On success returns 0, otherwise an negative error value is returned.
 */
int hip_add_host_id(struct hip_db_struct *db,
		    const struct hip_lhi *lhi,
		    const struct hip_host_id *host_id)
{
	int err = 0;
	struct hip_host_id_entry *id_entry;
	struct hip_host_id_entry *old_entry;
	unsigned long lf;
	
	_HIP_HEXDUMP("adding host id",lhi,sizeof(struct hip_lhi));

	HIP_ASSERT(lhi != NULL);

	id_entry = kmalloc(sizeof(id_entry),GFP_KERNEL);
	if (id_entry == NULL) {
		HIP_ERROR("No memory available for host id\n");
		err = -ENOMEM;
		goto out_err;
	}

	id_entry->host_id = kmalloc(hip_get_param_total_len(host_id),
				    GFP_KERNEL);
	if (!id_entry->host_id) {
		HIP_ERROR("lhost_id mem alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	
	/* copy lhi and host_id (host_id is already in network byte order) */
	id_entry->lhi.anonymous = lhi->anonymous;
	ipv6_addr_copy(&id_entry->lhi.hit, &lhi->hit);
	memcpy(id_entry->host_id, host_id, hip_get_param_total_len(host_id));

	HIP_WRITE_LOCK_DB(db);

	/* check for duplicates */
	old_entry = hip_get_hostid_entry_by_lhi(db, lhi);
	if (old_entry != NULL) {
		HIP_WRITE_UNLOCK_DB(db);
		HIP_ERROR("Trying to add duplicate lhi\n");
		err = -EEXIST;
		goto out_err;
	}

	list_add(&id_entry->next, &db->db_head);

	HIP_WRITE_UNLOCK_DB(db);

	return err;

 out_err:
	if (id_entry) {
		if (id_entry->host_id)
			kfree(id_entry->host_id);
		kfree(id_entry);
	}

	return err;
}

/**
 * hip_add_localhost_id - add a localhost id to the databases
 * @lhi: the HIT of the host
 * @host_id: the host id of the host
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_add_localhost_id(const struct hip_lhi *lhi,
			 const struct hip_host_id *host_id)
{
	return hip_add_host_id(&hip_local_hostid_db, lhi, host_id);
}


/**
 * hip_del_host_id - delete the given HI (network byte order) from the database.
 * @db: Database from which to delete
 * @lhi: the HIT to be deleted from the database
 *
 * Matches HIs based on the HIT
 *
 * Returns: returns 0, otherwise returns negative.
 */
int hip_del_host_id(struct hip_db_struct *db, struct hip_lhi *lhi)
{
	int err = -ENOENT;
	struct hip_host_id_entry *id = NULL;
	unsigned long lf;

	HIP_ASSERT(lhi != NULL);

	HIP_WRITE_LOCK_DB(db);

	id = hip_get_hostid_entry_by_lhi(db, lhi);
	if (id == NULL) {
		HIP_WRITE_UNLOCK_DB(db);
		HIP_ERROR("lhi not found\n");
		err = -ENOENT;
		return err;
	}

	list_del(&id->next);

	HIP_WRITE_UNLOCK_DB(db);

	/* free the dynamically reserved memory and
	   set host_id to null to signal that it is free */
	kfree(id->host_id);
	kfree(id);
	err = 0;
	return err;
}


/**
 * hip_copy_any_locahost_hit - Copy to the the @target the first 
 * local HIT that is found.
 * @target: Placeholder for the target
 *
 * Returns 0 if ok, and negative if failed.
 */
int hip_copy_any_localhost_hit(struct in6_addr *target)
{
	struct hip_host_id_entry *entry;
	int err = 0;
	unsigned long lf;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	entry = hip_get_hostid_entry_by_lhi(&hip_local_hostid_db,NULL);
	if (!entry) {
		err=-ENOENT;
		goto out;
	}
		
	ipv6_addr_copy(target,&entry->lhi.hit);
	err = 0;

 out:
	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
	return err;
}


/**
 * hip_copy_different_localhost_hit - Copy HIT that is not the same as the
 * argument HIT.
 * @target: Pointer to the area, where the differing HIT is copied.
 * @source: Pointer to the HIT that is used as a reference.
 *
 * If unable to find differing HIT, -ENOENT is returned. Otherwise 0.
 */
int hip_copy_different_localhost_hit(struct in6_addr *target,
				     struct in6_addr *source)
{
	struct hip_host_id_entry *entry;
	unsigned long lf;
	int err = -ENOENT;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	list_for_each_entry(entry,&hip_local_hostid_db.db_head,next) {
		if (ipv6_addr_cmp(&entry->lhi.hit,source)) {
			HIP_DEBUG("Found different\n");
			ipv6_addr_copy(target,&entry->lhi.hit);
			err = 0;
			break;
		}
	}

	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
	return err;
} 

static struct hip_lhi *hip_get_any_hit(struct hip_db_struct *db)
{
	struct hip_host_id_entry *tmp;
	struct hip_lhi *res;
	unsigned long lf;

	if (list_empty(&db->db_head))
		return NULL;

	res = kmalloc(sizeof(struct hip_lhi), GFP_KERNEL);
	if (!res)
		return NULL;

	HIP_READ_LOCK_DB(db);

	tmp = list_entry(db->db_head.next, struct hip_host_id_entry, next);
	if (!tmp) {
		HIP_READ_UNLOCK_DB(db);
		kfree(res);
		return NULL;
	}

	memcpy(res, &tmp->lhi, sizeof(struct hip_lhi));
	
	HIP_READ_UNLOCK_DB(db);

	return res;
}

int hip_get_any_local_hit(struct in6_addr *dst)
{
	struct hip_lhi *lhi;

	lhi = hip_get_any_hit(&hip_local_hostid_db);
	if (!lhi) {
		HIP_ERROR("Could not retrieve any local HIT\n");
		return -ENOENT;
	}

	if (dst) {
		memcpy(dst, &lhi->hit, sizeof(struct in6_addr));
		kfree(lhi);
		return 0;
	} 

	return -EINVAL;
}
/**
 * hip_get_host_id - Copies the host id into newly allocated memory
 * and returns it to the caller.
 * @db: Database
 * @lhi: HIT that is used as a database search key
 *
 * NOTE: Remember to free the returned host id structure.
 * This function should be only called by the HIP thread as it allocates
 * GFP_KERNEL memory. 
 * XXX: The memory that is allocated is 1024 bytes. If the key is longer,
 * we fail.
 * 
 * Returns hip_host_id structure, or %NULL, if the entry was not found.
 */
struct hip_host_id *hip_get_host_id(struct hip_db_struct *db, 
				    struct hip_lhi *lhi)
{

	struct hip_host_id_entry *tmp;
	struct hip_host_id *result;
	unsigned long lf;
	int t;
	
	result = kmalloc(1024, GFP_KERNEL);
	if (!result) {
		HIP_ERROR("no memory\n");
		return NULL;
	}

	memset(result, 0, 1024);

	HIP_READ_LOCK_DB(db);

	tmp = hip_get_hostid_entry_by_lhi(db, lhi);
	if (!tmp) {
		HIP_READ_UNLOCK_DB(db);
		HIP_ERROR("No host id found\n");
		return NULL;
	}

	t = hip_get_param_total_len(tmp->host_id);
	if (t > 1024) {
		HIP_READ_UNLOCK_DB(db);
		kfree(result);
		return NULL;
	}

	memcpy(result, tmp->host_id, t);

	HIP_READ_UNLOCK_DB(db);

	return result;
}

/**
 * hip_get_any_localhost_host_id - Self documenting.
 *
 * NOTE: Remember to free the host id structure after use.
 *
 * Returns pointer to newly allocated area that contains a localhost
 * HI. %NULL is returned is problems are encountered. 
 */
struct hip_host_id *hip_get_any_localhost_host_id(void)
{
	struct hip_host_id *result;

	result = hip_get_host_id(&hip_local_hostid_db,NULL);
	return result;
}

/**
 * hip_get_any_locahost_public_key - Self documenting.
 *
 * NOTE: Remember to free the return value.
 *
 * Returns newly allocated area that contains the public key part of
 * the localhost host identity. %NULL is returned if errors detected.
 */
struct hip_host_id *hip_get_any_localhost_public_key()
{
	struct hip_host_id *tmp;
	hip_tlv_len_t len;
	u8 T;

	/* T could easily have been an int, since the compiler will
	   probably add 3 alignment bytes here anyway. */

	tmp = hip_get_host_id(&hip_local_hostid_db,NULL);
	if (tmp == NULL) {
		HIP_ERROR("No host id for localhost\n");
		return NULL;
	}

       /* check T, Miika won't like this */
	T = *((u8 *)(tmp + 1));
	if (T > 8) {
		HIP_ERROR("Invalid T-value in DSA key (0x%x)\n",T);
		kfree(tmp);
		return NULL;
	}

	if (T != 8) {
		HIP_DEBUG("T-value in DSA-key not 8 (0x%x)!\n",T);
	}

	/* assuming all local keys are full DSA keys */
	len = hip_get_param_contents_len(tmp);

	HIP_DEBUG("Host ID len before cut-off: %d\n",
		  hip_get_param_total_len(tmp));

	/* the secret component of the DSA key is always 20 bytes */
	hip_set_param_contents_len(tmp, (len - 20));

	HIP_DEBUG("Host ID len after cut-off: %d\n",
		  hip_get_param_total_len(tmp));

	tmp->hi_length = htons(ntohs(tmp->hi_length) - 20);

	HIP_DEBUG("hi->hi_length=%d\n", htons(tmp->hi_length));

	return tmp;
}

#if 0
/**
 * hip_insert_any_localhost_public_key - Copy any localhost public key into 
 * the @target.
 * @target: Where to copy the public key
 *
 * Returns 0 if ok. Negative if errors.
 */

int hip_insert_any_localhost_public_key(u8 *target)
{
	struct hip_host_id *tmp = NULL;
	hip_tlv_len_t len;
	u8 *buf;
	int err = 0;

	tmp = hip_get_host_id(&hip_local_hostid_db,NULL);
	if (!tmp) {
		HIP_ERROR("No host id for localhost\n");
		err=-ENOENT;
		goto end_err;
	}
	
	buf = (u8 *)(tmp + 1); // skip header
	
	if (*buf > 8) { /* T is over 8... error */
		HIP_ERROR("Invalid T-value in DSA key (%x)\n",*buf);
		err=-EBADMSG;
		goto end_err;

	}

	if (*buf != 8) {
		HIP_DEBUG("T-value in DSA-key something else than 8!\n");
	}

	len = hip_get_param_contents_len(tmp);
	memcpy(target, tmp, sizeof(struct hip_tlv_common) + (len - 20));
	hip_set_param_contents_len(target,(len - 20));

	// XX BUG: set also host_id->hi_length

 end_err:
	if (tmp)
		kfree(tmp);
	return err;
}
#endif

/**
 * Currently deletes the whole entry...
 */		
int hip_del_peer_info(struct in6_addr *hit, struct in6_addr *addr)
{
	unsigned long lf;
	int err = 0;

	HIP_WRITE_LOCK_DB(&hip_hadb);

	err = hip_hadb_delete_by_hit(hit);

	HIP_WRITE_UNLOCK_DB(&hip_hadb);
	return err;
}


int hip_add_peer_info_nolock(struct in6_addr *hit, struct in6_addr *addr)
{
	int err;
	struct hip_hadb_state *entry;
	char str[INET6_ADDRSTRLEN];

	/* note: can't lock here or else hip_sdb_add_peer_address will block
	 * unsigned long flags = 0;
	 * spin_lock_irqsave(&hip_sdb_lock, flags); */

	hip_in6_ntop(hit, str);
	HIP_DEBUG("called: HIT %s\n", str);

	entry = hip_hadb_access_db(hit,HIP_ARG_HIT);
	if (!entry) {
		entry = hip_hadb_create_entry();
		if (!entry) {
			HIP_ERROR("Unable to create a new entry\n");
			return -1;
			goto out;
		}
		HIP_DEBUG("created a new sdb entry\n");

		entry->state = HIP_STATE_UNASSOCIATED;
		ipv6_addr_copy(&entry->hit_peer,hit);
		/* XXX: This is wrong. As soon as we have native socket API, we
		 * should enter here the correct sender... (currently unknown).
		 */
		if (hip_get_any_local_hit(&entry->hit_our) == 0)
			HIP_DEBUG_HIT("our hit seems to be", &entry->hit_our);
		else 
			HIP_ERROR("Could not assign local hit... continuing\n");
		hip_hadb_insert_entry_nolock(entry);
	}

	err = hip_hadb_add_peer_addr(entry, addr, 0, 0);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		err = -2;
		goto out;
	}
	HIP_DEBUG("peer address add ok\n");

 out:
	return err;

}

/**
 * hip_add_peer_info - create a new entry or add an IPv6 address to the peer
 * @hit: HIT
 * @addr: IPv6 address
 *
 * If entry already exists in the database for the given HIT @hit, it
 * is updated by adding the given IPv6 address @addr to the list of
 * peer's IPv6 addresses. This allows changing entries even in
 * connected state.
 *
 * Returns: 0 if entry was added successfully, else < 0. 
 */
int hip_add_peer_info(struct in6_addr *hit, struct in6_addr *addr)
{
	int err;
	unsigned long lf;

	/* note: can't lock here or else hip_sdb_add_peer_address will block
	 * unsigned long flags = 0;
	 * spin_lock_irqsave(&hip_sdb_lock, flags); */

	HIP_WRITE_LOCK_DB(&hip_hadb);

	err = hip_add_peer_info_nolock(hit, addr);

	HIP_WRITE_UNLOCK_DB(&hip_hadb);

	return err;
}

/* PROC_FS FUNCTIONS */


#ifdef CONFIG_PROC_FS
/**
 * hip_proc_read_hadb_state - debug function for dumping hip_sdb_state
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * hip_hadb_state can be dumped from from file /proc/net/hip/sdb_state
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_hadb_state(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
        int len = 0;
	struct hip_hadb_state *entry;
	unsigned long lf = 0;


	len = snprintf(page, count,
		       "state peer_controls hit_our hit_peer "
		       "spi_our spi_peer new_spi_our new_spi_peer lsi_our lsi_peer esp_transform "
		       "birthday keymat_len keymat_offset keymat_index keymat_calc_index "
		       "update_id_in update_id_out dh_len list_of_peer_addrs curr_dst_addr\n");
	if (len >= count)
		goto err;

	HIP_READ_LOCK_DB(&hip_hadb);

	list_for_each_entry(entry,&hip_hadb.db_head,next) {
		char addr_str[INET6_ADDRSTRLEN];
		char *esp_transforms[] = { "none/reserved", "aes-sha1", "3des-sha1", "3des-md5",
					   "blowfish-sha1", "null-sha1", "null-md5" };
		struct list_head *pos;
		struct hip_peer_addr_list_item *s;
		struct in6_addr addr;
		int i = 0;

		if ( (len += snprintf(page+len, count-len, "%s 0x%x",
				      hip_state_str(entry->state),
				      entry->peer_controls)) >= count)
			break;
		hip_in6_ntop(&entry->hit_our, addr_str);
		if ( (len += snprintf(page+len, count-len, " %s", addr_str)) >= count)
			break;
		hip_in6_ntop(&entry->hit_peer, addr_str);
		if ( (len += snprintf(page+len, count-len, " %s", addr_str)) >= count)
			break;
		if ( (len += snprintf(page+len, count-len,
				      " 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x %s",
				      entry->spi_our, entry->spi_peer, entry->new_spi_our,
				      entry->new_spi_peer, entry->lsi_our, entry->lsi_peer,
				      entry->esp_transform <=
				      (sizeof(esp_transforms)/sizeof(esp_transforms[0])) ?
				      esp_transforms[entry->esp_transform] : "UNKNOWN")) >= count)
 			break;

 		if ( (len += snprintf(page+len, count-len,
				      " 0x%llx %u %u %u %u %u %u %u",
				      entry->birthday, entry->keymat.keymatlen,
				      entry->keymat.offset, entry->current_keymat_index,
				      entry->keymat_calc_index, entry->update_id_in,
				      entry->update_id_out, entry->dh_shared_key_len )) >= count)
			break;

		list_for_each(pos, &entry->peer_addr_list) {
			s = list_entry(pos, struct hip_peer_addr_list_item, list);
			hip_in6_ntop(&s->address, addr_str);
			if ( (len += snprintf(page+len, count-len,
					      i>0 ? ",%d=%s" : " %d=%s", i+1, addr_str)) >= count)
				goto err;
			i++;
		}

		if (hip_hadb_get_peer_addr(entry, &addr) == 0) {
			hip_in6_ntop(&addr, addr_str);
			len += snprintf(page+len, count-len, " %s", addr_str);
		} else
			len += snprintf(page+len, count-len, " (no addr)");

		if (len >= count)
			goto err;

		if ( (len += snprintf(page+len, count-len, "\n")) >= count)
			break;
	}

 err:
	HIP_READ_UNLOCK_DB(&hip_hadb);

	if (len >= count) {
		HIP_DEBUG("len %d >= count %d\n", len, count);
		page[count-1] = '\0';
		len = count;
	} else {
		page[len] = '\0';
	}



	*eof = 1;
        return(len);
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
        int len = 0;
	struct hip_hadb_state *entry;
	struct timeval now, addr_age;
	unsigned long lf = 0;

	do_gettimeofday(&now);

	HIP_READ_LOCK_DB(&hip_hadb);

	list_for_each_entry(entry,&hip_hadb.db_head,next) {
		char addr_str[INET6_ADDRSTRLEN];
		struct list_head *pos;
		struct hip_peer_addr_list_item *s;
		int i = 0;

		hip_in6_ntop(&entry->hit_peer, addr_str);
		if ( (len += snprintf(page+len, count-len, "HIT %s", addr_str)) >= count)
			break;

		list_for_each(pos, &entry->peer_addr_list) {
			s = list_entry(pos, struct hip_peer_addr_list_item, list);
			hip_in6_ntop(&s->address, addr_str);
			(void)hip_timeval_diff(&now, &s->modified_time, &addr_age);
			if ( (len += snprintf(page+len, count-len,
					      "\n %s state=0x%x if=0x%x lifetime=0x%x "
					      "age=%ld.%01ld",
					      addr_str, s->address_state, s->interface_id,
					      s->lifetime, addr_age.tv_sec,
					      addr_age.tv_usec / 100000 /* show 1/10th sec */)
			      ) >= count)
				goto err;
			i++;
		}

		if (i == 0 && (len += snprintf(page+len, count-len, "\n no addresses")) >= count)
			goto err;

		if ( (len += snprintf(page+len, count-len, "\n")) >= count)
			break;
	}

 err:
	HIP_READ_UNLOCK_DB(&hip_hadb);

	if (len >= count) {
		HIP_DEBUG("len %d >= count %d\n", len, count);
		page[count-1] = '\0';
		len = count;
	} else {
		page[len] = '\0';
	}


	*eof = 1;

        return(len);
}

/**
 * hip_proc_read_lhi - debug function for dumping LHIs from procfs file /proc/net/hip/lhi
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_lhi(char *page, char **start, off_t off,
		      int count, int *eof, void *data) 
{
	/* XX: Called with sdb lock held ? */

        int len = 0;
	int i;
	unsigned long lf = 0;
	struct hip_host_id_entry *item;
	char in6buf[INET6_ADDRSTRLEN];

	_HIP_DEBUG("off=%d count=%d eof=%d\n", (int) off, count, *eof);


	len += snprintf(page, count, "# used type HIT\n");
	if (len >= count)
		goto err;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	i=0;
	list_for_each_entry(item,&hip_local_hostid_db.db_head,next) {
		hip_in6_ntop(&item->lhi.hit, in6buf);
		len += snprintf(page+len, count-len, "%d %d %s %s\n",
				++i,
				1,
				item->lhi.anonymous?"anon":"public",
				in6buf);
		if (len >= count)
			break;
	}

	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);

	if (len >= count) {
		page[count-1] = '\0';
		len = count;
	} else {
		page[len] = '\0';
	}

 err:
	*eof = 1;
        return(len);
}

int hip_proc_send_update(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
	HIP_DEBUG("\n");
#if 0
	hip_send_update_all();
#endif
	*eof = 1;

	return 0;
}

#endif /* CONFIG_PROC_FS */



/**
 * hip_hadb_get_peer_address - Get some of the peer's usable IPv6 address
 * @arg: Key to find the HADB entry
 * @target: Placeholder for the IPv6 address found in the HADB
 * @type: Type of the key
 *
 * Current destination address selection algorithm:
 * select the address which was added/updated last
 *
 * Returns: 0 if some of the addresses was copied successfully, else < 0.
 *
 */
int hip_hadb_get_peer_address(void *arg, struct in6_addr *target, int type)
{
	HIP_HADB_WRAP_BEGIN(int);

	if (!target)
		return -EINVAL;

	HIP_HADB_WRAP_R_CALL_FUNC(-EINVAL,hip_hadb_get_peer_addr(entry,target));
}

/**
 * hip_hadb_get_peer_address_info - get infomation on the given peer IPv6 address
 * @arg: Database key
 * @addr: the IPv6 address for which the information is to be retrieved
 * @interface_id: where the Interface ID of @addr is copied to
 * @lifetime: where the lifetime of @addr is copied to
 * @modified_time: where the time when @addr was added or updated is copied to
 * @type: Type of the database key
 *
 * Returns: if the HADB entry, that is found using the @arg key, has the address 
 * @addr in its peer address list
 * parameters @interface_id, @lifetime, and @modified_time are
 * assigned if they are non-NULL and 1 is returned, else @interface_id
 * and @lifetime are not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_address_info(void *arg, struct in6_addr *addr, 
				   uint32_t *interface_id, uint32_t *lifetime,
				   struct timeval *modified_time, int type)
{
	HIP_HADB_WRAP_BEGIN(int);

	HIP_HADB_WRAP_R_CALL_FUNC(0,
        hip_hadb_get_peer_addr_info(entry,addr,interface_id,lifetime,modified_time));
}

/**
 * hip_hadb_set_peer_address_info - set entry's peer address Interface ID and/or address lifetime
 * @arg: Database key
 * @entry: corresponding hadb entry of the peer
 * @addr: the IPv6 address for which the information is to be set
 * @interface_id: Interface ID
 * @lifetime: address lifetime
 * @type: Type of the database key
 * 
 * Find entry by the @arg key and set entry's 
 * peer address @addr Interface ID and address
 * lifetime to given values. If @interface_id is non-NULL
 * @addr's Interface Id is changed to value pointed to by
 * @interface_id, similarly for parameter @lifetime.
 *
 * Returns: if the entry has the address @addr in its peer address list and
 * the parameters @interface_id and @lifetime were assigned successfully, 0
 * is returned. Else no values are changed and a negative (<0) value is 
 * returned.
 * XXX
 */
int hip_hadb_set_peer_address_info(void *arg,struct in6_addr *addr, 
				   uint32_t *interface_id,
				   uint32_t *lifetime,int type)
{
	HIP_HADB_WRAP_BEGIN(int);

	HIP_HADB_WRAP_W_CALL_FUNC(0,
        hip_hadb_set_peer_addr_info(entry,addr,interface_id,lifetime));
}

/**
 * hip_hadb_delete_peer_address_list - delete all peer addresses of the given entry
 * @arg: Database key used to find the entry
 * @type: Type of the key (HIP_ARG_SPI or HIP_ARG_HIT)
 */
void hip_hadb_delete_peer_address_list(void *arg, int type)
{
	HIP_HADB_WRAP_BEGIN_VOID;

	HIP_HADB_WRAP_W_CALL_FUNC_VOID(hip_hadb_delete_peer_addrlist(entry));
}

/**
 * hip_hadb_delete_peer_address_list_one - delete IPv6 address from entry's list of peer addresses
 * @arg: Database key for the entry
 * @addr: IPv6 address to be deleted
 * @type: Type of the key
 */
void hip_hadb_delete_peer_address_list_one(void *arg, struct in6_addr *addr,
				       int type)
{
	HIP_HADB_WRAP_BEGIN_VOID;

	HIP_HADB_WRAP_W_CALL_FUNC_VOID(
        hip_hadb_delete_peer_addrlist_one(entry,addr));
}

/**
 * hip_hadb_exists_entry - Check if certain entry exists in database
 * @arg: Database key
 * @type: Type of the key
 */
int hip_hadb_exists_entry(void *arg, int type)
{
	HIP_HADB_WRAP_BEGIN(int);
	HIP_HADB_WRAP_R_ACCESS(0);
	res = 1;
	HIP_HADB_WRAP_R_END;
}


/**
 * hip_hadb_reinitialize_state - Change entry's state back to HIP_STATE_UNASSOCIATED
 * @arg: Database key
 * @type: Type of key
 *
 * Also clears (and frees other fields). The only fields that are not touched
 * are hit_peer and peer_addr_list. To clear those fields call some other 
 * function that deletes mappings. 
 *
 * Returns 0, -ENOENT, if the entry was not found in the first place.
 */
int hip_hadb_reinitialize_state(void *arg, int type)
{
	HIP_HADB_WRAP_BEGIN(int);
	HIP_HADB_WRAP_W_CALL_FUNC(-ENOENT,
				  hip_hadb_reinit_state(entry));
}

void hip_hadb_delete_entry(void *arg, int type)
{
	HIP_HADB_WRAP_BEGIN_VOID;
	HIP_HADB_WRAP_W_CALL_FUNC_VOID(hip_hadb_delete_entry_nolock(entry));
}


void hip_hadb_delete_peer_addr_not_in_list(void *arg, void *addrlist, int n_addrs,
					   uint32_t iface, int type)
{
	HIP_HADB_WRAP_BEGIN_VOID;
	HIP_HADB_WRAP_W_CALL_FUNC_VOID(
	hip_hadb_delete_peer_address_not_in_list(entry,addrlist,n_addrs,
						 iface));
}


int hip_hadb_add_peer_address(void *arg, struct in6_addr *addr, uint32_t interface_id,
			      uint32_t lifetime, int type)
{
	HIP_HADB_WRAP_BEGIN(int);

	HIP_HADB_WRAP_W_CALL_FUNC(-EINVAL,
        hip_hadb_add_peer_addr(entry,addr,interface_id,lifetime));
}

void hip_hadb_delete_peer_addr_iface(void *arg, uint32_t interface_id,
				     int type)
{
	HIP_HADB_WRAP_BEGIN_VOID;
	HIP_HADB_WRAP_W_CALL_FUNC_VOID(
	hip_hadb_delete_peer_addr_if(entry,interface_id));
}
	

void hip_hadb_free_entry(void *arg, int type)
{
	HIP_HADB_WRAP_BEGIN_VOID;
	HIP_HADB_WRAP_W_CALL_FUNC_VOID(
		hip_hadb_entry_free(entry));
}


void hip_hadb_free_socks(struct in6_addr *arg, int error)
{
	HIP_HADB_WRAP_BEGIN_VOID;
	int type = HIP_ARG_HIT;

	HIP_HADB_WRAP_W_CALL_FUNC_VOID(
		hip_hadb_free_socks_nolock(entry, error));

}

/** hip_hadb_multiget - get information on given HIT or SPI
 * @arg: pointer to HIT or SPI depending on @type
 * @amount: number of elements to be fetched
 * @getlist: list containing the element types to be fetched
 * @setlist: list of pointers where the results are stored
 * @type: HIP_ARG_HIT or HIP_ARG_SPI
 *
 * Returns: On success @amount, on error -EINVAL
*/
int hip_hadb_multiget(void *arg, int amount, int *getlist, void **setlist, int type)
{
	HIP_HADB_WRAP_BEGIN(int);
	void *target;
	int num = 0;
	int err = 0;
	_HIP_DEBUG("amount=%d getlist=0x%p setlist=0x%p\n", amount, getlist, setlist);

	if (amount <= 0) {
		HIP_ERROR("invalid amount %d\n", amount);
		return -EINVAL;
	}

	if (!getlist || !setlist) {
		HIP_ERROR("getlist or setlist is null\n");
		return -EINVAL;
	}

	HIP_HADB_WRAP_R_ACCESS(0);

	while(num < amount) {
		target = setlist[num];
		_HIP_DEBUG("index=%d request=0x%x getlist=0x%p target=0x%p\n",
			   num, *getlist, getlist, target);
		if (!target) {
			HIP_ERROR("null target at index %d\n", num);
			err = -EINVAL;
			goto out_err;
		}
		switch(*getlist) {
		case HIP_HADB_OWN_SPI:
			*((uint32_t *)target) = entry->spi_our;
			break;
		case HIP_HADB_PEER_SPI:
			*((uint32_t *)target) = entry->spi_peer;
			break;
		case HIP_HADB_OWN_NEW_SPI:
			*((uint32_t *)target) = entry->new_spi_our;
			break;
		case HIP_HADB_PEER_NEW_SPI:
			*((uint32_t *)target) = entry->new_spi_peer;
			break;
		case HIP_HADB_OWN_LSI:
			*((uint32_t *)target) = entry->lsi_our;
			break;
		case HIP_HADB_PEER_LSI:
			*((uint32_t *)target) = entry->lsi_peer;
			break;
		case HIP_HADB_ESP_TRANSFORM:
			*((int *)target) = entry->esp_transform;
			break;
		case HIP_HADB_SK:
			memcpy(target, &entry->kg, sizeof(struct hip_kludge));
			break;
		case HIP_HADB_STATE:
			*((int *)target) = entry->state;
			break;
		case HIP_HADB_BIRTHDAY:
			*((uint64_t *)target) = entry->birthday;
			break;
		case HIP_HADB_PEER_CONTROLS:
			*((uint16_t *)target) = entry->peer_controls;
			break;
		case HIP_HADB_OWN_HIT:
			ipv6_addr_copy(target, &entry->hit_our);
			break;
		case HIP_HADB_PEER_HIT:
			ipv6_addr_copy(target, &entry->hit_peer);
			break;
		case HIP_HADB_OWN_ESP:
			memcpy(target,&entry->esp_our, sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_PEER_ESP:
			memcpy(target,&entry->esp_peer, sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_OWN_AUTH:
			memcpy(target,&entry->auth_our, sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_PEER_AUTH:
			memcpy(target,&entry->auth_peer, sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_OWN_HMAC:
			memcpy(target,&entry->hmac_our, sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_PEER_HMAC:
			memcpy(target,&entry->hmac_peer, sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_OWN_UPDATE_ID_IN:
			*((uint16_t *)target) = entry->update_id_in;
			break;
		case HIP_HADB_OWN_UPDATE_ID_OUT:
			*((uint16_t *)target) = entry->update_id_out;
			break;
		case HIP_HADB_KEYMAT_INDEX:
			*((uint16_t *)target) = entry->current_keymat_index;
			break;
		case HIP_HADB_OWN_DH_SHARED:
			memcpy(target, entry->dh_shared_key, entry->dh_shared_key_len);
			break;
		case HIP_HADB_OWN_DH_SHARED_LEN:
			*((size_t *) target) = entry->dh_shared_key_len;
			break;
		default:
			HIP_ERROR("Unknown request 0x%x at index %d\n", *getlist, num);
			err = -EINVAL;
			goto out_err;
			break;
		}
		num++;
		getlist++;
	}

 out_err:
	res = err ? err : amount;
	_HIP_DEBUG("err=%d res=%d amount=%d\n", err, res, amount);
 	HIP_HADB_WRAP_R_END;
}


/** hip_hadb_get_info - get given information on HIT or SPI
 * @arg: pointer to HIT or SPI depending on @type
 * @dst: pointer where the result is stored to
 * @type: contains request type and type for @arg
 *
 * Returns: 1 on success, on error -EINVAL
 */
int hip_hadb_get_info(void *arg, void *dst, int type)
{
  	int itype = (type & (~HIP_HADB_ACCESS_ARGS));
  	int res;

	res = hip_hadb_multiget(arg, 1, &itype, &dst, type & HIP_HADB_ACCESS_ARGS);
  	return res;
}


/** hip_hadb_multiset - set information on given HIT or SPI
 * @arg: pointer to HIT or SPI depending on @type
 * @amount: number of elements to be fetched
 * @getlist: list containing the element types to be set
 * @setlist: list of pointers containing the information to be stored
 * @type: HIP_ARG_HIT or HIP_ARG_SPI
 *
 * Returns: On success @amount, on error -EINVAL
 */
int hip_hadb_multiset(void *arg, int amount, int *getlist, void **setlist, int type)
{
	HIP_HADB_WRAP_BEGIN(int);
	void *target;
	int num = 0, err = 0;

	_HIP_DEBUG("amount=%d getlist=0x%p setlist=0x%p\n", amount, getlist, setlist);

	if (amount <= 0) {
		HIP_ERROR("invalid amount %d\n", amount);
		return -EINVAL;
	}

	if (!getlist || !setlist) {
		HIP_ERROR("getlist or setlist is null\n");
		return -EINVAL;
	}

	HIP_HADB_WRAP_W_ACCESS(0);

	while(num < amount) {
		target = setlist[num];
		_HIP_DEBUG("index=%d request=0x%x getlist=0x%p target=0x%p\n",
			   num, *getlist, getlist, target);
		if (!target) {
			HIP_ERROR("null target at index %d\n", num);
			err = -EINVAL;
			goto out_err;
		}

		switch((*getlist)) {
		case HIP_HADB_OWN_SPI:
			entry->spi_our = *((uint32_t *)target);
			break;
		case HIP_HADB_PEER_SPI:
			entry->spi_peer = *((uint32_t *) target);
			break;
		case HIP_HADB_OWN_NEW_SPI:
			entry->new_spi_our = *((uint32_t *) target);
			break;
		case HIP_HADB_PEER_NEW_SPI:
			entry->new_spi_peer = *((uint32_t *) target);
			break;
		case HIP_HADB_OWN_LSI:
			entry->lsi_our = *((uint32_t *) target);
			break;
		case HIP_HADB_PEER_LSI:
			entry->lsi_peer = *((uint32_t *) target);
			break;
		case HIP_HADB_ESP_TRANSFORM:
			entry->esp_transform = *((int *) target);
			break;
		case HIP_HADB_SK:
			memcpy(&entry->kg, target, sizeof(struct hip_kludge));
			break;
		case HIP_HADB_STATE:
			entry->state = *((int *) target);
			break;
		case HIP_HADB_BIRTHDAY:
			entry->birthday = *((uint64_t *) target);
			break;
		case HIP_HADB_PEER_CONTROLS:
			entry->peer_controls = *((uint16_t *) target);
			break;
		case HIP_HADB_OWN_HIT:
			ipv6_addr_copy(&entry->hit_our,target);
			break;
		case HIP_HADB_PEER_HIT:
			ipv6_addr_copy(&entry->hit_peer,target);
			break;
		case HIP_HADB_OWN_ESP:
			memcpy(&entry->esp_our,target,sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_PEER_ESP:
			memcpy(&entry->esp_peer,target,sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_OWN_AUTH:
			memcpy(&entry->auth_our,target,sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_PEER_AUTH:
			memcpy(&entry->auth_peer,target,sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_OWN_HMAC:
			memcpy(&entry->hmac_our,target,sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_PEER_HMAC:
			memcpy(&entry->hmac_peer,target,sizeof(struct hip_crypto_key));
			break;
		case HIP_HADB_OWN_UPDATE_ID_IN:
			entry->update_id_in = *((uint16_t *)target);
			break;
		case HIP_HADB_OWN_UPDATE_ID_OUT:
			entry->update_id_out = *((uint16_t *)target);
			break;
		default:
			HIP_ERROR("Unknown request 0x%x at index %d\n", *getlist, num);
			err = -EINVAL;
			goto out_err;
			break;
		}
		num++;
		getlist++;
	}

 out_err:

	res = err ? err : amount;
	_HIP_DEBUG("err=%d res=%d amount=%d\n", err, res, amount);
	HIP_HADB_WRAP_W_END;
}

/** hip_hadb_set_info - set given information on HIT or SPI
 * @arg: pointer to HIT or SPI depending on @type
 * @dst: pointer to where the stored information is at
 * @type: contains element type and type for @arg
 *
 * Returns: 1 on success, on error -EINVAL
 */
int hip_hadb_set_info(void *arg, void *dst, int type)
{
	int itype = (type & (~HIP_HADB_ACCESS_ARGS));
	int res;

	res = hip_hadb_multiset(arg, 1, &itype, &dst, type & HIP_HADB_ACCESS_ARGS);
	return res;
}

void hip_hadb_acquire_ex_db_access(int *flags)
{
	unsigned long lf;

	HIP_WRITE_LOCK_DB(&hip_hadb);
	*flags = lf;
}

void hip_hadb_release_ex_db_access(int flags)
{
	unsigned long lf = flags;
	HIP_WRITE_UNLOCK_DB(&hip_hadb);
}

void hip_hadb_acquire_db_access(int *flags)
{
	unsigned long lf;
       
	HIP_READ_LOCK_DB(&hip_hadb);
	*flags = lf;
}

void hip_hadb_release_db_access(int flags)
{
	unsigned long lf = flags;
	HIP_READ_UNLOCK_DB(&hip_hadb);
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_hit_no_lock(struct hip_db_struct *db,
						     const struct hip_lhi *lhi)
{
	struct hip_eid_db_entry *entry;

	HIP_DEBUG("\n");

	list_for_each_entry(entry, &db->db_head, next) {
		/* XX TODO: Skip the anonymous bit. Is it ok? */
		if (!ipv6_addr_cmp(&entry->lhi.hit,
				   (struct in6_addr *) &lhi->hit))
			return entry;
	}
	
	return NULL;
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_eid_no_lock(struct hip_db_struct *db,
						const struct sockaddr_eid *eid)
{
	struct hip_eid_db_entry *entry;

	list_for_each_entry(entry, &db->db_head, next) {
		HIP_DEBUG("comparing %d with %d\n",
			  ntohs(entry->eid.eid_val), ntohs(eid->eid_val));
		if (entry->eid.eid_val == eid->eid_val)
			    return entry;
	}
	
	return NULL;
}

int hip_db_set_eid(struct sockaddr_eid *eid,
		   const struct hip_lhi *lhi,
		   const struct hip_eid_owner_info *owner_info,
		   int is_local)
{
	struct hip_db_struct *db;
	int err = 0;
	unsigned long lf;
	struct hip_eid_db_entry *entry = NULL;

	HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

	HIP_WRITE_LOCK_DB(db);

	entry = hip_db_find_eid_entry_by_hit_no_lock(db, lhi);
	if (!entry) {
		entry = kmalloc(sizeof(struct hip_eid_db_entry), GFP_KERNEL);
		if (!entry) {
			err = -ENOMEM;
			goto out_err;
		}

		entry->eid.eid_val = ((is_local) ?
			htons(hip_create_unique_local_eid()) :
			htons(hip_create_unique_peer_eid()));
		entry->eid.eid_family = PF_HIP;
		memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));

		HIP_DEBUG("Generated eid val %d\n", entry->eid.eid_val);

		memcpy(&entry->lhi, lhi, sizeof(struct hip_lhi));
		memcpy(&entry->owner_info, owner_info,
		       sizeof(struct hip_eid_owner_info));

		/* Finished. Add the entry to the list. */
		list_add(&entry->next, &db->db_head);
	} else {
		/* XX TODO: Ownership is not changed here; should it? */
		memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));
	}

 out_err:
	HIP_WRITE_UNLOCK_DB(db);

	return err;
}

int hip_db_set_my_eid(struct sockaddr_eid *eid,
		      const struct hip_lhi *lhi,
		      const struct hip_eid_owner_info *owner_info)
{
	return hip_db_set_eid(eid, lhi, owner_info, 1);
}

int hip_db_set_peer_eid(struct sockaddr_eid *eid,
			const struct hip_lhi *lhi,
			const struct hip_eid_owner_info *owner_info)
{
	return hip_db_set_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info,
			  int is_local)
{
	struct hip_db_struct *db;
	int err = 0;
	unsigned long lf;
	struct hip_eid_db_entry *entry = NULL;

	HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

	HIP_READ_LOCK_DB(db);

	entry = hip_db_find_eid_entry_by_eid_no_lock(db, eid);
	if (!entry) {
		err = -ENOENT;
		goto out_err;
	}

	memcpy(lhi, &entry->lhi, sizeof(struct hip_lhi));
	memcpy(owner_info, &entry->owner_info,
	       sizeof(struct hip_eid_owner_info));
	
 out_err:
	HIP_READ_UNLOCK_DB(db);

	return err;

}

int hip_db_get_peer_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info)
{
	return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_my_lhi_by_eid(const struct sockaddr_eid *eid,
			     struct hip_lhi *lhi,
			     struct hip_eid_owner_info *owner_info)
{
	return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 1);
}

#undef HIP_HADB_WRAP_W_CALL_FUNC
#undef HIP_HADB_WRAP_R_CALL_FUNC
#undef HIP_HADB_WRAP_W_CALL_FUNC_VOID
#undef HIP_HADB_WRAP_R_CALL_FUNC_VOID
#undef HIP_HADB_WRAP_R_ACCESS
#undef HIP_HADB_WRAP_W_ACCESS
#undef HIP_HADB_WRAP_R_ACCESS_VOID
#undef HIP_HADB_WRAP_W_ACCESS_VOID
#undef HIP_HADB_WRAP_W_END
#undef HIP_HADB_WRAP_W_END_VOID
#undef HIP_HADB_WRAP_R_END_VOID
#undef HIP_HADB_WRAP_R_END
#undef HIP_HADB_WRAP_BEGIN
#undef HIP_HADB_WRAP_BEGIN_VOID
#undef HIP_READ_LOCK_DB
#undef HIP_WRITE_LOCK_DB
#undef HIP_READ_UNLOCK_DB
#undef HIP_WRITE_UNLOCK_DB

