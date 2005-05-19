/*
 * XX FIX: integrate the BEET db into the standard xfrm code when this works.
 * The information stored in this database is actually a partial replica of
 * the information stored in the hadb.
 *
 * XX FIX: there is still some redundant code with hadb.c... use macros!
 *
 */

#include "beet.h"

/*
 * hip_beetdb_hit is indexed by peer HIT. Each {our_hit, peer_hit} pair is
 * listed only once in this list. Each entry contains also the default
 * outbound SPI. Even if the peer has multiple SPIs, only the default is
 * included in this hashtable database.
 *
 * hip_beetdb_spi_list is indexed with inbound SPIs. Each enty contains the
 * peer_hit (and inbound SPI, even though it is unnecessary because it is the
 * key). This list is used when an ESP packet arrives and we need to figure
 * out the corresponding our_hit and peer_hit (not included in the ESP
 * envelope!). You should notice that there may be multiple inbound SPIs for
 * a given {hit_our, hit_peer} pair. However, given one inbound SPI, it will
 * match to single xfrm entry.
 *
 */

HIP_HASHTABLE hip_beetdb_hit;
HIP_HASHTABLE hip_beetdb_spi_list;

/* byhit and byspi list contain also both local and peer SPI lists */
static struct list_head hip_beetdb_byhit[HIP_BEETDB_SIZE];
static struct list_head hip_beetdb_byspi_list[HIP_BEETDB_SIZE];

void hip_beetdb_delete_state(hip_xfrm_t *x)
{
	HIP_DEBUG("xfrm=0x%p\n", x);
	_HIP_ERROR("Miika: this should be implemented\n");
	HIP_LOCK_XF(x);
	hip_ht_delete(&hip_beetdb_hit, x);
	HIP_UNLOCK_XF(x);
	HIP_FREE(x);
}

void hip_beetdb_delete_hs(struct hip_hit_spi *hs)
{
	HIP_DEBUG("hs=0x%p SPI=0x%x\n", hs, hs->spi);
	HIP_LOCK_HS(hs);
	hip_ht_delete(&hip_beetdb_spi_list, hs);
	HIP_UNLOCK_HS(hs);
	HIP_FREE(hs);
}

static void hip_beetdb_hold_entry(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, hip_xfrm_t);
}

static void hip_beetdb_put_entry(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, hip_xfrm_t, hip_beetdb_delete_state);
}

static void *hip_beetdb_get_key_hit(void *entry)
{
	return (void *)&(((hip_xfrm_t *)entry)->hash_key);
	//return HIP_DB_GET_KEY_HIT(entry, hip_xfrm_t);
}

static void hip_beetdb_hold_hs(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry, struct hip_hit_spi);
}

static void hip_beetdb_put_hs(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, struct hip_hit_spi, hip_beetdb_delete_hs);
}

static void *hip_beetdb_get_key_spi(void *entry)
{
	return (void *)(((struct hip_hit_spi *)entry)->spi);
}

void hip_init_beetdb(void)
{
	memset(&hip_beetdb_hit,0,sizeof(hip_beetdb_hit));
	memset(&hip_beetdb_spi_list,0,sizeof(hip_beetdb_spi_list));

	hip_beetdb_hit.head =      hip_beetdb_byhit;
	hip_beetdb_hit.hashsize =  HIP_BEETDB_SIZE;
	hip_beetdb_hit.offset =    offsetof(hip_ha_t, next_hit);
	hip_beetdb_hit.hash =      hip_hash_hit;
	hip_beetdb_hit.compare =   hip_match_hit;
	hip_beetdb_hit.hold =      hip_beetdb_hold_entry;
	hip_beetdb_hit.put =       hip_beetdb_put_entry;
	hip_beetdb_hit.get_key =   hip_beetdb_get_key_hit;

	strncpy(hip_beetdb_hit.name,"HIP_BEETDB_BY_HIT", 15);
	hip_beetdb_hit.name[15] = 0;

	hip_beetdb_spi_list.head =      hip_beetdb_byspi_list;
	hip_beetdb_spi_list.hashsize =  HIP_BEETDB_SIZE;
	hip_beetdb_spi_list.offset =    offsetof(struct hip_hit_spi, list);
	hip_beetdb_spi_list.hash =      hip_hash_spi;
	hip_beetdb_spi_list.compare =   hip_hadb_match_spi;
	hip_beetdb_spi_list.hold =      hip_beetdb_hold_hs;
	hip_beetdb_spi_list.put =       hip_beetdb_put_hs;
	hip_beetdb_spi_list.get_key =   hip_beetdb_get_key_spi;

	strncpy(hip_beetdb_spi_list.name,"HIP_BEETDB_BY_SPI_LIST", 15);
	hip_beetdb_spi_list.name[15] = 0;

	hip_ht_init(&hip_beetdb_hit);
	hip_ht_init(&hip_beetdb_spi_list);
}
void hip_uninit_beetdb(void)
{
	// XX FIXME: this does not work
	int i;
	hip_xfrm_t *ha, *tmp;
	//struct hip_hit_spi *hs, *tmp_hs;

	HIP_DEBUG("\n");

	HIP_DEBUG("DEBUG: DUMP SPI LISTS\n");
	//hip_beetdb_dump_hs_ht();

	/* I think this is not very safe deallocation. Locking the
	 * hip_beetdb_spi and hip_beetdb_hit could be one option,
	 * but I'm not very sure that it will work, as they are locked later
	 * in hip_beetdb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
	HIP_DEBUG("DELETING HA HT\n");
	for(i = 0; i < HIP_BEETDB_SIZE; i++) {
		list_for_each_entry_safe(ha, tmp, &hip_beetdb_byhit[i], next) {
			//hip_beetdb_hold_entry(ha);
			//hip_hold_ha(ha);
			//hip_beetdb_delete_state(ha);
			//hip_put_xfrm(ha);
			hip_beetdb_put_entry(ha);
		}
	}

#if 0
	/* HIT-SPI mappings should be already deleted by now, but check
	   anyway */
	HIP_DEBUG("DELETING HS HT\n");
	for(i = 0; i < HIP_BEETDB_SIZE; i++) {
		_HIP_DEBUG("HS HT [%d]\n", i);
		list_for_each_entry_safe(hs, tmp_hs,
					 &hip_beetdb_byspi_list[i], list) {
			HIP_ERROR("BUG: HS NOT ALREADY DELETED, DELETING HS %p, HS SPI=0x%x\n",
				  hs, hs->spi);
			if (atomic_read(&hs->refcnt) > 1)
				HIP_ERROR("HS: %p, in use while removing it from HADB, refcnt=%d\n",
					  hs, atomic_read(&hs->refcnt));
			hip_beetdb_hold_hs(hs);
			hip_beetdb_delete_hs(hs);
			hip_beetdb_put_hs(hs);
		}
	}
	HIP_DEBUG("Done deleting hs ht\n");
#endif
}

/**
 * hip_beetdb_create_state - Allocates and initializes a new HA structure
 * @gfpmask - passed directly to HIP_MALLOC().
 *
 * Return NULL if memory allocation failed, otherwise the HA.
 */
hip_xfrm_t *hip_beetdb_create_state(int gfpmask)
{
	hip_xfrm_t *entry = NULL;

	entry = HIP_MALLOC(sizeof(struct hip_xfrm_state), gfpmask);
	if (!entry)
		return NULL;

	memset(entry, 0, sizeof(hip_xfrm_t));

	INIT_LIST_HEAD(&entry->next);

	spin_lock_init(&entry->lock);
	atomic_set(&entry->refcnt, 0);

	entry->state = HIP_STATE_UNASSOCIATED;

	return entry;
}

/*
 * XX FIXME: create a macro - this is almost the same as in hadb
 */
int hip_beetdb_insert_state(hip_xfrm_t *x)
{
	hip_xfrm_t *tmp = NULL;
	int err = 0;

	/* assume already locked */

	HIP_ASSERT(!(ipv6_addr_any(&x->hit_peer)));

	if (!ipv6_addr_any(&x->hit_peer)) {
		hip_xor_hits(&x->hash_key, &x->hit_our, &x->hit_peer);
		tmp = hip_ht_find(&hip_beetdb_hit, (void *)&(x->hash_key));
		if (!tmp) {
			err = hip_ht_add(&hip_beetdb_hit, x);
		} else {
			hip_put_xfrm(tmp);
			HIP_DEBUG("HIT already taken\n");
		}
	}

	return err;
}

int hip_xfrm_insert_state_spi_list(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
				   uint32_t spi)
{
	int err = 0;
	HIP_INSERT_STATE_SPI_LIST(&hip_beetdb_spi_list, hip_beetdb_put_entry,
				  hit_peer, hit_our, spi);
	return err;
}

// Inbound (addr = hit_our)
// 2a) create a new inbound SPI:
//     - Create and fill spi_list{SPI} with peer hit and peer SPI
//       (insert_state does this). This way we can match ESP SPIs to HIT-pairs.
//       Note that peer HIT was already filled in xfrm_update_outbound
//     - write hit_our (not written by xfrm_update_outbound)
// 2b) or change the state?
int hip_xfrm_update_inbound(hip_hit_t *hit_peer, struct in6_addr *hit_our,
			    int spi_in, int state)
{
	hip_xfrm_t *entry;
	int err = 0;

	HIP_DEBUG("\n");

	entry = hip_xfrm_find_by_spi(spi_in);
	if (!entry) {
		/* create a new inbound SPI to HIT mapping */
		HIP_IFEL((err = hip_xfrm_insert_state_spi_list(hit_peer, 
							       hit_our, 
							       spi_in)), err, 
			 "Failed to create new SPI entry\n");

		entry = hip_xfrm_find_by_spi(spi_in);
		if (!entry) {
			err = -EFAULT;
			HIP_ERROR("Outbound BEET entry was not added first?\n");
			goto out_err;
		}

		HIP_DEBUG("Created a new inbound SPI %x\n", spi_in);
	}

	memcpy(&entry->hit_our, hit_our, sizeof(hip_hit_t));

	HIP_DEBUG_HIT("our hit",  &entry->hit_our);
	HIP_DEBUG_HIT("peer hit", &entry->hit_peer);

	if (state && state != entry->state) {
		HIP_DEBUG("Changing state from %s to %s\n", 
			  hip_state_str(entry->state), hip_state_str(state));

		entry->state = state;
	}

 out_err:
	if (entry)
		hip_put_xfrm(entry);
	return err;
}

// Outbound
// 1a) create a dst HIT - dst IP mapping to db_hit (without SPI)
// 1b) or update default outbound SPI for given dst HIT in db_hit
// 1c) or update default dst IP for given dst HIT in db_hit
// 1d) or change the state
//
int hip_xfrm_update_outbound(hip_hit_t *hit_peer, hip_hit_t *hit_our, 
			     struct in6_addr *peer_addr,
			     int spi_out, int state)
{
	hip_xfrm_t *entry = NULL;
	int err = 0;
	int created = 0;

	HIP_DEBUG("\n");

	if (!hit_peer || !hit_our) {
		HIP_DEBUG("hit_peer=0x%p hit_our=0x%p\n", hit_peer, hit_our);
		goto out_err;
	}

	entry = hip_xfrm_find_by_hits(hit_peer, hit_our);
	if (!entry) {
		entry = hip_beetdb_create_state(GFP_KERNEL);
		if (!entry) {
			HIP_ERROR("Unable to create a new entry\n");
			err = -ENOMEM;
			goto out_err;
		}
		ipv6_addr_copy(&entry->hit_peer, hit_peer);
		ipv6_addr_copy(&entry->hit_our, hit_our);
		hip_xor_hits(&entry->hash_key, hit_our, hit_peer);

		err = hip_beetdb_insert_state(entry);
		if (err) {
			HIP_ERROR("Failed to insert state\n");
			goto out_err;
		}
		created = 1;
		HIP_DEBUG_HIT("Created a new outbound entry for ", hit_peer);
	}

	if (spi_out && entry->spi != spi_out) {
		HIP_DEBUG("Changed SPI out from %x to %x\n", entry->spi, spi_out);
		entry->spi = spi_out;
	}
	if (peer_addr &&
	    memcmp(&entry->preferred_peer_addr, peer_addr,
		   sizeof(struct in6_addr))) {
		HIP_DEBUG_HIT("old peer addr", &entry->preferred_peer_addr);
		HIP_DEBUG_HIT("new peer addr", peer_addr);
		memcpy(&entry->preferred_peer_addr, peer_addr,
		       sizeof(struct in6_addr));
	}
	if (state && state != entry->state) {
		HIP_DEBUG("Changing state from %s to %s\n", 
			  hip_state_str(entry->state), hip_state_str(state));
		entry->state = state;
	}
	
 out_err:
	if (entry && !created)
		hip_put_xfrm(entry);
	return err;
}

int hip_xfrm_update(hip_hit_t *hit_peer, hip_hit_t *hit_our,
		    struct in6_addr *peer_addr,
		    uint32_t spi, int state, int dir)
{
	int err = 0;

	if (dir == HIP_SPI_DIRECTION_IN)
		err = hip_xfrm_update_inbound(hit_peer, hit_our,
					      spi, state);
	else
		err = hip_xfrm_update_outbound(hit_peer, hit_our, peer_addr,
					       spi, state);
	
	return err;
}

// XX FIX: this can be done with xfrm_update (select the state appropiately)
int hip_xfrm_delete(hip_hit_t * hit, uint32_t spi, int dir) {
//	if (dir == HIP_SPI_DIRECTION_IN) {
//	} else if (dir == HIP_SPI_DIRECTION_OUT){
//	} else {
//           return -EFAULT;
//      }
        // FIXME
	return 0;
}

#if 0
hip_xfrm_t *hip_xfrm_find_by_hit(const hip_hit_t *dst_hit)
{
	HIP_DEBUG("\n");
	return (hip_xfrm_t *)hip_ht_find(&hip_beetdb_hit, (void *)dst_hit);
}
#endif

/**
 * This function searches for a hip_xfrm_t entry from the hip_beetdb_hit
 * by a HIT pair (local,peer).
 *
 */
hip_xfrm_t *hip_xfrm_find_by_hits(const hip_hit_t *hit, const hip_hit_t *hit2)
{
	hip_hit_t key;
	hip_xor_hits(&key, hit, hit2);
	return (hip_xfrm_t *)hip_ht_find(&hip_beetdb_hit, (void *)&key);
}

/**
 * This function simply goes through all local xfrm entries and tries
 * to find an entry that matches the given peer hit. First matching xfrm 
 * entry is then returned.
 *
 * XX TODO: find a better solution, see the text below:
 * This function is needed because we index the xfrm now by 
 * key values calculated from <peer_hit,local_hit> pairs. Unfortunately, in 
 * some functions like the ipv6 stack hooks hip_get_saddr() and 
 * hip_handle_output() we just can't know the local_hit so we have to
 * improvise and just try to find some xfrm entry. 
 * 
 * NOTE: This way of finding xfrm entries doesn't work properly if we 
 * have multiple xfrm entries with the same peer_hit..
 */
hip_xfrm_t *hip_xfrm_try_to_find_by_peer_hit(const hip_hit_t *hit) 
{
	hip_xfrm_t *x, *tmp;
	int i;

	for(i = 0; i < HIP_BEETDB_SIZE; i++) {
		if(!list_empty(&hip_beetdb_byhit[i])) {
  			list_for_each_entry_safe(x, tmp, &hip_beetdb_byhit[i],
						 next) {
				if(x) 
					if (!ipv6_addr_cmp(&x->hit_peer, hit)){
						hip_beetdb_hold_entry(x);
						return x;
					}
			}
		}
	}
	
	return NULL;
}

/* find HA by inbound SPI */
struct hip_xfrm_state *hip_xfrm_find_by_spi(uint32_t spi_in)
{
	struct hip_hit_spi *hs;
	hip_hit_t hit_our, hit_peer;
	hip_xfrm_t *ha;

	hs = (struct hip_hit_spi *) hip_ht_find(&hip_beetdb_spi_list,
						(void *)spi_in);
	if (!hs) {
		HIP_DEBUG("HIT-SPI not found for SPI=0x%x\n", spi_in);
		return NULL;
	}

	ipv6_addr_copy(&hit_our, &hs->hit_our);
	ipv6_addr_copy(&hit_peer, &hs->hit_peer);
	hip_beetdb_put_hs(hs);

	/* searches based on the dst HIT? is this correct? */
	ha = hip_xfrm_find_by_hits(&hit_our, &hit_peer);
	if (!ha) {
		HIP_DEBUG("HA not found for SPI=0x%x\n", spi_in);
	}

	return ha;
}

/** hip_get_default_spi_out - Get the SPI to use in the outbound ESP packet
 * @hit: peer HIT
 * @state_ok: status of SPI lookup
 *
 * On successful return state_ok is 1, on error it is 0.
 *
 * Returns: the SPI value to use in the packet, or 0 on error.
*/
uint32_t hip_get_default_spi_out(hip_hit_t *hit, int *state_ok)
{
	uint32_t spi;
	hip_xfrm_t *entry;

	_HIP_DEBUG("\n");

	entry = hip_xfrm_try_to_find_by_peer_hit(hit);
	if (!entry) {
		HIP_DEBUG("entry not found\n");
		*state_ok = 0;
		return 0;
	}

	HIP_LOCK_HA(entry);
	spi = entry->spi;
	HIP_UNLOCK_HA(entry);
	hip_put_xfrm(entry);
	*state_ok = spi ? 1 : 0;
	return spi;
}

int hip_xfrm_hit_is_our(const hip_hit_t *hit)
{
	hip_xfrm_t *x, *tmp;
	int i;

	for(i = 0; i < HIP_BEETDB_SIZE; i++) {
		list_for_each_entry_safe(x, tmp, &hip_beetdb_byhit[i], next) {
			if (!ipv6_addr_cmp(&x->hit_our, hit)) {
				return 1;
			}
		}
	}

	return 0;
}
