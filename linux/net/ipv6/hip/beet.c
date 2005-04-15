/*
 * XX FIX: integrate the BEET db into the standard xfrm code when this works.
 * The information stored in this database is actually a partial replica of
 * the information stored in the hadb.
 *
 */

#include "beet.h"

HIP_HASHTABLE hip_beetdb_hit;
HIP_HASHTABLE hip_beetdb_spi_list;

/* byhit and byspi list contain also both local and peer SPI lists */
static struct list_head hip_beetdb_byhit[HIP_BEETDB_SIZE];
static struct list_head hip_beetdb_byspi_list[HIP_BEETDB_SIZE];

void hip_beetdb_delete_state(hip_xfrm_t *x)
{
	HIP_DEBUG("xfrm=0x%p\n", x);
	HIP_ERROR("Miika: this should be implemented\n");
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
	return HIP_DB_GET_KEY_HIT(entry, hip_xfrm_t);
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
	struct hip_hit_spi *hs, *tmp_hs;

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
			if (atomic_read(&ha->refcnt) > 2)
				HIP_ERROR("HA: %p, in use while removing it from HADB\n", ha);
			hip_hold_ha(ha);
			hip_beetdb_delete_state(ha);
			hip_put_xfrm(ha);
		}
	}

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
				HIP_ERROR("HS: %p, in use while removing it from HADB\n", hs);
			hip_beetdb_hold_hs(hs);
			hip_beetdb_delete_hs(hs);
			hip_beetdb_put_hs(hs);
		}
	}
	HIP_DEBUG("Done deleting hs ht\n");
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

	memset(entry, 0, sizeof(*entry));

	INIT_LIST_HEAD(&entry->next);

	spin_lock_init(&entry->lock);
	atomic_set(&entry->refcnt, 0);

	entry->state = HIP_STATE_UNASSOCIATED;

	return entry;
}

int hip_beetdb_insert_state(hip_xfrm_t *x)
{
	hip_xfrm_t *tmp = NULL;
	int err = 0;

	/* assume already locked */

	HIP_ASSERT(!(ipv6_addr_any(&x->hit_peer)));

	if (!ipv6_addr_any(&x->hit_peer)) {
		tmp = hip_ht_find(&hip_beetdb_hit, (void *)&(x->hit_peer));
		if (!tmp) {
			err = hip_ht_add(&hip_beetdb_hit, x);
		} else {
			hip_put_xfrm(tmp);
			HIP_DEBUG("HIT already taken\n");
		}
	}

	return err;
}

int hip_xfrm_dst_init(struct in6_addr *dst_hit, struct in6_addr *dst_addr) {
	int err = 0;
	hip_xfrm_t *entry;

	HIP_DEBUG("\n");
	
	entry = hip_xfrm_find_by_hit(dst_hit);
	if (entry) {
		/* initialized already */
		HIP_DEBUG("Initialized already\n");
		goto out_err;
	}

	entry = hip_beetdb_create_state(GFP_KERNEL);
	if (!entry) {
		HIP_ERROR("Unable to create a new entry\n");
		err = -ENOMEM;
		goto out_err;
	}
	
	/* insert IP address before dst HIT to avoid silly locking */
	ipv6_addr_copy(&entry->preferred_peer_addr, dst_addr);
	ipv6_addr_copy(&entry->hit_peer, dst_hit);

	/* experimenting here: no source HIT selected at this 
	   point of time (contrary to hip_hadb_add_peer_info) */
	
	err = hip_beetdb_insert_state(entry);
	if (err) {
		goto out_err;
	}

 out_err:
	
	return err;
}

int hip_xfrm_update(uint32_t spi, struct in6_addr *dst_addr, int state,
		    int dir) {
        // FIXME
	return 0;
}

int hip_xfrm_delete(uint32_t spi, struct in6_addr * hit, int dir) {
//	if (dir == HIP_FLOW_DIR_IN) {
//	} else if (dir == HIP_FLOW_DIR_OUT){
//	} else {
//           return -EFAULT;
//      }
        // FIXME
	return 0;
}

hip_xfrm_t *hip_xfrm_find_by_hit(struct in6_addr *dst_hit)
{
	HIP_DEBUG("\n");
	return (hip_xfrm_t *)hip_ht_find(&hip_beetdb_hit, (void *)dst_hit);
}

/* find HA by inbound SPI */
struct hip_xfrm_state *hip_xfrm_find_by_spi(uint32_t spi_in)
{
	struct hip_hit_spi *hs;
	hip_hit_t hit;
	hip_xfrm_t *ha;

	hs = (struct hip_hit_spi *) hip_ht_find(&hip_beetdb_spi_list,
						(void *)spi_in);
	if (!hs) {
		HIP_DEBUG("HIT-SPI not found for SPI=0x%x\n", spi_in);
		return NULL;
	}

	ipv6_addr_copy(&hit, &hs->hit);
	hip_beetdb_put_hs(hs);

	/* searches based on the dst HIT? is this correct? */
	ha = hip_xfrm_find_by_hit(&hit);
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

	entry = hip_xfrm_find_by_hit(hit);
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
