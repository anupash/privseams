#include "beet.h"

HIP_HASHTABLE hip_beetdb_hit;
HIP_HASHTABLE hip_beetdb_spi_list;

/* byhit and byspi list contain also both local and peer SPI lists */
static struct list_head hip_beetdb_byhit[HIP_BEETDB_SIZE];
static struct list_head hip_beetdb_byspi_list[HIP_BEETDB_SIZE];

void hip_beetdb_delete_state(hip_xfrm_t *x)
{
	HIP_DEBUG("xfrm=0x%p\n", x);
	HIP_FREE(x);
}

void hip_beetdb_delete_hs(struct hip_hit_spi *h)
{
	HIP_DEBUG("xfrm=0x%p\n", h);
	HIP_FREE(h);
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

	/* I think this is not very safe deallocation.
	 * Locking the hip_beetdb_spi and hip_beetdb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in 
	 * hip_beetdb_remove_state() for a while.
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

	/* HIT-SPI mappings should be already deleted by now, but check anyway */
	HIP_DEBUG("DELETING HS HT\n");
	for(i = 0; i < HIP_BEETDB_SIZE; i++) {
		_HIP_DEBUG("HS HT [%d]\n", i);
		list_for_each_entry_safe(hs, tmp_hs, &hip_beetdb_byspi_list[i], list) {
			HIP_ERROR("BUG: HS NOT ALREADY DELETED, DELETING HS %p, HS SPI=0x%x\n",
				  hs, hs->spi);
			if (atomic_read(&hs->refcnt) > 1)
				HIP_ERROR("HS: %p, in use while removing it from HADB\n", hs);
			hip_beetdb_hold_hs(hs);
			//hip_beetdb_delete_hs(hs);
			hip_hadb_remove_hs2(hs);
			hip_beetdb_put_hs(hs);
			//} else
			//	HIP_DEBUG("HS refcnt < 1, BUG ?\n");
		}
	}
	HIP_DEBUG("DONE DELETING HS HT\n");
}

/**
 *
 */
int hip_xfrm_dst_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr) {
	return 0;
}

int hip_xfrm_update(uint32_t spi, struct in6_addr *dst_addr, int state,
		    int dir) {
	return 0;
}

int hip_xfrm_delete(uint32_t spi, struct in6_addr * hit, int dir) {
	return 0;
}

struct hip_xfrm_state * hip_xfrm_find_by_spi(uint32_t spi)
{
	// XX FIXME: search the hashtable 
	return NULL;
}

struct hip_xfrm_state * hip_xfrm_find_by_hit(struct in6_addr *dst_hit)
{
        // XX FIXME: 
	return NULL;
}
