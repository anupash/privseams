#ifndef HIP_HADB_H
#define HIP_HADB_H

//#ifndef __KERNEL__
//#include "hashtable.h"
//#else
#include <net/hip.h>
#include "debug.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"
#include "builder.h"

#ifdef __KERNEL__
#define HIP_LOCK_HA(ha) do { spin_lock_bh(&ha->lock); } while(0)
#define HIP_UNLOCK_HA(ha) do { spin_unlock_bh(&ha->lock); } while(0)
#define HIP_LOCK_HS(hs) do { spin_lock_bh(&hs->lock); } while(0)
#define HIP_UNLOCK_HS(hs) do { spin_unlock_bh(&hs->lock); } while(0)
#else
#include <sys/time.h>
#include <time.h>

#define HIP_LOCK_HA(ha) 
#define HIP_UNLOCK_HA(ha)
#define HIP_LOCK_HS(hs) 
#define HIP_UNLOCK_HS(hs)

#define do_gettimeofday(x) gettimeofday(x, NULL)
#endif

#define HIP_HADB_SIZE 53
#define HIP_MAX_HAS 100

/*************** BASE FUNCTIONS *******************/

/* Initialization functions */
void hip_init_hadb(void);
void hip_uninit_hadb(void);

/* Accessors */
hip_ha_t *hip_hadb_find_byhit(hip_hit_t *hit);
hip_ha_t *hip_hadb_find_byspi_list(uint32_t spi);

/* insert/create/delete */
int hip_hadb_insert_state(hip_ha_t *ha);
int hip_hadb_insert_state_spi_list(hip_ha_t *ha, uint32_t spi);
void hip_hadb_remove_state(hip_ha_t *ha);
void hip_hadb_remove_state_hit(hip_ha_t *ha);
void hip_hadb_remove_hs(uint32_t spi);

/* existence */
int hip_hadb_exists_entry(void *key, int type);

/* debugging */
void hip_hadb_dump_hits(void);
void hip_hadb_dump_spis(void);

/*************** CONSTRUCTS ********************/
int hip_hadb_exists_entry(void *arg, int type);

int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr);

int hip_hadb_get_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr, 
				uint32_t *spi, uint32_t *lifetime,
				struct timeval *modified_time);

int hip_hadb_set_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *lifetime);

int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t interface_id, uint32_t lifetime,
			   int state);

void hip_hadb_delete_peer_addrlist_one(hip_ha_t *entry, struct in6_addr *addr);

void hip_hadb_delete_peer_addrlist(hip_ha_t *entry);

int hip_for_each_ha(int (func)(hip_ha_t *entry, void *opaq), void *opaque);

int hip_hadb_add_peer_info(hip_hit_t *hit, struct in6_addr *addr);

int hip_del_peer_info(struct in6_addr *hit, struct in6_addr *addr);

int hip_hadb_add_spi(hip_ha_t *entry, int direction, void *data);
void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi);
void hip_hadb_delete_inbound_spis(hip_ha_t *entry);
void hip_hadb_delete_outbound_spi(hip_ha_t *entry, uint32_t spi);
void hip_hadb_delete_outbound_spis(hip_ha_t *entry);

uint32_t hip_hadb_get_latest_inbound_spi(hip_ha_t *entry);

void hip_hadb_set_spi_ifindex(hip_ha_t *entry, uint32_t spi, int ifindex);
uint32_t hip_hadb_get_spi(hip_ha_t *entry, int ifindex);
int hip_hadb_get_spi_ifindex(hip_ha_t *entry, uint32_t spi);
uint32_t hip_update_get_prev_spi_in(hip_ha_t *entry, uint32_t prev_spi_out);
uint32_t hip_get_spi_to_update(hip_ha_t *entry);
uint32_t hip_get_spi_to_update_in_established(hip_ha_t *entry, struct in6_addr *dev_addr);
void hip_set_spi_update_status(hip_ha_t *entry, uint32_t spi, int set);
void hip_update_set_new_spi_in(hip_ha_t *entry, uint32_t spi, uint32_t new_spi, uint32_t spi_out);
void hip_update_set_new_spi_out(hip_ha_t *entry, uint32_t spi, uint32_t new_spi);
uint32_t hip_update_get_new_spi_in(hip_ha_t *entry, uint32_t spi);
void hip_update_switch_spi_in(hip_ha_t *entry, uint32_t old_spi);
void hip_update_switch_spi_out(hip_ha_t *entry, uint32_t old_spi);
void hip_update_set_status(hip_ha_t *entry, uint32_t spi, int set_flags,
			   uint32_t update_id, int update_flags_or, struct hip_nes *nes,
			   uint16_t keymat_index);
void hip_update_clear_status(hip_ha_t *entry, uint32_t spi);
int hip_update_exists_spi(hip_ha_t *entry, uint32_t spi,
			  int direction, int test_new_spi);
uint32_t hip_hadb_relookup_default_out(hip_ha_t *entry);
void hip_hadb_set_default_out_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out,
                                   struct in6_addr *addr);
void hip_update_handle_ack(hip_ha_t *entry, struct hip_ack *ack, int have_nes,
			   struct hip_echo_response *echo_esp);
void hip_update_handle_nes(hip_ha_t *entry, uint32_t peer_update_id);
int hip_update_get_spi_keymat_index(hip_ha_t *entry, uint32_t spi);

struct hip_spi_out_item *hip_hadb_get_spi_list(hip_ha_t *entry, uint32_t spi);
int hip_hadb_add_addr_to_spi(hip_ha_t *entry, uint32_t spi, struct in6_addr *addr,
			     int address_state, uint32_t lifetime,
			     int is_preferred_addr);
uint32_t hip_get_default_spi_out(struct in6_addr *hit, int *state_ok);

/***********************************************/
int hip_proc_read_hadb_state(char *page, char **start, off_t off,
			     int count, int *eof, void *data);
int hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
				  int count, int *eof, void *data);
/**************** other useful utilities ******************/
void hip_hadb_delete_state(hip_ha_t *ha);
hip_ha_t *hip_hadb_create_state(int gfpmask);
void hip_hadb_deactivate_hs_spi(uint32_t spi);

void hip_hadb_dump_spis_in(hip_ha_t *entry);
void hip_hadb_dump_spis_out(hip_ha_t *entry);
void hip_hadb_dump_hs_ht(void);

#define hip_hold_ha(ha) do { \
	atomic_inc(&ha->refcnt); \
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n",ha, atomic_read(&ha->refcnt)); \
} while(0)

#define hip_put_ha(ha) do { \
	if (atomic_dec_and_test(&ha->refcnt)) { \
                HIP_DEBUG("HA: deleting %p\n", ha); \
		hip_hadb_delete_state(ha); \
                HIP_DEBUG("HA: %p deleted\n", ha); \
	} else { \
                _HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha, atomic_read(&ha->refcnt)); \
        } \
} while(0)

//#endif /* __KERNEL__ */
#endif /* HIP_HADB_H */
