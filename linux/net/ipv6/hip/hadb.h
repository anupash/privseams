#ifndef HIP_HADB_H
#define HIP_HADB_H

#include "debug.h"

#include <net/hip.h>

#define HIP_HADB_SIZE 53
#define HIP_MAX_HAS 100

#define HIP_LOCK_HA(ha) do { spin_lock_bh(&ha->lock); } while(0)
#define HIP_UNLOCK_HA(ha) do { spin_unlock_bh(&ha->lock); } while(0)


/*************** BASE FUNCTIONS *******************/

/* Initialization functions */
void hip_init_hadb(void);
void hip_uninit_hadb(void);

/* Accessors */
hip_ha_t *hip_hadb_find_byspi(u32 spi);
hip_ha_t *hip_hadb_find_byspi_list(u32 spi);
hip_ha_t *hip_hadb_find_byhit(hip_hit_t *hit);

/* insert/create/delete */
int hip_hadb_insert_state(hip_ha_t *ha);
int hip_hadb_insert_state_spi_list(hip_ha_t *ha, uint32_t spi);
void hip_hadb_remove_state(hip_ha_t *ha);
void hip_hadb_remove_state_hit(hip_ha_t *ha);

/* existence */
int hip_hadb_exists_entry(void *key, int type);

/* debugging */
void hip_hadb_dump_hits(void);
void hip_hadb_dump_spis(void);

/*************** CONSTRUCTS ********************/
int hip_hadb_exists_entry(void *arg, int type);

int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr);

int hip_hadb_get_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr, 
				uint32_t *interface_id, uint32_t *lifetime, 
				struct timeval *modified_time);

int hip_hadb_set_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *interface_id, uint32_t *lifetime);

int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t interface_id, uint32_t lifetime);

void hip_hadb_delete_peer_addrlist_one(hip_ha_t *entry, struct in6_addr *addr);

void hip_hadb_delete_peer_addr_if(hip_ha_t *entry, uint32_t interface_id);

void hip_hadb_delete_peer_addr_not_in_list(hip_ha_t *entry, void *addrlist,
					   int n_addrs, uint32_t iface);

void hip_hadb_delete_peer_addrlist(hip_ha_t *entry);

int hip_for_each_ha(int (func)(hip_ha_t *entry, void *opaq), void *opaque);

int hip_hadb_add_peer_info(hip_hit_t *hit, struct in6_addr *addr);

int hip_del_peer_info(struct in6_addr *hit, struct in6_addr *addr);

int hip_hadb_add_peer_spi(hip_ha_t *entry, uint32_t spi);
struct hip_peer_spi_list_item *hip_hadb_get_spi_list(hip_ha_t *entry, uint32_t spi);
int hip_hadb_add_addr_to_spi(hip_ha_t *entry, uint32_t spi, struct in6_addr *addr,
			     int address_state, uint32_t lifetime,
			     int is_preferred_addr);
int hip_hadb_dump_spi_list(hip_ha_t *entry, void *unused);
void hip_hadb_dump_spi_list_all(void);
void hip_hadb_delete_spi_list(hip_ha_t *entry, uint32_t spi);
void hip_hadb_delete_spi_list_all(hip_ha_t *entry);
uint32_t hip_get_default_spi_out(struct in6_addr *hit, int *state_ok);

/***********************************************/
int hip_proc_read_hadb_state(char *page, char **start, off_t off,
			     int count, int *eof, void *data);
int hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
				  int count, int *eof, void *data);
int hip_proc_read_hadb_peer_spi_list(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
/**************** other useful ******************/
void hip_hadb_delete_state(hip_ha_t *ha);
hip_ha_t *hip_hadb_create_state(int gfpmask);
void hip_hadb_deactivate_hs_spi(uint32_t spi);

#define hip_hold_ha(ha) do { \
	atomic_inc(&ha->refcnt); \
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n",ha, atomic_read(&ha->refcnt)); \
} while(0)

#define hip_put_ha(ha) do { \
	if (atomic_dec_and_test(&ha->refcnt)) { \
		hip_hadb_delete_state(ha); \
                HIP_DEBUG("HA: %p deleted\n", ha); \
	} else { \
                _HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha, atomic_read(&ha->refcnt)); \
        } \
} while(0)

#endif /* HIP_HADB_H */
