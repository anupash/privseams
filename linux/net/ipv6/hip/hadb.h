#ifndef HIP_HADB_H
#define HIP_HADB_H
#include <net/hip.h>
#include "debug.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"
#include "builder.h"

#ifdef __KERNEL__
#define HIP_LOCK_INIT(ha) do { spin_lock_init(&ha->lock); } while(0)
#define HIP_LOCK_HA(ha) do { spin_lock_bh(&ha->lock); } while(0)
#define HIP_UNLOCK_HA(ha) do { spin_unlock_bh(&ha->lock); } while(0)
#define HIP_LOCK_HS(hs) do { spin_lock_bh(&hs->lock); } while(0)
#define HIP_UNLOCK_HS(hs) do { spin_unlock_bh(&hs->lock); } while(0)
#define HIP_LOCK_XF(xf) do { spin_lock_bh(&xf->lock); } while(0)
#define HIP_UNLOCK_XF(xf) do { spin_unlock_bh(&xf->lock); } while(0)
#else
#include "netdev.h"

#define HIP_LOCK_INIT(ha)
#define HIP_LOCK_HA(ha) 
#define HIP_UNLOCK_HA(ha)
#define HIP_LOCK_HS(hs) 
#define HIP_UNLOCK_HS(hs)

#define do_gettimeofday(x) gettimeofday(x, NULL)
#endif /* __KERNEL__ */

#define HIP_HADB_SIZE 53
#define HIP_MAX_HAS 100

#define HIP_DB_HOLD_ENTRY(entry, entry_type)                  \
    do {                                                      \
        entry_type *ha = (entry_type *)entry;                 \
	if (!entry)                                           \
		return;                                       \
	atomic_inc(&ha->refcnt);                              \
	HIP_DEBUG("HA: %p, refcnt incremented to: %d\n", ha, \
		   atomic_read(&ha->refcnt));                 \
    } while(0)

#define HIP_DB_PUT_ENTRY(entry, entry_type, destructor)                      \
    do {                                                                     \
	entry_type *ha = (entry_type *)entry;                                \
	if (!entry)                                                          \
		return;                                                      \
	if (atomic_dec_and_test(&ha->refcnt)) {                              \
                HIP_DEBUG("HA: refcnt decremented to 0, deleting %p\n", ha); \
		destructor(ha);                                              \
                HIP_DEBUG("HA: %p deleted\n", ha);                           \
	} else {                                                             \
                HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha,        \
			   atomic_read(&ha->refcnt));                        \
        }                                                                    \
    } while(0);

#define HIP_DB_GET_KEY_HIT(entry, entry_type) \
            (void *)&(((entry_type *)entry)->hit_peer);

#define hip_hold_ha(ha) do { \
	atomic_inc(&ha->refcnt); \
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n",ha, atomic_read(&ha->refcnt)); \
} while(0)

#define HIP_INSERT_STATE_SPI_LIST(hashtable, put_hs, hit_peer, hit_our, spi) \
  do {                                                                       \
	struct hip_hit_spi *tmp;                                             \
	hip_hit_t hit_p, hit_o;                                              \
	struct hip_hit_spi *new_item;                                        \
	/* assume already locked entry */                                    \
	ipv6_addr_copy(&hit_p, hit_peer);                                    \
	ipv6_addr_copy(&hit_o, hit_our);                                     \
	tmp = hip_ht_find(hashtable, (void *)spi);                           \
	if (tmp) {                                                           \
		put_hs(tmp);                                                 \
		HIP_ERROR("BUG, SPI already inserted\n");                    \
		err = -EEXIST;                                               \
		break;                                                       \
	}                                                                    \
	new_item = (struct hip_hit_spi *)                                    \
           HIP_MALLOC(sizeof(struct hip_hit_spi), GFP_ATOMIC);               \
	if (!new_item) {                                                     \
		HIP_ERROR("new_item HIP_MALLOC failed\n");                   \
		err = -ENOMEM;                                               \
		break;                                                       \
	}                                                                    \
	atomic_set(&new_item->refcnt, 0);                                    \
	HIP_LOCK_INIT(new_item);                                             \
	new_item->spi = spi;                                                 \
	ipv6_addr_copy(&new_item->hit_peer, &hit_p);                         \
	ipv6_addr_copy(&new_item->hit_our, &hit_o);                          \
	hip_ht_add(hashtable, new_item);                                     \
	_HIP_DEBUG("SPI 0x%x added to HT spi_list, HS=%p\n", spi, new_item); \
  } while (0)

#define hip_db_put_ha(ha, destructor) do { \
	if (atomic_dec_and_test(&ha->refcnt)) { \
                HIP_DEBUG("HA: deleting %p\n", ha); \
		destructor(ha); \
                HIP_DEBUG("HA: %p deleted\n", ha); \
	} else { \
                HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha, \
                           atomic_read(&ha->refcnt)); \
        } \
} while(0)

#define hip_put_ha(ha) hip_db_put_ha(ha, hip_hadb_delete_state)

/*************** BASE FUNCTIONS *******************/

/* Matching */
static inline int hip_hadb_match_spi(const void *key_1, const void *key_2)
{
	return (uint32_t)key_1 == (uint32_t)key_2;
}

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
/* Initialization functions */
void hip_init_hadb(void);
void hip_uninit_hadb(void);

/* Accessors */
//hip_ha_t *hip_hadb_find_byhit(hip_hit_t *hit);
hip_ha_t *hip_hadb_find_byspi_list(uint32_t spi);
hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2);
hip_ha_t *hip_hadb_try_to_find_by_peer_hit(hip_hit_t *hit);

/* insert/create/delete */
int hip_hadb_insert_state(hip_ha_t *ha);
int hip_hadb_insert_state_spi_list(hip_hit_t *peer_hit, hip_hit_t *our_hit,
				   uint32_t spi);
int hip_init_peer(hip_ha_t *entry, struct hip_common *msg, 
		     struct hip_host_id *peer);
int hip_init_us(hip_ha_t *entry, struct in6_addr *our_hit);

/* existence */
int hip_hadb_hit_is_our(const hip_hit_t *src);

/* debugging */
void hip_hadb_dump_hits(void);
void hip_hadb_dump_spis(void);

/*************** CONSTRUCTS ********************/
int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr);

int hip_hadb_get_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr, 
				uint32_t *spi, uint32_t *lifetime,
				struct timeval *modified_time);

int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t interface_id, uint32_t lifetime,
			   int state);

void hip_hadb_delete_peer_addrlist_one(hip_ha_t *entry, struct in6_addr *addr);



/* Useless? */
int hip_hadb_add_peer_info(hip_hit_t *hit, struct in6_addr *addr);

int hip_del_peer_info(struct in6_addr *hit, struct in6_addr *addr);

int hip_hadb_add_spi(hip_ha_t *entry, int direction, void *data);

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
int hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				 struct hip_context *ctx, int is_initiator);
/* Utilities */

hip_ha_t *hip_hadb_create_state(int gfpmask);
void hip_hadb_deactivate_hs_spi(uint32_t spi);

void hip_hadb_dump_spis_in(hip_ha_t *entry);
void hip_hadb_dump_spis_out(hip_ha_t *entry);
void hip_hadb_dump_hs_ht(void);

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */

typedef struct hip_peer_addr_opaque {
        struct in6_addr addr;
        struct hip_peer_addr_opaque *next;
} hip_peer_addr_opaque_t;         /* Structure to record peer addresses */

typedef struct hip_peer_entry_opaque {
	unsigned int count;
        struct hip_host_id *host_id;
	hip_hit_t hit;
        hip_peer_addr_opaque_t *addr_list;
        struct hip_peer_entry_opaque *next;
} hip_peer_entry_opaque_t;         /* Structure to record kernel peer entry */

typedef struct hip_peer_opaque {
	unsigned int count;
        struct hip_peer_entry_opaque *head;
        struct hip_peer_entry_opaque *end;
} hip_peer_opaque_t;         /* Structure to record kernel peer list */

void hip_hadb_remove_hs(uint32_t spi);

void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi);
void hip_hadb_delete_outbound_spi(hip_ha_t *entry, uint32_t spi);

void hip_hadb_delete_state(hip_ha_t *ha);
int hip_for_each_ha(int (func)(hip_ha_t *entry, void *opaq), void *opaque);

int hip_list_peers_add(struct in6_addr *address,
		       hip_peer_entry_opaque_t *entry,
		       hip_peer_addr_opaque_t **last);

int hip_hadb_list_peers_func(hip_ha_t *entry, void *opaque);


#endif /* HIP_HADB_H */
