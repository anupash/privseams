#ifndef HIP_HADB_H
#define HIP_HADB_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "keymat.h"
#include "lib/tool/pk.h"
#include "lib/core/debug.h"
#include "lib/core/misc.h"
#include "hidb.h"
#include "lib/core/hashtable.h"
#include "lib/core/state.h"
#include "lib/core/builder.h"
#include "input.h" 	// required for declaration of receive functions
#include "update.h"	// required for declaration of update function
#include "user_ipsec_sadb_api.h"
#include "lib/tool/xfrmapi.h"
#include "nat.h"
#include "hadb_legacy.h"

#ifdef CONFIG_HIP_BLIND
#include "blind.h"
#endif

#define HIP_LOCK_INIT(ha)
#define HIP_LOCK_HA(ha) 
#define HIP_UNLOCK_HA(ha)

#define do_gettimeofday(x) gettimeofday(x, NULL)

#if 0
#define HIP_DB_HOLD_ENTRY(entry, entry_type)                  \
    do {                                                      \
        entry_type *ha = (entry_type *)entry;                 \
	if (!entry)                                           \
		return;                                       \
	atomic_inc(&ha->refcnt);                              \
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n", ha,  \
		   atomic_read(&ha->refcnt));                 \
    } while(0)

#define HIP_DB_GET_KEY_HIT(entry, entry_type) \
            (void *)&(((entry_type *)entry)->hit_peer);

#define hip_hold_ha(ha) do { \
	atomic_inc(&ha->refcnt); \
	_HIP_DEBUG("HA: %p, refcnt incremented to: %d\n",ha, atomic_read(&ha->refcnt)); \
} while(0)

#define HIP_DB_PUT_ENTRY(entry, entry_type, destructor)                      \
    do {                                                                     \
	entry_type *ha = (entry_type *)entry;                                \
	if (!entry)                                                          \
		return;                                                      \
	if (atomic_dec_and_test(&ha->refcnt)) {                              \
                _HIP_DEBUG("HA: refcnt decremented to 0, deleting %p\n", ha); \
		destructor(ha);                                              \
                _HIP_DEBUG("HA: %p deleted\n", ha);                           \
	} else {                                                             \
                _HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha,        \
			   atomic_read(&ha->refcnt));                        \
        }                                                                    \
    } while(0);

#define hip_db_put_ha(ha, destructor) do { \
	if (atomic_dec_and_test(&ha->refcnt)) { \
                HIP_DEBUG("HA: deleting %p\n", ha); \
		destructor(ha); \
                HIP_DEBUG("HA: %p deleted\n", ha); \
	} else { \
                _HIP_DEBUG("HA: %p, refcnt decremented to: %d\n", ha, \
                           atomic_read(&ha->refcnt)); \
        } \
} while(0)

#define hip_put_ha(ha) hip_db_put_ha(ha, hip_hadb_delete_state)

#endif

#define HIP_DB_HOLD_ENTRY(entry, entry_type)  do {} while(0)
#define HIP_DB_GET_KEY_HIT(entry, entry_type)  do {} while(0)
#define hip_hold_ha(ha)  do {} while(0)
#define HIP_DB_PUT_ENTRY(entry, entry_type, destructor)  do {} while(0)
#define hip_put_ha(ha) do {} while(0)
#define hip_db_put_ha(ha, destructor)  do {} while(0)


#ifdef CONFIG_HIP_BLIND
extern int hip_blind_status;
#endif

/* For switch userspace / kernel IPsec */
extern int hip_use_userspace_ipsec;

extern hip_xmit_func_set_t nat_xmit_func_set;

void hip_hadb_hold_entry(void *entry);

/*************** BASE FUNCTIONS *******************/

/* Matching */
static inline int hip_hadb_match_spi(const void *key_1, const void *key_2)
{
	return (* (const u32 *) key_1 == * (const u32 *) key_2);
}

int hip_ha_compare(const hip_ha_t *ha1, const hip_ha_t *ha2);

void hip_init_hadb(void);
void hip_uninit_hadb(void);

void hip_delete_all_sp(void);

/* Initialization functions */

/* Accessors */
hip_ha_t *hip_hadb_find_byhits(const hip_hit_t *hit, const hip_hit_t *hit2);
hip_ha_t *hip_hadb_try_to_find_by_peer_hit(const hip_hit_t *hit);

/* insert/create/delete */
void hip_hadb_delete_state(hip_ha_t *ha);
int hip_hadb_insert_state(hip_ha_t *ha);
void hip_delete_security_associations_and_sp(struct hip_hadb_state *ha);
int hip_init_peer(hip_ha_t *entry, struct hip_common *msg, 
		     struct hip_host_id *peer);
int hip_init_us(hip_ha_t *entry, hip_hit_t *hit_our);


/*************** CONSTRUCTS ********************/
int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr);

int hip_hadb_add_peer_addr(hip_ha_t *entry, const struct in6_addr *new_addr,
			   uint32_t interface_id, uint32_t lifetime,
			   int state, in_port_t port);

int hip_add_peer_map(const struct hip_common *input);

int hip_hadb_add_peer_info(hip_hit_t *hit, struct in6_addr *addr, hip_lsi_t *peer_lsi,
			   const char *peer_hostname);

int hip_hadb_add_peer_info_complete(const hip_hit_t *local_hit,
				    const hip_hit_t *peer_hit,
				    const hip_lsi_t *peer_lsi,
				    const struct in6_addr *local_addr,
				    const struct in6_addr *peer_addr,
				    const char *peer_hostname);

int hip_del_peer_info_entry(hip_ha_t *ha);
int hip_del_peer_info(hip_hit_t *, hip_hit_t *);

void hip_hadb_set_spi_ifindex(hip_ha_t *entry, uint32_t spi, int ifindex);
int hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				 struct hip_context *ctx, int is_initiator);
/* Utilities */

hip_ha_t *hip_hadb_create_state(int gfpmask);

#if 0
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
#endif

int hip_for_each_ha(int (func)(hip_ha_t *entry, void *opaq), void *opaque);

// next 2 functions are not called from outside but make sense and are 'proposed' in libhipcore/state.h
int hip_hadb_set_rcv_function_set(hip_ha_t *entry,
				   hip_rcv_func_set_t *new_func_set);
int hip_hadb_set_handle_function_set(hip_ha_t *entry,
				   hip_handle_func_set_t *new_func_set);

int hip_hadb_set_xmit_function_set(hip_ha_t * entry,
				   hip_xmit_func_set_t * new_func_set);

void hip_hadb_set_local_controls(hip_ha_t *entry, hip_controls_t mask);
void hip_hadb_set_peer_controls(hip_ha_t *entry, hip_controls_t mask);
void hip_hadb_cancel_local_controls(hip_ha_t *entry, hip_controls_t mask);

void hip_remove_addresses_to_send_echo_request(hip_ha_t *ha);

int hip_count_open_connections(void);

hip_ha_t *hip_hadb_find_rvs_candidate_entry(hip_hit_t *, hip_hit_t *);
hip_ha_t *hip_hadb_find_by_blind_hits(hip_hit_t *local_blind_hit,
				      hip_hit_t *peer_blind_hit);

int hip_handle_get_ha_info(hip_ha_t *entry, void *);
int hip_hadb_map_ip_to_hit(hip_ha_t *entry, void *id2);

/*lsi support functions*/
int hip_generate_peer_lsi(hip_lsi_t *lsi);
hip_ha_t *hip_hadb_try_to_find_by_peer_lsi(hip_lsi_t *lsi);
hip_ha_t *hip_hadb_try_to_find_by_pair_lsi(hip_lsi_t *lsi_src, hip_lsi_t *lsi_dst);
int hip_get_local_addr(struct hip_common *msg);

int hip_recreate_security_associations_and_sp(struct hip_hadb_state *ha, in6_addr_t *src_addr,
        in6_addr_t *dst_addr);

hip_rcv_func_set_t *hip_get_rcv_default_func_set(void);
hip_handle_func_set_t *hip_get_handle_default_func_set(void);

#endif /* HIP_HADB_H */
