#ifndef _HIP_DB
#define _HIP_DB

//#include <linux/in6.h>
//#include <linux/socket.h>
//#include <linux/sched.h>
//#include <linux/random.h>

#include <linux/list.h>
#include <linux/spinlock.h>
#include <net/ipv6.h>
#include <net/hip.h>


#include "hip.h"
//#include "debug.h"
//#include "misc.h"
//#include "security.h"
//#include "daemon.h"
//#include "builder.h"
//#include "socket.h"


#define HIP_MAX_COOKIE_INFO 10
/* for debugging with in6_ntop */
#define INET6_ADDRSTRLEN 46

/* should implement with another data structure. 2.6.x will provide
 * ready code, so for now, the linked-list is fine.
 */
struct hip_db_struct {
	struct list_head  db_head;
        rwlock_t          db_lock;
	char *            db_name;
        int               db_cnt;
};

#define HIP_INIT_DB(name,id) \
        struct hip_db_struct name = { LIST_HEAD_INIT(name.db_head), \
        RW_LOCK_UNLOCKED, id, 0}


/*
 * Note: lhit->hit and hid are stored in network byte order.
 */

#define HIP_ARG_HIT                 0x000001
#define HIP_ARG_SPI                 0x000002
#define HIP_HADB_ACCESS_ARGS        (HIP_ARG_HIT | HIP_ARG_SPI)

#define HIP_DB_LOCAL_HID   (&hip_local_hostid_db)
#define HIP_DB_PEER_HID    (&hip_peer_hostid_db)

#if 0
/* HADB functions */
#define hip_hadb_get_birthday_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_BIRTHDAY|HIP_ARG_HIT))
#define hip_hadb_get_esp_tfm_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_ESP_TRANSFORM|HIP_ARG_HIT))
#define hip_hadb_get_own_hit_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_OWN_HIT|HIP_ARG_HIT))
#define hip_hadb_get_own_hmac_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_OWN_HMAC|HIP_ARG_HIT))
#define hip_hadb_get_keymat_index_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_KEYMAT_INDEX|HIP_ARG_HIT))
#define hip_hadb_get_our_new_spi_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_OUR_NEW_SPI|HIP_ARG_HIT))
#define hip_hadb_get_update_id_in_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_OWN_UPDATE_ID_IN|HIP_ARG_HIT))
#define hip_hadb_get_update_id_out_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_OWN_UPDATE_ID_OUT|HIP_ARG_HIT))
#define hip_hadb_get_peer_spi_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_SPI_OUT|HIP_ARG_HIT))
#define hip_hadb_get_peer_new_spi_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_NEW_SPI_OUT|HIP_ARG_HIT))
#define hip_hadb_get_state_by_hit(hit,a) \
            (hip_hadb_get_info(hit,a,HIP_HADB_STATE|HIP_ARG_HIT))


#define hip_hadb_get_spis_by_hit(hit,list,a,b) \
            (hip_hadb_multiget(hit,list,2,a,b,NULL,NULL,HIP_ARG_HIT))
#define hip_hadb_set_lsis_by_hit(hit,list,a,b) \
            (hip_hadb_multiset(hit,list,2,a,b,NULL,NULL,HIP_ARG_HIT))


#define hip_hadb_set_update_id_in_by_hit(hit,list,a) \
            (hip_hadb_multiset(hit,list,1,a,NULL,NULL,NULL,HIP_ARG_HIT))
#define hip_hadb_set_update_id_out_by_hit(hit,list,a) \
            (hip_hadb_multiset(hit,list,1,a,NULL,NULL,NULL,HIP_ARG_HIT))

#endif

#define HIP_READ_LOCK_DB(db) do { \
	KRISU_START_TIMER(KMM_SPINLOCK);\
        read_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_WRITE_LOCK_DB(db) do { \
        KRISU_START_TIMER(KMM_SPINLOCK);\
	write_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_READ_UNLOCK_DB(db) do { \
        KRISU_STOP_TIMER(KMM_SPINLOCK,"read lock "__FUNCTION__);\
	read_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)

#define HIP_WRITE_UNLOCK_DB(db) do { \
	write_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)


struct hip_entry_list {
        struct list_head list;
        struct in6_addr peer_hit;
        /* These two _MUST_ be left untouched. Feel free to add more
         * to the end */
};

struct hip_hadb_multi {
	struct list_head m_head;
	void *           m_arg;
	int              m_type;
};

typedef struct hip_host_id HIP_HID;

#if 0
void hip_hadb_free_kludge(struct in6_addr *hit);
int hip_hadb_flush_states(struct in6_addr *hit);
void hip_hadb_acquire_ex_db_access(unsigned long *flags);
void hip_hadb_release_ex_db_access(unsigned long flags);
void hip_hadb_acquire_db_access(unsigned long *flags);
void hip_hadb_release_db_access(unsigned long flags);
struct hip_hadb_state *hip_hadb_access_db(void *arg, int type);
int hip_hadb_reinitialize_state(void *arg, int type);

struct hip_hadb_multi *hip_hadb_add_multi(struct hip_hadb_multi *target,
					  void *arg, int type, int gfpmask);

int        hip_hadb_add_peer_address(void *, struct in6_addr *, uint32_t, 
				     uint32_t, int);
int        hip_hadb_copy_addr_by_spi(uint32_t, struct in6_addr *, 
				     struct in6_addr *);
int hip_add_peer_info_nolock(struct in6_addr *hit, struct in6_addr *addr);

HIP_STATE *hip_hadb_create_entry(void);
void hip_hadb_delete_peer_addr_iface(void *arg, uint32_t interface_id, int);
void hip_hadb_delete_peer_addr_not_in_list(void *arg, void *addrlist,
					   int n_addrs,
					   uint32_t iface, int type);
void       hip_hadb_delete_peer_address_list(void *arg, int type);
void       hip_hadb_delete_peer_address_list_one(void *,
						 struct in6_addr *, int);
void hip_hadb_destroy_multi(struct hip_hadb_multi *m);
int        hip_hadb_exists_entry(void *arg, int type);
int hip_hadb_get_peer_address_info(void *arg, struct in6_addr *addr, 
				   uint32_t *interface_id, uint32_t *lifetime,
				   struct timeval *modified_time, int type);
int hip_hadb_get_peer_address(void *arg, struct in6_addr *addr, int type);
void       hip_hadb_insert_entry(struct hip_hadb_state *entry);
int hip_hadb_set_peer_address_info(void *arg,struct in6_addr *,
				   uint32_t *interface_id,
				   uint32_t *lifetime,int type);
int hip_del_peer_info(struct in6_addr *hit, struct in6_addr *addr);

int hip_hadb_multiget(void *arg, int amount, int *getlist, void **setlist, int type);
int hip_hadb_get_info(void *arg, void *dst, int type);
int hip_hadb_multiset(void *arg, int amount, int *getlist, void **setlist, int type);
int hip_hadb_set_info(void *arg, void *dst, int type);
int hip_hadb_save_sk(struct in6_addr *hit, struct sock *sk);
void hip_hadb_free_socks(struct in6_addr *arg, int error);

#endif

// host id functions
int hip_get_any_local_hit(struct in6_addr *dst);

int        hip_add_host_id(struct hip_db_struct *db,const struct hip_lhi *lhi,
			   const struct hip_host_id *host_id);
int        hip_add_localhost_id(const struct hip_lhi *lhi,
				const struct hip_host_id *host_id);
int        hip_add_peer_info(struct in6_addr *hit, struct in6_addr *addr);
int        hip_copy_any_localhost_hit(struct in6_addr *target);
HIP_HID   *hip_get_any_localhost_host_id(void);
int        hip_insert_any_localhost_public_key(uint8_t *target);
struct hip_host_id *hip_get_any_localhost_public_key(void);

struct hip_host_id *hip_get_host_id(struct hip_db_struct *db, 
				    struct hip_lhi *lhi);
int        hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
					 int count, int *eof, void *data);
int        hip_proc_read_hadb_state(char *page, char **start, off_t off,
				    int count, int *eof, void *data);
int        hip_proc_read_lhi(char *page, char **start, off_t off,
			     int count, int *eof, void *data);

/* for update packet testing */
int hip_proc_send_update(char *page, char **start, off_t off,
			 int count, int *eof, void *data);
/* for notify packet testing */
int hip_proc_send_notify(char *page, char **start, off_t off,
			 int count, int *eof, void *data);

void       hip_uninit_host_id_dbs(void);
void       hip_uninit_all_eid_db(void);
int hip_db_set_eid(struct sockaddr_eid *eid,
		   const struct hip_lhi *lhi,
		   const struct hip_eid_owner_info *owner_info,
		   int is_local);
int hip_db_set_my_eid(struct sockaddr_eid *eid,
		      const struct hip_lhi *lhi,
		      const struct hip_eid_owner_info *owner_info);
int hip_db_set_peer_eid(struct sockaddr_eid *eid,
			const struct hip_lhi *lhi,
			const struct hip_eid_owner_info *owner_info);
int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info,
			  int is_local);
int hip_db_get_peer_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			       struct hip_eid_owner_info *owner_info);
int hip_db_get_my_lhi_by_eid(const struct sockaddr_eid *eid,
			     struct hip_lhi *lhi,
			     struct hip_eid_owner_info *owner_info);
void hip_ifindex2spi_map_add(hip_ha_t *entry, uint32_t spi, int ifindex);
void hip_ifindex2spi_map_del(hip_ha_t *entry, uint32_t spi);
void hip_ifindex2spi_map_delete_all(hip_ha_t *entry);
uint32_t hip_ifindex2spi_get_spi(hip_ha_t *entry, int ifindex);
int hip_ifindex2spi_get_ifindex(hip_ha_t *entry, uint32_t spi);
uint32_t hip_update_get_prev_spi_in(hip_ha_t *entry, uint32_t prev_spi_out);
uint32_t hip_get_spi_to_update(hip_ha_t *entry);
uint32_t hip_get_spi_to_update_in_established(hip_ha_t *entry, struct in6_addr *dev_addr);
void hip_set_spi_update_status(hip_ha_t *entry, uint32_t spi, int set);
void hip_update_set_new_spi(hip_ha_t *entry, uint32_t spi, uint32_t new_spi, uint32_t spi_out);
uint32_t hip_update_get_new_spi(hip_ha_t *entry, uint32_t spi);
void hip_update_set_status(hip_ha_t *entry, uint32_t spi, int direction, int set_flags,
			   uint32_t update_id, int update_flags, struct hip_nes *nes);
int hip_update_exists_spi(hip_ha_t *entry, uint32_t spi,
			  int direction, int test_new_spi);

extern struct hip_db_struct hip_peer_hostid_db;
extern struct hip_db_struct hip_local_hostid_db;

#endif /* _HIP_DB */
