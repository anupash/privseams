#ifndef _HIP_DB
#define _HIP_DB

#ifdef __KERNEL__
#  include <linux/list.h>
#  include <linux/spinlock.h>
#  include <net/ipv6.h>
#  include <net/hip.h>
#  include "hip.h"
#else

typedef struct { } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { }

#endif /* __KERNEL__ */

#include "debug.h"
#include "hip.h"
#include "misc.h"
#include "builder.h"
#include "socket.h"
#include "output.h"
#include "update.h"
#include "hidb.h"

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

#define HIP_READ_LOCK_DB(db) do { \
	HIP_START_TIMER(KMM_SPINLOCK);\
        read_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_WRITE_LOCK_DB(db) do { \
        HIP_START_TIMER(KMM_SPINLOCK);\
	write_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_READ_UNLOCK_DB(db) do { \
        HIP_STOP_TIMER(KMM_SPINLOCK,"read lock "__FUNCTION__);\
	read_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)

#define HIP_WRITE_UNLOCK_DB(db) do { \
	write_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)


typedef struct hip_host_id HIP_HID;

// host id functions
int hip_get_any_local_hit(struct in6_addr *dst, uint8_t algo);
int        hip_add_host_id(struct hip_db_struct *db,const struct hip_lhi *lhi,
			   const struct hip_host_id *host_id);
int        hip_add_localhost_id(const struct hip_lhi *lhi,
				const struct hip_host_id *host_id);
int        hip_add_peer_info(struct in6_addr *hit, struct in6_addr *addr);
int        hip_copy_any_localhost_hit(struct in6_addr *target);
int        hip_copy_any_localhost_hit_by_algo(struct in6_addr *target, int algo);
struct hip_host_id *hip_get_any_localhost_host_id(int);
int        hip_insert_any_localhost_public_key(uint8_t *target);
struct hip_host_id *hip_get_any_localhost_public_key(int);
int hip_hit_is_our(struct in6_addr *hit);
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

extern struct hip_db_struct hip_peer_hostid_db;
extern struct hip_db_struct hip_local_hostid_db;

#endif /* _HIP_DB */
