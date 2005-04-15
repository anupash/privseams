#ifndef _HIP_DB
#define _HIP_DB

#ifdef __KERNEL__
#  include <linux/list.h>
#  include <linux/spinlock.h>
#  include <net/ipv6.h>
#  include <net/hip.h>
#  include "hip.h"
#else
#  include <sys/socket.h>

typedef struct { } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { }
#endif /* __KERNEL__ */

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
#include "debug.h"
#include "hip.h"
#include "misc.h"
#include "builder.h"
#include "socket.h"
#include "output.h"
#include "update.h"
#include "hidb.h"
#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */

#define HIP_INIT_DB(name,id) \
        struct hip_db_struct name = { LIST_HEAD_INIT(name.db_head), \
        RW_LOCK_UNLOCKED, id, 0}

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

/* should implement with another data structure. 2.6.x will provide
 * ready code, so for now, the linked-list is fine.
 */
struct hip_db_struct {
	struct list_head  db_head;
        rwlock_t          db_lock;
	char *            db_name;
        int               db_cnt;
};

#if !defined __KERNEL__ || defined CONFIG_HIP_USERSPACE
#define HIP_MAX_COOKIE_INFO 10
/* for debugging with in6_ntop */
#define INET6_ADDRSTRLEN 46

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

/*
 * Note: lhit->hit and hid are stored in network byte order.
 */

#define HIP_ARG_HIT                 0x000001
#define HIP_ARG_SPI                 0x000002
#define HIP_HADB_ACCESS_ARGS        (HIP_ARG_HIT | HIP_ARG_SPI)

/* Use these to point your target while accessing a database */
#define HIP_DB_LOCAL_HID   (&hip_local_hostid_db)
#define HIP_DB_PEER_HID    (&hip_peer_hostid_db)

int hip_get_any_localhost_hit(struct in6_addr *target, int algo);
struct hip_host_id *hip_get_any_localhost_public_key(int algo);
struct hip_host_id *hip_get_host_id(struct hip_db_struct *db, 
				    struct hip_lhi *lhi, int algo);
int hip_add_host_id(struct hip_db_struct *db,
		    const struct hip_lhi *lhi,
		    const struct hip_host_id *host_id,
		    int (*insert)(void **arg),		
		    int (*remove)(void **arg),
		    void *arg);
int hip_hit_is_our(struct in6_addr *hit);

void hip_uninit_host_id_dbs(void);

extern struct hip_db_struct hip_peer_hostid_db;
extern struct hip_db_struct hip_local_hostid_db;

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
#endif /* _HIP_DB */
