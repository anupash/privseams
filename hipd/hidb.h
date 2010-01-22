#ifndef _HIP_DB
#define _HIP_DB

#include <asm/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include "lib/core/kerncompat.h"
#include "lib/core/list.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "cookie.h"

#if 0
#define HIP_READ_LOCK_DB(db) do { \
        read_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_WRITE_LOCK_DB(db) do { \
	write_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_READ_UNLOCK_DB(db) do { \
	read_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)

#define HIP_WRITE_UNLOCK_DB(db) do { \
	write_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)
#else
#define HIP_READ_LOCK_DB(db)
#define HIP_WRITE_LOCK_DB(db)
#define HIP_READ_UNLOCK_DB(db)
#define HIP_WRITE_UNLOCK_DB(db)
#endif

typedef  HIP_HASHTABLE hip_db_struct_t;

#define HIP_MAX_COOKIE_INFO 10
/* for debugging with in6_ntop */
#define INET6_ADDRSTRLEN 46

struct hip_entry_list {
	hip_list_t list;
	struct in6_addr peer_hit;
	/* These two _MUST_ be left untouched. Feel free to add more
	 * to the end */
};

/* Use this to point your target while accessing a database */
#define HIP_DB_LOCAL_HID   (hip_local_hostid_db)

/* ... and not this! */
extern hip_db_struct_t *hip_local_hostid_db;

struct hip_host_id_entry *hip_get_hostid_entry_by_lhi_and_algo(hip_db_struct_t *db,
							       const struct in6_addr *hit,
							       int algo, int anon);
int hip_get_any_localhost_hit(struct in6_addr *target, int algo, int anon);
int hip_get_host_id_and_priv_key(hip_db_struct_t *db, struct in6_addr *hit,
                        int algo, struct hip_host_id **host_id, void **key);
int hip_hit_is_our(struct in6_addr *hit);

void hip_uninit_host_id_dbs(void);

int hip_handle_add_local_hi(const struct hip_common *input);

int hip_handle_del_local_hi(const struct hip_common *input);
int hip_for_each_hi(int (*func)(struct hip_host_id_entry *entry, void *opaq), void *opaque);

int hip_build_host_id_and_signature(struct hip_common *msg,  hip_hit_t *hit);
/*lsi support*/
int hip_hidb_exists_lsi(hip_lsi_t *lsi);
int hip_hidb_associate_default_hit_lsi(hip_hit_t *default_hit, hip_lsi_t *default_lsi);
int hip_hidb_get_lsi_by_hit(const hip_hit_t *our, hip_lsi_t *our_lsi);

/* existence */
int hip_hidb_hit_is_our(const hip_hit_t *src);

unsigned long hip_hidb_hash(const void *ptr);
int hip_hidb_match(const void *ptr1, const void *ptr2);
void hip_init_hostid_db(hip_db_struct_t **db);
int hip_for_all_hi(int (*func)(struct hip_host_id_entry *entry, void *opaq), void *opaque);

#endif /* _HIP_DB */
