#ifndef EID_DB_H
#define EID_DB_H

#include <linux/list.h>
#include <linux/spinlock.h>

#include "builder.h"
#include "hidb.h"
#include "misc.h"
#include "timer.h"

struct hip_eid_owner_info {
	uid_t            uid;
	gid_t            gid;
	pid_t            pid;
	se_hip_flags_t   flags;  /* HIP_HI_REUSE_* */
};

struct hip_eid_db_entry {
	struct list_head           next;
	struct hip_eid_owner_info  owner_info;
	struct sockaddr_eid        eid; /* XX FIXME: the port is unneeded */
	struct hip_lhi             lhi;
	int                        use_cnt;
};

int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
                          struct hip_lhi *lhi,
                          struct hip_eid_owner_info *owner_info,
                          int is_local);

int hip_db_set_eid(struct sockaddr_eid *eid,
                   const struct hip_lhi *lhi,
                   const struct hip_eid_owner_info *owner_info,
                   int is_local);

int hip_socket_handle_set_my_eid(struct hip_common *msg);
int hip_socket_handle_set_peer_eid(struct hip_common *msg);

#endif /* EID_DB_H */
