#ifndef HIP_DAEMON_H
#define HIP_DAEMON_H

#include <net/hip.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/in6.h>

#include "unit.h"
#include "db.h"
#include "debug.h"
#include "ioctl.h"
#include "daemon.h"

#ifndef __KERNEL__
#  define __KERNEL__
#endif

#ifndef MODULE
#  define MODULE
#endif

#define HIPD_MSG_EXCHANGE_QUEUE_MAX 64

#define HIPD_AUTO_SETUP_STATE_NULL       0
#define HIPD_AUTO_SETUP_STATE_RUNNING    1
#define HIPD_AUTO_SETUP_STATE_FINISHED   2

/* Used for storing both host ids from peer and host ids of localhost */
struct hip_host_id_info {
        spinlock_t lock;                   /* irq save */
        struct hip_host_id_entry entry[HIP_HOST_ID_MAX];
};

int hip_init_user(void);
void hip_uninit_user(void);
int hip_user_handle_add_local_hi(const struct hip_common *input,
				 struct hip_common *output);
int hip_user_handle_del_local_hi(const struct hip_common *input,
				 struct hip_common *output);
int hip_user_handle_add_peer_map_hit_ip(const struct hip_common *input,
					struct hip_common *output);
int hip_user_handle_del_peer_map_hit_ip(const struct hip_common *input,
					struct hip_common *output);
int hip_user_handle_unit_test(const struct hip_common *input,
			      struct hip_common *output);
int hip_user_handle_rst(const struct hip_common *input,
			struct hip_common *output);
int hip_user_handle_set_my_eid(const struct hip_common *input,
			       struct hip_common *output);
int hip_user_handle_set_peer_eid(const struct hip_common *input,
				 struct hip_common *output);
#endif /* HIP_DAEMON_H */
