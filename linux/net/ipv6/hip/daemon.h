#ifndef HIP_DAEMON_H
#define HIP_DAEMON_H

#include <net/hip.h>
#include <linux/hip_ioctl.h>
#include <linux/skbuff.h>
#include <linux/list.h>

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

int hipd_init(void);
void hipd_uninit(void);
int hip_init_daemon(void);
void hip_uninit_daemon(void);
int hipd_handle_async_add_hi(const struct hip_common *msg);
int hipd_handle_async_del_hi(const struct hip_common *msg);
int hipd_handle_async_add_map_hit_ip(const struct hip_common *msg);
int hipd_handle_async_del_map_hit_ip(const struct hip_common *msg);
int hipd_handle_async_unit_test(const struct hip_common *msg);
int hipd_handle_async_rst(const struct hip_common *msg);

#endif /* HIP_DAEMON_H */
