#ifndef HIP_WORKQUEUE
#define HIP_WORKQUEUE

#include <net/hip.h>
#include <linux/spinlock.h>
#include <net/ipv6.h>

#include "debug.h"

#define HIP_WO_TYPE_INCOMING 1
#define HIP_WO_TYPE_OUTGOING 2
#define HIP_WO_TYPE_MSG      3
#define HIP_MAX_WO_TYPES  3 // this should be equal to the greates type number

/* subtypes from 1 to 100, reserved for HIP_WO_TYPE_INCOMING */
#define HIP_WO_SUBTYPE_RECV_I1      1
#define HIP_WO_SUBTYPE_RECV_R1      2
#define HIP_WO_SUBTYPE_RECV_I2      3
#define HIP_WO_SUBTYPE_RECV_R2      4
#define HIP_WO_SUBTYPE_RECV_UPDATE     5
#define HIP_WO_SUBTYPE_RECV_REA     6
#define HIP_WO_SUBTYPE_RECV_AC      7
#define HIP_WO_SUBTYPE_RECV_ACR     8

/* subtypes from 101 to 200 reserved for HIP_WO_TYPE_OUTGOING */

#define HIP_WO_SUBTYPE_NEW_CONN   101
#define HIP_WO_SUBTYPE_DEL_CONN   102 // reinitialize state to start
#define HIP_WO_SUBTYPE_SKWAIT     103

/* subtypes from 201 to 300 reserved for HIP_WO_TYPE_MSG */

#define HIP_WO_SUBTYPE_STOP       201 // stop kernel thread
#define HIP_WO_SUBTYPE_ADDMAP     202
#define HIP_WO_SUBTYPE_DELMAP     203
#define HIP_WO_SUBTYPE_FLUSHMAPS  204 // flush states
#define HIP_WO_SUBTYPE_ADDHI      205
#define HIP_WO_SUBTYPE_DELHI      206
#define HIP_WO_SUBTYPE_FLUSHHIS   207
#define HIP_WO_SUBTYPE_NEWDH      208 // request new DH-key (implies UPDATE)

extern struct semaphore hip_work;

void hip_stop_khipd(void);
int hip_init_workqueue(void);
void hip_uninit_workqueue(void);
int hip_insert_work_order(struct hip_work_order *hwo);
struct hip_work_order *hip_get_work_order(void);
struct hip_work_order *hip_create_job_with_hit(int mask,
					       const struct in6_addr *hit);
struct hip_work_order *hip_init_job(int mask);

#endif /* HIP_WORKQUEUE */
