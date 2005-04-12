#ifndef HIP_WORKQUEUE
#define HIP_WORKQUEUE

#ifdef __KERNEL__
#  include <asm/semaphore.h>
#  include <asm/percpu.h>
#  include <asm/system.h>
#  include <linux/list.h>
#  include <linux/interrupt.h>
#  include <net/ipv6.h>
#  include <net/hip.h>
#else
#  include <stdio.h>

#define HIP_INIT_WORK_ORDER_HDR(work_order_hdr, hwo_type, hwo_subtype, hwo_src, hwo_dst, hwo_arg1, hwo_arg2) \
	do { \
		work_order_hdr.type = hwo_type; \
		work_order_hdr.subtype = hwo_subtype; \
		if (hwo_dst) ipv6_addr_copy(&work_order_hdr.dst_addr, hwo_dst); \
		if (hwo_src) ipv6_addr_copy(&work_order_hdr.src_addr, hwo_src); \
		work_order_hdr.arg1 = hwo_arg1; \
		work_order_hdr.arg2 = hwo_arg2; \
		} while(0)

#endif

#include "timer.h"
#include "netlink.h" /* hip_netlink_* functions */
#include "debug.h"
#include "builder.h"
#include "misc.h"
//#include "beet.h"

#define HIP_WO_TYPE_INCOMING 1
#define HIP_WO_TYPE_OUTGOING 2
#define HIP_WO_TYPE_MSG      3
#define HIP_MAX_WO_TYPES  3 // this should be equal to the greates type number

/* subtypes from 1 to 100, reserved for HIP_WO_TYPE_INCOMING */
#define HIP_WO_SUBTYPE_RECV_I1     1
#define HIP_WO_SUBTYPE_RECV_R1     2
#define HIP_WO_SUBTYPE_RECV_I2     3
#define HIP_WO_SUBTYPE_RECV_R2     4
#define HIP_WO_SUBTYPE_RECV_UPDATE 5
#define HIP_WO_SUBTYPE_RECV_NOTIFY 6
#define HIP_WO_SUBTYPE_RECV_BOS    7

/* subtypes from 101 to 200 reserved for HIP_WO_TYPE_OUTGOING */

#define HIP_WO_SUBTYPE_NEW_CONN    101
#define HIP_WO_SUBTYPE_DEL_CONN    102 // reinitialize state to start
#define HIP_WO_SUBTYPE_SKWAIT      103
#define HIP_WO_SUBTYPE_SEND_PACKET 104
#define HIP_WO_SUBTYPE_ACQSPI      105
#define HIP_WO_SUBTYPE_DELSA       106
#define HIP_WO_SUBTYPE_FINSA       107
#define HIP_WO_SUBTYPE_XFRM_INIT   108
#define HIP_WO_SUBTYPE_XFRM_DEL    109
#define HIP_WO_SUBTYPE_XFRM_UPD    110
#define HIP_WO_SUBTYPE_ADDSA       111
#define HIP_WO_SUBTYPE_PING        112


/* subtypes from 201 to 300 reserved for HIP_WO_TYPE_MSG */

#define HIP_WO_SUBTYPE_ADDMAP     202
#define HIP_WO_SUBTYPE_DELMAP     203
#define HIP_WO_SUBTYPE_FLUSHMAPS  204 // flush states
#define HIP_WO_SUBTYPE_ADDHI      205
#define HIP_WO_SUBTYPE_DELHI      206
#define HIP_WO_SUBTYPE_FLUSHHIS   207
#define HIP_WO_SUBTYPE_NEWDH      208 // request new DH-key (implies UPDATE)
#define HIP_WO_SUBTYPE_IN6_EVENT  209
#define HIP_WO_SUBTYPE_DEV_EVENT  210
#define HIP_WO_SUBTYPE_ADDRVS     211

void hwo_default_destructor(struct hip_work_order *hwo);
int hip_init_workqueue(void);
void hip_uninit_workqueue(void);
int hip_insert_work_order(struct hip_work_order *hwo);
int hip_insert_work_order_cpu(struct hip_work_order *hwo, int cpu);
struct hip_work_order *hip_get_work_order(void);
struct hip_work_order *hip_init_job(int mask);
void hip_free_work_order(struct hip_work_order *hwo);
int hip_do_work(struct hip_work_order *job);

#endif /* HIP_WORKQUEUE */
