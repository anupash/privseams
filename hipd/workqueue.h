#ifndef HIP_WORKQUEUE
#define HIP_WORKQUEUE

#include "hip.h"

#  include <stdio.h>
#  include "list.h"
#  include <asm/byteorder.h>

/* Remove when not necessary, taken from linux/ipv6.h */
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8                    priority:4,
                                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8                    version:4,
                                priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8                    flow_lbl[3];

        __u16                   payload_len;
        __u8                    nexthdr;
        __u8                    hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};

#define HIP_INIT_WORK_ORDER_HDR(work_order_hdr, hwo_type, hwo_subtype, hwo_id1, hwo_id2, hwo_id3, hwo_arg1, hwo_arg2, hwo_arg3) \
	do { \
                memset(&work_order_hdr, 0, sizeof(struct hip_work_order_hdr)); \
		work_order_hdr.type = hwo_type; \
		work_order_hdr.subtype = hwo_subtype; \
		if (hwo_id1) ipv6_addr_copy(&work_order_hdr.id1, hwo_id1); \
		if (hwo_id2) ipv6_addr_copy(&work_order_hdr.id2, hwo_id2); \
		if (hwo_id3) ipv6_addr_copy(&work_order_hdr.id3, hwo_id3); \
		work_order_hdr.arg1 = hwo_arg1; \
		work_order_hdr.arg2 = hwo_arg2; \
		work_order_hdr.arg3 = hwo_arg3; \
		} while(0)

#include <net/hip.h>
#include "debug.h"
#include "timer.h"
#include "hip.h"
#include "bos.h"

#define HIP_WO_TYPE_INCOMING 1
#define HIP_WO_TYPE_OUTGOING 2
#define HIP_WO_TYPE_MSG      3
#define HIP_MAX_WO_TYPES  3 // this should be equal to the greates type number

/* subtypes from 1 to 100, reserved for HIP_WO_TYPE_INCOMING */
#define HIP_WO_SUBTYPE_RECV_CONTROL     1

/* subtypes from 101 to 200 reserved for HIP_WO_TYPE_OUTGOING */
#define HIP_WO_SUBTYPE_SEND_I1     101

#define HIP_WO_SUBTYPE_NEW_CONN    101
#define HIP_WO_SUBTYPE_DEL_CONN    102 // reinitialize state to start
#define HIP_WO_SUBTYPE_SKWAIT      103
#define HIP_WO_SUBTYPE_SEND_PACKET 104
#define HIP_WO_SUBTYPE_ACQSPI      105
#define HIP_WO_SUBTYPE_DELSA       106
//#define HIP_WO_SUBTYPE_FINSA       107
//#define HIP_WO_SUBTYPE_XFRM_INIT   108
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
#define HIP_WO_SUBTYPE_SEND_BOS   212 // sending BOS packet
#define HIP_WO_SUBTYPE_SEND_CLOSE 213

int hip_init_workqueue(void);
void hip_uninit_workqueue(void);
int hip_insert_work_order(struct hip_work_order *hwo);
int hip_insert_work_order_cpu(struct hip_work_order *hwo, int cpu);
struct hip_work_order *hip_get_work_order(void);
struct hip_work_order *hip_init_job(int mask);
void hip_free_work_order(struct hip_work_order *hwo);
int hip_do_work(struct hip_work_order *job);

#endif /* HIP_WORKQUEUE */
