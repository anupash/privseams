#ifndef HIP_HIP_H
#define HIP_HIP_H

#include <linux/spinlock.h>
#include <linux/crypto.h>
#include <linux/hip_ioctl.h>
#include <net/hip_glue.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <net/hip.h>

#include "../../key/pfkey_v2_msg.h"
#include "workqueue.h"
#include "daemon.h"
#include "debug.h"
#include "cookie.h"
#include "input.h"
#include "output.h"
#include "ioctl.h"
#include "builder.h"
#include "crypto/dh.h"
#include "crypto/dsa.h"

/*
#ifndef __KERNEL__
#  define __KERNEL__
#endif

#ifndef MODULE
#  define MODULE
#endif
*/

#ifdef KRISUS_THESIS

extern int kmm; // hip.c
extern struct timeval gtv_start, gtv_stop, gtv_result;
extern int gtv_inuse;

#define KMM_GLOBAL 1
#define KMM_PARTIAL 2
#define KMM_SPINLOCK 3

#define KRISU_START_TIMER(mod) do {\
   if (mod == kmm) {\
      gtv_inuse = 1;\
      do_gettimeofday(&gtv_start);\
   }\
 } while(0)

#define KRISU_STOP_TIMER(mod,msg) do {\
   if (mod == kmm) {\
      do_gettimeofday(&gtv_stop);\
      gtv_inuse = 0;\
      hip_timeval_diff(&gtv_start,&gtv_stop,&gtv_result);\
      HIP_INFO("%s: %ld usec\n", msg, \
               gtv_result.tv_usec + gtv_result.tv_sec * 1000000);\
   }\
 } while(0)

#else

#define KRISU_START_TIMER(x)
#define KRISU_STOP_TIMER(x,y)

#endif /* KRISUS_THESIS */

/* used by hip worker to announce completion of work order */
#define KHIPD_OK                   0
#define KHIPD_QUIT                -1
#define KHIPD_ERROR               -2
#define KHIPD_UNRECOVERABLE_ERROR -3

uint16_t hip_get_dh_size(uint8_t hip_dh_group_type);
struct hip_common *hip_create_r1(struct in6_addr *src_hit);
int hip_build_digest(const int type, const void *in, int in_len, void *out);
hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_auth_key_length_esp(int tid);
int hip_transform_key_length(int tid);
void hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				  struct hip_context *ctx, int is_initiator);
int hip_hmac_key_length(int tid);
int hip_enc_key_length(int tid);
int hip_crypto_encrypted(void *, void *, int, int, void*, int);
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd);
uint64_t hip_get_current_birthday(void);
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);

extern DH *dh_table[HIP_MAX_DH_GROUP_ID];  // see crypto/dh.[ch]
extern struct cipher_implementation *impl_null;
extern struct cipher_implementation *impl_dsa;
extern struct cipher_implementation *impl_dh;
extern struct digest_implementation *impl_sha1;
extern struct list_head hip_sent_rea_info_pkts;
extern struct list_head hip_sent_ac_info_pkts;
extern struct semaphore hip_work;
extern struct socket *hip_socket;
extern spinlock_t hip_workqueue_lock;
extern spinlock_t dh_table_lock;

#endif /* HIP_HIP_H */
