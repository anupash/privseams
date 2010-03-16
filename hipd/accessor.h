#ifndef HIP_HIPD_ACCESSOR_H
#define HIP_HIPD_ACCESSOR_H

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <sys/time.h>

#include "lib/core/hashtable.h"

/** @addtogroup daemon_states
 * @{
 */

/** Low mask for daemon states. */
#define HIPD_STATE_MASK         0xff
/** Daemon is ok and executing. */
#define HIPD_STATE_EXEC         0x00
/** Daemon is closing. */
#define HIPD_STATE_CLOSING      0x01
/** Daemon is closed, exiting main(). */
#define HIPD_STATE_CLOSED       0x02

/** Daemon is restarting. */
#define HIPD_FLAG_RESTART       0x00000100


/* @}  */

#define INDEX_HASH_LENGTH       SHA_DIGEST_LENGTH

#define INDEX_HASH_FN           HIP_DIGEST_SHA1

/** Specifies the NAT status of the daemon. This value indicates if the current
 *  machine is behind a NAT. Defined in hipd.c */
extern int hipproxy;

extern unsigned int opportunistic_mode;

unsigned int hipd_get_state(void);
void hipd_set_state(unsigned int);
int hipd_get_flag(unsigned int);
void hipd_set_flag(unsigned int);
int hip_agent_is_alive(void);

int hip_get_opportunistic_tcp_status(void);
int hip_set_opportunistic_mode(struct hip_common *msg);
int hip_query_opportunistic_mode(struct hip_common *msg);
int hip_query_ip_hit_mapping(struct hip_common *msg);

#ifdef CONFIG_HIP_I3
int hip_get_hi3_status(void);
void hip_set_hi3_status(struct hip_common *msg);
#endif /* CONFIG_HIP_I3 */

int hip_get_hip_proxy_status(void);
int hip_set_hip_proxy_on(void);
int hip_set_hip_proxy_off(void);


#endif /* HIP_HIPD_ACCESSOR_H */
