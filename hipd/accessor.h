#ifndef _HIPD_ACCESSOR
#define _HIPD_ACCESSOR

#include "hipd.h"

#include "hashtable.h"

#include <sys/time.h>


#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>

/** @addtogroup daemon_states
 * @{
 */

/** Low mask for daemon states. */
#define HIPD_STATE_MASK		0xff
/** Daemon is ok and executing. */
#define HIPD_STATE_EXEC		0x00
/** Daemon is closing. */
#define HIPD_STATE_CLOSING	0x01
/** Daemon is closed, exiting main(). */
#define HIPD_STATE_CLOSED	0x02

/** High mask for daemon states. */
#define HIPD_FLAG_MASK		0xffffff00
/** Daemon is restarting. */
#define HIPD_FLAG_RESTART	0x00000100


/* @}  */

#define INDEX_HASH_LENGTH	SHA_DIGEST_LENGTH

#define INDEX_HASH_FN		HIP_DIGEST_SHA1

unsigned int hipd_get_state(void);
void hipd_set_state(unsigned int);
int hipd_get_flag(unsigned int);
void hipd_set_flag(unsigned int);
void hipd_clear_flag(unsigned int);

int hip_agent_is_alive();
int hip_set_opportunistic_mode(const struct hip_common *msg);
int hip_get_peer_hit(struct hip_common *msg, const struct sockaddr_un *src);
int hip_get_pseudo_hit(struct hip_common *msg);
int hip_query_opportunistic_mode(struct hip_common *msg);
int hip_query_ip_hit_mapping(struct hip_common *msg);
int hip_get_hip_proxy_status(void);
int hip_set_hip_proxy_on(void);
int hip_set_hip_proxy_off(void);
int hip_get_sava_client_status(void);
int hip_get_sava_server_status(void);
void  hip_set_sava_client_on(void);
void hip_set_sava_server_on(void);
void hip_set_sava_client_off(void);
void hip_set_sava_server_off(void);
void hip_set_bex_start_timestamp(hip_ha_t *entry);
void hip_set_bex_end_timestamp(hip_ha_t * entry);

/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. Defined in hipd.c */
extern int hipproxy;

/*SAVAH modes*/
extern int hipsava_client;
extern int hipsava_server;

/*Measurements*/

extern HIP_HASHTABLE *bex_timestamp_db;

typedef struct hip_bex_duration {
  unsigned int sec;
  unsigned int msec;
  unsigned int mrsec;
} hip_bex_duration_t;

typedef struct hip_bex_timestamp {
  struct in6_addr * addr;
  struct timeval * timestamp;
} hip_bex_timestamp_t;

static DECLARE_LHASH_HASH_FN(hip_bex_timestamp_hash, const hip_bex_timestamp_t *)
static DECLARE_LHASH_COMP_FN(hip_bex_timestamp_compare, const hip_bex_timestamp_t *)

unsigned long hip_bex_timestamp_hash(const hip_bex_timestamp_t * entry);

int hip_bex_timestamp_compare(const hip_bex_timestamp_t * entry1,
			      const hip_bex_timestamp_t * entry2);

int hip_bex_timestamp_db_init();
int hip_bex_timestamp_db_uninit();

hip_bex_timestamp_t * hip_bex_timestamp_find(struct in6_addr * addr);

int hip_bex_timestamp_db_add(const struct in6_addr * addr, const struct timeval * time);

int hip_bex_timestamp_db_delete(const struct in6_addr * addr);

/*initializes the timestamp at startup of base exchange*/
int bex_add_initial_timestamp(const struct in6_addr *);

/*Return base exchange for given host*/
struct timeval * bex_get_duration_timestamp(const struct in6_addr *);

#endif /* _HIPD_ACCESSOR */

