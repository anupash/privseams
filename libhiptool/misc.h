#ifndef HIP_MISC_H
#define HIP_MISC_H

#include "list.h" /* userspace list implementation */
#include "hipd.h"
#include "debug.h"
#include "hip.h"
#include "crypto.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
//#include <net/if.h>  /* Excluded for RH/Fedora compilation */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/bn.h>

#ifdef CONFIG_HIP_LIBHIPTOOL
#  include "hipconf.h"
#endif /* CONFIG_HIP_LIBHIPTOOL */

#define HOST_ID_FILENAME_MAX_LEN 256

static inline int ipv6_addr_cmp(const struct in6_addr *a1,
				const struct in6_addr *a2)
{
	return memcmp((const void *) a1, (const void *) a2,
		      sizeof(struct in6_addr));
}

static inline void ipv6_addr_copy(struct in6_addr *a1,
				  const struct in6_addr *a2)
{
	memcpy((void *) a1, (const void *) a2, sizeof(struct in6_addr));
}

static inline int ipv6_addr_any(const struct in6_addr *a)
{
	return ((a->s6_addr32[0] | a->s6_addr32[1] | 
		 a->s6_addr32[2] | a->s6_addr32[3] ) == 0); 
}

int hip_dsa_host_id_to_hit(const struct hip_host_id *host_id,
			   struct in6_addr *hit, int hit_type);

int hip_rsa_host_id_to_hit(const struct hip_host_id *host_id,
			   struct in6_addr *hit, int hit_type);

int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type);
int hip_private_host_id_to_hit(const struct hip_host_id *host_id,
			       struct in6_addr *hit, int hit_type);
int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result);
char* hip_in6_ntop(const struct in6_addr *in6, char *buf);
int hip_in6_ntop2(const struct in6_addr *in6, char *buf);
char* hip_hit_ntop(const hip_hit_t *hit, char *buf);
int hip_is_hit(const hip_hit_t *hit);
int hip_host_id_contains_private_key(struct hip_host_id *host_id);
u8 *hip_host_id_extract_public_key(u8 *buffer, struct hip_host_id *data);
int hip_hit_is_bigger(const struct in6_addr *hit1,
		      const struct in6_addr *hit2);
void hip_xor_hits(struct in6_addr *res, 
		  const struct in6_addr *hit1, 
		  const struct in6_addr *hit2);

int hip_hash_hit(const void *hit, int range);
int hip_hash_spi(const void *spi, int range);
int hip_match_hit(const void *hitA, const void *hitB);
const char *hip_algorithm_to_string(int algo);

hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_auth_key_length_esp(int tid);
int hip_transform_key_length(int tid);
int hip_hmac_key_length(int tid);
int hip_enc_key_length(int tid);
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd);
uint64_t hip_get_current_birthday(void);
int hip_serialize_host_id_action(struct hip_common *msg, int action, int anon,
				 int use_default, const char *hi_fmt,
				 const char *hi_file);
char *hip_convert_hit_to_str(const hip_hit_t *local_hit, const char *prefix);
int maxof(int num_args, ...);

int addr2ifindx(struct in6_addr *local_address);

#endif /* HIP_MISC_H */
