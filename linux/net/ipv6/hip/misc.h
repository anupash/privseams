#ifndef HIP_MISC_H
#define HIP_MISC_H

#ifdef __KERNEL__
#  include <net/ipv6.h>
#  include <linux/types.h>
#  include <net/hip.h>
#  include "hip.h"
#else
#  include "list.h" /* userspace list implementation */
#  include "hipd.h"

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

#endif /* __KERNEL__ */

#include "debug.h"
#include "hip.h"

int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type);
int hip_private_host_id_to_hit(const struct hip_host_id *host_id,
			       struct in6_addr *hit, int hit_type);
int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result);
void hip_set_sockaddr(struct sockaddr_in6 *sin, struct in6_addr *addr);
int hip_lhi_are_equal(const struct hip_lhi *lhi1,
		      const struct hip_lhi *lhi2);
char* hip_in6_ntop(const struct in6_addr *in6, char *buf);
int hip_in6_ntop2(const struct in6_addr *in6, char *buf);
char* hip_hit_ntop(const hip_hit_t *hit, char *buf);
int hip_is_hit(const hip_hit_t *hit);
int hip_host_id_contains_private_key(struct hip_host_id *host_id);
u8 *hip_host_id_extract_public_key(u8 *buffer, struct hip_host_id *data);
int hip_hit_is_bigger(const struct in6_addr *hit1,
		      const struct in6_addr *hit2);

int hip_hash_hit(const void *hit, int range);
int hip_hash_spi(const void *spi, int range);
int hip_match_hit(const void *hitA, const void *hitB);
const char *hip_algorithm_to_string(int algo);

uint16_t hip_get_dh_size(uint8_t hip_dh_group_type);
struct hip_common *hip_create_r1(const struct in6_addr *src_hit);
hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_auth_key_length_esp(int tid);
int hip_transform_key_length(int tid);
int hip_hmac_key_length(int tid);
int hip_enc_key_length(int tid);
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd);
uint64_t hip_get_current_birthday(void);

#endif /* HIP_MISC_H */
