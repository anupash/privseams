#ifndef HIP_LIB_CORE_HIT_H
#define HIP_LIB_CORE_HIT_H

#include <netinet/in.h>
#include "protodefs.h"

int hip_convert_hit_to_str(const hip_hit_t *hit, const char *prefix, char *str);
int hip_hit_is_bigger(const struct in6_addr *hit1,
                      const struct in6_addr *hit2);
int hip_hit_are_equal(const struct in6_addr *hit1,
                      const struct in6_addr *hit2);
unsigned long hip_hash_hit(const void *hit);
int hip_match_hit(const void *, const void *);

#endif /* HIP_LIB_CORE_HIT_H */
