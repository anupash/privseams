/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_HIPD_BLIND_H
#define HIP_HIPD_BLIND_H

#include "lib/core/debug.h"
#include "lib/core/crypto.h"
#include "lib/core/ife.h"
#include "lib/core/state.h"
#include "lib/core/builder.h"

extern int hip_blind_status; //blind on/off flag

int hip_check_whether_to_use_blind(hip_common_t *msg, hip_ha_t *entry,
                                   int *use_blind);
int hip_set_blind_on(void);
int hip_set_blind_off(void);
int hip_blind_get_status(void);
int hip_blind_get_nonce(struct hip_common *msg,
                        uint16_t *msg_nonce);
int hip_plain_fingerprint(uint16_t *nonce,
                          struct in6_addr *blind_hit,
                          struct in6_addr *plain_hit);
int hip_do_blind(char *key, unsigned int key_len, struct in6_addr *blind_hit);
int hip_blind_verify(uint16_t *nonce,
                     struct in6_addr *plain_hit,
                     struct in6_addr *blind_hit);
int hip_blind_verify_r2(struct hip_common *r2,
                        hip_ha_t *entry);

struct hip_common *hip_blind_build_i1(hip_ha_t *entry, uint16_t *mask);
int hip_blind_build_r2(struct hip_common *i2,
                       struct hip_common *r2,
                       hip_ha_t *entry,
                       uint16_t *mask);

struct hip_common *hip_blind_create_r1(const struct in6_addr *src_hit,
                                       int (*sign)(void *key, struct hip_common *m),
                                       void *private_key,
                                       const struct hip_host_id *host_id_pub,
                                       int cookie_k);

int hip_blind_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit,
                           int (*sign)(void *key, struct hip_common *m),
                           void *privkey, struct hip_host_id *pubkey);

#endif /* HIP_HIPD_BLIND_H */
