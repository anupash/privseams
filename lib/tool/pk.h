#ifndef HIP_LIB_TOOL_PK_H
#define HIP_LIB_TOOL_PK_H

#include <openssl/bn.h>

#include "lib/core/protodefs.h"

int hip_dsa_verify(void *const priv_key, struct hip_common *const msg);
int hip_dsa_sign(void *const peer_pub, struct hip_common *const msg);
int hip_rsa_verify(void *const priv_key, struct hip_common *const msg);
int hip_rsa_sign(void *const priv_key, struct hip_common *const msg);
int bn2bin_safe(const BIGNUM *const a, unsigned char *const to, const int len);

#endif /* HIP_LIB_TOOL_PK_H */
