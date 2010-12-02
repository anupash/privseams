#ifndef HIP_LIB_TOOL_PK_H
#define HIP_LIB_TOOL_PK_H

#include <openssl/bn.h>

#include "lib/core/protodefs.h"

int hip_dsa_verify(void *priv_key, struct hip_common *msg);
int hip_dsa_sign(void *peer_pub, struct hip_common *msg);
int hip_rsa_verify(void *priv_key, struct hip_common *msg);
int hip_rsa_sign(void *peer_pub, struct hip_common *msg);
int hip_ecdsa_verify(void *peer_pub, struct hip_common *msg);
int hip_ecdsa_sign(void *peer_pub, struct hip_common *msg);
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);

#endif /* HIP_LIB_TOOL_PK_H */
