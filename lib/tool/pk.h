#ifndef HIP_PK_H
#define HIP_PK_H

#include "hipd/hidb.h"
#include "lib/core/crypto.h"

int hip_dsa_verify(void *priv_key, struct hip_common *msg);
int hip_dsa_sign(void *peer_pub, struct hip_common *msg);
int hip_rsa_verify(void *priv_key, struct hip_common *msg);
int hip_rsa_sign(void *peer_pub, struct hip_common *msg);
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);

#endif /* HIP_PK_H */
