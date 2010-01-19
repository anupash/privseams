#ifndef HIP_PK_H
#define HIP_PK_H

#include "hipd/hidb.h"
#include "lib/tool/crypto.h"

int hip_dsa_verify(void *peer_pub, struct hip_common *msg);
int hip_dsa_sign(void *peer_pub, struct hip_common *msg);
int hip_rsa_verify(void *peer_pub, struct hip_common *msg);
int hip_rsa_sign(void *peer_pub, struct hip_common *msg);

#endif /* HIP_PK_H */
