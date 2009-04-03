#ifndef HIP_PK_H
#define HIP_PK_H

#include "hidb.h"
#include "crypto.h"

int hip_dsa_verify(struct hip_host_id *peer_pub, struct hip_common *);
int hip_dsa_sign(struct hip_host_id *hi, struct hip_common *);
int hip_rsa_verify(struct hip_host_id *peer_pub, struct hip_common *);
int hip_rsa_sign(struct hip_host_id *hi, struct hip_common *);

#endif /* HIP_PK_H */
