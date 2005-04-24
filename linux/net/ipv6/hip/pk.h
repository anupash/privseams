#ifndef HIP_PK_H
#define HIP_PK_H

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
#include <net/hip.h>
#include "hidb.h"
#include "crypto.h"
#ifdef __KERNEL__
#  include "crypto/dh.h"
#  include "crypto/rsa.h"
#  include "crypto/dsa.h"
#endif

int hip_dsa_verify(struct hip_host_id *peer_pub, struct hip_common *);
int hip_dsa_sign(struct hip_host_id *hi, struct hip_common *);
int hip_rsa_verify(struct hip_host_id *peer_pub, struct hip_common *);
int hip_rsa_sign(struct hip_host_id *hi, struct hip_common *);

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
#endif /* HIP_PK_H */
