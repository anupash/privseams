#ifndef HIP_DH_H
#define HIP_DH_H

#include <linux/types.h>
#include <net/ipv6.h>

#include "hadb.h"

int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
int hip_generate_shared_secret(int group_id, u8* peerkey, size_t peer_len, u8 *out, size_t outlen);
void hip_regen_dh_keys(u32 bitmask);

#endif /* HIP_DH_H */
