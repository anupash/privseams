#ifndef HIP_SECURITY_H
#define HIP_SECURITY_H

#include <net/spd.h>
#include <linux/pfkeyv2.h>
#include <linux/in6.h>
#include <net/hip.h>
#include <net/ipv6.h>

#include "../../key/pfkey_v2_msg.h"
#include "debug.h"
#include "db.h"

int hip_setup_esp(struct in6_addr *dst, struct in6_addr *src,
		  uint32_t spi, int encalg, void *enckey,
		  void *authkey);

int hip_delete_esp(struct in6_addr *own, struct in6_addr *peer);

int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
int hip_generate_shared_secret(int group_id, u8* peerkey, size_t peer_len, u8 *out, size_t outlen);
void hip_regen_dh_keys(u32 bitmask);


#endif /* HIP_SECURITY_H */
