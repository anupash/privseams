#ifndef HIP_SECURITY_H
#define HIP_SECURITY_H

#include <linux/pfkeyv2.h>
#include <linux/in6.h>
#include <net/hip.h>
#include <net/ipv6.h>
#include <net/xfrm.h>

#include "debug.h"
#include "db.h"


#define ESP_3DES_KEY_BITS 192


int hip_setup_esp(struct in6_addr *srchit, struct in6_addr *dsthit,
		  struct in6_addr *dstip, uint32_t *spi, int alg, 
		  void *enckey, void *authkey, int dir, int is_active);

int hip_delete_esp(struct in6_addr *own, struct in6_addr *peer);


int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
int hip_generate_shared_secret(int group_id, u8* peerkey, size_t peer_len, u8 *out, size_t outlen);
void hip_regen_dh_keys(u32 bitmask);
int hip_delete_sa(u32 spi, struct in6_addr *dst);
int hip_delete_spd(struct in6_addr *hitd, struct in6_addr *hits, int dir);


#endif /* HIP_SECURITY_H */
