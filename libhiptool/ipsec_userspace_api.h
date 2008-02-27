

#ifndef IPSEC_USERSPACE_API_H
#define IPSEC_USERSPACE_API_H

#include <time.h>
#include <netdb.h>
//#include <net/if.h> /* Excluded for RH/Fedora compilation */
#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>

#include "nlink.h"
#include "debug.h"
#include "hashtable.h"
#include "hadb.h"
#include "user.h"
#include "misc.h"
#include "state.h"
#include "protodefs.h"



typedef __u8 hip_hit [sizeof(hip_hit_t)];  /* 16-byte (128 bit) Host Identity Tag */


/* For wrapper the API of the usespace IPsec implementation */
#define TYPE_USERSPACE_IPSEC 0

/* 0-default, 1-transport, 2-tunnel, 3 - beet */

#define IPSEC_MODE 0  




__u16 checksum_magic(const hip_hit *i, const hip_hit *r);


uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
			      struct in6_addr *src_hit, struct in6_addr *dst_hit,
			      uint32_t *spi, int ealg,
			      struct hip_crypto_key *enckey,
			      struct hip_crypto_key *authkey,
			      int already_acquired,
			      int direction, int update,
			      int sport, int dport);
int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
				    struct in6_addr *src_addr,
				    struct in6_addr *dst_addr, u8 proto,
				    int use_full_prefix, int update);
void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
				      int use_full_prefix);
int hip_userspace_ipsec_flush_all_policy();
int hip_userspace_ipsec_flush_all_sa();
uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);
void hip_userspace_ipsec_delete_default_prefix_sp_pair();
int hip_userspace_ipsec_setup_default_sp_prefix_pair();

#endif /* IPSEC_USERSPACE_IPSEC_API_H */
