/**
 * BEET API for the kernel and the userspace. XFRM API is for
 * management of IPsec SAs and BEET API is for management of
 * HIT<->SPI,IP mappings.
 */
#ifndef HIP_LIB_TOOL_XFRMAPI_H
#define HIP_LIB_TOOL_XFRMAPI_H

#include <time.h>
#include <netdb.h>
#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>

#include "hipd/netdev.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "hipd/hadb.h"
#include "hipd/user.h"
#include "lib/core/misc.h"
#include "lib/core/state.h"
#include "nlink.h"

/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#ifndef NETLINK_XFRM
#  define NETLINK_XFRM            6       /* ipsec */
#endif

void hip_beetdb_hold_entry(void *entry);
void hip_beetdb_put_entry(void *entry);

/*
 * These are wrappers to netlink calls (from the userspace daemon to
 * the kernel XFRM management) or to the BEET patch (from the kernel
 * daemon to the kernel XFRM management). The functions are used to
 * manage the replica of HADB within the kernel.
 */
void hip_xfrm_set_nl_ipsec(struct rtnl_handle *nl_ipsec);
int hip_xfrm_dst_init(struct in6_addr *dst_hit, struct in6_addr *dst_addr);
int hip_xfrm_update(hip_hit_t *hit, hip_hit_t *hit2, struct in6_addr *addr,
                    uint32_t spi, int state, int dir, hip_portpair_t *sa_info);
int hip_xfrm_delete(hip_hit_t *hit, uint32_t spi, int dir);

/* Allocates SPI for fixed time */
uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);

/* Setups the SA (with a given SPI if so said) */
uint32_t hip_add_sa(const struct in6_addr *saddr,
                    const struct in6_addr *daddr,
                    const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    const uint32_t spi, const int ealg,
                    const struct hip_crypto_key *enckey,
                    const struct hip_crypto_key *authkey,
                    const int already_acquired,
                    const int direction, const int update,
                    hip_ha_t *entry);

void hip_delete_sa(const uint32_t spi, const struct in6_addr *peer_addr,
                   const struct in6_addr *not_used,
                   const int direction, hip_ha_t *entry);


int hip_setup_hit_sp_pair(const hip_hit_t *src_hit,
                          const hip_hit_t *dst_hit,
                          const struct in6_addr *src_addr,
                          const struct in6_addr *dst_addr,
                          u8 proto,
                          int use_full_prefix,
                          int update);

void hip_delete_hit_sp_pair(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
                            const uint8_t proto, const int use_full_prefix);


void hip_xfrm_set_beet(int beet);
void hip_xfrm_set_algo_names(int new_algo_names);

int hip_flush_all_policy(void);
int hip_flush_all_sa(void);

void hip_xfrm_set_default_sa_prefix_len(int len);
void hip_delete_default_prefix_sp_pair(void);
int hip_setup_default_sp_prefix_pair(void);


#endif /* HIP_LIB_TOOL_XFRMAPI_H */
