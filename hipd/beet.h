/**
 * BEET API for the kernel and the userspace. XFRM API is for
 * management of IPsec SAs and BEET API is for management of
 * HIT<->SPI,IP mappings. 
 */
#ifndef HIP_BEET_H
#define HIP_BEET_H

#include <linux/xfrm.h>


#include <time.h>
#include <netdb.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <errno.h>

#include "nlink.h"
#include "debug.h"
#include "hip.h"
#include "hashtable.h"
#include "hadb.h"
#include "workqueue.h"
#include "misc.h"

#define HIP_BEETDB_SIZE  53
#define RTA_BUF_SIZE     2048
#define XFRM_MODE_BEET   2
#define XFRM_TMPLS_BUF_SIZE 1024
#define XFRM_ALGO_KEY_BUF_SIZE 512
#define PREFIXLEN_SPECIFIED 1

/* BEET database entry struct and access functions to retrieve them. */
struct hip_xfrm_state {
	struct list_head     next;
	spinlock_t           lock;
	atomic_t             refcnt;
        uint32_t             spi;                 /* SPI out */
        //int                  dir;                 /* Direction */
        hip_hit_t            hit_our;             /* The HIT we use with
                                                   * this host */
        hip_hit_t            hit_peer;            /* Peer's HIT */ 
	hip_hit_t            hash_key;            /* key for the hash table */
	struct in6_addr      preferred_peer_addr; /* preferred dst
						   * address to use when
						   * sending data to
						   * peer */
	int                  state;               /* state */
};

struct idxmap
{
        struct idxmap * next;
        unsigned        index;
        int             type;
        int             alen;
        unsigned        flags;
        unsigned char   addr[8];
        char            name[16];
};

typedef struct
{
        __u8 family;
        __u8 bytelen;
        __s16 bitlen;
        __u32 flags;
        __u32 data[4];
} inet_prefix;



typedef struct hip_xfrm_state hip_xfrm_t;

void hip_beetdb_hold_entry(void *entry);
void hip_beetdb_put_entry(void *entry);
int get_ctl_fd(void);
int do_chflags(const char *dev, __u32 flags, __u32 mask);
int set_up_device(char *dev, int up);
/*
 * These are wrappers to netlink calls (from the userspace daemon to
 * the kernel XFRM management) or to the BEET patch (from the kernel
 * daemon to the kernel XFRM management). The functions are used to
 * manage the replica of HADB within the kernel.
 */
int hip_xfrm_dst_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr);
int hip_xfrm_update(hip_hit_t *hit, hip_hit_t *hit2, struct in6_addr *addr, 
		    uint32_t spi, int state, int dir);
int hip_xfrm_delete(hip_hit_t * hit, uint32_t spi, int dir);
int hip_xfrm_policy_modify(int cmd, struct in6_addr *hit_our,
			   struct in6_addr *hit_peer, 
			   struct in6_addr *tmpl_saddr,
			   struct in6_addr *tmpl_daddr, int dir, u8 proto,
			   u8 hit_prefix);
int hip_xfrm_policy_delete(struct in6_addr *hit_our, struct in6_addr *hit_peer,
			   int dir, u8 proto, u8 hit_prefix);

int hip_xfrm_state_modify(int cmd, struct in6_addr *saddr,
			  struct in6_addr *daddr, 
			  struct in6_addr *src_hit, 
			  struct in6_addr *dst_hit,
			  __u32 spi, int ealg, struct hip_crypto_key *enckey,
			  int enckey_len,
			  int aalg, struct hip_crypto_key *authkey,
			  int authkey_len);
int hip_xfrm_state_delete(struct in6_addr *peer_addr, __u32 spi);

#endif /* HIP_BEET_H */

