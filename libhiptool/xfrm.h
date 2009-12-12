#ifndef _LINUX_XFRM_H
#define _LINUX_XFRM_H

#include <linux/types.h>

/* All of the structures in this file may not change size as they are
 * passed into the kernel from userspace via netlink sockets.
 */

/* Structure to encapsulate addresses. I do not want to use
 * "standard" structure. My apologies.
 */
typedef union
{
	__u32		a4;
	__u32		a6[4];
} xfrm_address_t;

/* Ident of a specific xfrm_state. It is used on input to lookup
 * the state by (spi,daddr,ah/esp) or to store information about
 * spi, protocol and tunnel address on output.
 */
struct xfrm_id
{
	xfrm_address_t	daddr;
	__u32		spi;
	__u8		proto;
};

/* Selector, used as selector both on policy rules (SPD) and SAs. */

struct xfrm_selector
{
	xfrm_address_t	daddr;
	xfrm_address_t	saddr;
	__u16	dport;
	__u16	dport_mask;
	__u16	sport;
	__u16	sport_mask;
	__u16	family;
	__u8	prefixlen_d;
	__u8	prefixlen_s;
	__u8	proto;
	int	ifindex;
	uid_t	user;
};

#define XFRM_INF (~(__u64)0)

struct xfrm_lifetime_cfg
{
	__u64	soft_byte_limit;
	__u64	hard_byte_limit;
	__u64	soft_packet_limit;
	__u64	hard_packet_limit;
	__u64	soft_add_expires_seconds;
	__u64	hard_add_expires_seconds;
	__u64	soft_use_expires_seconds;
	__u64	hard_use_expires_seconds;
};

struct xfrm_encap_tmpl {
	__u16		encap_type;
	__u16		encap_sport;
	__u16		encap_dport;
	xfrm_address_t	encap_oa;
};

/* Netlink message attributes.  */
enum xfrm_attr_type_t {
	XFRMA_UNSPEC,
	XFRMA_ALG_AUTH,		/* struct xfrm_algo */
	XFRMA_ALG_CRYPT,	/* struct xfrm_algo */
	XFRMA_ALG_COMP,		/* struct xfrm_algo */
	XFRMA_ENCAP,		/* struct xfrm_algo + struct xfrm_encap_tmpl */
	XFRMA_TMPL,		/* 1 or more struct xfrm_user_tmpl */
	XFRMA_SA,
	XFRMA_POLICY,
	__XFRMA_MAX

#define XFRMA_MAX (__XFRMA_MAX - 1)
};

struct xfrm_algo {
	char	alg_name[64];
	int	alg_key_len;    /* in bits */
	char	alg_key[0];
};

#define XFRMGRP_ACQUIRE		1
#define XFRMGRP_EXPIRE		2
#define XFRMGRP_SA		4
#define XFRMGRP_POLICY		8

/* Netlink configuration messages.  */
enum {
	XFRM_MSG_BASE = 0x10,

	XFRM_MSG_NEWSA = 0x10,
#define XFRM_MSG_NEWSA XFRM_MSG_NEWSA
	XFRM_MSG_DELSA,
#define XFRM_MSG_DELSA XFRM_MSG_DELSA
	XFRM_MSG_GETSA,
#define XFRM_MSG_GETSA XFRM_MSG_GETSA

	XFRM_MSG_NEWPOLICY,
#define XFRM_MSG_NEWPOLICY XFRM_MSG_NEWPOLICY
	XFRM_MSG_DELPOLICY,
#define XFRM_MSG_DELPOLICY XFRM_MSG_DELPOLICY
	XFRM_MSG_GETPOLICY,
#define XFRM_MSG_GETPOLICY XFRM_MSG_GETPOLICY

	XFRM_MSG_ALLOCSPI,
#define XFRM_MSG_ALLOCSPI XFRM_MSG_ALLOCSPI
	XFRM_MSG_ACQUIRE,
#define XFRM_MSG_ACQUIRE XFRM_MSG_ACQUIRE
	XFRM_MSG_EXPIRE,
#define XFRM_MSG_EXPIRE XFRM_MSG_EXPIRE

	XFRM_MSG_UPDPOLICY,
#define XFRM_MSG_UPDPOLICY XFRM_MSG_UPDPOLICY
	XFRM_MSG_UPDSA,
#define XFRM_MSG_UPDSA XFRM_MSG_UPDSA

	XFRM_MSG_POLEXPIRE,
#define XFRM_MSG_POLEXPIRE XFRM_MSG_POLEXPIRE

	XFRM_MSG_FLUSHSA,
#define XFRM_MSG_FLUSHSA XFRM_MSG_FLUSHSA
	XFRM_MSG_FLUSHPOLICY,
#define XFRM_MSG_FLUSHPOLICY XFRM_MSG_FLUSHPOLICY

	__XFRM_MSG_MAX
};
#define XFRM_MSG_MAX (__XFRM_MSG_MAX - 1)

struct xfrm_lifetime_cur
{
	__u64	bytes;
	__u64	packets;
	__u64	add_time;
	__u64	use_time;
};

struct xfrm_userpolicy_info {
	struct xfrm_selector		sel;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	__u32				priority;
	__u32				index;
	__u8				dir;
	__u8				action;
	__u8				flags;
	__u8				share;
};

struct xfrm_user_acquire {
	struct xfrm_id			id;
	xfrm_address_t			saddr;
	struct xfrm_selector		sel;
	struct xfrm_userpolicy_info	policy;
	__u32				aalgos;
	__u32				ealgos;
	__u32				calgos;
	__u32				seq;
};

#endif /* _LINUX_XFRM_H */
