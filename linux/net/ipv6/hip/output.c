/*
 * HIP output
 *
 * Licence: GNU/GPL
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 */

#include "output.h"
#include "debug.h"
#include "misc.h"
#include "hip.h"
#include "hadb.h"
#include "db.h"
#include "builder.h"
#include "cookie.h"
#include "builder.h"

#include <net/checksum.h>
#include <net/addrconf.h>
#include <net/xfrm.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/ip6_route.h>

/**
 * hip_csum_verify - verify HIP header checksum
 * @skb: the socket buffer which contains the HIP header
 *
 * Returns: the checksum of the HIP header.
 */
int hip_csum_verify(struct sk_buff *skb)
{
	struct hip_common *hip_common;
	int len;
	int csum;

	hip_common = (struct hip_common*) skb->h.raw;
        len = hip_get_msg_total_len(hip_common);

	_HIP_HEXDUMP("hip_csum_verify data", skb->h.raw, len);
	_HIP_DEBUG("len=%d\n", len);
	_HIP_HEXDUMP("saddr", &(skb->nh.ipv6h->saddr),
		     sizeof(struct in6_addr));
	_HIP_HEXDUMP("daddr", &(skb->nh.ipv6h->daddr),
		     sizeof(struct in6_addr));

        csum = csum_partial((char *) hip_common, len, 0);

	return csum_ipv6_magic(&(skb->nh.ipv6h->saddr),
			       &(skb->nh.ipv6h->daddr),
			       len, IPPROTO_HIP, csum);
}



/**
 * hip_send_i1 - send an I1 packet to the responder
 * @entry: the HIP database entry reserved for the peer
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * Returns: 0 on success, otherwise < 0 on error.
 */
int hip_send_i1(struct in6_addr *dsthit, hip_ha_t *entry)
{
	struct hip_common i1;
	struct in6_addr daddr;
	struct in6_addr hit_our;
	int mask;
	int err = 0;

	HIP_DEBUG("\n");

	/* TODO: we must use the same algorithm that is used in the dsthit */
	if (hip_copy_any_localhost_hit_by_algo(&hit_our, HIP_HI_DEFAULT_ALGO) < 0) {
		HIP_ERROR("Out HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG_HIT("DEFAULT ALGO HIT: ", &hit_our);
#if 0
	if (hip_copy_any_localhost_hit(&hit_our) < 0) {
		HIP_ERROR("Out HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG_HIT("ANY HIT: ", &hit_our);
#endif
	mask = HIP_CONTROL_NONE;
#ifdef CONFIG_HIP_RVS
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS))
		mask |= HIP_CONTROL_RVS_CAPABLE;
#endif

	//HIP_DEBUG("mask pre=0x%x\n", mask);
	//mask |= (HIP_CONTROL_SHT_TYPE1 << HIP_CONTROL_SHT_SHIFT);
	//HIP_DEBUG("mask post=0x%x\n", mask);

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr((struct hip_common* ) &i1, HIP_I1,
			      mask, &hit_our,
			      dsthit);
	/* Eight octet units, not including first */
	i1.payload_len = (sizeof(struct hip_common) >> 3) - 1;

	HIP_HEXDUMP("HIT SOURCE in send_i1", &i1.hits,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("HIT DEST in send_i1", &i1.hitr,
		    sizeof(struct in6_addr));

	err = hip_hadb_get_peer_addr(entry, &daddr);
	if (err) {
		HIP_ERROR("hip_sdb_get_peer_address returned error = %d\n",
			  err);
		goto out_err;
	}

	_HIP_DEBUG("hip: send I1 packet\n");	
	err = hip_csum_send(NULL, &daddr, (struct hip_common*) &i1);

 out_err:
	return err;
}

/**
 * hip_xmit_r1 - transmit an R1 packet to the network
 * @dst_addr: the destination IPv6 address where the R1 should be sent
 * @dst_hit:  the destination HIT of peer
 *
 * Sends an R1 to the peer and stores the cookie information that was sent.
 *
 * Returns: zero on success, or negative error value on error.
 */
int hip_xmit_r1(struct sk_buff *skb, struct in6_addr *dst_ip,
		struct in6_addr *dst_hit)
{
	struct hip_common *r1pkt;
	struct in6_addr *own_addr;
	struct in6_addr *dst_addr;
	int err = 0;

	HIP_DEBUG("\n");

	own_addr = &skb->nh.ipv6h->daddr;
	if (!dst_ip || ipv6_addr_any(dst_ip)) {
		dst_addr = &skb->nh.ipv6h->saddr;
	} else {
		dst_addr = dst_ip;
	}

	/* dst_addr is the IP address of the Initiator... */
	r1pkt = hip_get_r1(dst_addr, own_addr);
	if (!r1pkt) {
		HIP_ERROR("No precreated R1\n");
		err = -ENOENT;
		goto out_err;
	}

	if (dst_hit) 
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));

	/* set cookie state to used (more or less temporary solution ?) */
	_HIP_HEXDUMP("R1 pkt", r1pkt, hip_get_msg_total_len(r1pkt));

	err = hip_csum_send(NULL, dst_addr, r1pkt);	
	if (err) {
		HIP_ERROR("hip_csum_send failed, err=%d\n", err);
		goto out_err;
	}

	HIP_ASSERT(!err);
	return 0;

 out_err:
	HIP_ERROR("hip_xmit_r1 failed, err=%d\n", err);
	return err;
}

/**
 * hip_send_r1 - send an R1 to the peer
 * @skb: the socket buffer for the received I1
 *
 * Send an I1 to the peer. The addresses and HITs will be digged
 * out from the @skb.
 *
 * Returns: zero on success, or a negative error value on failure.
 */
int hip_send_r1(struct sk_buff *skb) 
{
	int err = 0;
	struct in6_addr *dst;
	dst = &(((struct hip_common *)skb->h.raw)->hits);

	err = hip_xmit_r1(skb, NULL, dst);

	return err;
}


void hip_send_notify(hip_ha_t *entry)
{
	int err = 0; /* actually not needed, because we can't do
		      * anything if packet sending fails */
	struct hip_common *notify_packet;
	struct in6_addr daddr;

	HIP_DEBUG("\n");

	notify_packet = hip_msg_alloc();
	if (!notify_packet) {
		HIP_DEBUG("notify_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	hip_build_network_hdr(notify_packet, HIP_NOTIFY, 0,
			      &entry->hit_our, &entry->hit_peer);

	err = hip_build_param_notify(notify_packet, 1234, "ABCDEFGHIJ", 10);
	if (err) {
		HIP_ERROR("building of NOTIFY failed (err=%d)\n", err);
		goto out_err;
	}

        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }
        HIP_DEBUG("Sending NOTIFY packet\n");
	err = hip_csum_send(NULL, &daddr, notify_packet);

 out_err:
	if (notify_packet)
		kfree(notify_packet);
	return;
}

struct hip_rea_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

static int hip_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_rea_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	/* should we check the established status also? */
	if ((entry->hastate & HIP_HASTATE_VALID) == HIP_HASTATE_VALID) {
		rk->array[rk->count] = entry;
		hip_hold_ha(entry);
		rk->count++;
	}

	return 0;
}

void hip_send_notify_all(void)
{
        int err = 0, i;
        hip_ha_t *entries[HIP_MAX_HAS] = {0};
        struct hip_rea_kludge rk;

        HIP_DEBUG("\n");

        rk.array = entries;
        rk.count = 0;
        rk.length = HIP_MAX_HAS;

        err = hip_for_each_ha(hip_get_all_valid, &rk);
        if (err) {
                HIP_ERROR("for_each_ha err=%d\n", err);
                return;
        }

        for (i = 0; i < rk.count; i++) {
                if (rk.array[i] != NULL) {
                        hip_send_notify(rk.array[i]);
                        hip_put_ha(rk.array[i]);
                }
        }

        return;
}
