/*
 * HIP output
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 * TODO:
 * - If a function returns a value, we MUST NOT ignore it
 * - make null-cipher optional, so that the module can be loaded without it
 * - timeouts to cookies
 * - LOCKING TO REA/AC sent lists
 * - AC/ACR: more accurate RTT timing than jiffies ?
 * - hip_send_rea_all: test with multiple REA_INFO payloads (mm-00 sec 6.1.1)
 * - document hip_getfrag using docbook
 * - rename hip_rea_delete_sent_list_one -> hip_rea_delete_sent_list
 * - remove duplicate code, REA/AC list
 * - adding of HMAC/signature to the packet: own functions
 *
 * BUGS:
 * - It should be signalled somehow when building of R1 is 100 % 
 *   complete. Otherwise an incomplete packet could be sent for
 *   the initiator?
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
 * hip_handle_output - handle outgoing IPv6 packets
 * @hdr: a pointer to the beginning of IPv6 header in the @skb
 * @skb: the socket buffer that is going to be output
 *
 * Handle outgoing packets sent by the transport layer. Depending on the
 * current state of the HIP association, the packet may be dropped (if it
 * has a HIT as the destination address) until base exchange or other HIP
 * related packet exchange is completed. If the packet is not destined
 * for a HIT, nothing is done for it.
 *
 * The @skb will be freed if the return value is not zero.
 *
 * Returns: a negative error value on failure. This will be interpreted as
 *          "drop the packet".
 *          Zero if the destination address
 *          was an ordinary IPv6 address or the state was already established.
 */
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb)
{
	/* XX TODO:
	   - remove retransmission of I1 from here and use timers instead
	   - output buffer to temporarily store outgoing packets during
             base exchange
	 */
	int err = 0;
	int state = 0;
	hip_ha_t *entry;

	if (!ipv6_addr_is_hit(&hdr->daddr)) {
		/* The address was an IPv6 address, ignore. */
		return 0;
	}

	/* The source address is not yet a HIT, just the dst address. */
	entry = hip_hadb_find_byhit(&hdr->daddr);
	if (!entry) {
		HIP_ERROR("Unknown HA\n");
		err = -EFAULT;
		goto out;
	}

	smp_wmb();
	state = entry->state;

       	_HIP_DEBUG("hadb entry state is %s\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_NONE:
		HIP_DEBUG("No state with peer\n");
		break;
	case HIP_STATE_UNASSOCIATED:
		HIP_DEBUG("Initiating connection\n");
#ifdef KRISUS_THESIS
		if (!gtv_inuse) {
			KRISU_START_TIMER(KMM_GLOBAL);
			gtv_inuse = 1;
			do_gettimeofday(&gtv_start);
		}
#endif
		barrier();
		entry->state = HIP_STATE_I1_SENT;

		err = hip_send_i1(&hdr->daddr, entry);
		if (err < 0) {
			HIP_ERROR("Sending of I1 failed (%d)\n", err);
			err = -ENOMEM;

			barrier();
			entry->state = HIP_STATE_UNASSOCIATED;
			goto out;
		}

		err = -1; // drop the TCP/UDP packet
		break;
	case HIP_STATE_I1_SENT:
		HIP_DEBUG("I1 retransmission\n");
		/* XX TODO: we should have timers on HIP layer and
		   not depend on transport layer timeouts? In that case
		   we should not send I1 here. For the time being, this
		   will act as a poor man's timeout... */
		err = hip_send_i1(&hdr->daddr, entry);
		if (err) {
			HIP_ERROR("I1 retransmission failed");
			goto out;
		}
		err = -1; // just something to drop the TCP packet;
		break;
	case HIP_STATE_I2_SENT:
		/* XX TODO: Should the packet be buffered instead? */
		HIP_INFO("Not established yet. Dropping the packet.\n");
		err = -1;
		break;
	case HIP_STATE_ESTABLISHED:
		/* State is already established; just rewrite HITs to IPv6
		   addresses and continue normal IPv6 packet processing. */
		/* first get peer IPv6 addr */
		err = hip_hadb_get_peer_addr(entry, &hdr->daddr);
		if (err) {
			HIP_ERROR("Could not find peer address\n");
			err = -EADDRNOTAVAIL;
			goto out;
		}

		_HIP_DEBUG_IN6ADDR("dst addr", &hdr->daddr);
		if (!skb) {
			HIP_ERROR("Established state and no SKB!");
			err = -EADDRNOTAVAIL;
			goto out;
		}

		err = ipv6_get_saddr(skb->dst, &hdr->daddr, &hdr->saddr);
		if (err) {
			HIP_ERROR("Couldn't get a source address\n");
			err = -EADDRNOTAVAIL;
			goto out;
		}

		break;
	case HIP_STATE_REKEYING:
		/* XX TODO: Should the packet be buffered instead? */
		HIP_INFO("Rekey pending. Dropping the packet.\n");
		err = -1;
		break;
	default:
		HIP_ERROR("Unknown HIP state %d\n", state);
		err = -EFAULT;
		break;
	}

	if (entry->skbtest) {
		/* sock needs to relookup its dst, todo */
		HIP_DEBUG("skbtest is 1, setting back to 0\n");
		entry->skbtest = 0;
	        err = 5;
	}
 out:
	if (entry)
		hip_put_ha(entry);
	_HIP_DEBUG("err=%d\n", err);
	return err;
}

/**
 * hip_getfrag - handle IPv6 fragmentation
 * @data: start of the data to be copied from
 * @saddr: source IPv6 address, ignored
 * @buff: destination buffer where to data is copied to
 * @offset: offset from the beginning of @data
 * @len: length of the data to be copied from @data+@offset
 *
 * Returns: always 0.
 */
static int hip_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	memcpy(to, ((u8 *)from)+offset, len);	
	if (skb->ip_summed != CHECKSUM_HW) {
		unsigned int csum;

		csum = csum_partial((u8 *)from+offset, len, 0);
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

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
	len = hip_common->payload_len;

	_HIP_HEXDUMP("hip_csum_verify data", skb->h.raw, (len + 1) << 3);
	_HIP_DEBUG("len=%d\n", len);
	_HIP_HEXDUMP("saddr", &(skb->nh.ipv6h->saddr),
		     sizeof(struct in6_addr));
	_HIP_HEXDUMP("daddr", &(skb->nh.ipv6h->daddr),
		     sizeof(struct in6_addr));
	csum = csum_partial(skb->h.raw, (len + 1) << 3, 0);

	return csum_ipv6_magic(&(skb->nh.ipv6h->saddr),
			       &(skb->nh.ipv6h->daddr),
			       (len + 1) << 3,
			       IPPROTO_HIP,
			       csum);
}

/**
 * hip_csum_send - send a HIP packet
 * @src_addr: packet's source IPv6 address
 * @peer_addr: packet's destination IPv6 address
 * @buf: start of the HIP packet
 *
 * If @src_addr is NULL, kernel selects which source IPv6 address to
 * use is the packet.
 *
 * Returns: 0 if packet was delivered to lower layer, < 0 otherwise.
 */
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf)
{
	return hip_csum_send_fl(src_addr, peer_addr, buf, (struct flowi *) NULL);
}

int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		     struct hip_common* buf, struct flowi *out_fl)
{

	int err = 0;
	struct dst_entry *dst = NULL;

	struct flowi fl, *ofl;
	unsigned int csum;
	unsigned int len;
#ifdef CONFIG_HIP_DEBUG
	char addrstr[INET6_ADDRSTRLEN];
#endif

	if (out_fl == NULL) {
		fl.proto = IPPROTO_HIP;
		fl.oif = 0;
		fl.fl6_flowlabel = 0;
		fl.fl6_dst = *peer_addr;
		if (src_addr)
			fl.fl6_src = *src_addr;
		else
			memset(&fl.fl6_src, 0, sizeof(*src_addr));
		ofl = &fl;
	} else {
		ofl = out_fl;
	}

	buf->checksum = htons(0);
	len = (buf->payload_len + 1) << 3;
	csum = csum_partial((char*) buf, len, 0);

	lock_sock(hip_output_socket->sk);

	err = ip6_dst_lookup(hip_output_socket->sk, &dst, ofl);
	if (err) {
		HIP_ERROR("Unable to route HIP packet\n");
		release_sock(hip_output_socket->sk);
		goto out_err;
	}

#ifdef CONFIG_HIP_DEBUG
	_HIP_DUMP_MSG(buf);
	HIP_DEBUG("pkt out: len=%d proto=%d\n", len, ofl->proto);
	hip_in6_ntop(&(ofl->fl6_src), addrstr);
	HIP_DEBUG("pkt out: src IPv6 addr: %s\n", addrstr);
	hip_in6_ntop(&(ofl->fl6_dst), addrstr);
	HIP_DEBUG("pkt out: dst IPv6 addr: %s\n", addrstr);
#endif

	buf->checksum = csum_ipv6_magic(&(ofl->fl6_src), &(ofl->fl6_dst), len,
					ofl->proto, csum);
	HIP_DEBUG("pkt out: checksum value (host order): 0x%x\n",
		  ntohs(buf->checksum));

	if (buf->checksum == 0)
		buf->checksum = -1;

 	err = ip6_append_data(hip_output_socket->sk, hip_getfrag, buf, len, 0,
			      0xFF, NULL, ofl, (struct rt6_info *)dst, MSG_DONTWAIT);
	if (err) {
 		HIP_ERROR("ip6_append_data failed (err=%d)\n", err);
		ip6_flush_pending_frames(hip_output_socket->sk);
	} else
		err = ip6_push_pending_frames(hip_output_socket->sk);

	release_sock(hip_output_socket->sk);
 out_err:
	return err;
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

	if (hip_copy_any_localhost_hit(&hit_our) < 0) {
		HIP_ERROR("Out HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}

	mask = HIP_CONTROL_NONE;
#ifdef CONFIG_HIP_RVS
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS))
		mask |= HIP_CONTROL_RVS_CAPABLE;
#endif

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

/* copied from rea.c */
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

        /* code ripped from rea.c */
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
