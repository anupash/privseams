#include "preoutput.h"

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
	//hip_ha_t *entry;
	struct hip_xfrm_state *xs;

	if (!ipv6_addr_is_hit(&hdr->daddr)) {
		/* The address was an IPv6 address, ignore. */
		return 0;
	}

        /* XX FIX: the following call breaks kernel-only HIP */

	/* The source address is not yet a HIT, just the dst address. */
	//entry = hip_hadb_find_byhit(&hdr->daddr);
	xs = hip_xfrm_find_by_hit(&hdr->daddr);
	if (!xs) {
		HIP_ERROR("Unknown HA\n");
		err = -EFAULT;
		goto out;
	}

	smp_wmb();
	//state = entry->state;
	state = xs->state;
	
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
		//entry->state = HIP_STATE_I1_SENT;
		xs->state = HIP_STATE_I1_SENT;

#if 0
		// FIXME: replace this with a work order to workqueue
		// to send i1 the work order execution then changes
		// the state in the userspace/hadb too.
		err = hip_send_i1(&hdr->daddr, entry);
		if (err < 0) {
			HIP_ERROR("Sending of I1 failed (%d)\n", err);
			err = -ENOMEM;

			barrier();
			entry->state = HIP_STATE_UNASSOCIATED;
			goto out;
		}
#endif
		err = -1; // drop the TCP/UDP packet (FIXME: tkoponen, dropping does not happen due to blocking happening earlier?)
		break;
	case HIP_STATE_I1_SENT:
#if 0
// FIXME: no i1 retransmission until its properly done.
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
#endif
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
		//err = hip_hadb_get_peer_addr(entry, &hdr->daddr);
		//FIXME: tkoponen, is it ok to assume the xs to have a
		//single address that is always used if such exists?
		if (ipv6_addr_any(&xs->preferred_peer_addr)) {
			HIP_ERROR("Could not find peer address\n");
			err = -EADDRNOTAVAIL;
			goto out;
		}
		ipv6_addr_copy(&hdr->daddr, &xs->preferred_peer_addr);
		    
		_HIP_DEBUG_IN6ADDR("dst addr", &hdr->daddr);
		if (!skb) {
			HIP_ERROR("ESTABLISHED state and no skb!\n");
			HIP_ERROR("Called by xfrm state re-acquire ? do BEX again ?\n");
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

#if 0
	if (entry->skbtest) {
		/* sock needs to relookup its dst, todo */
		HIP_DEBUG("skbtest is 1, setting back to 0\n");
		entry->skbtest = 0;
	        err = 5;
	}
#endif
 out:
#if 0
	// FIXME: find_byhit increases the reference count, perhaps it
	// should be renamed? (tkoponen)
	if (entry)
		hip_put_ha(entry);
#endif
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

/**
 * hip_csum_send_fl - send a HIP packet to given address
 * @src_addr: packet's source IPv6 address
 * @peer_addr: packet's destination IPv6 address
 * @buf: start of the HIP packet
 * @out_fl: flow containing the source and the destination IPv6 address of the packet
 *
 * If @src_addr is NULL, kernel selects which source IPv6 address to
 * use is the packet.
 *
 * Returns: 0 if packet was delivered to lower layer, < 0 otherwise.
 */
int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		     struct hip_common* buf, struct flowi *out_fl)
{

	int err = 0;
	struct dst_entry *dst = NULL;

	struct flowi fl, *ofl;
	unsigned int csum;
	unsigned int len;

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
        len = hip_get_msg_total_len(buf);
	csum = csum_partial((char*) buf, len, 0);
	_HIP_DEBUG("csum test=0x%x\n", csum);

	lock_sock(hip_output_socket->sk);

	err = ip6_dst_lookup(hip_output_socket->sk, &dst, ofl);
	if (err) {
		HIP_ERROR("Unable to route HIP packet\n");
		release_sock(hip_output_socket->sk);
		goto out_err;
	}

	_HIP_DUMP_MSG(buf);
	HIP_DEBUG("pkt out: len=%d proto=%d csum=0x%x\n", len, ofl->proto, csum);
	HIP_DEBUG_IN6ADDR("pkt out: src IPv6 addr: ", &(ofl->fl6_src));
 	HIP_DEBUG_IN6ADDR("pkt out: dst IPv6 addr: ", &(ofl->fl6_dst));

	buf->checksum = csum_ipv6_magic(&(ofl->fl6_src), &(ofl->fl6_dst), len,
					ofl->proto, csum);
	HIP_DEBUG("pkt out: checksum value (host order): 0x%x\n",
		  ntohs(buf->checksum));

	if (buf->checksum == 0)
		buf->checksum = -1;

	_HIP_HEXDUMP("whole packet", buf, len);

 	err = ip6_append_data(hip_output_socket->sk, hip_getfrag, buf, len, 0,
			      0xFF, NULL, ofl, (struct rt6_info *)dst, MSG_DONTWAIT);
	if (err) {
 		HIP_ERROR("ip6_build_xmit failed (err=%d)\n", err);
		ip6_flush_pending_frames(hip_output_socket->sk);
	} else {
		err = ip6_push_pending_frames(hip_output_socket->sk);
		if (err)
			HIP_ERROR("Pushing of pending frames failed (%d)\n",
				  err);
	}

	release_sock(hip_output_socket->sk);

 out_err:
	return err;
}
