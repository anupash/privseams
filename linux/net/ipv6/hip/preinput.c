#include "preinput.h"

/**
 * hip_csum_verify - verify HIP header checksum
 * @skb: the socket buffer which contains the HIP header
 *
 * Returns: the checksum of the HIP header.
 */
static int hip_csum_verify(struct sk_buff *skb)
{
	struct hip_common *hip_common;
	int len, csum;

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
 * hip_verify_network_header - validate an incoming HIP header
 * @hip_common: pointer to the HIP header
 * @skb: sk_buff in which the HIP packet is in
 *
 * Returns: zero if the HIP message header was ok, or negative error value on
 *          failure
 */
static int hip_verify_network_header(struct hip_common *hip_common,
				     struct sk_buff **skb)
{
	int err = 0;
	uint16_t csum;

	HIP_DEBUG("skb len=%d, skb data_len=%d, v6hdr payload_len=%d msgtotlen=%d\n",
		  (*skb)->len, (*skb)->data_len,
		  ntohs((*skb)->nh.ipv6h->payload_len),
		  hip_get_msg_total_len(hip_common));

	HIP_IFEL(ntohs((*skb)->nh.ipv6h->payload_len) !=
		 hip_get_msg_total_len(hip_common), -EINVAL,
		 "Invalid HIP packet length (IPv6 hdr payload_len=%d/HIP pkt payloadlen=%d). Dropping\n",
		 ntohs((*skb)->nh.ipv6h->payload_len),
		 hip_get_msg_total_len(hip_common));

	/* Currently no support for piggybacking */
	HIP_IFEL(hip_common->payload_proto != IPPROTO_NONE, -EOPNOTSUPP,
		 "Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n", 
		 hip_common->payload_proto);
	HIP_IFEL((hip_common->ver_res & HIP_VER_MASK) != HIP_VER_RES, -EPROTOTYPE,
		 "Invalid version in received packet. Dropping\n");
	HIP_IFEL(!hip_is_hit(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a non-HIT in HIT-source. Dropping\n");
	HIP_IFEL(!hip_is_hit(&hip_common->hitr) && !ipv6_addr_any(&hip_common->hitr), 
		 -EAFNOSUPPORT, "Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
	HIP_IFEL(ipv6_addr_any(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a NULL in HIT-sender. Dropping\n");

	/*
	 * XX FIXME: handle the RVS case better
	 */
	if (ipv6_addr_any(&hip_common->hitr)) {
		/* Required for e.g. BOS */
		HIP_DEBUG("Received opportunistic HIT\n");
	} else {
#ifdef CONFIG_HIP_RVS
		HIP_DEBUG("Received HIT is ours or we are RVS\n");
#else
	        HIP_IFEL(!hip_xfrm_hit_is_our(&hip_common->hitr), -EFAULT,
			 "Receiver HIT is not ours\n");

#endif
	}

	HIP_IFEL(!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr), -ENOSYS,
		 "Dropping HIP packet. Loopback not supported.\n");

        /* Check checksum. */
        csum = hip_common->checksum;
        hip_zero_msg_checksum(hip_common);
        HIP_IFEL(hip_csum_verify(*skb) != csum, -EBADMSG,
		 "HIP checksum failed (0x%x). Should have been: 0x%x\n", 
		 csum, ntohs(hip_csum_verify(*skb)));
 out_err:
	return err;
}

/**
 * hip_handle_esp - handle incoming ESP packet
 * @spi: SPI from the incoming ESP packet
 * @hdr: IPv6 header of the packet
 *
 * If the packet's SPI belongs to a HIP connection, the IPv6 addresses
 * are replaced with the corresponding HITs before the packet is
 * delivered to ESP.
 */
void hip_handle_esp(uint32_t spi, struct ipv6hdr *hdr)
{
        struct hip_xfrm_state *xs;

        /* XX FIX: the following call breaks kernel-only HIP */

	/* We are called only from bh.
	 * No locking will take place since the data
	 * that we are copying is very static
	 */
	_HIP_DEBUG("SPI=0x%x\n", spi);
	xs = hip_xfrm_find_by_spi(spi);
	if (!xs) {
		HIP_INFO("HT BYSPILIST: NOT found, unknown SPI 0x%x\n",spi);
		return;
	}

	/* New in draft-10: If we are responder and in some proper state, then
	   as soon as we receive ESP packets for a valid SA, we should
	   transition to ESTABLISHED state. Since we want to avoid excessive
	   hooks, we will do it here, although the SA check is done later...
	   (and the SA might be invalid).
	*/

        /* XX FIXME:
	  - xs->state is read-only in the kernel
	  - this can be removed if the state machine transitions directly
	    to established
	  - currently this is may break things?
	*/

#if 0
          if (ha->state == HIP_STATE_R2_SENT) {
		ha->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Transition to ESTABLISHED state from R2_SENT\n");
          }
#endif

	ipv6_addr_copy(&hdr->daddr, &xs->hit_our);
	ipv6_addr_copy(&hdr->saddr, &xs->hit_peer);

#if 0
	hip_put_ha(ha);
#endif
	return;
}

/**
 * hip_inbound - entry point for processing of an incoming HIP packet
 * @skb: sk_buff containing the HIP packet
 * @nhoff: XXX unused ?
 *
 * This function if the entry point for all incoming HIP packet. First
 * we try to parse and validate the HIP header, and if it is valid the
 * packet type is determined and control is passed to corresponding
 * handler function which processes the packet.
 *
 * We must free the skb by ourselves, if an error occures!
 *
 * Return 0, if packet accepted
 *       <0, if error
 *       >0, if other protocol payload (piggybacking)
 */
int hip_inbound(struct sk_buff **skb, unsigned int *nhoff)
{
        struct hip_common *hip_common = 
		(struct hip_common*) (*skb)->h.raw;
        struct hip_work_order *hwo = NULL;
	int len, err = 0;

	/* Should we do some early state processing now?  we could
 	   prevent further DoSsing by dropping illegal packets right
 	   now.  */
	/* See if there is at least the HIP header in the packet */
        HIP_IFEL(!pskb_may_pull(*skb, sizeof(struct hip_common)), 0,
		 "Received packet too small. Dropping\n");
        /* TODO: use hip_state_str */
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);
	_HIP_DEBUG_SKB((*skb)->nh.ipv6h, skb);
	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     hip_get_msg_total_len(hip_common));

	HIP_IFEL(hip_verify_network_header(hip_common, skb), -1, 
		 "Verifying of the network header failed\n");
	HIP_IFEL(hip_check_network_msg(hip_common), -1,
		 "HIP packet is invalid\n");
	HIP_IFEL(!(hwo = hip_init_job(GFP_ATOMIC)), -ENOMEM,
		 "No memory, dropping packet\n");

	len = hip_get_msg_total_len(hip_common);
        HIP_IFEL(!(hwo->msg = HIP_MALLOC(len, GFP_ATOMIC)), -ENOMEM,
		 "Out of memomry, dropping packet\n");
	memcpy(hwo->msg, hip_common, len);

        /* We need to save the addresses because the actual input
	   handlers may need them later */
	HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_INCOMING, 
				HIP_WO_SUBTYPE_RECV_CONTROL, &(*skb)->nh.ipv6h->saddr,
				&(*skb)->nh.ipv6h->daddr, 0, 0);
        hip_insert_work_order(hwo);

 out_err:
	if (err) 
		HIP_FREE(hwo);
	kfree_skb(*skb);
	return 0;
}





