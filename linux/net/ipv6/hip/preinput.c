#include "preinput.h"

/**
 * hip_verify_network_header - validate an incoming HIP header
 * @hip_common: pointer to the HIP header
 * @skb: sk_buff in which the HIP packet is in
 *
 * Returns: zero if the HIP message header was ok, or negative error value on
 *          failure
 */
int hip_verify_network_header(struct hip_common *hip_common,
			      struct sk_buff **skb)
{
	int err = 0;
	uint16_t csum;

	HIP_DEBUG("skb len=%d, skb data_len=%d, v6hdr payload_len=%d msgtotlen=%d\n",
		  (*skb)->len, (*skb)->data_len,
		  ntohs((*skb)->nh.ipv6h->payload_len),
		  hip_get_msg_total_len(hip_common));

	if (ntohs((*skb)->nh.ipv6h->payload_len) !=
	     hip_get_msg_total_len(hip_common)) {
		HIP_ERROR("Invalid HIP packet length (IPv6 hdr payload_len=%d/HIP pkt payloadlen=%d). Dropping\n",
			  ntohs((*skb)->nh.ipv6h->payload_len),
			  hip_get_msg_total_len(hip_common));
		err = -EINVAL;
		goto out_err;
	}

	/* Currently no support for piggybacking */
	if (hip_common->payload_proto != IPPROTO_NONE) {
		HIP_ERROR("Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n", 
			  hip_common->payload_proto);
		err = -EOPNOTSUPP;
		goto out_err;
	}
	
	if ((hip_common->ver_res & HIP_VER_MASK) != HIP_VER_RES) {
		HIP_ERROR("Invalid version in received packet. Dropping\n");
		err = -EPROTOTYPE;
		goto out_err;
	}

	if (!hip_is_hit(&hip_common->hits)) {
		HIP_ERROR("Received a non-HIT in HIT-source. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

	if (!hip_is_hit(&hip_common->hitr) &&
	    !ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

	if (ipv6_addr_any(&hip_common->hits)) {
		HIP_ERROR("Received a NULL in HIT-sender. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

	/*
	 * XX FIXME: handle the RVS case better
	 */
	if (ipv6_addr_any(&hip_common->hitr)) {
		/* Required for e.g. BOS */
		HIP_DEBUG("Received opportunistic HIT\n");
#ifdef CONFIG_HIP_RVS
	} else
		HIP_DEBUG("Received HIT is ours or we are RVS\n");
#else
	} else if (!hip_hit_is_our(&hip_common->hitr)) {
		HIP_ERROR("Receiver HIT is not ours\n");
		err = -EFAULT;
		goto out_err;
	} else
		_HIP_DEBUG("Receiver HIT is ours\n");
#endif

	if (!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr)) {
		HIP_DEBUG("Dropping HIP packet. Loopback not supported.\n");
		err = -ENOSYS;
		goto out_err;
	}

        /* Check checksum. */
        /* jlu XXX: We should not write into received skbuffs! */
        csum = hip_common->checksum;
        hip_zero_msg_checksum(hip_common);
	/* Interop with Julien: no htons here */
        if (hip_csum_verify(*skb) != csum) {
	       HIP_ERROR("HIP checksum failed (0x%x). Should have been: 0x%x\n", 
			 csum, ntohs(hip_csum_verify(*skb)) );
	       err = -EBADMSG;
	}

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
	  - currently this is may break things...
	*/

#if 0
          if (ha->state == HIP_STATE_R2_SENT) {
		ha->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Transition to ESTABLISHED state from R2_SENT\n");
          }
#endif

	ipv6_addr_copy(&hdr->daddr, &xs->hit_our);
	ipv6_addr_copy(&hdr->saddr, &xs->hit_peer);

	/* hip_hadb_find_byspi_list gets are reference to the HA, so it needs
	   to be decremented here - there is no other way to do this */
#if 0 /* XX FIXME: probably breaks something? */
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
        struct hip_common *hip_common;
        struct hip_work_order *hwo;
	int err = 0;

	/* See if there is at least the HIP header in the packet */
        if (!pskb_may_pull(*skb, sizeof(struct hip_common))) {
		HIP_ERROR("Received packet too small. Dropping\n");
		goto out_err;
        }

        hip_common = (struct hip_common*) (*skb)->h.raw;
        /* TODO: use hip_state_str */
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);
	_HIP_DEBUG_SKB((*skb)->nh.ipv6h, skb);
	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     hip_get_msg_total_len(hip_common));

	err = hip_verify_network_header(hip_common, skb);
	if (err) {
		HIP_ERROR("Verifying of the network header failed\n");
		goto out_err;
	}

	err = hip_check_network_msg(hip_common);
	if (err) {
		HIP_ERROR("HIP packet is invalid\n");
		goto out_err;
	}

	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("No memory, dropping packet\n");
		err = -ENOMEM;
		goto out_err;
	}

	hwo->destructor = hip_hwo_input_destructor;

	/* should we do some early state processing now?
	 * we could prevent further DoSsing by dropping
	 * illegal packets right now.
	 */

	_HIP_DEBUG("Entering switch\n");
	hwo->hdr.type = HIP_WO_TYPE_INCOMING;
        //hwo->arg1 = *skb;
        hwo->msg = hip_common;

        /* We need to save the addresses because the actual input handlers
	   may need them later */
        memcpy(&hwo->hdr.src_addr, &(*skb)->nh.ipv6h->saddr,
		sizeof(struct in6_addr));
        memcpy(&hwo->hdr.dst_addr, &(*skb)->nh.ipv6h->daddr,
		sizeof(struct in6_addr));

        switch(hip_get_msg_type(hip_common)) {
	case HIP_I1:
		HIP_DEBUG("Received HIP I1 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_I1;
		break;
	case HIP_R1:
		HIP_DEBUG("Received HIP R1 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_R1;
		break;
	case HIP_I2:
		HIP_DEBUG("Received HIP I2 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_I2;
		break;
	case HIP_R2:
		HIP_DEBUG("Received HIP R2 packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_R2;
		break;
	case HIP_UPDATE:
		HIP_DEBUG("Received HIP UPDATE packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_UPDATE;
		break;
	case HIP_NOTIFY:
		HIP_DEBUG("Received HIP NOTIFY packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_NOTIFY;
		break;
	case HIP_BOS:
		HIP_DEBUG("Received HIP BOS packet\n");
		hwo->hdr.subtype = HIP_WO_SUBTYPE_RECV_BOS;
		break;
	default:
		HIP_ERROR("Received HIP packet of unknown/unimplemented type %d\n",
			  hip_common->type_hdr);
		kfree_skb(*skb);  /* sic */
		kfree(hwo);
		/*  KRISUXXX: return value? */
		return -1;
                break;
        }

        hip_insert_work_order(hwo);

 out_err:
	/* We must not use kfree_skb here... (worker thread releases) */
	// FIXME: this is a memory leak for now, as the skb is not free-ed anywhere! (tkoponen)

	return 0;
}





