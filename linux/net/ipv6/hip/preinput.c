#include "preinput.h"

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
	hip_xfrm_state *xs;

	/* We are called only from bh.
	 * No locking will take place since the data
	 * that we are copying is very static
	 */
	_HIP_DEBUG("SPI=0x%x\n", spi);
	xs = hip_xfrm_find(spi);
	if (!xs) {
		HIP_INFO("HT BYSPILIST: NOT found, unknown SPI 0x%x\n",spi);
		return;
	}

	/* New in draft-10: If we are responder and in some proper state, then
	   as soon as we receive ESP packets for a valid SA, we should transition
	   to ESTABLISHED state.
	   Since we want to avoid excessive hooks, we will do it here, although the
	   SA check is done later... (and the SA might be invalid).
	*/
     /*	if (ha->state == HIP_STATE_R2_SENT) {
		ha->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Transition to ESTABLISHED state from R2_SENT\n");
          FIXME: tkoponen, miika said this could be removed.. note, xs->state is readonly in kernel!
          }*/

	ipv6_addr_copy(&hdr->daddr, &xs->hit_our);
	ipv6_addr_copy(&hdr->saddr, &xs->hit_peer);

     //	hip_put_ha(ha); FIXME: tkoponen, what is this doing here?
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
	hwo->type = HIP_WO_TYPE_INCOMING;
        //hwo->arg1 = *skb;
        hwo->msg = hip_common;

        /* We need to save the addresses because the actual input handlers
	   may need them later */
        memcpy(&hwo->hdr.src_addr, (*skb)->nh.ipv6h->saddr,
		sizeof(struct in6_addr));
        memcpy(&hwo->hdr.dst_addr, (*skb)->nh.ipv6h->daddr,
		sizeof(struct in6_addr));

        switch(hip_get_msg_type(hip_common)) {
	case HIP_I1:
		HIP_DEBUG("Received HIP I1 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_I1;
		break;
	case HIP_R1:
		HIP_DEBUG("Received HIP R1 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_R1;
		break;
	case HIP_I2:
		HIP_DEBUG("Received HIP I2 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_I2;
		break;
	case HIP_R2:
		HIP_DEBUG("Received HIP R2 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_R2;
		break;
	case HIP_UPDATE:
		HIP_DEBUG("Received HIP UPDATE packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_UPDATE;
		break;
	case HIP_NOTIFY:
		HIP_DEBUG("Received HIP NOTIFY packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_NOTIFY;
		break;
	case HIP_BOS:
		HIP_DEBUG("Received HIP BOS packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_BOS;
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

	return 0;
}
