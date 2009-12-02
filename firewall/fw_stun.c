#include "fw_stun.h"
extern int hip_fw_async_sock;

// add a database here for TURN
// hashtable with key = SPI, value = hip_turn_info
// see libopphip/wrap_db.c

int hip_fw_handle_turn_esp_output(hip_fw_context_t* ctx){
	/* XX FIXME */
	/* Map SPI number to TURN information from TURN database */
	/* Allocate some memory for new packet and copy relevant fields */
	/* Rewrite source port and add extra field for TURN */
	/* Recalculate UDP checksum */
	/* Add length of TURN field to IP header and recalculate IP checksum */
	/* Reinject the new packet using a raw socket (with sendto(), see e.g. firewall_send_outgoing_pkt) */

	/* Deallocate memory for new packet */
	return DROP;
}


int hip_fw_handle_stun_packet(hip_fw_context_t* ctx) {
	struct hip_common *hip_msg = NULL;
	struct udphdr *incoming_udp_msg;
	struct ip *incoming_ip_msg;
	int err = 0;
	uint16_t udp_len;

	if (esp_relay) {
		DList *list;
		int recv = 0;

		if ((list = get_tuples_by_nat(ctx)))
		{
			struct iphdr *iph;
			struct tuple *tuple;
			int len;

			for (list = list_first(list); list; list = list->next) {
				tuple = list->data;
				if (hip_fw_hit_is_our(&tuple->hip_tuple->data->dst_hit)) {
					recv = 1;
					continue;
				}
				if (!tuple->dst_ip)
					continue;

				iph = (struct iphdr *)ctx->ipq_packet->payload;
				len = ctx->ipq_packet->data_len - iph->ihl * 4;

				HIP_DEBUG("Relaying STUN packet\n");
				firewall_send_outgoing_pkt(&ctx->dst, tuple->dst_ip,
					(u8 *)iph + iph->ihl * 4, len, IPPROTO_UDP);
			}
		if (!recv)
			goto out_err;
		}
	}

	incoming_ip_msg = ctx->ip_hdr.ipv4;
	incoming_udp_msg = ctx->udp_encap_hdr;
	udp_len = ntohs(ctx->udp_encap_hdr->len);
	
	HIP_IFEL(!(hip_msg = hip_msg_alloc()), -ENOMEM, "Allocation failed\n");

	HIP_IFEL(hip_build_user_hdr(hip_msg, SO_HIP_STUN, 0), -1, "hdr\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  incoming_udp_msg + 1,
					  HIP_PARAM_STUN,
					  udp_len - sizeof(struct udphdr)),
		 -1, "build_param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &incoming_udp_msg->dest,
					  HIP_PARAM_LOCAL_NAT_PORT,
					  sizeof(incoming_udp_msg->dest)),
		 -1, "build param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &incoming_udp_msg->source,
					  HIP_PARAM_PEER_NAT_PORT,
					  sizeof(incoming_udp_msg->source)),
		 -1, "build param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &ctx->dst,
					  HIP_PARAM_IPV6_ADDR_LOCAL,
					  sizeof(ctx->dst)),
		 -1, "build param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &ctx->src,
					  HIP_PARAM_IPV6_ADDR_PEER,
					  sizeof(ctx->src)),
		 -1, "build param\n");

	HIP_IFEL(hip_send_recv_daemon_info(hip_msg, 1, hip_fw_async_sock), -1,
		 "send/recv daemon info\n");

	HIP_DEBUG("STUN message forwarded to hipd successfully\n");
					  
 out_err:
	if (hip_msg)
		free(hip_msg);
	return err;
}
