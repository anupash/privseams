#include "libhipcore/debug.h"
#include "libhipcore/builder.h"

#include "sysopp.h"
#include "firewall.h"
#include "firewalldb.h"
#include "lsi.h"
#include "common_hipd_msg.h"

/**
 * Checks whether a particular hit is one of the local ones.
 * Goes through all the local hits and compares with the given hit.
 *
 * @param *hit	the input src hit
 *
 * @return	1 if *hit is a local hit
 * 		0 otherwise
 */
static int hit_is_local_hit(const struct in6_addr *hit){
	struct hip_tlv_common *current_param = NULL;
	struct hip_hit_info   *info = NULL;
	struct hip_common     *msg = NULL;
	hip_tlv_type_t         param_type = 0;
	int res = 0, err = 0;

	HIP_DEBUG("\n");

	/* Build a HIP message with socket option to get all HITs. */
	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFE(hip_build_user_hdr(msg, SO_HIP_GET_HITS, 0), -1);

	/* Send the message to the daemon.
	The daemon fills the message. */
	HIP_IFE(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -ECOMM);

	/* Loop through all the parameters in the message just filled. */
	while((current_param = hip_get_next_param(msg, current_param)) != NULL){

		param_type = hip_get_param_type(current_param);

		if(param_type == HIP_PARAM_HIT_INFO){
			info = (struct hip_hit_info *)
				hip_get_param_contents_direct(
					current_param);

			if(ipv6_addr_cmp(hit, &info->lhi.hit) == 0)
				return 1;
		}
	}
 out_err:
	return res;
}

static void hip_fw_add_non_hip_peer(const hip_fw_context_t *ctx, const int verdict)
{
	char command[64];
	char addr_str[INET_ADDRSTRLEN];
	struct in_addr addr_v4;

	IPV6_TO_IPV4_MAP(&ctx->dst, &addr_v4);

	if (!inet_ntop(AF_INET, &addr_v4, addr_str,
				sizeof(struct sockaddr_in))) {
		HIP_ERROR("inet_ntop() failed\n");
		return;
	}

	HIP_DEBUG("Adding rule for non-hip-capable peer: %s\n", addr_str);

	snprintf(command, sizeof(command), "iptables -I HIPFWOPP-INPUT -s %s -j %s",
			addr_str, verdict ? "ACCEPT" : "DROP");
	if ( system(command) == -1 ) {
		HIP_ERROR("Cannot execure %s", command);
	};
	snprintf(command, sizeof(command), "iptables -I HIPFWOPP-OUTPUT -d %s -j %s",
			addr_str, verdict ? "ACCEPT" : "DROP");
	if (system(command) == -1 ) {
		HIP_ERROR("Cannot execure %s", command);
	};
}

/**
 * Checks if the outgoing packet has already ESTABLISHED
 * the Base Exchange with the peer host. In case the BEX
 * is not done, it triggers it. Otherwise, it looks up
 * in the local database the necessary information for
 * doing the packet reinjection with HITs.
 *
 * @param *ctx	the contect of the packet
 * @return	the verdict for the packet
 */
int hip_fw_handle_outgoing_system_based_opp(const hip_fw_context_t *ctx, const int default_verdict) {
	int state_ha, fallback, reject, new_fw_entry_state;
	hip_lsi_t src_lsi, dst_lsi;
	struct in6_addr src_hit, dst_hit;
	firewall_hl_t *entry_peer = NULL;
	struct sockaddr_in6 all_zero_hit;
	int verdict = default_verdict;

	HIP_DEBUG("\n");

	//get firewall db entry
	entry_peer = firewall_ip_db_match(&ctx->dst);
	if (entry_peer) {
		//if the firewall entry is still undefined
		//check whether the base exchange has been established
		if (entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT) {
			//get current connection state from hipd
			state_ha = hip_get_bex_state_from_IPs(&ctx->src,
							      &ctx->dst,
							      &src_hit,
							      &dst_hit,
							      &src_lsi,
							      &dst_lsi);

			//find the correct state for the fw entry state
			if (state_ha == HIP_STATE_ESTABLISHED)
				new_fw_entry_state = FIREWALL_STATE_BEX_ESTABLISHED;
			else if ((state_ha == HIP_STATE_FAILED)  ||
				 (state_ha == HIP_STATE_CLOSING) ||
				 (state_ha == HIP_STATE_CLOSED)) {
				new_fw_entry_state = FIREWALL_STATE_BEX_NOT_SUPPORTED;

			} else
				new_fw_entry_state = FIREWALL_STATE_BEX_DEFAULT;

			HIP_DEBUG("New state %d\n", new_fw_entry_state);
			//update fw entry state accordingly
			firewall_update_entry(&src_hit, &dst_hit, &dst_lsi,
					      &ctx->dst, new_fw_entry_state);

			//reobtain the entry in case it has been updated
			entry_peer = firewall_ip_db_match(&ctx->dst);
		}

		//decide what to do with the packet
		if(entry_peer->bex_state == FIREWALL_STATE_BEX_DEFAULT)
			verdict = 0;
		else if (entry_peer->bex_state == FIREWALL_STATE_BEX_NOT_SUPPORTED) {
			hip_fw_add_non_hip_peer(ctx, verdict);
			verdict = default_verdict;
		} else if (entry_peer->bex_state == FIREWALL_STATE_BEX_ESTABLISHED){
			if( &entry_peer->hit_our                       &&
			    (ipv6_addr_cmp(hip_fw_get_default_hit(),
					   &entry_peer->hit_our) == 0)    ){
				reinject_packet(&entry_peer->hit_our,
						&entry_peer->hit_peer,
						ctx->ipq_packet, 4, 0);
				verdict = 0;
			} else {
				verdict = default_verdict;
			}
		}
	} else {
		/* add default entry in the firewall db */
		firewall_add_default_entry(&ctx->dst);

		/* get current connection state from hipd */
		state_ha = hip_get_bex_state_from_IPs(&ctx->src, &ctx->dst,
						      &src_hit, &dst_hit,
						      &src_lsi, &dst_lsi);
		if (state_ha == -1) {
			hip_hit_t *def_hit = hip_fw_get_default_hit();
			HIP_DEBUG("Initiate bex at firewall\n");
			memset(&all_zero_hit, 0, sizeof(struct sockaddr_in6));
			hip_request_peer_hit_from_hipd_at_firewall(
				&ctx->dst,
				&all_zero_hit.sin6_addr,
				(const struct in6_addr *) def_hit,
				(in_port_t *) &(ctx->transport_hdr.tcp)->source,
				(in_port_t *) &(ctx->transport_hdr.tcp)->dest,
				&fallback,
				&reject);
			verdict = 0;
		} else if (state_ha == HIP_STATE_ESTABLISHED) {
			if (hit_is_local_hit(&src_hit)) {
				HIP_DEBUG("is local hit\n");
				firewall_update_entry(&src_hit, &dst_hit,
						      &dst_lsi, &ctx->dst,
						      FIREWALL_STATE_BEX_ESTABLISHED);
				reinject_packet(&src_hit, &dst_hit,
						ctx->ipq_packet, 4, 0);
				verdict = 0;
			} else {
				verdict = default_verdict;
			}
		} else if ((state_ha == HIP_STATE_FAILED)  ||
			  (state_ha == HIP_STATE_CLOSING) ||
			   (state_ha == HIP_STATE_CLOSED)) {
			verdict = default_verdict;
		} else {
			verdict = 0;
		}
	}

	return verdict;
}

int hip_fw_sys_opp_set_peer_hit(const struct hip_common *msg) {
	int err = 0, state;
	hip_hit_t *local_hit, *peer_hit;
	struct in6_addr *peer_addr;
	hip_lsi_t *local_addr;

	local_hit = hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
	peer_hit = hip_get_param_contents(msg, HIP_PARAM_HIT_PEER);
	local_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_LOCAL);
	peer_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);
	if (peer_hit)
		state = FIREWALL_STATE_BEX_ESTABLISHED;
	else
		state = FIREWALL_STATE_BEX_NOT_SUPPORTED;
	firewall_update_entry(local_hit, peer_hit, local_addr,
			      peer_addr, state);

	return err;
}
