#include "common_hipd_msg.h"
#include "libhipcore/ife.h"
#include "libhipcore/debug.h"
#include "libhipcore/builder.h"
#include "firewall.h"

/**
 * Gets the state of the bex for a pair of ip addresses.
 * @param src_ip	input for finding the correct entries
 * @param dst_ip	input for finding the correct entries
 * @param src_hit	output data of the correct entry
 * @param dst_hit	output data of the correct entry
 * @param src_lsi	output data of the correct entry
 * @param dst_lsi	output data of the correct entry
 *
 * @return		the state of the bex if the entry is found
 *			otherwise returns -1
 */
int hip_get_bex_state_from_IPs(const struct in6_addr *src_ip,
		      	const struct in6_addr *dst_ip,
		      	struct in6_addr *src_hit,
		      	struct in6_addr *dst_hit,
		      	hip_lsi_t *src_lsi,
		      	hip_lsi_t *dst_lsi){
	int err = 0, res = -1;
	struct hip_tlv_common *current_param = NULL;
	struct hip_common *msg = NULL;
	struct hip_hadb_user_info_state *ha;

	HIP_ASSERT(src_ip != NULL && dst_ip != NULL);

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
			-1, "Building of daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send recv daemon info\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
		ha = hip_get_param_contents_direct(current_param);

		if( (ipv6_addr_cmp(dst_ip, &ha->ip_our) == 0) &&
		    (ipv6_addr_cmp(src_ip, &ha->ip_peer) == 0) ){
			memcpy(src_hit, &ha->hit_peer, sizeof(struct in6_addr));
			memcpy(dst_hit, &ha->hit_our, sizeof(struct in6_addr));
			memcpy(src_lsi, &ha->lsi_peer, sizeof(hip_lsi_t));
			memcpy(dst_lsi, &ha->lsi_our, sizeof(hip_lsi_t));
			res = ha->state;
			break;
		}else if( (ipv6_addr_cmp(src_ip, &ha->ip_our) == 0) &&
		         (ipv6_addr_cmp(dst_ip, &ha->ip_peer) == 0) ){
			memcpy(src_hit, &ha->hit_our, sizeof(struct in6_addr));
			memcpy(dst_hit, &ha->hit_peer, sizeof(struct in6_addr));
			memcpy(src_lsi, &ha->lsi_our, sizeof(hip_lsi_t));
			memcpy(dst_lsi, &ha->lsi_peer, sizeof(hip_lsi_t));
			res = ha->state;
			break;
		}
	}

 out_err:
        if(msg)
                HIP_FREE(msg);
        return res;

}
