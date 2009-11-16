/*
 * Firewall control
 *
 */

#include "firewall_control.h"

int control_thread_started = 0;


void hip_fw_uninit_esp_relay();

int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL;
	socklen_t alen;
	int type, err = 0, param_type;
	struct hip_keys *keys = NULL;
	struct in6_addr *hit_s = NULL, *hit_r = NULL;
	extern int hip_lsi_support;

	HIP_DEBUG("Handling message from hipd\n");

	type = hip_get_msg_type(msg);

	switch(type) {
	case SO_HIP_FW_I2_DONE:
		break;
	case SO_HIP_FW_BEX_DONE:
	case SO_HIP_FW_UPDATE_DB:
	        if(hip_lsi_support)
	          handle_bex_state_update(msg);
		break;
	case SO_HIP_IPSEC_ADD_SA:
		HIP_DEBUG("Received add sa request from hipd\n");
		HIP_IFEL(handle_sa_add_request(msg), -1,
				"hip userspace sadb add did NOT succeed\n");
		break;
	case SO_HIP_IPSEC_DELETE_SA:
		HIP_DEBUG("Received delete sa request from hipd\n");
		HIP_IFEL(handle_sa_delete_request(msg), -1,
				"hip userspace sadb delete did NOT succeed\n");
		break;
	case SO_HIP_IPSEC_FLUSH_ALL_SA:
		HIP_DEBUG("Received flush all sa request from hipd\n");
		HIP_IFEL(handle_sa_flush_all_request(msg), -1,
				"hip userspace sadb flush all did NOT succeed\n");
		break;
	case SO_HIP_RESET_FIREWALL_DB:
		hip_firewall_cache_delete_hldb();
		hip_firewall_delete_hldb();
		break;
	default:
		HIP_ERROR("Unhandled message type %d\n", type);
		err = -1;
		break;
	}
 out_err:

	return err;
}

inline u16 inchksum(const void *data, u32 length){
	long sum = 0;
    	const u16 *wrd =  (u16 *) data;
    	long slen = (long) length;

    	while (slen > 1) {
        	sum += *wrd++;
        	slen -= 2;
    	}

    	if (slen > 0)
        	sum += * ((u8 *)wrd);

    	while (sum >> 16)
        	sum = (sum & 0xffff) + (sum >> 16);

    	return (u16) sum;
}

u16 ipv6_checksum(u8 protocol, struct in6_addr *src, struct in6_addr *dst, void *data, u16 len)
{
	u32 chksum = 0;
    	pseudo_v6 pseudo;
    	memset(&pseudo, 0, sizeof(pseudo_v6));

    	pseudo.src = *src;
    	pseudo.dst = *dst;
    	pseudo.length = htons(len);
    	pseudo.next = protocol;

    	chksum = inchksum(&pseudo, sizeof(pseudo_v6));
    	chksum += inchksum(data, len);

    	chksum = (chksum >> 16) + (chksum & 0xffff);
    	chksum += (chksum >> 16);

    	chksum = (u16)(~chksum);
    	if (chksum == 0)
    		chksum = 0xffff;

    	return chksum;
}

#ifdef CONFIG_HIP_HIPPROXY
int request_hipproxy_status(void)
{
        struct hip_common *msg = NULL;
        int err = 0, n;
        socklen_t alen;
        HIP_DEBUG("Sending hipproxy msg to hipd.\n");
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg,
                SO_HIP_HIPPROXY_STATUS_REQUEST, 0),
                -1, "Build hdr failed\n");

        //n = hip_sendto(msg, &hip_firewall_addr);

        //n = sendto(hip_fw_sock, msg, hip_get_msg_total_len(msg),
        //		0,(struct sockaddr *)dst, sizeof(struct sockaddr_in6));

        HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
		 "HIP_HIPPROXY_STATUS_REQUEST: Sendto HIPD failed.\n");
	HIP_DEBUG("HIP_HIPPROXY_STATUS_REQUEST: Sendto hipd ok.\n");

out_err:
	if(msg)
		free(msg);
        return err;
}
#endif /* CONFIG_HIP_HIPPROXY */

int handle_bex_state_update(struct hip_common * msg)
{
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	struct hip_tlv_common *param = NULL;
	int err = 0, msg_type = 0;

	msg_type = hip_get_msg_type(msg);

	/* src_hit */
        param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HIT);
	src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source HIT: ", src_hit);

	/* dst_hit */
	param = hip_get_next_param(msg, param);
	dst_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

	/* update bex_state in firewalldb */
	switch(msg_type)
	{
	        case SO_HIP_FW_BEX_DONE:
		        err = firewall_set_bex_state(src_hit,
						     dst_hit,
						     (dst_hit ? 1 : -1));
			break;
                case SO_HIP_FW_UPDATE_DB:
		        err = firewall_set_bex_state(src_hit, dst_hit, 0);
			break;
                default:
		        break;
	}
	return err;
}
