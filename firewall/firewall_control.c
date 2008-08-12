/*
 * Firewall control
 * 
 */
 
#include "firewall_control.h"

int hip_fw_sock = 0;
int control_thread_started = 0;
//GThread * control_thread = NULL; 

void* run_control_thread(void* data)
{
	/* Variables. */
	int err = 0;
	int n;
	int len;
	int ret;
	int max_fd;
	struct hip_common *msg = (struct hip_common *)data;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval tv;

	HIP_DEBUG("Executing connection thread\n");

	HIP_DEBUG("Waiting messages...\n\n");
      
	/* Start handling. */

	control_thread_started = 1;
	while (control_thread_started)
	{
		FD_ZERO(&read_fdset);
		FD_SET(hip_fw_sock, &read_fdset);
		max_fd = hip_fw_sock;
		tv.tv_sec = HIP_SELECT_TIMEOUT;
		tv.tv_usec = 0;

		/* Wait for incoming packets. */
		if ((err = HIPD_SELECT((max_fd + 1), &read_fdset, 
				       NULL, NULL, &tv)) < 0) {
			HIP_ERROR("select() error: %s.\n", strerror(errno));
		} 
		else if (err == 0) {
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle\n");
		}
		else if (FD_ISSET(hip_fw_sock, &read_fdset))
		{
		}
		else {
			HIP_INFO("Unknown socket activity.\n");
		}
	}
out_err:
	/* Send quit message to daemon. */
	hip_build_user_hdr(msg, SO_HIP_FIREWALL_QUIT, 0);
	n = sendto_hipd(msg, sizeof(struct hip_common));
	if (n < 0) HIP_ERROR("Could not send quit message to daemon.\n");
	
	if (hip_fw_sock)
		close(hip_fw_sock);
	if (msg != NULL)
		HIP_FREE(msg);

	control_thread_started = 0;
	
	HIP_DEBUG("Connection thread exit.\n");

	return NULL;	
	
}

int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL;
	socklen_t alen;
	int type, err = 0, param_type;
	struct hip_keys *keys = NULL;
	struct in6_addr *hit_s = NULL, *hit_r = NULL;	
	
	HIP_DEBUG("Handling message from hipd\n");
	
	type = hip_get_msg_type(msg);
	
	switch(type) {
	case SO_HIP_FW_BEX_DONE:
	case SO_HIP_FW_UPDATE_DB:
	        handle_bex_state_update(msg);
	        break;
	case SO_HIP_IPSEC_ADD_SA:
		HIP_DEBUG("Received add sa request from hipd\n");
		HIP_IFEL(handle_sa_add_request(msg, param), -1, "hip userspace sadb add did NOT succeed\n");
		break;
	case SO_HIP_ADD_ESCROW_DATA:
		while((param = hip_get_next_param(msg, param)))
		{
			if (hip_get_param_type(param) == HIP_PARAM_HIT)
			{
				_HIP_DEBUG("Handling HIP_PARAM_HIT\n");
				if (!hit_s)
					hit_s = hip_get_param_contents_direct(param);
				else 
					hit_r =hip_get_param_contents_direct(param);
			}
			if (hip_get_param_type(param) == HIP_PARAM_KEYS)
			{
				_HIP_DEBUG("Handling HIP_PARAM_KEYS\n");	
				int alg;
				int auth_len;
				int key_len;
				int spi;
				
				keys = (struct hip_keys *)param;
				
				// TODO: Check values!!
				auth_len = 0;
				//op = ntohs(keys->operation);
		 		//spi = ntohl(keys->spi);
		 		spi = ntohl(keys->spi);
		 		//spi_old = ntohl(keys->spi_old);
		 		key_len = ntohs(keys->key_len);
		 		alg = ntohs(keys->alg_id);
				
				if (alg == HIP_ESP_3DES_SHA1)
					auth_len = 24;
				else if (alg == HIP_ESP_AES_SHA1)
					auth_len = 32;	
				else if (alg == HIP_ESP_NULL_SHA1)	
					auth_len = 32;	
				else	
					HIP_DEBUG("Authentication algorithm unsupported\n");
				err = add_esp_decryption_data(hit_s, hit_r, (struct in6_addr *)&keys->address, 
		     					      spi, alg, auth_len, key_len, &keys->enc);
		     		
				HIP_IFEL(err < 0, -1,"Adding esp decryption data failed"); 
				_HIP_DEBUG("Successfully added esp decryption data\n");	
			}
		}
	case SO_HIP_DELETE_ESCROW_DATA:
	{
                struct in6_addr * addr = NULL;
                uint32_t * spi = NULL;
                
                HIP_DEBUG("Received delete message from hipd\n\n");
                while((param = hip_get_next_param(msg, param)))
                {
                        
                        if (hip_get_param_type(param) == HIP_PARAM_HIT)
                        {
                                HIP_DEBUG("Handling HIP_PARAM_HIT\n");
                                addr = hip_get_param_contents_direct(param);
                        }
                        if (hip_get_param_type(param) == HIP_PARAM_UINT)
                        {
                                HIP_DEBUG("Handling HIP_PARAM_UINT\n");
                                spi = hip_get_param_contents(msg, HIP_PARAM_UINT);
                        }
                }
                if ((addr != NULL) && (spi != NULL)) {
                        HIP_IFEL(remove_esp_decryption_data(addr, *spi), -1, 
				 "Error while removing decryption data\n");
                }
		break;
	}
	case SO_HIP_SET_ESCROW_ACTIVE:
		HIP_DEBUG("Received activate escrow message from hipd\n");
		set_escrow_active(1);
		break;
	case SO_HIP_SET_ESCROW_INACTIVE:
		HIP_DEBUG("Received deactivate escrow message from hipd\n");
		set_escrow_active(0);
		break;
	case SO_HIP_SET_HIPPROXY_ON:
	        HIP_DEBUG("Received HIP PROXY STATUS: ON message from hipd\n");
	        HIP_DEBUG("Proxy is on\n");
		if (!hip_proxy_status)
			hip_fw_init_proxy();
		hip_proxy_status = 1;
		break;
	case SO_HIP_SET_HIPPROXY_OFF:
		HIP_DEBUG("Received HIP PROXY STATUS: OFF message from hipd\n");
		HIP_DEBUG("Proxy is off\n");
		if (hip_proxy_status)
			hip_fw_uninit_proxy();
		hip_proxy_status = 0;
		break;
	/*   else if(type == HIP_HIPPROXY_LOCAL_ADDRESS){
	     HIP_DEBUG("Received HIP PROXY LOCAL ADDRESS message from hipd\n");
	     if (hip_get_param_type(param) == HIP_PARAM_IPV6_ADDR)
		{
		_HIP_DEBUG("Handling HIP_PARAM_IPV6_ADDR\n");
		hit_s = hip_get_param_contents_direct(param);
		}
		}
	*/	
	case SO_HIP_SET_OPPTCP_ON:
		HIP_DEBUG("Opptcp on\n");
		if (!hip_opptcp)
			hip_fw_init_opptcp();
		hip_opptcp = 1;
		break;
	case SO_HIP_SET_OPPTCP_OFF:
		HIP_DEBUG("Opptcp on\n");
		if (hip_opptcp)
			hip_fw_uninit_opptcp();
		hip_opptcp = 0;
		break;
	default:
		HIP_ERROR("Unhandled message type %d\n", type);
		err = -1;
		break;
	}
 out_err:	
		
	return err;
}

int sendto_hipd(void *msg, size_t len)
{
	/* Variables. */
	struct sockaddr_in6 sock_addr;
	int n, alen;
	
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
    
	alen = sizeof(sock_addr);
	n = sendto(hip_fw_sock, msg, len, 0,
		   (struct sockaddr *)&sock_addr, alen);

	return (n);
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

u16 ipv4_checksum(u8 protocol, u8 src[], u8 dst[], u8 data[], u16 len)
{

	u16 word16;
	u32 sum;	
	u16 i;

	//initialize sum to zero
	sum=0;

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for (i=0;i<len;i=i+2){
		word16 =((((u16)(data[i]<<8)))&0xFF00)+(((u16)data[i+1])&0xFF);
		sum = sum + (unsigned long)word16;
	}	
	// add the TCP pseudo header which contains:
	// the IP source and destination addresses,
	for (i=0;i<4;i=i+2){
		word16 =((src[i]<<8)&0xFF00)+(src[i+1]&0xFF);
		sum=sum+word16;	
	}
	for (i=0;i<4;i=i+2)
	{
		word16 =((dst[i]<<8)&0xFF00)+(dst[i+1]&0xFF);
		sum=sum+word16; 	
	}
	// the protocol number and the length of the TCP packet
	sum = sum + protocol + len;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;
	return (htons((unsigned short) sum));
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
        int err = 0;
        int n;
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
        
        n = sendto_hipd(msg, hip_get_msg_total_len(msg));
        if (n < 0) {
                HIP_ERROR("HIP_HIPPROXY_STATUS_REQUEST: Sendto HIPD failed.\n");
                err = -1;
                goto out_err;
        }
        else {
                HIP_DEBUG("HIP_HIPPROXY_STATUS_REQUEST: Sendto firewall OK.\n");
        }  
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
		        if (dst_hit)
		                err = firewall_set_bex_state(src_hit, dst_hit, 1);
			else
			        err = firewall_set_bex_state(src_hit, dst_hit, -1);
			break;
                case SO_HIP_FW_UPDATE_DB:
		        err = firewall_set_bex_state(src_hit, dst_hit, 0);
			break;
                default:
		        break;
	}
	return err;
}
