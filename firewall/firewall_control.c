/*
 * Firewall control
 * 
 */
 
#include "firewall_control.h"


int hip_firewall_sock = 0;
int control_thread_started = 0;
GThread * control_thread = NULL; 


gpointer run_control_thread(gpointer data)
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
		FD_SET(hip_firewall_sock, &read_fdset);
		max_fd = hip_firewall_sock;
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
		else if (FD_ISSET(hip_firewall_sock, &read_fdset))
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
	
	if (hip_firewall_sock)
		close(hip_firewall_sock);
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
	hip_hdr_type_t type;
	socklen_t alen;
	int err = 0;
	

	HIP_DEBUG("Handling message from hipd\n");
	type = hip_get_msg_type(msg);
	
	if (type == SO_HIP_ADD_ESCROW_DATA)
	{
		struct hip_keys * keys = NULL;
		struct in6_addr * hit_s = NULL;
		struct in6_addr * hit_r = NULL;
		
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
		     	if (err < 0) {
		     		HIP_ERROR("Adding esp decryption data failed");
		     		goto out_err;
		     	}
				_HIP_DEBUG("Successfully added esp decryption data\n");	
			}
		}
	}
	else if (type == SO_HIP_DELETE_ESCROW_DATA) {
                HIP_DEBUG("Received delete message from hipd\n\n");
                struct in6_addr * addr = NULL;
                uint32_t * spi = NULL;
                
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
                
	}

    else if (type == SO_HIP_SET_ESCROW_ACTIVE) {
            HIP_DEBUG("Received activate escrow message from hipd\n\n");
            set_escrow_active(1);
            
    }
    else if (type == SO_HIP_SET_ESCROW_INACTIVE) {
            HIP_DEBUG("Received deactivate escrow message from hipd\n\n");
            set_escrow_active(0);
    }
    else if (type == SO_HIP_SET_HIPPROXY_ON){
	        HIP_DEBUG("Received HIP PROXY STATUS: ON message from hipd\n\n");
	        HIP_DEBUG("Firewall is working on Proxy Mode!\n\n");
	        hip_proxy_status = 1;
	        firewall_init_rules();
    }
    else if (type == SO_HIP_SET_HIPPROXY_OFF){
	        HIP_DEBUG("Received HIP PROXY STATUS: OFF message from hipd\n\n");
  	        HIP_DEBUG("Firewall is working on Firewall Mode!\n\n");
	        hip_proxy_status = 0;
	        firewall_init_rules();
    }
 /*   else if(type == HIP_HIPPROXY_LOCAL_ADDRESS){
	    	HIP_DEBUG("Received HIP PROXY LOCAL ADDRESS message from hipd\n\n");
		if (hip_get_param_type(param) == HIP_PARAM_IPV6_ADDR)
		{
			_HIP_DEBUG("Handling HIP_PARAM_IPV6_ADDR\n");
			hit_s = hip_get_param_contents_direct(param);
		}
    }
*/	

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
	n = sendto(hip_firewall_sock, msg, len, 0,
		   (struct sockaddr *)&sock_addr, alen);

	return (n);
}


#ifdef CONFIG_HIP_HIPPROXY
int request_hipproxy_status(void)
{
        struct hip_common *msg;
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
        
        //n = sendto(hip_firewall_sock, msg, hip_get_msg_total_len(msg),
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
        return err;
}
#endif /* CONFIG_HIP_HIPPROXY */
