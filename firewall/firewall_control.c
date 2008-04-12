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
	struct sockaddr_in6 sock_addr;
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
			HIP_DEBUG("****** Received HIPD message ******\n");
			bzero(&sock_addr, sizeof(sock_addr));
			alen = sizeof(sock_addr);
			n = recvfrom(hip_firewall_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&sock_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Error receiving message header from daemon.\n");
				err = -1;
				goto out_err;
			}

			_HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			_HIP_DEBUG("Receiving message (%d bytes)\n", len);
			n = recvfrom(hip_firewall_sock, msg, len, 0,
		             (struct sockaddr *)&sock_addr, &alen);

			if (n < 0)
			{
				HIP_ERROR("Error receiving message parameters from daemon.\n");
				err = -1;
				goto out_err;
			}

			HIP_ASSERT(n == len);
		
			err = handle_msg(msg, &sock_addr);
			if (err < 0){
				HIP_ERROR("Error handling message\n");
				//goto out_err;	 
			}
		}
		else {
			HIP_INFO("Unknown socket activity.\n");
		}
	}
out_err:
	/* Send quit message to daemon. */
	hip_build_user_hdr(msg, HIP_FIREWALL_QUIT, 0);
	n = sendto_hipd(msg, sizeof(struct hip_common));
	if (n < 0) HIP_ERROR("Could not send quit message to daemon.\n");
	
	if (hip_firewall_sock) close(hip_firewall_sock);
	if (msg != NULL) HIP_FREE(msg);

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
	

	_HIP_DEBUG("Handling message from hipd\n");
	type = hip_get_msg_type(msg);

	//for(param = hip_get_next_) {
	//	switch (type = hip_get_param_type(param))) 
	//      PARAM_XX:
	//      break;
	//}
	
	switch(type) 
	
	{

	
	case HIP_FIREWALL_BEX_DONE: {
		
		struct in6_addr *saddr = NULL, *daddr = NULL;
		struct in6_addr *src_hit = NULL, *dst_hit = NULL;
		uint32_t *spi_ipsec = NULL;
		int ealg;
		struct hip_crypto_key *enckey = NULL, *authkey = NULL;
		int already_acquired, direction, update, sport, dport;
		struct hip_tlv_t *param;
		
		HIP_DEBUG("Received base exchange done from hipd\n\n");
		
		/* now param: src addr */
		

		param = (struct hip_tlv_t *) hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
		saddr = (struct in6_addr *) hip_get_param_contents_direct(param); 
		HIP_DEBUG_IN6ADDR("Received in6_addr: ", saddr);
		
                /* now param: dst addr */
		 
		param = hip_get_next_param(msg, param);
		daddr = (struct in6_addr *) hip_get_param_contents_direct(param);
		HIP_DEBUG_IN6ADDR("Received in6_addr: ", daddr);		

		
		
		param =  (struct hip_tlv_t *) hip_get_param(msg, HIP_PARAM_HIT);

		/* now param: src_hit */
		src_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
		
		HIP_DEBUG_HIT("Received src_hit: ", src_hit);
		
		/* now param: dst_hit */
		
		param =  hip_get_next_param(msg, param);
		dst_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
		
		HIP_DEBUG_HIT("Received dst_hit: ", dst_hit);
		

		param =  (struct hip_tlv_t *) hip_get_param(msg, HIP_PARAM_UINT);
		
		/* now param: spi */
		spi_ipsec = (uint32_t *) hip_get_param_contents_direct(param);
		
		HIP_DEBUG("the spi value is %x \n", *spi_ipsec);
		
		
		
		param =  hip_get_next_param(msg, param);
		sport = *((unsigned int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the source port vaule is %d \n", sport);
		
		param =  hip_get_next_param(msg, param);
		dport = *((unsigned int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the destination port value is %d \n", dport);

		
		
		
		param =  (struct hip_tlv_t *) hip_get_param(msg, HIP_PARAM_KEYS);
		
		
                 /* now param: enckey */
		enckey = (struct hip_crypto_key *) hip_get_param_contents_direct(param);
		
		
		

		// HIP_DEBUG("crypto key is: \n");
		HIP_HEXDUMP("crypto key :", enckey, sizeof(struct hip_crypto_key));
		

		/* now param: anthkey */
		
		param =  hip_get_next_param(msg, param);
		authkey = (struct hip_crypto_key *)hip_get_param_contents_direct(param);
		// HIP_DEBUG("auth key key is: \n"); 
		
		
		HIP_HEXDUMP("authen key :", authkey, sizeof(struct hip_crypto_key));

		
		/* now param: ealg */
		param =  (struct hip_tlv_t *) hip_get_param(msg, HIP_PARAM_INT);
		
		ealg = *((int *) hip_get_param_contents_direct(param));
		
		HIP_DEBUG("ealg  value is %d \n", ealg);

		/* now param: already_acquired */
		param =  hip_get_next_param(msg, param);		
		already_acquired = *((int *) hip_get_param_contents_direct( param));
		HIP_DEBUG("already_acquired value is %d \n", already_acquired);

		/* now param: direction */
		param =  hip_get_next_param(msg, param);		
		direction = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the direction value is %d \n", direction);
		
                /* now param: update */

		param =  hip_get_next_param(msg, param);
		update = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("the update value is %d \n", update);
		
		
		
		
		err =  hipl_userspace_ipsec_api_wrapper_sadb_add(saddr, daddr, 
								 src_hit, dst_hit, 
								 spi_ipsec, ealg, enckey, 
								 authkey, already_acquired, 
								 direction, update, 
								 sport, dport);
		
		
		if (err < 0) {
			HIP_ERROR("hip userspace sadb add went wrong\n\n");
			goto out_err;
		}
		
		break;
	}

	case HIP_ADD_ESCROW_DATA:
		while((param = hip_get_next_param(msg, param)))
		{
			struct hip_keys * keys = NULL;
			struct in6_addr * hit_s = NULL;
			struct in6_addr * hit_r = NULL;
			
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
		break;
	case HIP_DELETE_ESCROW_DATA: 
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
                
		break;
        case HIP_SET_ESCROW_ACTIVE: 
                HIP_DEBUG("Received activate escrow message from hipd\n\n");
                set_escrow_active(1);
                
		break;
	case HIP_SET_ESCROW_INACTIVE: 
                HIP_DEBUG("Received deactivate escrow message from hipd\n\n");
                set_escrow_active(0);
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
	sock_addr.sin6_port = HIP_DAEMON_LOCAL_PORT;
	sock_addr.sin6_addr = in6addr_loopback;
    
	alen = sizeof(sock_addr);
	n = sendto(hip_firewall_sock, msg, len, 0, (struct sockaddr *)&sock_addr, alen);

	return (n);
}


int control_thread_init(void)
{
   int err = 0;
	int n;
	int len;
    struct sockaddr_in6 sock_addr;
    
	struct hip_common *msg = NULL;
	socklen_t alen;

	/* Allocate message. */
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}

	/*New UDP socket for communication with HIPD*/
	hip_firewall_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_firewall_sock < 0), 1, "Could not create socket for firewall.\n");
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(bind(hip_firewall_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed\n");

    	if( !g_thread_supported() )
  		{
     		g_thread_init(NULL);
     		HIP_DEBUG("control_thread_init: initialized thread system\n");
  		}
  		else
  		{
     		HIP_DEBUG("control_thread_init: thread system already initialized\n");
  		}
    	control_thread_started = 1;
    	control_thread = g_thread_create(run_control_thread, 
					   (gpointer)msg, 
					   FALSE,
					   NULL);   
		if (!control_thread)
		HIP_DEBUG("Could not initialize control_thread\n");			   

	return 0;

out_err:
	if (hip_firewall_sock) close(hip_firewall_sock);
	if (msg != NULL) HIP_FREE(msg);

	return err;			   
}

