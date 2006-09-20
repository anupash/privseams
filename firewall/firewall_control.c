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
	HIP_DEBUG("Executing connection thread\n");

/* Variables. */
	int err = 0;
	int n;
	int len;
	int ret;
	int max_fd;
	struct sockaddr_un sock_addr;
	struct hip_common *msg = (struct hip_common *)data;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval tv;

	HIP_DEBUG("Waiting messages...\n");

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
			HIP_DEBUG("****** Received HIPD packet ******\n");
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

			HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			HIP_DEBUG("Receiving message (%d bytes)\n", len);
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

int handle_msg(struct hip_common * msg, struct sockaddr_un * sock_addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL;
	hip_hdr_type_t type;
	socklen_t alen;
	int err = 0;
	

	HIP_DEBUG("Handling message from hipd\n");
	type = hip_get_msg_type(msg);
	
	if (type == HIP_ADD_ESCROW_DATA)
	{
		struct hip_keys * keys = NULL;
		struct in6_addr * hit_s = NULL;
		struct in6_addr * hit_r = NULL;
		
		HIP_DEBUG("Message received successfully from daemon with type" 
			" SO_HIP_ADD_ESCROW_DATA (%d).\n", type);

		while((param = hip_get_next_param(msg, param)))
		{
			
			if (hip_get_param_type(param) == HIP_PARAM_HIT)
			{
				HIP_DEBUG("Handling HIP_PARAM_HIT\n");
				if (!hit_s)
					hit_s = hip_get_param_contents_direct(param);
				else 
					hit_r =hip_get_param_contents_direct(param);
			}
			if (hip_get_param_type(param) == HIP_PARAM_KEYS)
			{
				HIP_DEBUG("Handling HIP_PARAM_KEYS\n");	
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
				HIP_DEBUG("Successfully added esp decryption data\n");	
			}
		}
	}
	return err;
	
out_err:	
	return err;

}


int sendto_hipd(void *msg, size_t len)
{
	/* Variables. */
	struct sockaddr_un sock_addr;
	int n, alen;
	
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sun_family = AF_LOCAL;
	strcpy(sock_addr.sun_path, HIP_FIREWALLADDR_PATH);
	alen = sizeof(sock_addr);
	n = sendto(hip_firewall_sock, msg, len, 0, (struct sockaddr *)&sock_addr, alen);

	return (n);
}


int control_thread_init(void)
{
   int err = 0;
	int n;
	int len;
	
	struct sockaddr_un sock_addr;
	struct hip_common *msg = NULL;
	socklen_t alen;

	/* Allocate message. */
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}

	/* Create and bind daemon socket. */
	hip_firewall_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (hip_firewall_sock < 0) {
		err = -1;
		HIP_ERROR("Failed to create socket.\n");
		return err;
	}
	
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sun_family = AF_LOCAL;
	strcpy(sock_addr.sun_path, tmpnam(NULL));
	err = bind(hip_firewall_sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	if (err != 0) {
	     err = -1;
	     HIP_ERROR("Bind failed.\n");
	     return err;
	}

	/* Test connection. */
	hip_build_user_hdr(msg, HIP_FIREWALL_PING, 0);
	n = sendto_hipd(msg, sizeof(struct hip_common));
	if (n < 0) {
		err =  -1;
		HIP_ERROR("Could not send ping to daemon.\n");
		return err;
	}

	bzero(&sock_addr, sizeof(sock_addr));
	alen = sizeof(sock_addr);
	n = recvfrom(hip_firewall_sock, msg, sizeof(struct hip_common), 0,
	             (struct sockaddr *)&sock_addr, &alen);
	HIP_IFEL(n < 0, -1,  "Did not receive ping reply from daemon.\n");
	
	/* Start thread for connection handling. */
	HIP_DEBUG("Received %d bytes of ping reply message from daemon.\n"
	          "Starting thread for HIP daemon connection handling\n", n);
    	
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

