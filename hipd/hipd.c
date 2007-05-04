
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "hipd.h" 

/* Defined as a global just to allow freeing in exit(). Do not use outside
   of this file! */
struct hip_common *hipd_msg = NULL;

int hip_blind_status = 0; /* Blind status */

/* For receiving of HIP control messages */
int hip_raw_sock_v6 = 0;
int hip_raw_sock_v4 = 0;
/** File descriptor of the socket used for hip control packet NAT traversal on
    UDP/IPv4. */
int hip_nat_sock_udp = 0;
/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. */
int hip_nat_status = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un hip_user_addr;

/* For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec  = { 0 };

/* For getting/setting routes and adding HITs (it was not possible to use
   nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

int hip_agent_sock = 0, hip_agent_status = 0;
struct sockaddr_un hip_agent_addr;

int hip_firewall_sock = 0;
struct sockaddr_un hip_firewall_addr;

/* 
For uploading and downloading openDHT mappings 
Used also from maintenance.c register_to_dht()
*/
int hip_opendht_sock_fqdn = 0; /* FQDN->HIT mapping */
int hip_opendht_sock_hit = 0; /* HIT->IP mapping */
int hip_opendht_fqdn_sent = 0;
int hip_opendht_hit_sent = 0;
int opendht_error = 0;
char opendht_response[1024];
struct addrinfo opendht_serving_gateway;
int opendht_serving_gateway_flag;

/* We are caching the IP addresses of the host here. The reason is that during
   in hip_handle_acquire it is not possible to call getifaddrs (it creates
   a new netlink socket and seems like only one can be open per process).
   Feel free to experiment by porting the required functionality from
   iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
   variable and most of the functions referencing them unnecessary -miika */
int address_count;
HIP_HASHTABLE *addresses;

time_t load_time;

#ifdef CONFIG_HIP_HI3
char *i3_config = NULL;
#endif

void usage() {
	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
        fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -b run in background\n");
#ifdef CONFIG_HIP_HI3
	fprintf(stderr, "  -3 <i3 client configuration file>\n");
#endif
	fprintf(stderr, "\n");
}

int hip_sendto(const struct hip_common *msg, const struct sockaddr_un *dst){
        int n = 0;
        HIP_DEBUG("hip_sendto() invoked.\n");
        n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
                   0,(struct sockaddr *)dst, sizeof(struct sockaddr_un));
        return n;
}

/**
 * Receive message from agent socket.
 */
int hip_sock_recv_agent(void)
{
	int n, err;
	socklen_t alen;
	hip_hdr_type_t msg_type;
	err = 0;
	hip_opp_block_t *entry;
	
	HIP_DEBUG("Receiving a message from agent socket "\
				"(file descriptor: %d).\n", hip_agent_sock);

	bzero(&hip_agent_addr, sizeof(hip_agent_addr));
	alen = sizeof(hip_agent_addr);
	n = recvfrom(hip_agent_sock, hipd_msg, sizeof(struct hip_common), MSG_PEEK,
	             (struct sockaddr *)&hip_agent_addr, &alen);
	HIP_IFEL(n < 0, 0, "recvfrom() failed on agent socket.\n");
	bzero(&hip_agent_addr, sizeof(hip_agent_addr));
	alen = sizeof(hip_agent_addr);
	n = recvfrom(hip_agent_sock, hipd_msg, hip_get_msg_total_len(hipd_msg), 0,
	             (struct sockaddr *) &hip_agent_addr, &alen);
	HIP_IFEL(n < 0, 0, "recvfrom() failed on agent socket.\n");
	HIP_DEBUG("Received %d bytes from agent.\n", n);

	msg_type = hip_get_msg_type(hipd_msg);
	
	if (msg_type == HIP_AGENT_PING)
	{
		memset(hipd_msg, 0, sizeof(struct hip_common));
		hip_build_user_hdr(hipd_msg, HIP_AGENT_PING_REPLY, 0);
		alen = sizeof(hip_agent_addr);
		n = sendto(hip_agent_sock, hipd_msg, sizeof(struct hip_common),
		           0, (struct sockaddr *) &hip_agent_addr, alen);
		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket.\n");

		if (err == 0)
		{
			HIP_DEBUG("HIP agent ok.\n");
			if (hip_agent_status == 0)
			{
				hip_agent_add_lhits();
			}
			hip_agent_status = 1;
		}
	}
	else if (msg_type == HIP_AGENT_QUIT)
	{
		HIP_DEBUG("Agent quit.\n");
		hip_agent_status = 0;
	}
	else if (msg_type == HIP_R1 || msg_type == HIP_I1)
	{
		struct hip_common *emsg;
		struct in6_addr *src_addr, *dst_addr;
		hip_portpair_t *msg_info;
		void *reject;

		emsg = hip_get_param_contents(hipd_msg, HIP_PARAM_ENCAPS_MSG);
		src_addr = hip_get_param_contents(hipd_msg, HIP_PARAM_SRC_ADDR);
		dst_addr = hip_get_param_contents(hipd_msg, HIP_PARAM_DST_ADDR);
		msg_info = hip_get_param_contents(hipd_msg, HIP_PARAM_PORTPAIR);
		reject = hip_get_param(hipd_msg, HIP_PARAM_AGENT_REJECT);

		if (emsg && src_addr && dst_addr && msg_info && !reject)
		{
			HIP_DEBUG("Received accepted I1/R1 packet from agent.\n");
			hip_receive_control_packet(emsg, src_addr, dst_addr, msg_info, 0);
		}
		else if (emsg && src_addr && dst_addr && msg_info)
		{
		#ifdef CONFIG_HIP_OPPORTUNISTIC

			HIP_DEBUG("Received rejected R1 packet from agent.\n");
			err = hip_for_each_opp(hip_handle_opp_reject, src_addr);
			HIP_IFEL(err, 0, "for_each_ha err.\n");
		#endif
		}
	}
	
out_err:
	return err;
}


/**
 * Receive message from firewall socket.
 */
int hip_sock_recv_firewall(void)
{
	int n, err;
	socklen_t alen;
	err = 0;
	hip_hdr_type_t msg_type;

	HIP_DEBUG("Receiving a message from firewall socket "
	          "(file descriptor: %d).\n",
	          hip_firewall_sock);
	
	bzero(&hip_firewall_addr, sizeof(hip_firewall_addr));
	alen = sizeof(hip_firewall_addr);
	n = recvfrom(hip_firewall_sock, hipd_msg, sizeof(struct hip_common), 0,
	             (struct sockaddr *) &hip_firewall_addr, &alen);
	HIP_IFEL(n < 0, 0, "recvfrom() failed on agent socket.\n");
	
	msg_type = hip_get_msg_type(hipd_msg);
	
	if (msg_type == HIP_FIREWALL_PING)
	{
		HIP_DEBUG("Received ping from firewall\n");
		memset(hipd_msg, 0, sizeof(struct hip_common));
		hip_build_user_hdr(hipd_msg, HIP_FIREWALL_PING_REPLY, 0);
		alen = sizeof(hip_firewall_addr);                    
		n = hip_sendto(hipd_msg, &hip_firewall_addr);
		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket.\n");

		if (err == 0)
		{
			HIP_DEBUG("HIP firewall ok.\n");
			if (hip_firewall_status == 0)
			{
				// TODO: initializing of firewall needed?
				HIP_DEBUG("First ping\n");
			}
			hip_firewall_status = 1;
		}
		
		if (hip_services_is_active(HIP_ESCROW_SERVICE))
			HIP_DEBUG("Escrow service is now active.\n");

		if (hip_firewall_is_alive())
			hip_firewall_set_escrow_active(1);
	}
	else if (msg_type == HIP_FIREWALL_QUIT)
	{
		HIP_DEBUG("Firewall quit.\n");
		hip_firewall_status = 0;
	}

out_err:
	return err;
}


/*int hip_sendto_firewall(const struct hip_common *msg){
#ifdef CONFIG_HIP_FIREWALL
	if (hip_get_firewall_status()) {
		int n = 0;
		n = sendto(hip_firewall_sock, msg, hip_get_msg_total_len(msg),
		   0, (struct sockaddr *)&hip_firewall_addr, sizeof(struct sockaddr_un));
		return n;
	}
#else
	HIP_DEBUG("Firewall is disabled.\n");
	return 0;
#endif // CONFIG_HIP_FIREWALL
}*/

int main(int argc, char *argv[])
{
	int ch;
	char buff[HIP_MAX_NETLINK_PACKET];
#ifdef CONFIG_HIP_HI3
	char *i3_config = NULL;
#endif
	fd_set read_fdset;
	int foreground = 1, highest_descriptor = 0, s_net, err = 0;
	struct timeval timeout;
	struct hip_work_order ping;

	struct msghdr sock_msg;
        /* The flushing is enabled by default. The reason for this is that
	   people are doing some very experimental features on some branches
	   that may crash the daemon and leave the SAs floating around to
	   disturb further base exchanges. Use -N flag to disable this. */
	int flush_ipsec = 1;

	/* Parse command-line options */
	while ((ch = getopt(argc, argv, "b")) != -1)
	{		
		switch (ch)
		{
		case 'b':
			foreground = 0;
			break;
#ifdef CONFIG_HIP_HI3
		case '3':
			i3_config = strdup(optarg);
			break;
#endif
		case 'N':
			flush_ipsec = 0;
			break;
		case '?':
		case 'h':
		default:
			usage();
			return err;
		}
	}

#ifdef CONFIG_HIP_HI3
	/* Note that for now the Hi3 host identities are not loaded in. */
	HIP_IFEL(!i3_config, 1,
		 "Please do pass a valid i3 configuration file.\n");
#endif
	
	hip_set_logfmt(LOGFMT_LONG);

	/* Configuration is valid! Fork a daemon, if so configured */
	if (foreground)
	{
		printf("foreground\n");
		hip_set_logtype(LOGTYPE_STDERR);
	}
	else
	{
		hip_set_logtype(LOGTYPE_SYSLOG);
		if (fork() > 0) return(0);
	}

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);
	
	/* Default initialization function. */
	HIP_IFEL(hipd_init(flush_ipsec), 1, "hipd_init() failed!\n");

	highest_descriptor = maxof(10, hip_nl_route.fd, hip_raw_sock_v6,
				   hip_user_sock, hip_nl_ipsec.fd,
				   hip_agent_sock, hip_raw_sock_v4,
				   hip_nat_sock_udp, hip_firewall_sock,
                                   hip_opendht_sock_fqdn, hip_opendht_sock_hit);

	/* Allocate user message. */
	HIP_IFE(!(hipd_msg = hip_msg_alloc()), 1);
	HIP_DEBUG("Daemon running. Entering select loop.\n");
	/* Enter to the select-loop */
	HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT, 
		     HIP_DEBUG_LEVEL_INFORMATIVE,
		     "Hipd daemon running.\n"
		     "Starting select loop.\n");
	hipd_set_state(HIPD_STATE_EXEC);
	while (hipd_get_state() != HIPD_STATE_CLOSED)
	{
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_v6, &read_fdset);
		FD_SET(hip_raw_sock_v4, &read_fdset);
		FD_SET(hip_nat_sock_udp, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(hip_nl_ipsec.fd, &read_fdset);
		FD_SET(hip_agent_sock, &read_fdset);
		FD_SET(hip_firewall_sock, &read_fdset);
		if (hip_opendht_fqdn_sent == 1)
		{
			FD_SET(hip_opendht_sock_fqdn, &read_fdset);
		}
		if (hip_opendht_hit_sent == 1)
		{
			FD_SET(hip_opendht_sock_hit, &read_fdset);
		}
		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		/*  XX FIXME: it is possible to have several FDs in
		    SELECT open at the same time. Currently only one is
		    handled and the rest are discarded. */
		
		_HIP_DEBUG("select loop\n");
		/* wait for socket activity */
		if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
						NULL, NULL, &timeout)) < 0)
		{
			HIP_ERROR("select() error: %s.\n", strerror(errno));
			goto to_maintenance;
		}
		else if (err == 0)
		{
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle.\n");
			goto to_maintenance;
		} 

		if (FD_ISSET(hip_raw_sock_v6, &read_fdset))
		{
			/* Receiving of a raw HIP message from IPv6 socket. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;

			HIP_DEBUG("Receiving a message on raw HIP from "\
				  "IPv6/HIP socket (file descriptor: %d).\n",
				  hip_raw_sock_v6);
			
			hip_msg_init(hipd_msg);
		
			if (hip_read_control_msg_v6(hip_raw_sock_v6, hipd_msg,
			                            &saddr, &daddr, &pkt_info, 0))
			{
				HIP_ERROR("Reading network msg failed\n");
			}
			else
			{
				err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
				if (err) HIP_ERROR("hip_receive_control_packet()!\n");
			}
		}

		if (FD_ISSET(hip_raw_sock_v4, &read_fdset))
		{
			/* Receiving of a raw HIP message from IPv4 socket. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;

			HIP_DEBUG("Receiving a message on raw HIP from "\
				  "IPv4/HIP socket (file descriptor: %d).\n",
				  hip_raw_sock_v4);

			hip_msg_init(hipd_msg);
			HIP_DEBUG("Getting a msg on v4\n");

			/* Assuming that IPv4 header does not include any
			   options */
			if (hip_read_control_msg_v4(hip_raw_sock_v4, hipd_msg,
			                            &saddr, &daddr, &pkt_info, IPV4_HDR_SIZE))
			{
				HIP_ERROR("Reading network msg failed\n");
			}
			else
			{
				err = hip_receive_control_packet(hipd_msg, &saddr, &daddr, &pkt_info, 1);
				if (err) HIP_ERROR("hip_receive_control_packet()!\n");
			}

		}

		if (FD_ISSET(hip_nat_sock_udp, &read_fdset))
		{
			/* Data structures for storing the source and
			   destination addresses and ports of the incoming
			   packet. */
			struct in6_addr saddr, daddr;
			hip_portpair_t pkt_info;

			/* Receiving of a UDP message from NAT socket. */
			HIP_DEBUG("Receiving a message on UDP from NAT "\
				  "socket (file descriptor: %d).\n",
				  hip_nat_sock_udp);
			
			/* Initialization of the hip_common header struct. We'll
			   store the HIP header data here. */
			hip_msg_init(hipd_msg);
			
			/* Read in the values to hip_msg, saddr, daddr and
			   pkt_info. */
        		if (hip_read_control_msg_v4(hip_nat_sock_udp, hipd_msg,
						    &saddr, &daddr,
						    &pkt_info, 0)) {
                                HIP_ERROR("Reading network msg failed\n");
				/* If the values were read in succesfully, we
				   do the UDP specific stuff next. */
                        } else {
				err =  hip_receive_udp_control_packet(
					hipd_msg, &saddr, &daddr, &pkt_info);
                        }

		}

		if (FD_ISSET(hip_user_sock, &read_fdset))
		{
			/* Receiving of a message from user socket. */
			struct sockaddr_un app_src;
			HIP_DEBUG("Receiving user message.\n");
			hip_msg_init(hipd_msg);

			HIP_DEBUG("Receiving a message from user socket "\
				  "(file descriptor: %d).\n",
				  hip_user_sock);

			if (hip_read_user_control_msg(hip_user_sock, hipd_msg, &app_src))
				HIP_ERROR("Reading user msg failed\n");
			else err = hip_handle_user_msg(hipd_msg, &app_src);
		}

		if (FD_ISSET(hip_opendht_sock_fqdn, &read_fdset))
		{
			/* Receive answer from openDHT FQDN->HIT mapping */
#ifdef CONFIG_HIP_OPENDHT
			if (hip_opendht_fqdn_sent == 1) 
			{
				memset(opendht_response, '\0', sizeof(opendht_response));
				opendht_error = opendht_read_response(hip_opendht_sock_fqdn, 
				                                      opendht_response); 
				if (opendht_error == -1)
					HIP_DEBUG("Put was unsuccesfull (FQDN->HIT)\n");
				else 
					HIP_DEBUG("Put was success (FQDN->HIT)\n");
				
				close(hip_opendht_sock_fqdn);
				hip_opendht_sock_fqdn = init_dht_gateway_socket(hip_opendht_sock_fqdn);
				hip_opendht_fqdn_sent = 0;
				opendht_error = 0;
			}
#endif
		} 

		if (FD_ISSET(hip_opendht_sock_hit, &read_fdset))
		{
#ifdef CONFIG_HIP_OPENDHT
			/* Receive answer from openDHT HIT->IP mapping */
			if (hip_opendht_hit_sent == 1) 
			{
				memset(opendht_response, '\0', sizeof(opendht_response));
				opendht_error = opendht_read_response(hip_opendht_sock_hit, 
				                                      opendht_response); 
				if (opendht_error == -1)
					HIP_DEBUG("Put was unsuccesfull (HIT->IP)\n");
				else 
					HIP_DEBUG("Put was success (HIT->IP)\n");
				close(hip_opendht_sock_hit);
				hip_opendht_sock_hit = init_dht_gateway_socket(hip_opendht_sock_hit);
				hip_opendht_hit_sent = 0;
				opendht_error= 0;
			}
#endif
		} 

		if (FD_ISSET(hip_agent_sock, &read_fdset))
		{
			err = hip_sock_recv_agent();
			if (err) HIP_ERROR("Receiving packet from agent socket failed!\n");
		}
 
		if (FD_ISSET(hip_firewall_sock, &read_fdset))
		{
			err = hip_sock_recv_firewall();
			if (err) HIP_ERROR("Receiving packet from firewall socket failed!\n");
		}
 
		if (FD_ISSET(hip_nl_ipsec.fd, &read_fdset))
		{
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink receive\n");
			if (hip_netlink_receive(&hip_nl_ipsec,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		}
 
		if (FD_ISSET(hip_nl_route.fd, &read_fdset))
		{
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink route receive\n");
			if (hip_netlink_receive(&hip_nl_route,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		} 

to_maintenance:
		err = periodic_maintenance();
		if (err)
		{
			HIP_ERROR("Error (%d) ignoring. %s\n", err,
				  ((errno) ? strerror(errno) : ""));
			err = 0;
		}
	}

out_err:
	/* free allocated resources */
	hip_exit(err);

	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

	return err;
}
