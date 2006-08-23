
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

/* For receiving of HIP control messages */
int hip_raw_sock_v6 = 0;
int hip_raw_sock_v4 = 0;
int hip_nat_sock_udp = 0;	/* For NAT traversal of IPv4 packets for base exchange*/
int hip_nat_sock_udp_data = 0;  /* For NAT traversal of IPv4 packets for Data traffic */

int hip_nat_status = 0; /*Specifies the NAT status of the daemon. It is turned off by default*/


/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un hip_user_addr;

/* For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec = { 0 };

/* For getting/setting routes and adding HITs (it was not possible to use
   nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

int hip_agent_sock = 0, hip_agent_status = 0;
struct sockaddr_un hip_agent_addr;

/* We are caching the IP addresses of the host here. The reason is that during
   in hip_handle_acquire it is not possible to call getifaddrs (it creates
   a new netlink socket and seems like only one can be open per process).
   Feel free to experiment by porting the required functionality from
   iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
   variable and most of the functions referencing them unnecessary -miika */
int address_count;
struct list_head addresses;

time_t load_time;

void usage() {
	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
        fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -b run in foreground\n");
#ifdef CONFIG_HIP_HI3
	fprintf(stderr, "  -3 <i3 client configuration file>\n");
#endif
	fprintf(stderr, "\n");
}

int hip_sendto(const struct hip_common *msg, const struct sockaddr_un *dst){
  int n = 0;

  HIP_DEBUG("hip_sendto sending phit...\n");

  n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
	     0,(struct sockaddr *)dst, sizeof(struct sockaddr_un));
  return n;
}

int main(int argc, char *argv[]) {
	int ch;
	char buff[HIP_MAX_NETLINK_PACKET];
#ifdef CONFIG_HIP_HI3
	char *i3_config = NULL;
#endif
	fd_set read_fdset;
	int foreground = 1, highest_descriptor = 0, s_net, err = 0;
	struct timeval timeout;
	struct hip_work_order ping;

	struct hip_common *hip_msg = NULL;
	struct msghdr sock_msg;
        /* The flushing is enabled by default. The reason for this is that
	   people are doing some very experimental features on some branches
	   that may crash the daemon and leave the SAs floating around to
	   disturb further base exchanges. Use -N flag to disable this. */
	int flush_ipsec = 1;

	/* Parse command-line options */
	while ((ch = getopt(argc, argv, "b")) != -1) {		
		switch (ch) {
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
		if (fork() > 0) return(0);
		hip_set_logtype(LOGTYPE_SYSLOG);
	}

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);
	
	/* Default initialization function. */
	HIP_IFEL(hipd_init(flush_ipsec), 1, "hipd_init() failed!\n");

	highest_descriptor = maxof(7, hip_nl_route.fd, hip_raw_sock_v6,
				   hip_user_sock, hip_nl_ipsec.fd,
				   hip_agent_sock, hip_raw_sock_v4,
				   hip_nat_sock_udp);

	/* Allocate user message. */
	HIP_IFE(!(hip_msg = hip_msg_alloc()), 1);

	HIP_DEBUG("Daemon running. Entering select loop.\n");
	/* Enter to the select-loop */
	HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT, 
		     HIP_DEBUG_LEVEL_INFORMATIVE,
		     "Hipd daemon running.\n"
		     "Starting select loop.\n");
	hipd_set_state(HIPD_STATE_EXEC);
	while (hipd_get_state() != HIPD_STATE_CLOSED)
	{
		struct hip_work_order *hwo;
		
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_v6, &read_fdset);
		FD_SET(hip_raw_sock_v4, &read_fdset);
		FD_SET(hip_nat_sock_udp, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(hip_nl_ipsec.fd, &read_fdset);
		FD_SET(hip_agent_sock, &read_fdset);
		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;
		
		_HIP_DEBUG("select loop\n");
		/* wait for socket activity */
		if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
				       NULL, NULL, &timeout)) < 0) {
			HIP_ERROR("select() error: %s.\n", strerror(errno));
		} else if (err == 0) {
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle\n");
		} else if (FD_ISSET(hip_raw_sock_v6, &read_fdset)) {
			struct in6_addr saddr, daddr;
			struct hip_stateless_info pkt_info;

			hip_msg_init(hip_msg);
		
			if (hip_read_control_msg_v6(hip_raw_sock_v6, hip_msg,
						    1, &saddr, &daddr,
						    &pkt_info, 0))
				HIP_ERROR("Reading network msg failed\n");
			else
				err = hip_receive_control_packet(hip_msg,
								 &saddr,
								 &daddr,
								 &pkt_info);
		} else if (FD_ISSET(hip_raw_sock_v4, &read_fdset)) {
			struct in6_addr saddr, daddr;
			struct hip_stateless_info pkt_info;
			//int src_port = 0;

			hip_msg_init(hip_msg);
			HIP_DEBUG("Getting a msg on v4\n");
			/* Assuming that IPv4 header does not include any
			   options */
			if (hip_read_control_msg_v4(hip_raw_sock_v4, hip_msg,
						    1, &saddr, &daddr,
						    &pkt_info, IPV4_HDR_SIZE))
				HIP_ERROR("Reading network msg failed\n");
			else
			{
			  /* For some reason, the IPv4 header is always
			     included. Let's remove it here. */
			  memmove(hip_msg, ((char *)hip_msg) + IPV4_HDR_SIZE,
				  HIP_MAX_PACKET - IPV4_HDR_SIZE);

			  pkt_info.src_port = 0;
	
			  err = hip_receive_control_packet(hip_msg, &saddr,
							   &daddr, &pkt_info);
			}
		} else if(FD_ISSET(hip_nat_sock_udp, &read_fdset)){
			/* do NAT recieving here !! --Abi */
			
			struct in6_addr saddr, daddr;
			struct hip_stateless_info pkt_info;
			//int src_port = 0;

			hip_msg_init(hip_msg);
			HIP_DEBUG("Getting a msg on udp\n");	

		//	if (hip_read_control_msg_udp(hip_nat_sock_udp, hip_msg, 1,
                  //                                 &saddr, &daddr))
        		if (hip_read_control_msg_v4(hip_nat_sock_udp, hip_msg,
						    1, &saddr, &daddr,
						    &pkt_info, 0))
                                HIP_ERROR("Reading network msg failed\n");
                        else
                        {
				err =  hip_receive_control_packet_udp(hip_msg,
                                                                 &saddr,
                                                                 &daddr,
								 &pkt_info);

                                //err = hip_receive_control_packet(hip_msg,
                                                                 //&saddr,
                                                                 //&daddr);
                        }

			
		} else if (FD_ISSET(hip_user_sock, &read_fdset)) {
		  	//struct sockaddr_un app_src, app_dst;
		  //  	struct sockaddr_storage app_src;
			struct sockaddr_un app_src;
			HIP_DEBUG("Receiving user message.\n");
			hip_msg_init(hip_msg);

			if (hip_read_user_control_msg(hip_user_sock, hip_msg, &app_src))
				HIP_ERROR("Reading user msg failed\n");
			else
				err = hip_handle_user_msg(hip_msg, &app_src);
		} else if (FD_ISSET(hip_agent_sock, &read_fdset)) {
			int n;
			socklen_t alen;
			err = 0;
			hip_hdr_type_t msg_type;
			
			HIP_DEBUG("Receiving message from agent(?).\n");
			
			bzero(&hip_agent_addr, sizeof(hip_agent_addr));
			alen = sizeof(hip_agent_addr);
			n = recvfrom(hip_agent_sock, hip_msg, sizeof(struct hip_common), 0,
			             (struct sockaddr *) &hip_agent_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Recvfrom() failed.\n");
				err = -1;
				continue;
			}
			
			msg_type = hip_get_msg_type(hip_msg);
			
			if (msg_type == HIP_AGENT_PING)
			{
				memset(hip_msg, 0, sizeof(struct hip_common));
				hip_build_user_hdr(hip_msg, HIP_AGENT_PING_REPLY, 0);
				alen = sizeof(hip_agent_addr);                    
				n = sendto(hip_agent_sock, hip_msg, sizeof(struct hip_common),
				           0, (struct sockaddr *) &hip_agent_addr, alen);
				if (n < 0)
				{
					HIP_ERROR("Sendto() failed.\n");
					err = -1;
					continue;
				}

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
			else if (msg_type == HIP_I1)
			{
				hip_ha_t *ha;
 				ha = hip_hadb_find_byhits(&hip_msg->hits, &hip_msg->hitr);
				if (ha)
				{
					ha->state = HIP_STATE_UNASSOCIATED;
					HIP_HEXDUMP("HA: ", ha, 4);
					HIP_DEBUG("Agent accepted I1.\n");
				}
			}
			else if (msg_type == HIP_I1_REJECT)
			{
				hip_ha_t *ha;
				ha = hip_hadb_find_byhits(&hip_msg->hits, &hip_msg->hitr);
				if (ha)
				{
					ha->state = HIP_STATE_UNASSOCIATED;
					ha->hip_msg_retrans.count = 0;
					HIP_DEBUG("Agent rejected I1.\n");
				}
			}
		} else if (FD_ISSET(hip_nl_ipsec.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink receive\n");
			if (hip_netlink_receive(&hip_nl_ipsec,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		} else if (FD_ISSET(hip_nl_route.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("netlink route receive\n");
			if (hip_netlink_receive(&hip_nl_route,
						hip_netdev_event, NULL))
				HIP_ERROR("Netlink receiving failed\n");
		} else {
			HIP_INFO("Unknown socket activity.");
		}

		err = periodic_maintenance();
		if (err) {
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

