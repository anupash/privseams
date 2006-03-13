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

float retrans_counter = HIP_RETRANSMIT_INIT;
float precreate_counter = HIP_R1_PRECREATE_INIT;

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

int hip_handle_retransmission(hip_ha_t *entry, void *not_used)
{
	int err = 0;

	if (!entry->hip_msg_retrans.buf)
		goto out_err;

	HIP_DEBUG("%d %d\n", entry->hip_msg_retrans.count, entry->state);

	if (entry->hip_msg_retrans.count > 0 &&
	    entry->state != HIP_STATE_ESTABLISHED) {
		err = entry->hadb_xmit_func->hip_csum_send(&entry->hip_msg_retrans.saddr,
							   &entry->hip_msg_retrans.daddr,
							   entry->hip_msg_retrans.buf,
							   entry, 0);
		entry->hip_msg_retrans.count--;
	} else {
		HIP_FREE(entry->hip_msg_retrans.buf);
		entry->hip_msg_retrans.buf = NULL;
		entry->hip_msg_retrans.count = 0;
	}

 out_err:
	return err;
}

int hip_scan_retransmissions()
{
	int err = 0;
	HIP_IFEL(hip_for_each_ha(hip_handle_retransmission, NULL), 0, 
		 "for_each_ha err.\n");
 out_err:
	return err;
}

int hip_agent_add_lhit(struct hip_host_id_entry *entry, void *msg)
{
	int err = 0;

	err = hip_build_param_contents(msg, (void *)&entry->lhi.hit, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
	if (err)
	{
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out_err;
	}

out_err:
	return (err);
}

int hip_agent_add_lhits(void)
{
	struct hip_common *msg;
	int err = 0, n;
	socklen_t alen;

#ifdef CONFIG_HIP_AGENT
/*	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}*/

	msg = malloc(HIP_MAX_PACKET);
	if (!msg)
	{
		HIP_ERROR("malloc failed\n");
		goto out_err;
	}
	hip_msg_init(msg);

	HIP_IFEL(hip_for_each_hi(hip_agent_add_lhit, msg), 0,
	         "for_each_hi err.\n");

	err = hip_build_user_hdr(msg, SO_HIP_ADD_LOCAL_HI, 0);
	if (err)
	{
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out_err;
	}

	HIP_DEBUG("Sending local HITs to agent,"
	          " message body size is %d bytes.\n",
	          hip_get_msg_total_len(msg) - sizeof(struct hip_common));

	alen = sizeof(hip_agent_addr);                      
	n = sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg),
	           0, (struct sockaddr *)&hip_agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
#endif

out_err:
	return (err);
}

int hip_agent_is_alive()
{
#ifdef CONFIG_HIP_AGENT
	if (hip_agent_status) HIP_DEBUG("Agent is alive.\n");
	else HIP_DEBUG("Agent is not alive.\n");
	return hip_agent_status;
#else
	HIP_DEBUG("Agent is disabled.\n");
       return 0;
#endif /* CONFIG_HIP_AGENT */
}

int hip_agent_filter(struct hip_common *msg)
{
	int err = 0;
	int n, sendn;
	socklen_t alen;
       
	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}
	
	HIP_DEBUG("Filtering hip control message trough agent,"
	          " message body size is %d bytes.\n",
	          hip_get_msg_total_len(msg) - sizeof(struct hip_common));
	
	alen = sizeof(hip_agent_addr);                      
	n = sendto(hip_agent_sock, msg, hip_get_msg_total_len(msg),
	           0, (struct sockaddr *)&hip_agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
	
	HIP_DEBUG("Sent %d bytes to agent for handling.\n", n);
	
	alen = sizeof(hip_agent_addr);
	sendn = n;
	n = recvfrom(hip_agent_sock, msg, n, 0,
	             (struct sockaddr *)&hip_agent_addr, &alen);
	if (n < 0) {
		HIP_ERROR("Recvfrom() failed.\n");
		err = -1;
		goto out_err;
	}
	/* This happens, if agent rejected the packet. */
	else if (sendn != n) {
		err = 1;
	}

out_err:
       return (err);
}


int hip_init_host_ids() {
	int err = 0;
	struct stat status;
	struct hip_common *user_msg = NULL;

	/* We are first serializing a message with HIs and then
	   deserializing it. This building and parsing causes
	   a minor overhead, but as a result we can reuse the code
	   with hipconf. */

	HIP_IFE((!(user_msg = hip_msg_alloc())), -1);
		
	/* Create default keys if necessary. */

	if (stat(DEFAULT_CONFIG_DIR, &status) && errno == ENOENT) {
		hip_msg_init(user_msg);
		err = hip_serialize_host_id_action(user_msg,
						   ACTION_NEW, 0, 1,
						   NULL, NULL);
		if (err) {
			err = 1;
			HIP_ERROR("Failed to create keys to %s\n",
				  DEFAULT_CONFIG_DIR);
			goto out_err;
		}
	}
	
        /* Retrieve the keys to hipd */
	hip_msg_init(user_msg);
	err = hip_serialize_host_id_action(user_msg, ACTION_ADD, 0, 1,
					   NULL, NULL);
	if (err) {
		HIP_ERROR("Could not load default keys\n");
		goto out_err;
	}
	
	err = hip_handle_add_local_hi(user_msg);
	if (err) {
		HIP_ERROR("Adding of keys failed\n");
		goto out_err;
	}

 out_err:

	if (user_msg)
		HIP_FREE(user_msg);

	return err;
}

int hip_init_raw_sock_v6(int *hip_raw_sock_v6) {
	int on = 1, err = 0;

	HIP_IFEL(((*hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW,
					 IPPROTO_HIP)) <= 0), 1,
		 "Raw socket creation failed. Not root?\n");

	HIP_IFEL(setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &on,
		   sizeof(on)), -1, "setsockopt recverr failed\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6,
			    IPV6_2292PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt pktinfo failed\n");

 out_err:
	return err;
}

int hip_init_raw_sock_v4(int *hip_raw_sock_v4) {
	int on = 1, err = 0;
	int off = 0;

	HIP_IFEL(((*hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW,
					 IPPROTO_HIP)) <= 0), 1,
		 "Raw socket v4 creation failed. Not root?\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &on,
		   sizeof(on)), -1, "setsockopt v4 recverr failed\n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on,
		   sizeof(on)), -1, "setsockopt v4 failed to set broadcast \n");
	HIP_IFEL(setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt v4 pktinfo failed\n");

 out_err:
	return err;
}

/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
	HIP_ERROR("Signal: %d\n", signal);

	//hip_delete_default_prefix_sp_pair();

	/* Close SAs with all peers */
	hip_send_close(NULL);

	hip_delete_all_sp();

	delete_all_addresses();

	set_up_device(HIP_HIT_DEV, 0);

#ifdef CONFIG_HIP_HI3
	cl_exit();
#endif
	//hip_uninit_workqueue();
#ifdef CONFIG_HIP_RVS
        hip_uninit_rvadb();
#endif
	// hip_uninit_host_id_dbs();
        // hip_uninit_hadb();
	// hip_uninit_beetdb();
	if (hip_raw_sock_v6)
		close(hip_raw_sock_v6);
	if (hip_raw_sock_v4)
		close(hip_raw_sock_v4);
	if (hip_user_sock)
		close(hip_user_sock);
	if (hip_nl_ipsec.fd)
		rtnl_close(&hip_nl_ipsec);
	if (hip_nl_route.fd)
		rtnl_close(&hip_nl_route);
	if (hip_agent_sock)
		close(hip_agent_sock);

	exit(signal);
}

int init_random_seed()
{
	struct timeval tv;
	struct timezone tz;
	int err = 0;

	err = gettimeofday(&tv, &tz);
	srandom(tv.tv_usec);

	return err;
}

int periodic_maintenance() {
	int err = 0;

	if (retrans_counter < 0) {
		HIP_IFEL(hip_scan_retransmissions(), -1,
			 "retransmission scan failed\n");
		retrans_counter = HIP_RETRANSMIT_INIT;
	} else {
		retrans_counter--;
	}

	if (precreate_counter < 0) {
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate puzzles\n");
		precreate_counter = HIP_R1_PRECREATE_INIT;
	} else {
		precreate_counter--;
	}
	
 out_err:
	
	return err;
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
	struct sockaddr_un daemon_addr;
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
	if (foreground) {
		printf("foreground\n");
		hip_set_logtype(LOGTYPE_STDERR);
	} else {
		if (fork() > 0) /* check ret val */
			return(0);
		hip_set_logtype(LOGTYPE_SYSLOG);
	}

	HIP_INFO("hipd pid=%d starting\n", getpid());
	time(&load_time);

	/* Register signal handlers */
	signal(SIGINT, hip_exit);
	signal(SIGTERM, hip_exit);

        HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

	HIP_IFE(init_random_seed(), -1);

        hip_init_hadb();

#ifdef CONFIG_HIP_RVS
        hip_init_rvadb();
#endif	

	/* Workqueue relies on an open netlink connection */
	hip_init_workqueue();

#ifdef CONFIG_HIP_HI3
	cl_init(i3_config);
#endif

	/* Resolve our current addresses, afterwards the events from kernel
	   will maintain the list This needs to be done before opening
	   NETLINK_ROUTE! See the comment about address_count global var. */
	HIP_DEBUG("Initializing the netdev_init_addresses\n");
	hip_netdev_init_addresses(&hip_nl_ipsec);

	/* Allocate user message. */
	HIP_IFE(!(hip_msg = hip_msg_alloc()), 1);

	if (rtnl_open_byproto(&hip_nl_ipsec, 0, NETLINK_XFRM) < 0) {
		err = 1;
		HIP_ERROR("IPsec socket error: %s\n", strerror(errno));
		goto out_err;
	}
	if (rtnl_open_byproto(&hip_nl_route,
			      RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6
				| RTMGRP_IPV4_IFADDR | IPPROTO_IP,
			      NETLINK_ROUTE) < 0) {
		err = 1;
		HIP_ERROR("Routing socket error: %s\n", strerror(errno));
		goto out_err;
	}

	/* Open the netlink socket for address and IF events */
	if (rtnl_open_byproto(&hip_nl_ipsec, XFRMGRP_ACQUIRE, NETLINK_XFRM) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		err = 1;
		goto out_err;
	}

	HIP_IFEL(hip_init_raw_sock_v6(&hip_raw_sock_v6), -1, "raw sock v6\n");
	HIP_IFEL(hip_init_raw_sock_v4(&hip_raw_sock_v4), -1, "raw sock v4\n");

	HIP_DEBUG("hip_raw_sock = %d highest_descriptor = %d\n",
		  hip_raw_sock_v6, highest_descriptor);
	HIP_DEBUG("hip_raw_sock_v4 = %d highest_descriptor = %d\n",
		  hip_raw_sock_v4, highest_descriptor);

	if (flush_ipsec) {
		hip_flush_all_sa();
		hip_flush_all_policy();
	}

	HIP_DEBUG("Setting SP\n");
	/*
	hip_delete_default_prefix_sp_pair();
	HIP_IFE(hip_setup_default_sp_prefix_pair(), 1);
	*/

	HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
	set_up_device(HIP_HIT_DEV, 0);
	HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);

	HIP_IFE(hip_init_host_ids(), 1);

	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1,
		 "Could not create socket for user communication.\n");
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_UNIX;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	unlink(HIP_DAEMONADDR_PATH);
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&daemon_addr,
		      /*sizeof(daemon_addr)*/
		      strlen(daemon_addr.sun_path) +
		      sizeof(daemon_addr.sun_family)),
		 1, "Bind on daemon addr failed.");
	HIP_IFEL(chmod(daemon_addr.sun_path, S_IRWXO),
		1, "Changing permissions of daemon addr failed.")

	hip_agent_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	HIP_IFEL((hip_agent_sock < 0), 1, "Could not create socket for agent communication.\n");
	unlink(HIP_AGENTADDR_PATH);
	bzero(&hip_agent_addr, sizeof(hip_agent_addr));
	hip_agent_addr.sun_family = AF_LOCAL;
	strcpy(hip_agent_addr.sun_path, HIP_AGENTADDR_PATH);
	HIP_IFEL(bind(hip_agent_sock, (struct sockaddr *)&hip_agent_addr,
	              sizeof(hip_agent_addr)), -1, "Bind on agent addr failed.");
	chmod(HIP_AGENTADDR_PATH, 0777);
	highest_descriptor = maxof(6, hip_nl_route.fd, hip_raw_sock_v6,
				   hip_user_sock, hip_nl_ipsec.fd,
				   hip_agent_sock, hip_raw_sock_v4);
	
	HIP_DEBUG("Daemon running. Entering select loop.\n");
	/* Enter to the select-loop */
	HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT, 
		     HIP_DEBUG_LEVEL_INFORMATIVE,
		     "Hipd daemon running.\n"
		     "Starting select loop.\n");
	for (;;) {
		struct hip_work_order *hwo;
		
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(hip_nl_route.fd, &read_fdset);
		FD_SET(hip_raw_sock_v6, &read_fdset);
		FD_SET(hip_raw_sock_v4, &read_fdset);
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

			hip_msg_init(hip_msg);
		
			if (hip_read_control_msg(hip_raw_sock_v6, hip_msg, 1,
						 &saddr, &daddr))
				HIP_ERROR("Reading network msg failed\n");
			else
				err = hip_receive_control_packet(hip_msg,
								 &saddr,
								 &daddr);
		} else if (FD_ISSET(hip_raw_sock_v4, &read_fdset)) {
			struct in6_addr saddr, daddr;

			hip_msg_init(hip_msg);
			HIP_DEBUG("Getting a msg on v4\n");	
			if (hip_read_control_msg_v4(hip_raw_sock_v4, hip_msg, 1,
						 &saddr, &daddr))
				HIP_ERROR("Reading network msg failed\n");
			else
			{
				err = hip_receive_control_packet(hip_msg,
								 &saddr,
								 &daddr);
			}
		} else if (FD_ISSET(hip_user_sock, &read_fdset)) {
			HIP_DEBUG("Receiving user message.\n");
			hip_msg_init(hip_msg);

			if (hip_read_control_msg(hip_user_sock, hip_msg, 0, NULL, NULL))
				HIP_ERROR("Reading user msg failed\n");
			else
				hip_handle_user_msg(hip_msg);
		} else if (FD_ISSET(hip_agent_sock, &read_fdset)) {
			int n;
			socklen_t alen;
			err = 0;
			hip_hdr_type_t msg_type;
			
			HIP_DEBUG("Receiving user message(?).\n");
			
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
			
			if (msg_type == SO_HIP_AGENT_PING)
			{
				memset(hip_msg, 0, sizeof(struct hip_common));
				hip_build_user_hdr(hip_msg, SO_HIP_AGENT_PING_REPLY, 0);
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
			else if (msg_type == SO_HIP_AGENT_QUIT)
			{
				HIP_DEBUG("Agent quit.\n");
				hip_agent_status = 0;
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

	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

	/* free allocated resources */
	hip_exit(err);

	return err;
}

