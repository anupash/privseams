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

/* For receiving/sending HIP control messages */
int hip_raw_sock = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
struct sockaddr_un user_addr;

struct hip_nl_handle nl_ifaddr;
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

int hip_handle_keys() {
	int err = 0;
	struct stat status;
	struct hip_common *user_msg = NULL;

	HIP_IFE((!(user_msg = hip_msg_alloc())), -1);
		
	/* Create default keys if necessary */

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

int hip_init_raw_sock() {
	int on = 1, err = 0;
	struct sockaddr_in6 any6_addr;

	memset(&any6_addr, 0, sizeof(any6_addr));
	any6_addr.sin6_addr = in6addr_any;

	HIP_IFEL(((hip_raw_sock = socket(AF_INET6, SOCK_RAW,
					 IPPROTO_HIP)) <= 0), 1,
		 "Raw socket creation failed. Not root?\n");
#if 0
	HIP_IFEL(setsockopt(hip_raw_sock, IPPROTO_IPV6, IPV6_RECVERR, &on,
		   sizeof(on)), -1, "setsockopt recverr failed\n");
	HIP_IFEL(setsockopt(hip_raw_sock, IPPROTO_IPV6, IPV6_PKTINFO, &on,
		   sizeof(on)), -1, "setsockopt pktinfo failed\n");

	/* getsockname() does not work without bind - but this did not help? */
	/* XX CHECK: does this fix the interface IP - bad for m&m ? */
	HIP_IFEL(bind(hip_raw_sock, (struct sockaddr *) &any6_addr,
		      sizeof(any6_addr)), -1, "bind to raw sock failed\n");
#endif
 out_err:
	return err;
}

int hip_recv_control_msg(int hip_raw_sock, struct hip_common *user_msg,
			 struct in6_addr *my_addr, struct in6_addr *peer_addr)
{
	socklen_t socklen = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 me, peer;
	int len, err = 0;
	
	HIP_IFEL(getsockname(hip_raw_sock, (struct sockaddr *) &me,
			    &socklen), -1, "getsockname failed\n");

	hip_msg_init(user_msg);
	len = recvfrom(hip_raw_sock, user_msg, HIP_MAX_PACKET, 0,
		       (struct sockaddr *) &peer, &socklen);
	HIP_IFEL(len <= 0, -1, "Receiving error or icmpv6?\n");

	memcpy(my_addr, &me.sin6_addr, sizeof(struct in6_addr));
	memcpy(peer_addr, &peer.sin6_addr, sizeof(struct in6_addr));

 out_err:
	return err;
}

/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
	HIP_ERROR("Signal: %d\n", signal);

	hip_delete_prefix_sp_pair();

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
	// rtnl_close(&rtnl);
	if (hip_raw_sock)
		close(hip_raw_sock);
	if (hip_user_sock)
		close(hip_user_sock);

	exit(signal);
}

int main(int argc, char *argv[]) {
	char ch;
	char buff[HIP_MAX_NETLINK_PACKET];
#ifdef CONFIG_HIP_HI3
	char *i3_config = NULL;
#endif
	fd_set read_fdset;
	int foreground = 1, highest_descriptor, s_net, err = 0;
	struct timeval timeout;
	struct hip_work_order ping;

	struct hip_common *user_msg = NULL;
	struct msghdr sock_msg;
	struct sockaddr_un daemon_addr;

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
		case '?':
		default:
			usage();
			goto out_err;
		}
	}

#ifdef CONFIG_HIP_HI3
	/* Note that for now the Hi3 host identities are not loaded in. */
	
	HIP_IFEL(!i3_config, 1,
		 "Please do pass a valid i3 configuration file.\n");
#endif

	/**********/
	/* ONLY FOR TESTING ... REMOVE AFTER THE HIPD WORKS PROPERLY */
	/** This is to delete the general security policies in case they exist
	 * due to for example a crash of the application
	 */
	hip_delete_prefix_sp_pair();
	/**********/

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

	/* Allocate user message. */
	HIP_IFE(!(user_msg = hip_msg_alloc()), 1);

	/* Open the netlink socket for address and IF events */
	if (hip_netlink_open(&nl_ifaddr, RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6 | XFRMGRP_ACQUIRE, NETLINK_ROUTE | NETLINK_XFRM) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		err = 1;
		goto out_err;
	}

	/* Resolve our current addresses, afterwards the events from
           kernel will maintain the list */
	HIP_DEBUG("Initializing the netdev_init_addresses\n");
	hip_netdev_init_addresses(&nl_ifaddr);

	HIP_IFE(hip_init_raw_sock(), -1);

	HIP_DEBUG("hip_raw_sock = %d highest_descriptor = %d\n",
		  hip_raw_sock, highest_descriptor);

	HIP_DEBUG("Setting SP\n");
	hip_delete_prefix_sp_pair();
	HIP_IFE(hip_setup_sp_prefix_pair(), 1);

	HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
	set_up_device(HIP_HIT_DEV, 0);
	HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);

	HIP_DEBUG("Setting ip route\n", HIP_HIT_DEV);
	{
		hip_hit_t hit;
		memset(&hit, 0, sizeof(hip_hit_t));
		hit.s6_addr32[0] = htons(HIP_HIT_PREFIX);
		HIP_IFE(hip_add_iface_local_route(&hit), 1);
	}

	HIP_IFE(hip_handle_keys(), 1);

	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	HIP_IFEL((hip_user_sock < 0), 1,
		 "Could not create socket for user communication.\n");
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_UNIX;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	unlink(HIP_DAEMONADDR_PATH);
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&daemon_addr,
		      /*sizeof(daemon_addr)*/
		strlen(daemon_addr.sun_path) + sizeof(daemon_addr.sun_family)),
		 1, "Bind failed.");
	HIP_DEBUG("Local server up\n");

	highest_descriptor = maxof(hip_raw_sock, hip_user_sock, nl_ifaddr.fd);
	
        HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

        hip_init_hadb();

#ifdef CONFIG_HIP_RVS
        hip_init_rvadb();
#endif	

	/* Workqueue relies on an open netlink connection */
	hip_init_workqueue();

#ifdef CONFIG_HIP_HI3
	cl_init(i3_config);
#endif

	/* Enter to the select-loop */
	for (;;) {
		struct hip_work_order *hwo;
		
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(hip_raw_sock, &read_fdset);
		FD_SET(hip_user_sock, &read_fdset);
		FD_SET(nl_ifaddr.fd, &read_fdset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		
		_HIP_DEBUG("select\n");
		/* wait for socket activity */
#ifndef CONFIG_HIP_HI3
		if ((err = select((highest_descriptor + 1), &read_fdset, 
				  NULL, NULL, &timeout)) < 0) {
#else
	        if ((err = cl_select((highest_descriptor + 1), &read_fdset, 
				     NULL, NULL, &timeout)) < 0) {
				
#endif
			HIP_INFO("select() error: %s.\n", strerror(errno));
		} else if (err == 0) {
			/* idle cycle - select() timeout */
			_HIP_DEBUG("Idle\n");
		} else if (FD_ISSET(hip_raw_sock, &read_fdset)) {
			struct in6_addr my_addr, peer_addr;
			err = hip_recv_control_msg(hip_raw_sock, user_msg,
						   &my_addr, &peer_addr);
			if (!err)
				err = hip_receive_control_packet(hip_raw_sock,
								 user_msg,
								 &my_addr,
								 &peer_addr);
		} else if (FD_ISSET(hip_user_sock, &read_fdset)) {
			int n;
			socklen_t alen;
			err = 0;
			HIP_DEBUG("Receiving user message(?).\n");
			bzero(&user_addr, sizeof(user_addr));
			hip_msg_init(user_msg);
			alen = sizeof(user_addr);
			n = recvfrom(hip_user_sock, (void *)user_msg,
				     HIP_MAX_PACKET, 0,
				     (struct sockaddr *)&user_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Recvfrom() failed.\n");
				err = -1;
			} 
			
			//HIP_HEXDUMP("packet", user_msg,  hip_get_msg_total_len(user_msg));
			HIP_IFEL((err = hip_handle_user_msg(user_msg)),
				 1, "Handing of user msg failed\n");
			
		} else if (FD_ISSET(nl_ifaddr.fd, &read_fdset)) {
			/* Something on IF and address event netlink socket,
			   fetch it. */
			HIP_DEBUG("we are getting something ... ACQUIRE?\n");
			hip_netlink_receive(&nl_ifaddr, hip_netdev_event, NULL);
		} else {
			HIP_INFO("Unknown socket activity.");
		}
		while (hwo = hip_get_work_order()) {
			HIP_DEBUG("Processing work order\n");
			hip_do_work(hwo);
		}
	}
out_err:
	/* free allocated resources */
	if (hip_raw_sock)
		close(hip_raw_sock);
	if (hip_user_sock)
		close(hip_user_sock);
	if (nl_ifaddr.fd)
		close(nl_ifaddr.fd);

	delete_all_addresses();
	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

	/* On exit the general policy must be cancelled */
	HIP_DEBUG("Deleting the General SPs\n"),
	hip_delete_prefix_sp_pair();

	return err;
}

