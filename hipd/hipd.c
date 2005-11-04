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

/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
	HIP_ERROR("Signal: %d\n", signal);
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
	int foreground = 1;
	int highest_descriptor;
	int s_net;
	int err;
	struct timeval timeout;
	struct hip_work_order ping;
	int ret = 0;

	struct hip_common *user_msg = NULL;
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
			goto out_out;
		}
	}

#ifdef CONFIG_HIP_HI3
	/* Note that for now the Hi3 host identities are not loaded in. */
	if (!i3_config) {
		fprintf(stderr, "Please do pass a valid i3 configuration file.\n");
		ret = 1;
		goto out_err;
	}
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

	/* Allocate user message. */
	user_msg = hip_msg_alloc();
	if (user_msg == NULL) goto out_err;

	/* Open the netlink socket for address and IF events */
	if (hip_netlink_open(&nl_ifaddr, RTMGRP_LINK | RTMGRP_IPV6_IFADDR, NETLINK_ROUTE | NETLINK_XFRM) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		ret = 1;
		goto out_err;
	}
	highest_descriptor = nl_ifaddr.fd;

	HIP_DEBUG("--->Setting SP\n");
	HIP_IFE(hip_setup_sp_prefix_pair(), -1);

	/* Resolve our current addresses, afterwards the events from
           kernel will maintain the list */
	HIP_DEBUG("Initializing the netdev_init_addresses\n");
	hip_netdev_init_addresses(&nl_ifaddr);
	HIP_DEBUG("***Opening netlink\n");

	/* See section 25 from Stevens */
	HIP_IFEL(((hip_raw_sock = socket(AF_INET6, SOCK_RAW, HIP_PROTO)) <= 0),
		 -1, "Raw socket creation failed. Not root?\n");

	{
		int on = 1;
		HIP_IFEL((setsockopt(hip_raw_sock, IPPROTO_IP, IP_HDRINCL,
				     &on, sizeof(on) < 0)), -1,
			 "Reading the IP header from raw socket forbidden\n");
	}



	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (hip_user_sock < 0)
	{
		HIP_ERROR("Could not create socket for user communication.\n");
		err = -1;
		goto out_err;
	}
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_UNIX;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	unlink(HIP_DAEMONADDR_PATH);
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&daemon_addr,
		      /*sizeof(daemon_addr)*/
		strlen(daemon_addr.sun_path) + sizeof(daemon_addr.sun_family)),
		 -1, "Bind failed.");
	HIP_DEBUG("Local server up\n");
	highest_descriptor = (hip_raw_sock > highest_descriptor) ?
	  hip_raw_sock : highest_descriptor;
	highest_descriptor = (hip_user_sock > highest_descriptor) ?
	  hip_user_sock : highest_descriptor;
	
        if (hip_init_cipher() < 0) {
		HIP_ERROR("Unable to init ciphers.\n");
		ret = 1;
		goto out_err;
	}

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
		} else if (FD_ISSET(hip_raw_sock, &read_fdset)) {
			/* XX FIX: read an IPv6(HIP) message from the raw
			   socket, and the IP addresses and IP header to
			   hip_receive_control_packet() */
			return -1;
		} else if (FD_ISSET(hip_user_sock, &read_fdset)) {
			int n;
			socklen_t alen;
			err = 0;
			HIP_DEBUG("Receiving user message(?).\n");
			bzero(&user_addr, sizeof(user_addr));
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
				-1, "Handing of user msg failed\n");

		} else if (FD_ISSET(nl_ifaddr.fd, &read_fdset)) {
				/* Something on IF and address event netlink socket,
				   fetch it. */
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
	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), ret);
out_out:
	return ret;
}

