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

#include <signal.h>     /* signal() */
#include <net/hip.h>
#include <stdio.h>      /* stderr and others */
#include <errno.h>      /* errno */
#include <unistd.h>
#include <fcntl.h>
#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */
#include <socket.h>
#include <sys/un.h>

#include "hipd.h"
#include "crypto.h"
#include "cookie.h"
#include "workqueue.h"
#include "debug.h"
#include "netdev.h"
#ifdef CONFIG_HIP_HI3
#include "i3_client_api.h"
#endif

struct hip_nl_handle nl_khipd;
struct hip_nl_handle nl_ifaddr;
time_t load_time;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;
int hip_agent_status = 0;
struct sockaddr_un agent_addr;


void usage() {
	fprintf(stderr, "HIPL Daemon %.2f\n", HIPL_VERSION);
        fprintf(stderr, "Usage: hipd [options]\n\n");
	fprintf(stderr, "  -f run in foreground\n");
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
	if (hip_netlink_open(&nl_ifaddr, RTMGRP_LINK | RTMGRP_IPV6_IFADDR, NETLINK_ROUTE) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		ret = 1;
		goto out_err;
	}
	highest_descriptor = nl_ifaddr.fd;

	/* Resolve our current addresses, afterwards the events from
           kernel will maintain the list */
	HIP_DEBUG("Initializing the netdev_init_addresses\n");
	hip_netdev_init_addresses(&nl_ifaddr);

	/* Open the netlink socket for kernel communication */
	if (hip_netlink_open(&nl_khipd, 0, NETLINK_HIP) < 0) {
		HIP_ERROR("Netlink khipd workorders socket error: %s\n", strerror(errno));
		ret = 1;
		goto out_err;
	}


	hip_user_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (hip_user_sock < 0)
	{
		HIP_ERROR("Could not create socket for user communication.\n");
		err = -1;
		goto out_err;
	}
	unlink(HIP_DAEMONADDR_PATH);
	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_LOCAL;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&daemon_addr,
		      sizeof(daemon_addr)),
		 -1, "Bind failed.");

	highest_descriptor = nl_khipd.fd > highest_descriptor ? nl_khipd.fd : highest_descriptor;
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

	/* Ping kernel and announce our PID */
	HIP_INIT_WORK_ORDER_HDR(ping.hdr, HIP_WO_TYPE_OUTGOING,
				HIP_WO_SUBTYPE_PING, NULL, NULL, NULL,
				getpid(), 0, 0);
	ping.msg = hip_msg_alloc();
	if (hip_netlink_talk(&nl_khipd, &ping, &ping)) {
		HIP_ERROR("Unable to connect to the kernel HIP daemon over netlink.\n");
		ret = 1;
		goto out_err;
	}
	
	hip_msg_free(ping.msg);

#ifdef CONFIG_HIP_HI3
	cl_init(i3_config);
#endif

	/* Enter to the select-loop */
	for (;;) {
		struct hip_work_order *hwo;
		
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(nl_khipd.fd, &read_fdset);
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
				
		} else if (FD_ISSET(nl_khipd.fd, &read_fdset)) {
				/* Something on kernel daemon netlink socket, fetch it
				   to the queue */
			hip_netlink_receive(&nl_khipd,
					    hip_netlink_receive_workorder,
					    NULL);
				
		} else if (FD_ISSET(hip_user_sock, &read_fdset)) {
			int n;
			socklen_t alen;
			err = 0;
			HIP_DEBUG("Receiving user message(?).\n");
			bzero(&agent_addr, sizeof(agent_addr));
			alen = sizeof(agent_addr);
			n = recvfrom(hip_user_sock, user_msg,
				     sizeof(struct hip_common), 0,
				     (struct sockaddr *)&agent_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Recvfrom() failed.\n");
				err = -1;
			}
			memset(user_msg, 0, sizeof(struct hip_common));
			hip_build_user_hdr(user_msg, SO_HIP_DAEMON_PING_REPLY, 0);
			alen = sizeof(agent_addr);			
			n = sendto(hip_user_sock, user_msg, sizeof(struct hip_common),
				   0, (struct sockaddr *)&agent_addr, alen);
			if (n < 0)
			{
				HIP_ERROR("Sendto() failed.\n");
				err = -1;
			}

			if (err == 0)
			{
				HIP_DEBUG("HIP agent ok.\n");
				hip_agent_status = 1;
			}
			
                        /* XX FIX: handle the message from agent */
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
	if (user_msg != NULL) HIP_FREE(user_msg);

	if (nl_ifaddr.fd)
		close(nl_ifaddr.fd);
	if (hip_user_sock)
		close(hip_user_sock);
	delete_all_addresses();
	HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), ret);
out_out:
	return ret;
}


int hip_agent_is_alive()
{
	return (hip_agent_status);
}


int hip_agent_filter(struct hip_common *msg)
{
	int err = 0;
	int n, sendn;
	socklen_t alen;
	
	if (!hip_agent_is_alive())
	{
		HIP_DEBUG("Agent is not alive\n");
		return (-ENOENT);
	}

	HIP_DEBUG("Filtering hip control message trough agent,"
	          " message body size is %d bytes.\n",
	          hip_get_msg_total_len(msg) - sizeof(struct hip_common));

	alen = sizeof(agent_addr);			
	n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
	           0, (struct sockaddr *)&agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("Sent %d bytes to agent for handling.\n", n);

	alen = sizeof(agent_addr);
	sendn = n;
	n = recvfrom(hip_user_sock, msg, n, 0,
	             (struct sockaddr *)&agent_addr, &alen);
	if (n < 0)
	{
		HIP_ERROR("Recvfrom() failed.\n");
		err = -1;
		goto out_err;
	}
	/* This happens, if agent rejected the packet. */
	else if (sendn != n)
	{
		err = 1;
	}

out_err:
	return (err);
}
