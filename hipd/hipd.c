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

#include "hipd.h"
#include "crypto.h"
#include "cookie.h"
#include "workqueue.h"
#include "debug.h"
#include "netdev.h"

struct hip_nl_handle nl_khipd;
struct hip_nl_handle nl_ifaddr;
time_t load_time;

void usage() {
     fprintf(stderr, "hipl usage\n");
}

/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
	HIP_ERROR("Signal: %d\n", signal);
//	hip_uninit_workqueue();
#ifdef CONFIG_HIP_RVS
        hip_uninit_rvadb();
#endif
	//        hip_uninit_host_id_dbs();
        //hip_uninit_hadb();
	// hip_uninit_beetdb();
//	rtnl_close(&rtnl);
	//	hip_uninit_r1();
	exit(signal);
}

int main(int argc, char *argv[]) {
	char ch;
	char buff[HIP_MAX_NETLINK_PACKET];
	fd_set read_fdset;
	int foreground = 0;
	int highest_descriptor;
	int s_net;
	int err;
	struct timeval timeout;
	struct hip_work_order ping;
	
	/* Parse command-line options */
	while ((ch = getopt(argc, argv, "f")) != -1) {
		switch (ch) {
		case 'f':
			foreground = 1;
			break;
		case '?':
		default:
			usage();
			return(0);
		}
	}
	
	/* Configuration is valid! Fork a daemon, if so configured */
	if (!foreground) {
		if (fork() > 0)
			return(0);
		hip_set_logtype(LOGTYPE_SYSLOG);
	} else {
		hip_set_logtype(LOGTYPE_STDERR);
	}
	
	time(&load_time);

	hip_set_logtype(LOGTYPE_SYSLOG);
	
	/* Register signal handlers */
	signal(SIGINT, hip_exit);
	signal(SIGTERM, hip_exit);

	/* Open the netlink socket for address and IF events */
	if (hip_netlink_open(&nl_ifaddr, RTMGRP_LINK | RTMGRP_IPV6_IFADDR, NETLINK_ROUTE) < 0) {
		HIP_ERROR("Netlink address and IF events socket error: %s\n", strerror(errno));
		return(1);
	}
	highest_descriptor = nl_ifaddr.fd;

	/* Resolve our current addresses, afterwards the events from
           kernel will maintain the list */
	hip_netdev_init_addresses(&nl_ifaddr);

	/* Open the netlink socket for kernel communication */
	if (hip_netlink_open(&nl_khipd, 0, NETLINK_HIP) < 0) {
		HIP_ERROR("Netlink khipd workorders socket error: %s\n", strerror(errno));
		return(1);
	}

	highest_descriptor = nl_khipd.fd > highest_descriptor ? nl_khipd.fd : highest_descriptor;

        if(!hip_init_r1()) {
		HIP_ERROR("Unable to init R1.\n");
		return(1);
	}

        if (hip_init_cipher() < 0) {
		HIP_ERROR("Unable to init ciphers.\n");
		return(1);
	}

        hip_init_hadb();

#ifdef CONFIG_HIP_RVS
        hip_init_rvadb();
#endif	

	/* Workqueue relies on an open netlink connection */
	hip_init_workqueue();

	/* Ping kernel and announce our PID */
	INIT_WORK_ORDER_HDR(ping.hdr, HIP_WO_TYPE_OUTGOING, HIP_WO_SUBTYPE_PING, NULL, NULL, getpid(), 0);
	ping.msg = hip_msg_alloc();
	if (hip_netlink_talk(&nl_khipd, &ping, &ping)) {
		HIP_ERROR("Unable to connect to the kernel HIP daemon over netlink.\n");
		return(1);
	}
	
	hip_msg_free(ping.msg);

	/* Enter to the select-loop */
	for (;;) {
		struct hip_work_order *hwo;

		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(nl.fd, &read_fdset);
		FD_SET(nl_ifaddr.fd, &read_fdset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		HIP_DEBUG("select\n");
		/* wait for socket activity */
		if ((err = select((highest_descriptor + 1), &read_fdset, 
				  NULL, NULL, &timeout)) < 0) {
			HIP_INFO("select() error: %s.\n", strerror(errno));
			
		} else if (err == 0) { 
			/* idle cycle - select() timeout */               
			
               } else if (FD_ISSET(nl_khipd.fd, &read_fdset)) {
                       /* Something on kernel daemon netlink socket, fetch it
			  to the queue */
                       hip_netlink_receive(&nl_khipd,
					   hip_netlink_receive_workorder,
					   NULL);
 
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

	/* Never enters here */
	return (1);
}
