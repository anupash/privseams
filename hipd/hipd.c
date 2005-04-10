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

#include "hipd.h"
#include "workqueue.h"
#include "debug.h"

struct hip_nl_handle nl;

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
//	rtnl_close(&rtnl);
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
	}
	
	/* Register signal handlers */
	signal(SIGINT, hip_exit);
	signal(SIGTERM, hip_exit);

	/* Open the netlink socket for kernel communication */
	if (hip_netlink_open(&nl, 0, NETLINK_HIP) < 0) {
		HIP_ERROR("Netlink socket error: %s\n", strerror(errno));
		return(1);
	}

	/* For now useless, but keep record of the highest fd for
	 * future purposes (multiple sockets to select from) */
	highest_descriptor = nl.fd;
	
	/* Workqueue relies on an open netlink connection */
	hip_init_workqueue();

	/* Ping kernel and announce our PID */
	INIT_WORK_ORDER_HDR(ping.hdr, HIP_WO_TYPE_OUTGOING, HIP_WO_SUBTYPE_PING, NULL, NULL, getpid(), 0);
	ping.msg = hip_msg_alloc();
	if (hip_netlink_talk(&ping, &ping)) {
		HIP_ERROR("Unable to connect to the kernel HIP daemon over netlink.\n");
		return(1);
	}
	
	hip_msg_free(ping.msg);

	/* Enter to the select-loop */
	for (;;) {
		struct hip_work_order *hwo;

		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(s_net, &read_fdset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		
		/* wait for socket activity */
		if ((err = select((highest_descriptor + 1), &read_fdset, 
				  NULL, NULL, &timeout)) < 0) {
			HIP_INFO("select() error: %s.\n", strerror(errno));
			
		} else if (err == 0) { 
			/* idle cycle - select() timeout */               
			
		} else if (FD_ISSET(s_net, &read_fdset)) {
			/* Something on Netlink socket, fetch it to
                           the queue */
			hip_netlink_receive();

		} else {
			HIP_INFO("Unknown socket activity.");
		}

		while (hwo = hip_get_work_order()) {
			hip_do_work(hwo);
		}
	}

	/* Never enters here */
	return (1);
}
