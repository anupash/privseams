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
//#include <linux/socket.h> /* sa_family_t */
#include <stdio.h>      /* stderr and others */
//#include <iproute/libnetlink.h> /* netlink connectivity */
#include <errno.h>      /* errno */
//#include <linux/time.h> /* struct timeval */

//#include <sys/socket.h> /* socket functions */
//#include <sys/select.h> /* select */



#include "hipd.h"
#include "workqueue.h"
#include "debug.h"

struct rtnl_handle rtnl;

void usage() {
     fprintf(stderr, "hipl usage\n");
}

/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
	hip_uninit_workqueue();
	rtnl_close(&rtnl);
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
	signal(SIGSEGV, hip_exit);

	/* Open the netlink socket for kernel communication */
	if (rtnl_open(&rtnl, 0) < 0) {
		HIP_ERROR("Netlink socket error: %s\n", strerror(errno));
		return(1);
	}

	/* For now useless, but keep record of the highest fd for
	 * future purposes (multiple sockets to select from) */
	highest_descriptor = rtnl.fd;
	
	/* Workqueue relies on an open netlink connection */
	hip_init_workqueue();
	
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
			HIP_DEBUG("Work done\n");
		}
	}

 out_err:
	/* never enters here */
	return (1);
}
