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

#include <errno.h>      /* errno */
#include <signal.h>     /* signal() */
#include <stdio.h>      /* stderr and others */
#include <sys/socket.h> /* socket functions */
#include <sys/select.h> /* select */
#include <net/hip.h>

#include "hipd.h"
#include "debug.h"

void usage() {
     fprintf(stderr, "hipl usage\n");
}

/*
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 */
void hip_exit(int signal) {
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

     /* Configuration is valid, fork a daemon, if so configured */
     if (!foreground) {
          if (fork() > 0)
               return(0);
     }

     /* Register signal handlers */
     signal(SIGINT, hip_exit);
     signal(SIGTERM, hip_exit);
     signal(SIGSEGV, hip_exit);

     /* Open the netlink socket for kernel communication */
     if (hip_netlink_open() < 0) {
          HIP_ERROR("Netlink socket error: %s\n", strerror(errno));
          //unlink(HIP_LOCK_FILENAME);
          return(1);
     }

     /* Workqueue stores a reference to the socket handle to provide a
      * simple interface its callers */
     hip_init_workqueue(s_net);

     highest_descriptor = s_net;

     /* Enter to the select-loop */
     for (;;) { 
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
		  /* Something on Netlink socket */
		  hip_get_work_order();
		  

		  /*err = read(s_net, buff, sizeof(buff));
               if (err < 0) {
	       HIP_INFO("Netlink read() error - %d %s\n", 
	       errno, strerror(errno));
	       }*/
		  
		  // FIXME: process the message kernel HIPL sent
		  // transform the netlink msg to a work order
		  
               // hip_handle_netlink(buff, err);
          } else {
              HIP_INFO("unknown socket activity.");
          } /* select */
     }

     return(0);
}
