/*
 * Echo server: get data from client and send it back. Use this with
 * conntest-client-native.
 *
 * Bugs: 
 * - xx
 *
 * Todo:
 * - rewrite the kludge stuff
 * - use native API stuff
 * - reuse port!
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
/* Workaround for some compilation problems on Debian */
#ifndef __user
#  define __user
#endif
#include <signal.h>

#include "libinet6/debug.h"

static void sig_handler(int signo) {
  if (signo == SIGTERM) {
    // close socket
    HIP_DIE("Sigterm\n");
  } else {
    HIP_DIE("Signal %d\n", signo);
  }
}

int main(int argc,char *argv[]) {
  struct endpointinfo hints, *res = NULL;
  struct sockaddr_eid peer_eid;
  char *port_name;
  char mylovemostdata[IP_MAXPACKET];
  int recvnum, sendnum;
  int serversock = 0, sockfd = 0;
  int err = 0;
  int socktype;
  socklen_t peer_eid_len = sizeof(struct sockaddr_eid);
  int endpoint_family = PF_HIP;

  hip_set_logtype(LOGTYPE_STDERR);

  if (signal(SIGTERM, sig_handler) == SIG_ERR) {
    err = 1;
    goto out;
  }
  
  if (argc != 3) {
    HIP_ERROR("Usage: %s tcp|udp port\n", argv[0]);
    err = 1;
    goto out;
  }
  
  if (strcmp(argv[1], "tcp") == 0) {
    socktype = SOCK_STREAM;
  } else if (strcmp(argv[1], "udp") == 0) {
    socktype = SOCK_DGRAM;
  } else {
    HIP_ERROR("error: uknown socket type\n");
    err = 1;
    goto out;
  }
  
  port_name = argv[2];

  serversock = socket(endpoint_family, socktype, 0);
  if (serversock < 0) {
    HIP_PERROR("socket");
    err = 1;
    goto out;
  }

  setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  memset(&hints, 0, sizeof(struct endpointinfo));
  hints.ei_family = endpoint_family;
  hints.ei_socktype = socktype;

  err = getendpointinfo(NULL, port_name, &hints, &res);
  if (err) {
    HIP_ERROR("Resolving of peer identifiers failed (%d)\n", err);
    goto out;
  }

  if (bind(serversock, res->ei_endpoint, res->ei_endpointlen) < 0) {
    HIP_PERROR("bind");
    err = 1;
    goto out;
  }

  if (socktype == SOCK_STREAM && listen(serversock, 1) < 0) {
      HIP_PERROR("listen");
      err = 1;
      goto out;
  }

  while(1) {
    if (socktype == SOCK_STREAM) {
      sockfd = accept(serversock, (struct sockaddr *) &peer_eid,
		      &peer_eid_len);
      if (sockfd < 0) {
	HIP_PERROR("accept");
	err = 1;
	goto out;
      }

      while((recvnum = recv(sockfd, mylovemostdata,
			    sizeof(mylovemostdata), 0)) > 0 ) {
	mylovemostdata[recvnum] = '\0';
	printf("%s", mylovemostdata);
	fflush(stdout);
	if (recvnum == 0) {
	  break;
	}
	
	/* send reply */
	sendnum = send(sockfd, mylovemostdata, recvnum, 0);
	if (sendnum < 0) {
	  HIP_PERROR("send");
	  err = 1;
	  goto out;
	}
      }
    } else { /* UDP */
      sockfd = serversock;

      HIP_DEBUG("receiving data\n");

      while((recvnum = recvfrom(sockfd, mylovemostdata,
			       sizeof(mylovemostdata), 0,
			       (struct sockaddr *) &peer_eid,
			       &peer_eid_len)) > 0) {
	mylovemostdata[recvnum] = '\0';
	printf("%s", mylovemostdata);
	fflush(stdout);
	//if (recvnum == 0) {
	//  break;
	//}

	HIP_DEBUG("port was %d\n", ntohs(peer_eid.eid_port));
	HIP_DEBUG("family was %d\n", peer_eid.eid_family);
	HIP_DEBUG("value was %d\n", ntohs(peer_eid.eid_val));
	HIP_DEBUG("received %d bytes\n", recvnum);
	
	HIP_DEBUG("sending data\n");

	sendnum = sendto(sockfd, mylovemostdata, recvnum, 0,
			 (struct sockaddr *) &peer_eid, peer_eid_len);
	if (sendnum < 0) {
	  HIP_PERROR("sendto");
	  err = 1;
	  goto out;
	}
      }

      HIP_DEBUG("port was %d\n", ntohs(peer_eid.eid_port));
      HIP_DEBUG("family was %d\n", peer_eid.eid_family);
      HIP_DEBUG("value was %d\n", ntohs(peer_eid.eid_val));
      HIP_DEBUG("received %d bytes\n", recvnum);
    }
  }

 out:

  if (res)
    free_endpointinfo(res);

  if (sockfd)
    close(sockfd); // discard errors
  if (serversock)
    close(serversock); // discard errors

  return err;
}
