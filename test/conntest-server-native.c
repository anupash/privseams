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
  struct endpointinfo hints, *res = NULL, *test = NULL;
  struct sockaddr_eid peer_eid;
  char *port_name, mylovemostdata[IP_MAXPACKET];
  int recvnum, sendnum, serversock = 0, sockfd = 0, err = 0, on = 1;
  int socktype, endpoint_family = PF_HIP;
  socklen_t peer_eid_len;

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

  /*debug*/
#if 0
  if (res->ei_next) {
    test = res->ei_next;
    printf("ei_flags[res]: %d \n",res->ei_flags);
    printf("ei_flags[next]: %d \n",test->ei_flags);
    test = test->ei_next;
    printf("ei_flags[next2]: %d \n",test->ei_flags);
    test = test->ei_next;
    printf("ei_flags[next3]: %d \n",test->ei_flags);

  }
#endif

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
      while(recvnum = recvfrom(sockfd, mylovemostdata,
			       sizeof(mylovemostdata), 0,
			       (struct sockaddr *)& peer_eid,
			       &peer_eid_len) > 0) {
	mylovemostdata[recvnum] = '\0';
	printf("%s", mylovemostdata);
	fflush(stdout);
	if (recvnum == 0) {
	  break;
	}
	
	/* send reply */
	sendnum = sendto(sockfd, mylovemostdata, recvnum, 0,
			 (struct sockaddr *) &peer_eid, peer_eid_len);
	if (sendnum < 0) {
	  HIP_PERROR("send");
	  err = 1;
	  goto out;
	}
      }
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
