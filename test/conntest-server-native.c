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
#include <signal.h>
#include <net/if.h>
#include "tools/debug.h"

static void sig_handler(int signo) {
  if (signo == SIGTERM) {
    // close socket
    exit(0);
  } else {
    exit(1);
  }
}

int main(int argc,char *argv[]) {
  struct endpointinfo hints, *res = NULL;
  struct if_nameindex *ifaces = NULL;
  struct sockaddr_eid my_eid, peer_eid;
  char *port_name;
  char mylovemostdata[IP_MAXPACKET];
  int recvnum, sendnum;
  int serversock = 0, sockfd = 0;
  int err = 0;
  int port;
  int proto;
  socklen_t peer_eid_len;

  set_logtype(LOGTYPE_STDERR);

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
    proto = IPPROTO_TCP;
  } else if (strcmp(argv[1], "udp") == 0) {
    proto = IPPROTO_UDP;
  } else {
    HIP_ERROR("error: protonum != tcp|udp\n");
    err = 1;
    goto out;
  }
  
  port_name = argv[2];
  port = atoi(port_name);
  if (port <= 0 || port >= 65535) {
    HIP_ERROR("error: port < 0 || port > 65535\n");
    err = 1;
    goto out;
  }

  if (proto == IPPROTO_TCP) {
    serversock = socket(AF_INET6, SOCK_STREAM, 0);
  } else {
    serversock = socket(AF_INET6, SOCK_DGRAM, 0);
  }
  if (serversock < 0) {
    HIP_PERROR("socket");
    err = 1;
    goto out;
  }

  memset(&hints, 0, sizeof(struct endpointinfo));
  hints.ei_family = PF_HIP;
  err = getendpointinfo(NULL, port_name, &hints, &res);
  if (err) {
    HIP_ERROR("Resolving of peer identifiers failed (%d)\n", err);
    goto out;
  }
  ifaces = if_nameindex();
  if (ifaces == NULL || (ifaces->if_index == 0)) {
    HIP_ERROR("%s\n", (ifaces == NULL) ? "Iface error" : "No ifaces.");
    err = 1;
    goto out;
  }

  err = setmyeid(sockfd, &my_eid, res->ei_endpoint, ifaces);
  if (err) {
    HIP_ERROR("Failed to set up my EID.\n");
    err = 1;
    goto out;
  }

  if (bind(serversock, (struct sockaddr *) &my_eid,
	   sizeof(my_eid)) < 0) {
    HIP_PERROR("bind");
    err = 1;
    goto out;
  }

  if (proto == IPPROTO_TCP && listen(serversock, 1) < 0) {
      HIP_PERROR("listen");
      err = 1;
      goto out;
  }

  while(1) {
    if (proto == IPPROTO_TCP) {
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
	HIP_ERROR("%s", mylovemostdata);
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

  if (ifaces)
    if_freenameindex(ifaces);
  if (res)
    free_endpointinfo(res);

  if (sockfd)
    close(sockfd); // discard errors
  if (serversock)
    close(serversock); // discard errors

  return err;
}
