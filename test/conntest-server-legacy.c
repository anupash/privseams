/*
 * Refactored from conntest-server to test the legacy API and getaddrinfo()
 * with multiple local addrinfo structures (for every local HI).
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

int create_serversocket(int proto, char *port) {
  int fd, on = 1, a, i;
  struct sockaddr_in6 *addr;
  struct addrinfo *res;
  struct addrinfo *ai;
  struct addrinfo hints;
  char *service = "12345";

  if (proto == IPPROTO_TCP) {
    fd = socket(AF_INET6, SOCK_STREAM, 0);
  } else {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
  }
  if (fd < 0) {
    perror("socket");
    exit(1);
  }

  //setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  hints.ai_flags = AI_HIP | AI_PASSIVE;
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = proto;

  HIP_DEBUG("PORT:%s\n",port);  

  a = getaddrinfo(NULL, port, &hints, &res);
  if (a != 0) {
    printf("*** ERROR: %s ***\n", gai_strerror(a));
    return(1);
  }

  //bzero(&addr, sizeof(addr));
  //addr.sin6_family = AF_INET6;
  //addr.sin6_port = htons(port);
  //addr.sin6_addr = in6addr_any;
  //addr.sin6_flowinfo = 0;
  // the following gives error "structure has no member named `sin6_scope_id'"
  // on gaijin:
  // addr.sin6_scope_id = 0 ;

  addr = (struct sockaddr_in6 *)res->ai_addr;

  printf("AF_INET6\tin6_addr=0x");
  for (i = 0; i < 16; i++)
    printf("%02x ", (unsigned char) (addr->sin6_addr.in6_u.u6_addr8[i]));
  printf("\n");
  
  if (bind(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_in6)) < 0) {
    perror("bind");
    close(fd);
    exit(1);
  }

  if (proto == IPPROTO_TCP) {
    if (listen(fd, 1) < 0) {
      perror("listen");
      close(fd);
      exit(1);
    }
  }

  return(fd);
}


int main(int argc,char *argv[]) {
  
  int serversock;
  int peer;
  unsigned int peerlen;
  struct sockaddr_in6 peeraddr;
  char mylovemostdata[IP_MAXPACKET];
  int recvnum, sendnum;
  char addrstr[INET6_ADDRSTRLEN];
  
  int port;
  int proto;

  if (signal(SIGTERM, sig_handler) == SIG_ERR) {
    exit(1);
  }
  
  if (argc != 3) {
    fprintf(stderr, "Usage: %s tcp|udp port\n", argv[0]);
    exit(1);
  }
  
  if (strcmp(argv[1], "tcp") == 0) {
    proto = IPPROTO_TCP;
  } else if (strcmp(argv[1], "udp") == 0) {
    proto = IPPROTO_UDP;
  } else {
    fprintf(stderr, "error: protonum != tcp|udp\n");
    exit(1);
  }
  
  //port = atoi(argv[2]);
  //if (port <= 0 || port >= 65535) {
  //  fprintf(stderr, "error: port < 0 || port > 65535\n");
  //  exit(1);
  //}
  serversock = create_serversocket(proto, argv[2]);
  
  peerlen = sizeof(struct sockaddr_in6);
  
  while(1) {
    
    if (proto == IPPROTO_TCP) {
      peer = accept(serversock, (struct sockaddr *)&peeraddr, &peerlen);
      if (peer < 0) {
	perror("accept");
	exit(2);
      }
      //fprintf(stderr, "accept %s\n", inet_ntop(AF_INET6, &peeraddr.sin6_addr, addrstr, sizeof(addrstr)));
      
      while((recvnum = recv(peer, mylovemostdata, sizeof(mylovemostdata), 0)) > 0 ) {
	mylovemostdata[recvnum] = '\0';
	printf("%s", mylovemostdata);
	fflush(stdout);
	if (recvnum == 0) {
	  close(peer);
	  break;
	}
	
	/* send reply */
	sendnum = send(peer, mylovemostdata, recvnum, 0);
	if (sendnum < 0) {
	  perror("send");
	  exit(2);
	}
      }
    } else { /* UDP */
      peerlen = sizeof(struct sockaddr_in6);
      peer = serversock;
      while((recvnum = recvfrom(peer, mylovemostdata, sizeof(mylovemostdata), 0, (struct sockaddr *)&peeraddr, &peerlen)) > 0 ) {
	//printf("server: peer addr=%s port=%d\n", inet_ntop(AF_INET6, &peeraddr.sin6_addr, addrstr, sizeof(addrstr)), ntohs(peeraddr.sin6_port));
	mylovemostdata[recvnum] = '\0';
	fprintf(stderr,"%s", mylovemostdata);
	fflush(stdout);
	if (recvnum == 0) {
	  close(peer);
	  break;
	}
	
	/* send reply */
	sendnum = sendto(peer, mylovemostdata, recvnum, 0, (struct sockaddr *)&peeraddr, peerlen);
	if (sendnum < 0) {
	  perror("send");
	  exit(2);
	}
      }
    }
    //fprintf(stderr, "\n*CLOSED*\n");
  }
  
  close(peer);
  close(serversock);
  return(0);
}
