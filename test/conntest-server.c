/*
 * Get data from client and send it back (echo server). Use this with
 * conntest-client.
 *
 * Bugs: 
 * - this is a kludge
 *
 * Todo:
 * - rewrite/refactor for better modularity
 * - reuse port!
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
/* Kludge: compilation problems on Debian testing 20040202 */
#if 0
#  include <signal.h>
#else
#  define SIGTERM 15
#  define SIG_ERR -1
typedef void (*__sighandler_t)(int);
#endif

#include "tools/debug.h"

static void sig_handler(int signo) {
  if (signo == SIGTERM) {
    // close socket
    HIP_DIE("Sigterm\n");
  } else {
    HIP_DIE("Signal %d\n", signo);
  }
}

int create_serversocket(int proto, int port) {
  int fd;
  struct sockaddr_in6 addr;
  
  if (proto == IPPROTO_TCP) {
    fd = socket(AF_INET6, SOCK_STREAM, 0);
  } else {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
  }
  if (fd < 0) {
    perror("socket");
    exit(1);
  }

  bzero(&addr, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
  addr.sin6_addr = in6addr_any;
  addr.sin6_flowinfo = 0;
  // the following gives error "structure has no member named `sin6_scope_id'"
  // on gaijin:
  // addr.sin6_scope_id = 0 ;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) {
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
  
  port = atoi(argv[2]);
  if (port <= 0 || port >= 65535) {
    fprintf(stderr, "error: port < 0 || port > 65535\n");
    exit(1);
  }
  serversock = create_serversocket(proto, port);
  
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
