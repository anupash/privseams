/*
 * Echo STDIN to a selected machine via tcp or udp using ipv6. Use this
 * with conntest-server.
 *
 * $Id: conntest-client-hip.c,v 1.6 2003/09/02 12:45:13 mkomu Exp $
 *
 * Notes:
 * - assumes that udp packets arrive in order (high probability within same
 *   network)
 * Bugs:
 * - none
 * Todo:
 * - rewrite/refactor for better modularity
 */

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
#include <sys/time.h>
#include <time.h>

int create_socket(int proto, int port) {
  int fd;

  if (proto == IPPROTO_TCP) {
    fd = socket(AF_INET6, SOCK_STREAM, 0);
  } else if (proto == IPPROTO_UDP)  {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
  } else {
    perror("unhandled proto");
    exit(1);
  }

  if (fd < 0) {
    perror("socket");
    exit(1);
  }

  return(fd);
}


// usage: ./conntest-client host tcp|udp port
// reads stdin

int main(int argc,char *argv[]) {
  struct timeval stats_before, stats_after;
  long stats_diff_sec, stats_diff_usec;
  int sock;
  struct sockaddr_hip6 peeraddr;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  int recvnum, sendnum;
  int datalen = 0;
  int port = 0;
  int proto;
  int datasent = 0;
  int datareceived = 0;
  int ch;

  if (argc != 5) {
    fprintf(stderr, "Usage: %s addr tcp|udp port hit\n", argv[0]);
    exit(1);
  }

  if (strcmp(argv[2], "tcp") == 0) {
    proto = IPPROTO_TCP;
  } else if (strcmp(argv[2], "udp") == 0) {
    proto = IPPROTO_UDP;
  } else {
    fprintf(stderr, "error: proto != tcp|udp\n");
    exit(1);
  }

  port = atoi(argv[3]);
  if (port <= 0 || port >= 65535) {
    fprintf(stderr, "error: port < 0 || port > 65535\n");
    exit(1);
  }

  sock = create_socket(proto, port);

  /* set server info */
  bzero(&peeraddr, sizeof(peeraddr));
  peeraddr.ship6_family = AF_INET6;
  peeraddr.ship6_port = htons(port);
  peeraddr.ship6_flowinfo = 0;
  if(inet_pton(AF_INET6, argv[1], (struct in6_addr *) &peeraddr.ship6_addr) < 0) {
    perror("inet_pton");
    exit(1);
  }
  if(inet_pton(AF_INET6, argv[4], (struct in6_addr *) &peeraddr.ship6_hit) < 0) {
    perror("inet_pton");
    exit(1);
  }

  // data from stdin to buffer
  bzero(receiveddata, IP_MAXPACKET);
  bzero(mylovemostdata, IP_MAXPACKET);

  while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) { // horrible code
    mylovemostdata[datalen] = (unsigned char) ch;
    datalen++;
  }
  //fprintf(stderr, "datalen=%d\n", datalen);


  /* send and receive data */
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    
    gettimeofday(&stats_before, NULL);
    if (connect(sock, (struct sockaddr *) &peeraddr, sizeof(peeraddr)) < 0) {
      perror("connect");
      exit(1);
    }
    gettimeofday(&stats_after, NULL);
    stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000;
    stats_diff_usec = (stats_after.tv_usec - stats_before.tv_usec) / 1000;
    /* note: the 1 ms error in diff_usec is cancelled by diff_sec */
    printf("connect took %ld ms\n", stats_diff_sec + stats_diff_usec);

    while((datasent < datalen) || (datareceived < datalen)) { // send all

      if (datasent < datalen) {
	sendnum = send(sock, mylovemostdata+datasent, datalen-datasent, 0);
	if (sendnum < 0) {
	  perror("send");
	  printf("FAIL\n");
	  exit(2);
	}
	datasent += sendnum;
	//fprintf(stderr, "sendnum=%d ", sendnum);
      }

      if (datareceived < datalen) {
	recvnum = recv(sock, receiveddata+datareceived, datalen-datareceived, 0);
	if (recvnum < 0) {
	  perror("recv");
	  exit(2);
	}
	datareceived += recvnum;
	// fprintf(stderr, "recvnum=%d\n", recvnum);
	//	receiveddata[datareceived] = '\0'; // turha ?
      }
      //fprintf(stderr, "datalen=%d datasent=%d datareceived=%d\n", datalen, datasent, datareceived);
    }
  } else {
    perror("weird proto");
    exit(1);
  }

  if (!memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
    printf("OK\n");
  } else {
    printf("FAIL\n");
    return(1);
  }

  close(sock);
  return(0);
}
