/*
 * Echo STDIN to a selected machine via tcp or udp using ipv6. Use this
 * with conntest-server.
 *
 * $Id: conntest-client-gai.c,v 1.16 2003/10/14 15:50:30 krisu Exp $
 */

/*
 * Notes:
 * - assumes that udp packets arrive in order (high probability within same
 *   network)
 * Bugs:
 * - none
 * Todo:
 * - rewrite/refactor for better modularity
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
#include <sys/time.h>
#include <time.h>
#include "tools/debug.h"

int create_socket(int proto) {
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
  unsigned long stats_diff_sec, stats_diff_usec;
  int sock, socktype;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  int recvnum, sendnum;
  int datalen = 0;
  int port = 0;
  int proto;
  int datasent = 0;
  int datareceived = 0;
  int ch;

  struct addrinfo hints;
  struct addrinfo *res, *ai;
  int gai_err;
 
  set_logtype(LOGTYPE_STDERR);

  if (argc != 4) {
    fprintf(stderr, "Usage: %s host tcp|udp port\n", argv[0]);
    exit(1);
  }

  if (strcmp(argv[2], "tcp") == 0) {
    proto = IPPROTO_TCP;
    socktype = SOCK_STREAM;
  } else if (strcmp(argv[2], "udp") == 0) {
    proto = IPPROTO_UDP;
    socktype = SOCK_DGRAM;
  } else {
    fprintf(stderr, "error: proto != tcp|udp\n");
    exit(1);
  }

  port = atoi(argv[3]);
  if (port <= 0 || port >= 65535) {
    fprintf(stderr, "error: port < 0 || port > 65535\n");
    exit(1);
  }

  /* lookup host */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_HIP;
  hints.ai_family = AF_INET6;
  hints.ai_socktype = socktype;
  hints.ai_protocol = proto;

  gai_err = getaddrinfo(argv[1], NULL, &hints, &res);
  if (gai_err) {
    printf("GAI ERROR %d: %s\n", gai_err, gai_strerror(gai_err));
    return(1);
  }

  printf("got gai addresses:\n");
  for(ai = res; ai != NULL; ai = ai->ai_next) {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
    int i = 0;

    s->sin6_port = htons(port);
    printf("GAI: ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ai_addrlen=%d ai_canonname=%s\n",
	   ai->ai_flags, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addrlen, ai->ai_canonname);
    printf("\tAF_INET6: ship6_port=%d in6_addr=0x", port);
    for (i = 0; i < 16; i++) printf("%02x", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
    printf("\n");
  }
  printf("\n\n");

  sock = create_socket(proto);

  // data from stdin to buffer
  bzero(receiveddata, IP_MAXPACKET);
  bzero(mylovemostdata, IP_MAXPACKET);

  printf("Input some text, press enter and ctrl+d\n");

  while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) { // horrible code
    mylovemostdata[datalen] = (unsigned char) ch;
    datalen++;
  }
  //fprintf(stderr, "datalen=%d\n", datalen);


  /* send and receive data */
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    gettimeofday(&stats_before, NULL);
    if (connect(sock, res->ai_addr, sizeof(struct sockaddr_in6)) < 0) {
      perror("connect");
      goto out;
    }
    gettimeofday(&stats_after, NULL);
    stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
    stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;

    printf("connect took %.10f sec\n", (stats_diff_sec+stats_diff_usec)/1000000.0);

    while((datasent < datalen) || (datareceived < datalen)) { // lähetä kaikki

      if (datasent < datalen) {
	sendnum = send(sock, mylovemostdata+datasent, datalen-datasent, 0);

	if (sendnum < 0) {
	  perror("send");
	  printf("FAIL\n");
	  goto out;
	}
	datasent += sendnum;
	//fprintf(stderr, "sendnum=%d ", sendnum);
      }

      if (datareceived < datalen) {
	recvnum = recv(sock, receiveddata+datareceived, datalen-datareceived, 0);
	if (recvnum <= 0) {
	  perror("recv");
	  goto out;
	}
	datareceived += recvnum;
	// fprintf(stderr, "recvnum=%d\n", recvnum);
	//	receiveddata[datareceived] = '\0'; // turha ?
      }
      //fprintf(stderr, "datalen=%d datasent=%d datareceived=%d\n", datalen, datasent, datareceived);
    }
  } else {
    perror("weird proto");
    goto out;
  }

  if (!memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
    printf("OK\n");
  } else {
    printf("FAIL\n");
    return(1);
  }

 out:
  close(sock);
  return(0);
}
