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
  char mylovemostdata[IP_MAXPACKET], receiveddata[IP_MAXPACKET];
  char *proto_name, *peer_port_name, *peer_name;
  int recvnum, sendnum, datalen = 0, port = 0, proto, datasent = 0;
  int datareceived = 0, ch, gai_err, sock = 0, socktype;
  struct addrinfo hints, *res = NULL, *ai;
 
  hip_set_logtype(LOGTYPE_STDERR);
  hip_set_logfmt(LOGFMT_SHORT);

  if (argc != 4) {
    fprintf(stderr, "Usage: %s host tcp|udp port\n", argv[0]);
    exit(1);
  }

  peer_name = argv[1];
  proto_name = argv[2];
  peer_port_name = argv[3];

  if (strcmp(proto_name, "tcp") == 0) {
    proto = IPPROTO_TCP;
    socktype = SOCK_STREAM;
  } else if (strcmp(proto_name, "udp") == 0) {
    proto = IPPROTO_UDP;
    socktype = SOCK_DGRAM;
  } else {
    fprintf(stderr, "error: proto != tcp|udp\n");
    exit(1);
  }

  /* lookup host */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_HIP;
  hints.ai_family = AF_INET6; /* Legacy API supports only HIT-in-IPv6 */
  hints.ai_socktype = socktype;
  hints.ai_protocol = proto;

  gai_err = getaddrinfo(peer_name, peer_port_name, &hints, &res);
  if (gai_err) {
    printf("GAI ERROR %d: %s\n", gai_err, gai_strerror(gai_err));
    return(1);
  }

  /* data from stdin to buffer */
  bzero(receiveddata, IP_MAXPACKET);
  bzero(mylovemostdata, IP_MAXPACKET);

  printf("Input some text, press enter and ctrl+d\n");

  /* horrible code */
  while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) {
    mylovemostdata[datalen] = (unsigned char) ch;
    datalen++;
  }

  gettimeofday(&stats_before, NULL);

   /* connect */

  for(ai = res; ai != NULL; ai = ai->ai_next) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ai->ai_addr;
    char addr_str[INET6_ADDRSTRLEN];

    HIP_ASSERT(ai->ai_family == AF_INET6);
    sock = create_socket(proto);
    if (sock < 0) {
      sock = 0;
      printf("socket creation failed\n");
      goto out_err;
    }

    if (!inet_ntop(AF_INET6, (char *) &sin6->sin6_addr, addr_str,
 		   sizeof(addr_str))) {
      perror("inet_ntop\n");
      goto out_err;
    }

    printf("Trying to connect to %s\n", addr_str);

    if (connect(sock, ai->ai_addr, sizeof(struct sockaddr_in6)) < 0) {
      close(sock);
      sock = 0;
      printf("trying next\n");
      continue; /* Try next address */
    }
    break; /* Connect succeeded and data can be sent/received. */
  }

  if (sock == 0) {
    printf("failed to connect\n");
    goto out_err;
  }

  gettimeofday(&stats_after, NULL);
  stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
  stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;

  printf("connect took %.3f sec\n",
 	 (stats_diff_sec+stats_diff_usec) / 1000000.0);

  /* send and receive data */

  while((datasent < datalen) || (datareceived < datalen)) {

    if (datasent < datalen) {
      sendnum = send(sock, mylovemostdata+datasent, datalen-datasent, 0);

      if (sendnum < 0) {
 	perror("send");
 	printf("FAIL\n");
 	goto out_err;
       }
      datasent += sendnum;
    }

    if (datareceived < datalen) {
      recvnum = recv(sock, receiveddata+datareceived, datalen-datareceived, 0);
      if (recvnum <= 0) {
 	perror("recv");
 	goto out_err;
      }
       datareceived += recvnum;
    }
  }

  if (!memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
    printf("OK\n");
  } else {
    printf("FAIL\n");
    return(1);
  }

 out_err:

  if (res)
    freeaddrinfo(res);
  if (sock)
    close(sock);
  return 0;

}
