/*
 * Echo STDIN to a selected machine via tcp or udp using ipv6. Use this
 * with conntest-server.
 *
 * $Id: conntest-client-ghbn.c,v 1.3 2003/09/01 14:18:17 mika Exp $
 *
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


int create_socket(int proto) {
  int fd;

  if (proto == IPPROTO_TCP) {
    fd = socket(AF_INET6, SOCK_STREAM, 0);
  } else if (proto == IPPROTO_UDP)  {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
  } else {
    perror("create_socket:unhandled proto");
    exit(1);
  }

  if (fd < 0) {
    perror("create_socket:socket");
    exit(1);
  }

  return(fd);
}


// usage: ./conntest-client host tcp|udp port
// reads stdin

int main(int argc,char *argv[]) {

  int sock;
  struct sockaddr_in6 peeraddr;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  struct hostent *he;
  int recvnum, sendnum;
  int datalen = 0;
  int port = 0;
  int proto;
  int datasent = 0;
  int datareceived = 0;
  int ch;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s host tcp|udp port\n", argv[0]);
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

  sock = create_socket(proto);

  /* set server info */
  memset(&peeraddr, 0, sizeof(struct sockaddr_in6));
  peeraddr.sin6_family = AF_INET6;
  peeraddr.sin6_port = htons(port);
  peeraddr.sin6_flowinfo = 0;

  he = gethostbyname(argv[1]);
  if (he == NULL) {
    perror("!gethostbyname\n");
    exit(1);
  }

  if(inet_pton(AF_INET6, he->h_addr_list[0], (struct in6_addr *) &peeraddr.sin6_addr) < 0) {
    perror("inet_pton");
    exit(1);
  }

  // data from stdin to buffer
  memset(receiveddata, 0, IP_MAXPACKET);
  memset(mylovemostdata, 0, IP_MAXPACKET);

  while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) { // horrible code
    mylovemostdata[datalen] = (unsigned char) ch;
    datalen++;
  }
  //fprintf(stderr, "datalen=%d\n", datalen);


  /* send and receive data */
  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {

    if (connect(sock, (struct sockaddr *) &peeraddr, sizeof(struct sockaddr_in6)) < 0) {
      perror("connect");
      exit(1);
    }

    while((datasent < datalen) || (datareceived < datalen)) { // lähetä kaikki

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
	if (recvnum <= 0) {
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
