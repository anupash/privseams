/*
 * Echo STDIN to a selected server which should echo it back.
 * Use this application with conntest-server-xx.
 *
 * usage: ./conntest-client-native host tcp|udp port
 *        (reads stdin)
 *
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
#include <net/if.h>

void debug_endpoint(struct endpointinfo *res)
{
  struct endpointinfo *ei;
  struct addrinfo *ai;

  for(ei = res; ei != NULL; ei = ei->ei_next) {
    HIP_HEXDUMP("endpoint: ", ei->ei_endpoint, ei->ei_endpoint->len);
    for(ai = &ei->ei_addrlist; ai != NULL; ai = ai->ai_next) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
      int i = 0;
      
      HIP_DEBUG("GAI: ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ",
		ai->ai_flags, ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      HIP_DEBUG("ai_addrlen=%d ai_canonname=%s\n",
		ai->ai_addrlen, ai->ai_canonname);
      
      for (i = 0; i < 16; i++)
	HIP_DEBUG("%02x", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
      HIP_DEBUG("\n");
    }
    HIP_DEBUG("\n\n");
  }
}

int main(int argc,char *argv[]) {
  struct endpointinfo hints, *res = NULL;
  struct sockaddr_eid peer;
  struct timeval stats_before, stats_after;
  unsigned long stats_diff_sec, stats_diff_usec;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  char *proto_name, *peer_port_name, *peer_name;
  int recvnum, sendnum;
  int datalen = 0;
  int proto;
  int datasent = 0;
  int datareceived = 0;
  int ch;
  int err = 0;
  int sockfd = 0, socktype;
  se_family_t endpoint_family;
  

  set_logtype(LOGTYPE_STDERR);
 
  if (argc != 4) {
    HIP_ERROR("Usage: %s host tcp|udp port\n", argv[0]);
    err = 1;
    goto out;
  }
  
  peer_name = argv[1];
  proto_name = argv[2];
  peer_port_name = argv[3];
  endpoint_family = PF_HIP;
  
  /* Set transport protocol */
  if (strcmp(proto_name, "tcp") == 0) {
    proto = IPPROTO_TCP;
    socktype = SOCK_STREAM;
  } else if (strcmp(proto_name, "udp") == 0) {
    proto = IPPROTO_UDP;
    socktype = SOCK_DGRAM;
  } else {
    HIP_ERROR("Error: only TCP and UDP supported.\n");
    err = 1;
    goto out;
  }

  sockfd = socket(endpoint_family, socktype, 0);
  if (sockfd == -1) {
    HIP_ERROR("\n");
    err = 1;
    goto out;
  }
    
  /* set up host lookup information  */
  memset(&hints, 0, sizeof(hints));
  hints.ei_flags = PF_HIP;
  hints.ei_addrlist.ai_family = AF_INET6;
  hints.ei_addrlist.ai_socktype = socktype;
  hints.ei_addrlist.ai_protocol = proto;

  /* lookup host */
  err = getendpointinfo(peer_name, peer_port_name, &hints, &res);
  if (err) {
    HIP_ERROR("getaddrinfo failed (%d): %s\n", err, gepi_strerror(err));
    goto out;
  }

  debug_endpoint(res);

  err = setpeereid(&peer, res->ei_endpoint, &res->ei_addrlist);
  if (err) {
    HIP_ERROR("association failed (%d): %s\n", err);
    goto out;
  }

  // data from stdin to buffer
  bzero(receiveddata, IP_MAXPACKET);
  bzero(mylovemostdata, IP_MAXPACKET);

  // horrible code
  while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) {
    mylovemostdata[datalen] = (unsigned char) ch;
    datalen++;
  }

  gettimeofday(&stats_before, NULL);

  err = connect(sockfd, (struct sockaddr *) &peer, sizeof(peer));
  if (err) {
    HIP_PERROR("connect");
    goto out;
  }

  gettimeofday(&stats_after, NULL);
  stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
  stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;
  
  HIP_DEBUG("connect took %.10f sec\n",
	    (stats_diff_sec + stats_diff_usec) / 1000000.0);
  
  /* Send the data read from stdin to the server and read the response.
     The server should echo all the data received back to here. */
  while((datasent < datalen) || (datareceived < datalen)) {
    
    if (datasent < datalen) {
      sendnum = send(sockfd, mylovemostdata + datasent, datalen - datasent, 0);
      
      if (sendnum < 0) {
	HIP_PERROR("send");
	err = 1;
	goto out;
      }
      datasent += sendnum;
    }
    
    if (datareceived < datalen) {
      recvnum = recv(sockfd, receiveddata + datareceived,
		     datalen-datareceived, 0);
      if (recvnum <= 0) {
	HIP_PERROR("recv");
	err = 1;
	goto out;
      }
      datareceived += recvnum;
    }
  }

  if (memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
    HIP_ERROR("Sent and received data did not match\n");
    err = 1;
    goto out;
  }

out:

  if (sockfd)
    close(sockfd); // discard errors
  if (res)
    free_endpointinfo(res);

  HIP_INFO("Result of data transfer: %s.\n", (err ? "FAIL" : "OK"));

  return err;
}
