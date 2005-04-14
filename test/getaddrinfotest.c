/*
 * getaddrinfo test program
 * 
 * getaddrinfo() function is tested both for a server application use 
 * (with NULL node parameter and AI_PASSIVE flag set) and also for a typical 
 * client application use (with NULL service parameter).
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>


int main(int argc, char **argv) {

  int a;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *ai;

  if (argc != 3) {
    printf("%s nodename servname\n", argv[0]);
    exit(2);
  }
    
  hints.ai_flags = AI_HIP | AI_PASSIVE;
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  printf("\n\n***getaddrinfo(NULL, %s, hints, res)***\n\n",argv[2]);  
  a = getaddrinfo(NULL, argv[2], &hints, &res);
  
  if (a != 0) {
    printf("*** ERROR: %s ***\n", gai_strerror(a));
    return(1);
  }
  
  for(ai = res; ai != NULL; ai = ai->ai_next) {
    printf("ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ai_addrlen=%d ai_canonname=%s\n", ai->ai_flags, ai->ai_family, ai->ai_socktype, 
	   ai->ai_protocol, ai->ai_addrlen, ai->ai_canonname);
    
    if (ai->ai_family == AF_INET6) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
      int i = 0;
      
      printf("AF_INET6\tship6_family=%d\n", s->sin6_family);    
      printf("AF_INET6\tship6_port=%d\n", s->sin6_port);
      printf("AF_INET6\tship6_flowinfo=%lu\n", 
	     (long unsigned int)s->sin6_flowinfo);
      printf("AF_INET6\tship6_scope_id=%lu\n", 
	     (long unsigned int)s->sin6_scope_id);
      printf("AF_INET6\tin6_addr=0x");
      for (i = 0; i < 16; i++)
	printf("%02x ", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
      printf("\n");
    } else if (ai->ai_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)ai->ai_addr;
      printf("AF_INET\tin_addr=0x%lx (%s)\n", 
	     (long unsigned int) ntohl(s->sin_addr.s_addr), 
	     inet_ntoa(s->sin_addr));
    }
  }
  
  freeaddrinfo(res);

  hints.ai_flags = AI_HIP;// AI_HIP | AI_PASSIVE;
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;

  //a = getaddrinfo(NULL, argv[1], &hints, &res);
  printf("\n\n***getaddrinfo(%s, NULL, hints, res)***\n\n",argv[1]);
  a = getaddrinfo(argv[1], NULL, &hints, &res);
  
  if (a != 0) {
    printf("*** ERROR: %s ***\n", gai_strerror(a));
    return(1);
  }
  
  for(ai = res; ai != NULL; ai = ai->ai_next) {
    printf("ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ai_addrlen=%d ai_canonname=%s\n", ai->ai_flags, ai->ai_family, ai->ai_socktype, 
	   ai->ai_protocol, ai->ai_addrlen, ai->ai_canonname);
    
    if (ai->ai_family == AF_INET6) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
      int i = 0;
      
      printf("AF_INET6\tship6_family=%d\n", s->sin6_family);    
      printf("AF_INET6\tship6_port=%d\n", s->sin6_port);
      printf("AF_INET6\tship6_flowinfo=%lu\n", 
	     (long unsigned int)s->sin6_flowinfo);
      printf("AF_INET6\tship6_scope_id=%lu\n", 
	     (long unsigned int)s->sin6_scope_id);
      printf("AF_INET6\tin6_addr=0x");
      for (i = 0; i < 16; i++)
	printf("%02x ", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
      printf("\n");
    } else if (ai->ai_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)ai->ai_addr;
      printf("AF_INET\tin_addr=0x%lx (%s)\n", 
	     (long unsigned int) ntohl(s->sin_addr.s_addr), 
	     inet_ntoa(s->sin_addr));
    }
  }
  
  
  freeaddrinfo(res);
  return(0);
}
