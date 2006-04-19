/*
  Put all the functions you want to override here
*/
#include <sys/types.h>
#include <sys/types.h>
//#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include "debug.h"
//#include "hipd.h"

//extern int opp_mode_enabled();

int opp_mode(){
  return 0; //opportunistic_mode;
}

int is_ip(const struct in6_addr *ip){
  
  return(!hit_is_real_hit(ip) && 
	 !hit_is_opportunistic_hashed_hit(ip));
}

int exist_mapping(){

  return 0;
}

int util_func(struct in6_addr *ip){
  int err;
  err = 0;

  if(hit_is_real_hit(ip)){
    HIP_DEBUG("!!!! is real hit \n");
    // TODO:Add mapping old socket == new socket

  }
  else {
    if(!hit_is_opportunistic_hashed_hit(ip)) {// is ip
      HIP_DEBUG("!!!! is ip\n");
      if(exist_mapping()){
	// change ip to phit
	struct in6_addr hit;
	err = hip_opportunistic_ipv6_to_hit(ip, &hit, HIP_HIT_TYPE_HASH120);
	if(err)
	  goto out_err;      
	HIP_DEBUG_HIT("!!!! opportunistic hit ", &hit);
	memcpy(ip, &hit, sizeof(struct in6_addr));
      }
      else { // no exit mapping
	if(opp_mode()) {//opp_mode_enabled()
	  // TODO: create new socket, old socket != new socket
	}
	else {
	  // TODO: Add mapping old socket == new socket
	}
      }
    }
  }
 out_err:
  return err;
}

int connect(int a, void * b, int c)
{
  int errno;
  errno = 0; 
  
  struct in6_addr hit;
  struct in6_addr *ip;
  HIP_DEBUG_HIT("connect b = ", b);
  HIP_DEBUG("!!!! sin_port=%d\n", ntohs(((struct sockaddr_in *)b)->sin_port) );
  HIP_HEXDUMP("!!!! HEXDUMP b =", b, 32);
  
  ip =  (struct in6_addr *)( &(((struct sockaddr_in *)b)->sin_addr)+sizeof(unsigned char) );
  
  HIP_DEBUG_HIT("!!!! ip = ", ip);
  printf("Calling __libc_connect....\n");

  errno = util_func(ip);
  errno = __libc_connect(a, b, c);
  printf("Called __libc_connect with err=%d\n", errno);
  
 out_err:
  return errno;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
int send(int a, void * b, size_t c, int flags)
{
  int errno;
  int charno;
  
  errno = 0;
  charno = 0;

  //printf("Calling __libc_send ....\n");
  charno =  __libc_send(a, b, c, flags);
  printf("Called __libc_send with number of returned char=%d\n", charno);

  return charno;
 out_err:
  return errno;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
int sendto(int a, const void * b, size_t c, int flags, void *to, int tolen)
{
  int errno; 
  int charno;
  
  errno = 0;
  charno = 0;

  //printf("Calling __libc_sendto ....\n");
  charno =  __libc_sendto(a, b, c, flags, to, tolen);
  printf("Called __libc_sendto with number of returned char=%d\n", charno);

  return charno;
 out_err:
  return errno;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
int sendmsg(int a, const struct msghdr* msg, int flags)
{
  int errno;
  int charno;
  
  errno = 0;
  charno = 0;
  
  //printf("Calling __libc_sendmsg ....\n");
  charno =  __libc_sendmsg(a, msg, flags);
  printf("Called __libc_sendmsg with number of returned chars=%d\n", charno);

  return charno;
 out_err:
  return errno;
}
