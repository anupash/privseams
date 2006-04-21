/*
  Put all the functions you want to override here
*/
#include <sys/types.h>
#include <sys/types.h>
//#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include "debug.h"
extern int connect(int a, const struct sockaddr * b, socklen_t c);
extern ssize_t send(int a, const void * b, size_t c, int flags);
extern ssize_t sendto(int a, const void * b, size_t c, int flags, const struct sockaddr  *to, socklen_t tolen);
extern ssize_t sendmsg(int a, const struct msghdr *msg, int flags);

int opp_mode(){
  int opp_mode;
  opp_mode = 0;

  // There are two choice to implement, which one is better?

  // Todo:
  // Send query message to hipd to query the value of opp_mode.
  // use recvfrom to get message.
  // return value of opp_mode

  // or

  // Todo:
  // send ip to hipd to query phit
  // use recvfrom to receive phit message
  // if get phit, then opp_mode is on.
  return opp_mode;
}

int is_ip(const struct in6_addr *ip){
  
  return(!hit_is_real_hit(ip) && 
	 !hit_is_opportunistic_hashed_hit(ip));
}

int exist_mapping(const struct in6_addr *ip){
  int err;
  err = 0;
  int has_mapping;
  has_mapping = 0;
  struct in6_addr hit;

  err = hip_opportunistic_ipv6_to_hit(ip, &hit, HIP_HIT_TYPE_HASH120);
  if(err)
    goto out_err;

  //TODO: 
  // send phit to hipd.
  // hipd handler function use phit to check if there is HA.
  // if yes/no, then there is/no  mapping, hipd send back the result.
  // using recvfrom to receive the result. 

  return has_mapping;

 out_err:
  return err;
}

int util_func(struct in6_addr *ip){
  int err;
  err = 0;

  if(hit_is_real_hit(ip)){
    HIP_DEBUG("!!!! is real hit \n");
    // TODO:
    //Add mapping old socket == new socket
  }
  else {
    if(!hit_is_opportunistic_hashed_hit(ip)) {
      HIP_DEBUG("!!!! is ip\n");
      if(exist_mapping(ip)){
	struct in6_addr hit;
	err = hip_opportunistic_ipv6_to_hit(ip, &hit, HIP_HIT_TYPE_HASH120);
	if(err)
	  goto out_err;      
	HIP_DEBUG_HIT("!!!! opportunistic hit ", &hit);
	// change ip to phit
	memcpy(ip, &hit, sizeof(struct in6_addr));
      }
      else { // no exit mapping
	if(opp_mode()) {
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

int connect(int a, const struct sockaddr * b, socklen_t c)
{
  int errno;
  errno = 0; 
  
  struct in6_addr *ip;

  HIP_DEBUG_HIT("connect b = ", b);
  HIP_DEBUG("!!!! sin_port=%d\n", ntohs(((struct sockaddr_in *)b)->sin_port) );
  HIP_HEXDUMP("!!!! HEXDUMP b =", b, 32);
  
  ip =  (struct in6_addr *)( &(((struct sockaddr_in *)b)->sin_addr)+sizeof(unsigned char) );
  
  HIP_DEBUG_HIT("!!!! ip = ", ip);
  printf("Calling __libc_connect....\n");

  //  errno = util_func(ip);
  errno = __libc_connect(a, b, c);
  printf("Called __libc_connect with err=%d\n", errno);
  
 out_err:
  return errno;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t send(int a, const void * b, size_t c, int flags)
{
  int charnum;  
  charnum = 0;

  //printf("Calling __libc_send ....\n");
  charnum =  __libc_send(a, b, c, flags);
  printf("Called __libc_send with number of returned char=%d\n", charnum);

  return charnum;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendto(int a, const void * b, size_t c, int flags, const struct sockaddr  *to, socklen_t tolen)
{
  ssize_t charnum;
  charnum = 0;

  //printf("Calling __libc_sendto ....\n");
  charnum =  __libc_sendto(a, b, c, flags, to, tolen);
  printf("Called __libc_sendto with number of returned char=%d\n", charnum);

  return charnum;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendmsg(int a, const struct msghdr *msg, int flags)
{
  ssize_t charnum;
  charnum = 0;
  
  //printf("Calling __libc_sendmsg ....\n");
  charnum =  __libc_sendmsg(a, msg, flags);
  printf("Called __libc_sendmsg with number of returned chars=%d\n", charnum);

  return charnum;
}
