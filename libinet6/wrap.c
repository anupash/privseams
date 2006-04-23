/*
  Put all the functions you want to override here
*/
#include <sys/types.h>
//#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include "debug.h"
extern int __libc_connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
extern ssize_t __libc_send(int s, const void *buf, size_t len, int flags);
extern ssize_t __libc_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
extern ssize_t __libc_sendmsg(int s, const struct msghdr *msg, int flags);

int get_opp_mode(){
  int err;
  int *opp_mode = NULL;
  struct hip_common *msg;
  
  err = 0;

  hip_msg_init(msg);
  
  err = hip_build_user_hdr(msg, SO_HIP_QUERY_OPPORTUNISTIC_MODE, 0);
  if (err) {
    HIP_ERROR("build hdr failed: %s\n", strerror(err));
    goto out_err;
  }
  
  /* send and receive msg to/from hipd */
  err = hip_send_recv_daemon_info(msg);
  if (err) {
    HIP_ERROR("send_recv msg failed\n");
    goto out_err;
  }
  HIP_DEBUG("!!!! send_recv msg succeed\n");
  
  /* getsockopt wrote the corresponding EID into the message, use it */
  err = hip_get_msg_err(msg);
  if (err) {
    goto out_err;
  }
  
  opp_mode = (int *)( hip_get_param_contents(msg, HIP_PARAM_UINT));
  if (!opp_mode) {
    err = -EINVAL;
    goto out_err;
  }
  return *opp_mode;
  
 out_err:
  return err;
}

int is_ip(const struct in6_addr *ip){
  
  return(!hit_is_real_hit(ip) && 
	 !hit_is_opportunistic_hashed_hit(ip));
}

int exist_mapping(const struct in6_addr * const phit){
  int err;
  int *mapping = NULL;
  struct hip_common *msg;

  msg = malloc(HIP_MAX_PACKET);
  hip_msg_init(msg);

  err = hip_build_param_contents(msg, (void *)(phit), HIP_PSEUDO_HIT,
				 sizeof(struct in6_addr));
  if (err) {
    HIP_ERROR("build param phit failed: %s\n", strerror(err));
    goto out_err;
  }
  
  err = hip_build_user_hdr(msg, SO_HIP_QUERY_IP_HIT_MAPPING, 0);
  if (err) {
    HIP_ERROR("build hdr failed: %s\n", strerror(err));
    goto out_err;
  }
  
  /* send and receive msg to/from hipd */
  err = hip_send_recv_daemon_info(msg);
  if (err) {
    HIP_ERROR("send_recv msg failed\n");
    goto out_err;
  }
  HIP_DEBUG("!!!! send_recv msg succeed\n");
  
  /* getsockopt wrote the corresponding EID into the message, use it */
  err = hip_get_msg_err(msg);
  if (err) {
    goto out_err;
  }
  
  mapping = (int *)(hip_get_param_contents(msg, HIP_PARAM_UINT));
  if (!mapping) {
    err = -EINVAL;
    goto out_err;
  }
  return *mapping;
  
 out_err:
  return err;
}

int util_func(struct in6_addr *id){
  int err;
  int opp_mode;
  unsigned int has_mapping;
  struct in6_addr hit;

  err = 0;
  opp_mode = 0;

  if(hit_is_real_hit(id)){
    HIP_DEBUG("!!!! is real hit \n");
    // TODO:
    //Add mapping old socket == new socket
  }
  else {
    if(!hit_is_opportunistic_hashed_hit(id)) {
      HIP_DEBUG("!!!! is ip\n");

      err = hip_opportunistic_ipv6_to_hit(id, &hit, HIP_HIT_TYPE_HASH120);
      if(err){
	HIP_ERROR("create phit failed: %s\n", strerror(err));
	goto out_err;
      }
      HIP_DEBUG_HIT("!!!! opportunistic hit ", &hit);
      HIP_ASSERT(hit_is_opportunistic_hashed_hit(&hit)); 

      has_mapping = exist_mapping(&hit);
      
      if (has_mapping == 1){ // found mapping
	memcpy(id, &hit, sizeof(*id));
	HIP_DEBUG_HIT("!!!! modified id=", id);
      } else if (has_mapping == 0) { // no mapping
	opp_mode = get_opp_mode();
	if(opp_mode == 1) {
	  err = hip_opportunistic_ipv6_to_hit(id, &hit, HIP_HIT_TYPE_HASH120);
	  if(err){
	    HIP_ERROR("create phit failed: %s\n", strerror(err));
	    goto out_err;
	  }
	  HIP_DEBUG_HIT("!!!! opportunistic hit ", &hit);
	  HIP_ASSERT(hit_is_opportunistic_hashed_hit(&hit)); 
	  memcpy(id, &hit, sizeof(*id));
	  
	  // TODO: create new socket, old socket != new socket
	} else if (opp_mode == 0) {
	  // TODO: Add mapping old socket == new socket
	} else {
	  err = -EINVAL;
	  HIP_ERROR("invalid opp_mode value: %s\n", strerror(err));
	  goto out_err;
	}
      } else {
	HIP_ERROR("Invalid mapping value received\n");
	err = -EINVAL;
	goto out_err;
      } 
    }
  }
 out_err:
  return err;
}

int connect(int a, const struct sockaddr * b, socklen_t c)
{
  int errno;
  int port;
  struct in6_addr *id;

  errno = 0;
  port = 0; 
  id = NULL;
 
  port = ntohs(((struct sockaddr_in *)b)->sin_port);

  HIP_DEBUG("!!!! connect sin_port=%d\n", port);
  HIP_HEXDUMP("!!!! connect HEXDUMP b\n", b, 110/*sizeof(struct sockaddr_in)*/);
  if(port == 1111){
    HIP_DEBUG("connect port 1111 1111 1111 1111 1111 1111 1111 1111\n\n\n");
  }
  
  id =  (struct in6_addr *)( &(((struct sockaddr_in *)b)->sin_addr)+sizeof(unsigned char) );
  
  HIP_DEBUG_HIT("!!!! id = ", id);
  printf("Calling __libc_connect....\n");
  //    errno = util_func(id);
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
  
  HIP_HEXDUMP("!!!! send HEXDUMP buffer\n", b, sizeof(*b));

  printf("Calling __libc_send ....\n");
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
  int port;
  int errno;
  struct in6_addr *id;

  charnum = 0;
  port = 0;
  errno = 0;
  id = NULL;
  port = ntohs(((struct sockaddr_in *)to)->sin_port);

  HIP_DEBUG("!!!! sizeof(sockaddr_in)=%d, tolen=%d\n", 
	    sizeof(struct sockaddr_in), tolen);
  HIP_DEBUG("!!!! sendto sin_port=%d\n", port);
  HIP_HEXDUMP("!!!! sendto HEXDUMP buffer\n", b, sizeof(*b));
  HIP_HEXDUMP("!!!! sendto HEXDUMP to\n", to, 110/*sizeof(struct sockaddr_un)*/);

  if(port == 1111){
    HIP_DEBUG("sendto port 1111 1111 1111 1111 1111 1111 1111 1111\n\n\n");
  }
  
  printf("Calling __libc_sendto ....\n");
  id =  (struct in6_addr *)( &(((struct sockaddr_in *)to)->sin_addr)+sizeof(unsigned char) );
  
  HIP_DEBUG_HIT("!!!! id = ", id);
 
  //  errno = util_func(id);
  //if(errno){
  //HIP_ERROR("!!!! wrap.c util_func failed\n");
  //goto out_err;
  //}
  charnum =  __libc_sendto(a, b, c, flags, to, tolen);
  printf("Called __libc_sendto with number of returned char=%d\n", charnum);
  if(charnum < 0){
    printf("!!!! sendto failed\n");
    errno = charnum;
    goto out_err;
  }
  //for debuging
  assert(charnum>0);
  return charnum;

 out_err:
  return errno;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendmsg(int a, const struct msghdr *msg, int flags)
{
  ssize_t charnum;
  charnum = 0;
  
  printf("Calling __libc_sendmsg ....\n");
  charnum =  __libc_sendmsg(a, msg, flags);
  printf("Called __libc_sendmsg with number of returned chars=%d\n", charnum);

  return charnum;
}
