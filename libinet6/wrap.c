/*
 * libinet6 wrap.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */

/*
  Put all the functions you want to override here
*/

#ifdef CONFIG_HIP_OPPORTUNISTIC
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <dlfcn.h>
#include "debug.h"
#include "hadb.h"
#include "hashtable.h"

#define SOFILE "/lib/libc.so.6" 

extern hip_hit_t *get_local_hits_wrapper();
typedef struct hip_opp_socket_entry hip_opp_socket_t;
static db_exist = 0;

// functions in wrap_db.c
void hip_init_socket_db();
void hip_uninit_socket_db();
hip_opp_socket_t *hip_create_opp_entry();
void hip_socketdb_dump();
//void hip_socketdb_get_entry(hip_opp_socket_t *entry, int pid, int socket);
hip_opp_socket_t *hip_socketdb_find_entry(int pid, int socket);
int hip_socketdb_add_entry(int pid, int socket);
int hip_socketdb_del_entry(int pid, int socket);
int hip_socketdb_add_entry_by_entry(hip_opp_socket_t *entry); //TODO::implement this func if need
void hip_socketdb_del_entry_by_entry(hip_opp_socket_t *entry);
inline int hip_socketdb_get_old_socket(hip_opp_socket_t *entry);
inline int hip_socketdb_get_new_socket(hip_opp_socket_t *entry);

void test_db();
int request_pseudo_hit_from_hipd(const struct in6_addr *ip, struct in6_addr *phit);
int request_peer_hit_from_hipd(const struct in6_addr *ip, 
			       struct in6_addr *peer_hit,
			       const struct in6_addr *local_hit);
int exists_mapping(int pid, int socket);

// used for dlsym_util
int (*socket_dlsym)(int domain, int type, int protocol);
int (*conn)(int a, const struct sockaddr * b, socklen_t c);
ssize_t (*send_dlsym)(int s, const void *buf, size_t len, int flags);
ssize_t (*sendto_dlsym)(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
ssize_t (*sendmsg_dlsym)(int s, const struct msghdr *msg, int flags);
int (*close_dlsym)(int fd);


int util_func(int * const socket)
{
  int err = 0;
  int pid = 0;
  int port = 0;
  int mapping = 0;
  hip_opp_socket_t *entry = NULL;

  if(!db_exist){
    hip_init_socket_db();
    HIP_DEBUG("socketdb initialized\n");
    db_exist = 1;
  }
  
  pid = getpid();
  
  entry =  hip_socketdb_find_entry(pid, *socket);
  if(entry){
    if(hip_socketdb_has_new_socket(entry)){
      *socket = hip_socketdb_get_new_socket(entry);
    }
  }
 out_err:
  return err;
}


int util_func_with_sockaddr(const struct sockaddr *to, struct in6_addr *id, 
			    int * const socket, const hip_hit_t *local_hit)
{
  int err = 0;
  int pid = 0;
  int port = 0;
  int mapping = 0;
  hip_hit_t peer_hit;
  
  // we are only interested in AF_INET and AFINET6
  if( ((struct sockaddr_in6 *)to)->sin6_family == AF_INET6 || 
      ((struct sockaddr_in6 *)to)->sin6_family == AF_INET ){ 

      if(!db_exist){
      hip_init_socket_db();
      HIP_DEBUG("socketdb initialized\n");
      db_exist = 1;
    }

    pid = getpid();
    port = ntohs(((struct sockaddr_in6 *)to)->sin6_port);
    id =   (struct in6_addr *)( &(((struct sockaddr_in6 *)to)->sin6_addr) );

    HIP_DEBUG("connect sin_port=%d\n", port);
    HIP_DEBUG_HIT("sin6_addr id = ", id);
    _HIP_HEXDUMP("connect HEXDUMP to\n", to, 110); //sizeof(struct sockaddr_in)
    
    if(hit_is_real_hit(id)){
      hip_opp_socket_t *entry = NULL;
      
      HIP_DEBUG("!!!!!!!!!!!!!!!! real hit !!!!!!!!!!!!!!!\n");
      //mapping = exists_mapping(pid, *socket);
      //assert(mapping);
      
      entry = hip_socketdb_find_entry(pid, *socket);
      assert(entry);
      hip_socketdb_add_new_socket(entry, *socket);
      hip_socketdb_add_dst_hit(entry, id);
    } else if(!hit_is_opportunistic_hashed_hit(id)){ // is ip
      HIP_DEBUG("!!!!!!!!!!!!!!!! ip !!!!!!!!!!!!!!!\n");
      err = request_peer_hit_from_hipd(id, &peer_hit, local_hit);
      if(err){
	HIP_ERROR("failed to get peer hit err=\n",  strerror(err));
	return err;
      }

      HIP_DEBUG("!!!!!!!!!!!!!!!!!!! request_peer_hit_from_hipd succeed!!!!!!!!!!!!!!!!\n");
      HIP_DEBUG_HIT("!!!! id ", id);
      HIP_DEBUG_HIT("!!!! peer_hit", &peer_hit);
      
      if(hit_is_real_hit(&peer_hit)){
	int type = SOCK_STREAM;;	
	int old_socket = 0;
	hip_opp_socket_t *entry = NULL;
	
	old_socket = *socket;
	
	// socket() call will add socket as old_socket in entry, 
	//we need to change it to new_socket later
	if(type != 0) {
	  *socket = create_new_socket(type, 0); // XX TODO: BING CHECK
	  if (*socket < 0) {
	    perror("socket");
	    err = *socket;
	    goto out_err;
	  }
	}    
	
	entry =  hip_socketdb_find_entry(pid, old_socket);
	assert(entry);
	
	hip_socketdb_add_new_socket(entry, *socket);
	hip_socketdb_add_dst_ip(entry, id);
	hip_socketdb_add_dst_hit(entry, &peer_hit);
	HIP_DEBUG("pid %d, new_socket %d, old_socket %d\n", pid, *socket, old_socket);
	//hip_socketdb_dump();
	// modify sockaddr, id points to sockaddr's sin6_addr
	memcpy(id, &peer_hit, sizeof(peer_hit));
	HIP_DEBUG_HIT("opp mode enabled, peer hit: id=", id);
      } else{ // not opp mode 
	hip_opp_socket_t *entry = NULL; 
	entry = hip_socketdb_find_entry(pid, *socket);
	assert(entry);
	hip_socketdb_add_new_socket(entry, *socket);
	hip_socketdb_add_dst_ip(entry, id);
      }
    }
  } // end if(AF_INET || AF_INET6)
  
 out_err:
  return err;
}

int request_peer_hit_from_hipd(const struct in6_addr *ip, 
			       hip_hit_t *peer_hit,
			       const struct in6_addr *local_hit)
{
  struct hip_common *msg = NULL;
  struct in6_addr *hit_recv = NULL;
  hip_hit_t *ptr = NULL;
  int err = 0;
  int ret = 0;

  if(!ipv6_addr_any(ip)) {
    msg = malloc(HIP_MAX_PACKET);
    if (!msg){
      HIP_ERROR("malloc failed\n");
      goto out_err;
    }	
    hip_msg_init(msg);
    
    err = hip_build_param_contents(msg, (void *)(local_hit), HIP_PARAM_HIT,
				   sizeof(struct in6_addr));
    if (err) {
      HIP_ERROR("build param HIP_PARAM_HIT  failed: %s\n", strerror(err));
      goto out_err;
    }
    err = hip_build_param_contents(msg, (void *)(ip), HIP_PARAM_IPV6_ADDR,
				   sizeof(struct in6_addr));
    if (err) {
      HIP_ERROR("build param HIP_PARAM_IPV6_ADDR  failed: %s\n", strerror(err));
      goto out_err;
    }
    
    /* Build the message header */
    err = hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0);
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
    HIP_DEBUG("send_recv msg succeed\n");
    
    /* getsockopt wrote the corresponding EID into the message, use it */
    err = hip_get_msg_err(msg);
    if (err) {
      goto out_err;
    }

    ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
    HIP_DEBUG_HIT("!!!! ptr", ptr);
    assert(ptr);
    memcpy(peer_hit, ptr, sizeof(hip_hit_t));
    HIP_DEBUG_HIT("!!!! peer_hit", peer_hit);
  } // end of  if(!ipv6_addr_any(&ip))
 out_err:
  if(msg)
    free(msg);
  return err;
}


// notwork_ prefix means this function is not implemented properly,
// because compiler complains __libc_ call
int socket(int domain, int type, int protocol)
{
  int pid;
  int socket_fd;
  int err;
  
  pid = 0;
  socket_fd = 0;
  err = 0;
  
  void *dp = NULL;
  char *error = NULL;
  
  dp=dlopen(SOFILE, RTLD_LAZY);
  
  if (dp==NULL)
    {
      fputs(dlerror(),stderr);
      exit(1);
    }
  socket_dlsym = dlsym(dp, "socket");
  
  error=dlerror();
  if (error)
    {
      fputs(error,stderr);
      exit(1);
    }
  HIP_DEBUG("Calling socket_dlsym\n");
  socket_fd = socket_dlsym(domain, type, protocol);
  HIP_DEBUG("Called socket_dlsym, return fd %d\n", socket_fd);
  dlclose(dp);

  if(!db_exist){
    HIP_DEBUG("db initializing...\n");
    hip_init_socket_db();
    HIP_DEBUG("db initialized\n");
    db_exist = 1;
  }
  
  if(socket_fd != -1){
    pid = getpid();
    
    if(exists_mapping(pid, socket_fd)){
      HIP_DEBUG("pid %d, socket_fd %d\n", pid, socket_fd);
      HIP_DEBUG("!!!! it should not happen, but indeed it happend and not the db problem!!!\n");
      //err = hip_socketdb_del_entry(pid, socket_fd);
      //HIP_DEBUG("delete entry returns %d\n", err);
      //HIP_ASSERT(0);
    } else{
      err = hip_socketdb_add_entry(pid, socket_fd);
      if(err)
	return err;
      hip_opp_socket_t *entry = NULL;
      entry = hip_socketdb_find_entry(pid, socket_fd);
      assert(entry);
    } 
  }
  else{
    assert(0);
  }

  HIP_DEBUG("Called socket_dlsym socket_fd=%d\n", socket_fd);
  
  return socket_fd;
}

int connect(int a, const struct sockaddr * b, socklen_t c)
{
  int errno;
  int socket = 0;
  struct sockaddr bindhit;
  hip_hit_t *hit_ptr = NULL;

  void *dp = NULL;
  char *error = NULL;
  struct in6_addr *id = NULL;
  hip_hit_t *hit_local = NULL;
  
  errno = 0;
  
  //assert(db_exist);
  if(!db_exist){
    hip_init_socket_db();
    HIP_DEBUG("db initialized\n");
    db_exist = 1;
  }

  hit_local = get_local_hits_wrapper();
  assert(hit_local);
  HIP_DEBUG_HIT("!!!! The local HIT =", hit_local);
  socket = a;

  errno = util_func_with_sockaddr(b, id, &socket, hit_local);
  if(errno)
    goto out_err;

  // we are only interested in AF_INET and AFINET6
  if( ((struct sockaddr_in6 *)b)->sin6_family == AF_INET6 || 
      ((struct sockaddr_in6 *)b)->sin6_family == AF_INET ){ 
    memcpy(&bindhit, b, sizeof(bindhit));
    HIP_HEXDUMP("bindhit before ", &bindhit, 110);
    hit_ptr = (struct in6_addr *)( &(((struct sockaddr_in6 *)&bindhit)->sin6_addr) );
    HIP_DEBUG_HIT("hit_ptr", hit_ptr);
    if(!hit_is_real_hit(hit_ptr)){
      memcpy(hit_ptr, hit_local, sizeof(hip_hit_t));
      HIP_HEXDUMP("bindhit after ", &bindhit, 110);
      errno = bind(a, &bindhit, sizeof(bindhit));
      if(errno){
	HIP_DEBUG("!!!! bind failed\n");
	assert(0);
	goto out_err;
      }
    }
  }
  
  dp=dlopen(SOFILE,RTLD_LAZY);
  if (dp==NULL)
    {
      fputs(dlerror(),stderr);
      exit(1);
    }
  conn = dlsym(dp, "connect");
  
  error=dlerror();
  if (error)
    {
      fputs(error,stderr);
      exit(1);
    }
  HIP_DEBUG("Calling connect_dlsym\n");

  errno = conn(socket, b, c);
  
  dlclose(dp);

  HIP_DEBUG("Called connect_dlsym with err=%d\n", errno);
  
 out_err:
  return errno;
}


/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t send(int a, const void * b, size_t c, int flags)
{
  int errno;
  int charnum = 0;  
  int socket = 0;

  errno = 0;
  socket = a;

  //  assert(db_exist);
  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("util_func call failed: %s\n", strerror(errno));
    return errno;
  }
  
  void *dp = NULL;
  char *error = NULL;

  dp=dlopen(SOFILE,RTLD_LAZY);
  
  if (dp==NULL)
    {
      fputs(dlerror(),stderr);
      exit(1);
    }
  send_dlsym = dlsym(dp, "send");
  
  error = dlerror();
  if (error){
    fputs(error,stderr);
    exit(1);
  }
  
  charnum = send_dlsym(socket, b, c, flags);
  dlclose(dp);
  
  HIP_DEBUG("Called send_dlsym with number of returned char=%d\n", charnum);

  return charnum;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendto(int a, const void * b, size_t c, int flags, 
	       const struct sockaddr  *to, socklen_t tolen)
{
  int errno;
  ssize_t charnum = 0;
  int socket = 0;
  struct in6_addr *id = NULL;
  void *dp = NULL;
  char *error = NULL;
  hip_hit_t *hit_local = NULL;

  errno = 0;
  socket = a;

  hit_local = get_local_hits_wrapper();
  assert(hit_local);
  HIP_DEBUG_HIT("!!!! The local HIT =", hit_local);

  //errno = util_func_with_sockaddr(to, id, &socket,hit_local );
  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("sendto util_func_with_sockaddr failed\n");
  }
    
  dp=dlopen(SOFILE,RTLD_LAZY);
  
  if (dp==NULL)
    {
      fputs(dlerror(),stderr);
      exit(1);
    }
  sendto_dlsym = dlsym(dp, "sendto");
  
  error=dlerror();
  if (error)
    {
      fputs(error,stderr);
      exit(1);
    }
  HIP_DEBUG("Calling sendto_dlsym\n");
  charnum = sendto_dlsym(socket, b, c, flags, to, tolen);
  
  dlclose(dp);
  
  HIP_DEBUG("Called sendto_dlsym with number of returned char=%d\n", charnum);
  if(charnum < 0)
    HIP_DEBUG("sendto failed\n");

  return charnum;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendmsg(int a, const struct msghdr *msg, int flags)
{
  int errno;
  int socket = 0;
  ssize_t charnum = 0;

  errno = 0;
  socket = a;

  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("sendmsg util_func call failed: %s\n", strerror(errno));
    return errno;
  }
  
  void *dp = NULL;
  char *error = NULL;

  dp=dlopen(SOFILE,RTLD_LAZY);
  
  if (dp==NULL)
    {
      fputs(dlerror(),stderr);
      exit(1);
    }
  sendmsg_dlsym = dlsym(dp, "sendmsg");
  
  error=dlerror();
  if (error)
    {
      fputs(error,stderr);
      exit(1);
    }
  
  charnum = sendmsg_dlsym(socket, msg, flags);
  
  dlclose(dp);
  
  HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);

  return charnum;
}


int close(int fd)
{
  int errno;
  int pid = 0;
  hip_opp_socket_t *entry = NULL;

  errno = 0;

  void *dp = NULL;
  char *error = NULL;
   
  //  dlsym_util(dp, error, conn, func_name);
  
  dp=dlopen(SOFILE,RTLD_LAZY);
  
  if (dp==NULL)
    {
      fputs(dlerror(),stderr);
      exit(1);
    }
  close_dlsym = dlsym(dp, "close");
  
  error=dlerror();
  if (error)
    {
      fputs(error,stderr);
      exit(1);
    }

  if(db_exist){
    pid = getpid();
    entry = hip_socketdb_find_entry(pid, fd);
    HIP_DEBUG("close() pid %d, fd %d\n", pid, fd);

    if(!entry){
      HIP_DEBUG("!!!!!!!!!!!!!!!!!!!!! should not happen, dumping socket db\n");
      hip_socketdb_dump();
      assert(0);
    }
    if(entry){

      if(hip_socketdb_has_new_socket(entry)){
	int old_socket = hip_socketdb_get_old_socket(entry);
	int new_socket = hip_socketdb_get_new_socket(entry);
	// close new_socket too
	if(old_socket != new_socket){
	  HIP_DEBUG("old_socket %d new_socket %d\n", 
		    old_socket, new_socket);	  
	  errno = close_dlsym(new_socket);
	  if(errno){
	    HIP_DEBUG("close new_socket failed errno %d\n", errno);
	  } else
	    HIP_DEBUG("close new_socket no error\n");
	}
      }
    }    
  }
  
  errno = close_dlsym(fd);
  dlclose(dp);
  //errno = __libc_close(fd);
  HIP_DEBUG("close_dlsym called with errno %d\n", errno);

  return errno;
}


// used to test socketdb
void test_db(){
  HIP_DEBUG("!!!!!!!!!!!!! testing db !!!!!!!!!!!!!\n\n\n");
  int pid = getpid();
  int socket = 1;
  int err = 0;
  hip_opp_socket_t *entry = NULL;
  //  struct hip_opp_socket_entry *entry = NULL;

  HIP_DEBUG("1111 pid=%d, socket=%d\n", pid, socket);
  entry =   hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(!entry);
  err = hip_socketdb_add_entry(pid, socket);
  HIP_ASSERT(!err);
  entry =  hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(entry);
  hip_socketdb_dump();


  //  pid++; 
  socket++;
  HIP_DEBUG("2222 pid=%d, socket=%d\n", pid, socket);
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(!entry);
  err = hip_socketdb_add_entry(pid, socket);
  HIP_ASSERT(!err);
  entry = hip_socketdb_find_entry(pid, socket);
  hip_socketdb_add_new_socket(entry, socket+100);
  HIP_ASSERT(entry);
  hip_socketdb_dump();


  //pid++; 
  socket++;
  HIP_DEBUG("3333 pid=%d, socket=%d\n", pid, socket);
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(!entry);
  err = hip_socketdb_add_entry(pid, socket);
  HIP_ASSERT(!err);
  entry = NULL;
  entry =  hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(entry);
  hip_socketdb_dump();

  HIP_DEBUG("3333  testing del entry\n\n");
  HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(entry);
  entry = NULL;
  err = hip_socketdb_del_entry(pid, socket);
  HIP_ASSERT(!err);
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(!entry);
  hip_socketdb_dump();


  HIP_DEBUG("2222 testing del entry by entry\n\n");
  socket--;
  HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(entry);
  hip_socketdb_del_entry_by_entry(entry);
  entry = NULL;
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(!entry);
  hip_socketdb_dump();

  HIP_DEBUG("1111 testing del entry by entry\n\n");
  socket--;
  HIP_DEBUG("pid=%d, socket=%d\n", pid, socket);
  entry = NULL;
  entry = hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(entry);
  hip_socketdb_del_entry_by_entry(entry);
  entry = NULL;
  entry =  hip_socketdb_find_entry(pid, socket);
  HIP_ASSERT(!entry);
  hip_socketdb_dump();
  HIP_DEBUG("end of testing db\n");
}


// we will request real hit
#if 0
int request_pseudo_hit_from_hipd(const struct in6_addr *ip, struct in6_addr *phit)
{
  struct hip_common *msg = NULL;
  struct in6_addr *hit_recv = NULL;
  int err = 0;
  int ret = 0;

  if(!ipv6_addr_any(ip)) {
    msg = malloc(HIP_MAX_PACKET);
    if (!msg){
      HIP_ERROR("malloc failed\n");
      goto out_err;
    }	
    hip_msg_init(msg);
    
    err = hip_build_param_contents(msg, (void *)(ip), HIP_PARAM_IPV6_ADDR,
				   sizeof(struct in6_addr));
    if (err) {
      HIP_ERROR("build param request_hipd_seudo_hit failed: %s\n", strerror(err));
      goto out_err;
    }
    
    /* Build the message header */
    err = hip_build_user_hdr(msg, SO_HIP_GET_PSEUDO_HIT, 0);
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
    HIP_DEBUG("send_recv msg succeed\n");
    
    /* getsockopt wrote the corresponding EID into the message, use it */
    err = hip_get_msg_err(msg);
    if (err) {
      goto out_err;
    }
    hit_recv = (struct in6_addr *) hip_get_param_contents(msg, HIP_PSEUDO_HIT);
    if(hit_recv)
      memcpy(phit, hit_recv, sizeof(*phit));
  } // end of  if(!ipv6_addr_any(&ip))
 out_err:
  if(msg)
    free(msg);
  return err;
}

int util_func_with_sockaddr(const struct sockaddr *to, struct in6_addr *id, int * const socket)
{
  // do not use, deprecated
  int err = 0;
  int pid = 0;
  int port = 0;
  int mapping = 0;
  struct in6_addr phit;
  
  // we are only interested in AF_INET and AFINET6
  if( ((struct sockaddr_in6 *)to)->sin6_family == AF_INET6 || 
      ((struct sockaddr_in6 *)to)->sin6_family == AF_INET ){ 

      if(!db_exist){
      hip_init_socket_db();
      HIP_DEBUG("socketdb initialized\n");
      db_exist = 1;
    }

    pid = getpid();
    port = ntohs(((struct sockaddr_in6 *)to)->sin6_port);
    id =   (struct in6_addr *)( &(((struct sockaddr_in6 *)to)->sin6_addr) );

    HIP_DEBUG("connect sin_port=%d\n", port);
    HIP_DEBUG_HIT("sin6_addr id = ", id);
    _HIP_HEXDUMP("connect HEXDUMP to\n", to, 110); //sizeof(struct sockaddr_in)
    
    if(hit_is_real_hit(id)){
      hip_opp_socket_t *entry = NULL;
      HIP_DEBUG("!!!!!!!!!!!!!!!! real hit !!!!!!!!!!!!!!!\n");
      mapping = exists_mapping(pid, *socket);
      // it should has mapping now, since we added mapping in socket() function
      //      assert(!mapping);
      //      hip_socketdb_add_entry(pid, *socket);
      assert(mapping);
      //if(!mapping)
      //hip_socketdb_add_entry(pid, *socket);
      
      entry = hip_socketdb_find_entry(pid, *socket);
      assert(entry);
      hip_socketdb_add_new_socket(entry, *socket);
      hip_socketdb_add_dst_hit(entry, id);
    } else if(!hit_is_opportunistic_hashed_hit(id)){ // is ip
      HIP_DEBUG("!!!!!!!!!!!!!!!! ip !!!!!!!!!!!!!!!\n");
      err = request_pseudo_hit_from_hipd(id, &phit);
      if(err){
	HIP_ERROR("failed to get pseudo hit err=\n",  strerror(err));
	return err;
      }
      HIP_DEBUG("request_pseudo_hit_from_hipd succeed\n");
      
      if(hit_is_opportunistic_hashed_hit(&phit)){
	int type = 0;
	struct hip_common option;
	int optlen = sizeof(option);
	int old_socket = 0;
	hip_opp_socket_t *entry = NULL;

	// no needed
	if (!getsockopt(*socket, IPPROTO_TCP, TCP_NODELAY, &option, &optlen))
	  type = SOCK_STREAM;
	else if (!getsockopt(*socket, IPPROTO_UDP, TIOCOUTQ, &option, &optlen))
	  type = SOCK_DGRAM;
	
	old_socket = *socket;
	
	// socket() call will add socket as old_socket in entry, 
	//we need to change it to new_socket later
	if(type != 0) {
	  *socket = create_new_socket(type, 0); // XX TODO: BING CHECK
	  if (*socket < 0) {
	    perror("socket");
	    err = *socket;
	    goto out_err;
	  }
	}    
	
	entry =  hip_socketdb_find_entry(pid, old_socket);
	assert(entry);
	
	hip_socketdb_add_new_socket(entry, *socket);
	hip_socketdb_add_dst_ip(entry, id);
	hip_socketdb_add_dst_hit(entry, &phit);
	HIP_DEBUG("pid %d, new_socket %d, old_socket %d\n", pid, *socket, old_socket);
	//hip_socketdb_dump();
	// modify sockaddr, id points to sockaddr's sin6_addr
	memcpy(id, &phit, sizeof(phit));
	HIP_DEBUG_HIT("opp mode enabled id ", id);
      } else{ // not opp mode 
	hip_opp_socket_t *entry = NULL; 
	entry = hip_socketdb_find_entry(pid, *socket);
	assert(entry);
	hip_socketdb_add_new_socket(entry, *socket);
	hip_socketdb_add_dst_ip(entry, id);
      }
    }
  } // end if(AF_INET || AF_INET6)
  
 out_err:
  return err;
}
#endif // if 0
#endif // CONFIG_HIP_OPPORTUNISTIC

/*
int notwork_socketpair(int d, int type, int protocol, int sv[2])
{
  int errno;
  errno = 0;

  //  errno =  __libc_socketpair(d, type, protocol, sv[2]);
  HIP_DEBUG("Called __libc_socketpair with errno=%d\n", errno);

  return errno;

}

int notwork_listen(int s, int backlog)
{
  int errno;
  errno = 0;

  //  errno =  __libc_listen(s, backlog);
  HIP_DEBUG("Called __libc_listen with errno=%d\n", errno);

  return errno;

}

int _accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
  int errno;
  errno = 0;

  //  errno =  __libc_accept(s, addr, addrlen);

  HIP_DEBUG("Called __libc_accept with errno=%d\n", errno);

  if(errno)
    return errno;

  return s;
}

int notwork_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
  int errno;
  errno = 0;

  //  errno =  __libc_getsockopt(s, level, optname, optval, optlen);
  HIP_DEBUG("Called __libc_getsockopt with errno=%d\n", errno);

  if(errno)
    return errno;
}

int notwork_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
  int errno;
  errno = 0;

  //errno =  __libc_setsockopt(s, level, optname, optval, optlen);
  HIP_DEBUG("Called __libc_setsockopt with errno=%d\n", errno);

  if(errno)
    return errno;
}

ssize_t _recv(int s, void *buf, size_t len, int flags)
{
  ssize_t charnum = 0;

  //  charnum =  __libc_recv(s, buf, len, flags);

  HIP_DEBUG("Called __libc_recv with number of returned chars=%d\n", charnum);

  return charnum;
}

ssize_t _recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
  ssize_t charnum = 0;

  //charnum =  __libc_recvfrom(s, buf, len, flags, from, fromlen);

  HIP_DEBUG("Called __libc_recvfrom with number of returned chars=%d\n", charnum);

  return charnum;
}

ssize_t _recvmsg(int s, struct msghdr *msg, int flags)
{
  ssize_t charnum = 0;

  //charnum =  __libc_recvmsg(s, msg, flags);

  HIP_DEBUG("Called __libc_recvmsg with number of returned chars=%d\n", charnum);

  return charnum;
}

int notwork_getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
  int errno;

  errno = 0;

  //  errno =  __libc_getpeername(s, name, namelen);
  HIP_DEBUG("Called __libc_getpeername with errno=%d\n", errno);

  return errno;
}

int notwork_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
  int errno;

  errno = 0;

  //  errno =  __libc_getsockname(s, name, namelen);
  HIP_DEBUG("Called __libc_getsockname with errno=%d\n", errno);

  return errno;
}
*/

