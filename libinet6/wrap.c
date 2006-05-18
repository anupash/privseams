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
//#include <sys/socket.h>
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
int (*connect_dlsym)(int a, const struct sockaddr * b, socklen_t c);
ssize_t (*send_dlsym)(int s, const void *buf, size_t len, int flags);
ssize_t (*sendto_dlsym)(int s, const void *buf, size_t len, int flags, 
			const struct sockaddr *to, socklen_t tolen);
ssize_t (*sendmsg_dlsym)(int s, const struct msghdr *msg, int flags);
ssize_t (*recv_dlsym)(int s, const void *buf, size_t len, int flags);
ssize_t (*recvfrom_dlsym)(int s, void *buf, size_t len, int flags, 
		 struct sockaddr *from, socklen_t *fromlen);
ssize_t (*recvmsg_dlsym)(int s, struct msghdr *msg, int flags);

int (*close_dlsym)(int fd);

inline int domain_is_PF_INET_INET6(int domain)
{
  return (domain == PF_INET || domain == PF_INET6);
}

inline int type_is_SOCK_STREAM_DGRAM(int type)
{
  return (type == SOCK_STREAM || type == SOCK_DGRAM);
}

inline int check_domain_type_protocol(int domain, int type, int protocol)
{
  return (!domain_is_PF_INET_INET6(domain)) ||
    (!type_is_SOCK_STREAM_DGRAM(type)) || 
    (!(protocol == 0));
}

inline int check_msg_name(const struct msghdr *msg)
{
  return ((msg->msg_name != NULL) && \
	  (!(((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == PF_INET || \
	     ((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == PF_INET6)));
}

inline int check_sin6_family_and_socket_type(const struct sockaddr  *to, int socket_type)
{
  return ( (((struct sockaddr_in6 *)to)->sin6_family == AF_INET6 || 
	    ((struct sockaddr_in6 *)to)->sin6_family == AF_INET) &&
	   socket_type != SOCK_RAW &&
	   (socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) );
}

void initialize_db_when_not_exist()
{
  if(!db_exist){
    hip_init_socket_db();
    HIP_DEBUG("socketdb initialized\n");
    db_exist = 1;
  }
}

int util_func(int * const socket)
{
  int err = 0;
  int pid = 0;
  int port = 0;
  int mapping = 0;
  hip_opp_socket_t *entry = NULL;

  initialize_db_when_not_exist();

  pid = getpid();
  entry =  hip_socketdb_find_entry(pid, *socket);
  if(entry){
    if(hip_socketdb_has_new_socket(entry)){
      *socket = hip_socketdb_get_new_socket(entry);
      HIP_DEBUG("hasnew socket %d\n", *socket);
    }
    else 
      HIP_DEBUG("no new socket\n");
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
  hip_opp_socket_t *entry = NULL;

  // we are only interested in AF_INET and AFINET6
  pid = getpid();
  port = ntohs(((struct sockaddr_in6 *)to)->sin6_port);
  id = (struct in6_addr *)( &(((struct sockaddr_in6 *)to)->sin6_addr) );
  
  _HIP_DEBUG("connect sin_port=%d\n", port);
  HIP_DEBUG_HIT("sin6_addr id = ", id);
  _HIP_HEXDUMP("connect HEXDUMP to\n", to, 110); //sizeof(struct sockaddr_in)
  
  if(hit_is_real_hit(id)){
    HIP_DEBUG("!!!!!!!!!!!!!!!! real hit !!!!!!!!!!!!!!!\n");
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
    
    HIP_DEBUG_HIT("!!!! id ", id);
    HIP_DEBUG_HIT("!!!! peer_hit", &peer_hit);
    
    if(hit_is_real_hit(&peer_hit)){
      int type = 0;	
      int old_socket = 0;
      
      entry = hip_socketdb_find_entry(pid, *socket); 
      assert(entry);
      type = hip_socketdb_get_type(entry);

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
      
      hip_socketdb_add_new_socket(entry, *socket);
      hip_socketdb_add_dst_ip(entry, id);
      hip_socketdb_add_dst_hit(entry, &peer_hit);
      HIP_DEBUG("pid %d, new_socket %d, old_socket %d\n", pid, *socket, old_socket);
      
      // modify sockaddr, id points to sockaddr's sin6_addr
      memcpy(id, &peer_hit, sizeof(peer_hit));
      HIP_DEBUG_HIT("opp mode enabled, peer hit: id=", id);
    } else{ // not opp mode 
      entry = hip_socketdb_find_entry(pid, *socket);
      assert(entry);
      hip_socketdb_add_new_socket(entry, *socket);
      hip_socketdb_add_dst_ip(entry, id);
    }
  }
  
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

void dlsym_wrapper(const char *funcName, void *dp, char *err)
{
  if (dp==NULL){
    fputs(dlerror(),stderr);
    exit(1);
  }

  if(!strcmp(funcName, "socket"))
    socket_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "connect"))
    connect_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "send"))
    send_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "sendto"))
    sendto_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "sendmsg"))
    sendmsg_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "recv"))
    recv_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "recvfrom"))
    recvfrom_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "recvmsg"))
    recvmsg_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "close"))
    close_dlsym = dlsym(dp, funcName);
  else{
    HIP_DEBUG("name: %s\n", funcName);
    HIP_ERROR("failed dlsym function assignment\n");
    assert(0);
  }
  
  err = dlerror();
  if (err){
    fputs(err,stderr);
    exit(1);
  }
}

int socket(int domain, int type, int protocol)
{
  int pid;
  int socket_fd;
  int err;
  void *dp = NULL;
  char *error = NULL;
  char *name = "socket";

  pid = 0;
  socket_fd = 0;
  err = 0;
  dp = dlopen(SOFILE, RTLD_LAZY);
  dlsym_wrapper(name, dp, error);
  assert(dp);  
  socket_fd = socket_dlsym(domain, type, protocol);
  HIP_DEBUG("Called socket_dlsym, return fd %d\n", socket_fd);
  HIP_DEBUG(" socket_dlsym dp closing \n");
  dlclose(dp);
  HIP_DEBUG(" socket_dlsym dp closed \n");
  initialize_db_when_not_exist();

  if(socket_fd != -1){
    pid = getpid();    
    if(exists_mapping(pid, socket_fd)){
      HIP_DEBUG("pid %d, socket_fd %d\n", pid, socket_fd);
    } else{
      err = hip_socketdb_add_entry(pid, socket_fd);
      if(err)
	return err;
      hip_opp_socket_t *entry = NULL;
      entry = hip_socketdb_find_entry(pid, socket_fd);
      assert(entry);
      if(entry){
	hip_socketdb_add_domain(entry, domain);
	hip_socketdb_add_type(entry, type);
	hip_socketdb_add_protocol(entry, protocol);
      }
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
  int pid = 0;
  struct sockaddr bindhit;
  hip_hit_t *hit_ptr = NULL;
  int socket_type = 0;
  void *dp = NULL;
  char *error = NULL;
  struct in6_addr *id = NULL;
  hip_hit_t *hit_local = NULL;
  char *name = "connect";
  hip_opp_socket_t *entry = NULL;

  errno = 0;
  socket = a;
  initialize_db_when_not_exist();

  pid = getpid();
  entry = hip_socketdb_find_entry(pid, socket);
  assert(entry);
  socket_type = hip_socketdb_get_type(entry);

  hit_local = get_local_hits_wrapper();
  assert(hit_local);
  HIP_DEBUG_HIT("!!!! The local HIT =", hit_local);
  


  // we are only interested in AF_INET and AFINET6
  if( check_sin6_family_and_socket_type(b, socket_type)){
    errno = util_func_with_sockaddr(b, id, &socket, hit_local);
    if(errno)
      goto out_err;

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
  dp = dlopen(SOFILE, RTLD_LAZY);
  dlsym_wrapper(name, dp, error);

  errno = connect_dlsym(socket, b, c);
  
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
  void *dp = NULL;
  char *error = NULL;
  char *name = "send";
  errno = 0;
  socket = a;

  //  assert(db_exist);
  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("util_func call failed: %s\n", strerror(errno));
    return errno;
  }
  
  dp=dlopen(SOFILE,RTLD_LAZY);
  dlsym_wrapper(name, dp, error);
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
  int pid = 0;
  int socket = 0;
  int socket_type = 0;
  struct in6_addr *id = NULL;
  void *dp = NULL;
  char *error = NULL;
  char *name = "sendto";
  hip_hit_t *hit_local = NULL;
  struct sockaddr bindhit;
  hip_hit_t *hit_ptr = NULL;
  hip_opp_socket_t *entry = NULL;

  errno = 0;
  socket = a;

  initialize_db_when_not_exist();
  pid = getpid();
  entry = hip_socketdb_find_entry(pid, socket);
  if(entry){
    socket_type = hip_socketdb_get_type(entry);
  }
  _HIP_DEBUG("socket_type %d\n", socket_type);
  _HIP_DEBUG("stream %d datagram %d raw %d\n", SOCK_STREAM, SOCK_DGRAM, SOCK_RAW);
  
  // we are only interested in (AF_INET/AFINET6 && !SOCKET_RAW)
  if(check_sin6_family_and_socket_type(to, socket_type)){
    hit_local = get_local_hits_wrapper();
    assert(hit_local);
    HIP_DEBUG_HIT("!!!! The local HIT =", hit_local);
    
    errno = util_func_with_sockaddr(to, id, &socket, hit_local);
    if(errno)
      goto out_err;
  }

  dp=dlopen(SOFILE,RTLD_LAZY);
  dlsym_wrapper(name, dp, error);
  charnum = sendto_dlsym(socket, b, c, flags, to, tolen);
  dlclose(dp);
  
  HIP_DEBUG("Called sendto_dlsym with number of returned char=%d\n", charnum);

  return charnum;
 out_err:
  return errno;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendmsg(int a, const struct msghdr *msg, int flags)
{
  int errno;
  int socket = 0;
  int pid = 0;
  ssize_t charnum = 0;
  hip_hit_t *local_hit = NULL;
  hip_opp_socket_t *entry = NULL;
  struct in6_addr *id = NULL;
  struct sockaddr *is = NULL;
  void *dp = NULL;
  char *error = NULL;
  char *name = "sendmsg";
  union {
    struct in_pktinfo *pktinfo_in4;
    struct in6_pktinfo *pktinfo_in6;
  } pktinfo;
  struct cmsghdr *cmsg = NULL;
  int cmsg_level, cmsg_type;
  struct msghdr *tmp_msg;
  
  errno = 0;
  socket = a;
  
  dp=dlopen(SOFILE,RTLD_LAZY);  
  dlsym_wrapper(name, dp, error);

  initialize_db_when_not_exist();
  
  pktinfo.pktinfo_in4 = NULL;
  pktinfo.pktinfo_in6 = NULL;
  //is_ipv4 = 1;
  cmsg_level = IPPROTO_IP;
  cmsg_type = IP_PKTINFO; //IPV6_2292PKTINFO;
  tmp_msg = (struct msghdr *)(msg);
  for (cmsg=CMSG_FIRSTHDR(tmp_msg); cmsg; cmsg=CMSG_NXTHDR(tmp_msg,cmsg)){
    if ((cmsg->cmsg_level == cmsg_level) && 
	(cmsg->cmsg_type == cmsg_type)) {
      /* The structure is a union, so this fills also the pktinfo_in6 pointer */
      pktinfo.pktinfo_in4 =
	(struct in_pktinfo*)CMSG_DATA(cmsg);
      //      gotip = 1;
      break;
    }
  }
  if(!(pktinfo.pktinfo_in4)){ // try ipv6
    cmsg_level = IPPROTO_IPV6;
    cmsg_type = IPV6_PKTINFO; //IPV6_2292PKTINFO;
    for (cmsg=CMSG_FIRSTHDR(tmp_msg); cmsg; cmsg=CMSG_NXTHDR(tmp_msg,cmsg)){
      if ((cmsg->cmsg_level == cmsg_level) && 
	  (cmsg->cmsg_type == cmsg_type)) {
	pktinfo.pktinfo_in4 =
	  (struct in_pktinfo*)CMSG_DATA(cmsg);
	//gotip = 1;
      break;
      }
    }
  }
  
  pid = getpid();
  entry = hip_socketdb_find_entry(pid, socket);
  if(entry){
    int domain = hip_socketdb_get_domain(entry);
    int type = hip_socketdb_get_type(entry);
    int protocol = hip_socketdb_get_protocol(entry);
    
    if( check_domain_type_protocol(domain, type, protocol) ||
	check_msg_name(msg) ||
	(!pktinfo.pktinfo_in4) ){
      charnum = sendmsg_dlsym(socket, msg, flags);
      dlclose(dp);
      HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);
      return charnum;
    }
  }
  assert(pktinfo.pktinfo_in6);
  HIP_HEXDUMP("pktinfo", &pktinfo.pktinfo_in6->ipi6_addr, sizeof(struct in6_addr));
  assert(msg->msg_name);
  is = (struct sockaddr *)(msg->msg_name);
  _HIP_HEXDUMP("msg->msgname", is, sizeof(struct sockaddr));
 
  local_hit = get_local_hits_wrapper();
  assert(local_hit);

  errno = util_func_with_sockaddr(is, id, &socket, local_hit);
  
  if(errno){
    HIP_ERROR("sendmsg util_func call failed: %s\n", strerror(errno));
    return errno;
  }
  charnum = sendmsg_dlsym(socket, msg, flags);
  
  dlclose(dp);
  
  HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);

  return charnum;
}

ssize_t recv(int a, void *b, size_t c, int flags)
{
  int errno;
  int charnum = 0;  
  int socket = 0;
  void *dp = NULL;
  char *error = NULL;
  char *name = "recv";

  errno = 0;
  socket = a;

  //  assert(db_exist);
  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("util_func call failed: %s\n", strerror(errno));
    return errno;
  }

  dp=dlopen(SOFILE,RTLD_LAZY);
  dlsym_wrapper(name, dp, error);
  charnum = recv_dlsym(socket, b, c, flags);
  dlclose(dp);
  
  HIP_DEBUG("Called recv_dlsym with number of returned char=%d\n", charnum);

  return charnum;
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags, 
		 struct sockaddr *from, socklen_t *fromlen)
{
  int errno;
  int charnum = 0;  
  int socket = 0;
  void *dp = NULL;
  char *error = NULL;
  char *name = "recvfrom";

  errno = 0;
  socket = s;

  //  assert(db_exist);
  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("util_func call failed: %s\n", strerror(errno));
    return errno;
  }
  dp=dlopen(SOFILE,RTLD_LAZY);
  dlsym_wrapper(name, dp, error);
  charnum = recvfrom_dlsym(socket, buf, len, flags, from, fromlen);
  HIP_DEBUG("recvfrom_dlsym dlopen recvfrom\n");
  dlclose(dp);
  
  HIP_DEBUG("Called recvfrom_dlsym with number of returned char=%d\n", charnum);

  return charnum;
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
  int errno;
  int charnum = 0;  
  int socket = 0;
  void *dp = NULL;
  char *error = NULL;
  char *name = "recvmsg";

  socket = s;
  errno = util_func(&socket);
  if(errno){
    HIP_ERROR("util_func call failed: %s\n", strerror(errno));
    return errno;
  }
  
  dp=dlopen(SOFILE,RTLD_LAZY);
  dlsym_wrapper(name, dp, error);
  charnum = recvmsg_dlsym(socket, msg, flags);
  dlclose(dp);

  HIP_DEBUG("Called recvmsg_dlsym with number of returned chars=%d\n", charnum);

  return charnum;
}
int close(int fd)
{
  int errno;
  int pid = 0;
  hip_opp_socket_t *entry = NULL;
  void *dp = NULL;
  char *error = NULL;
  char *name = "close";

  errno = 0;

  dp=dlopen(SOFILE,RTLD_LAZY);
  dlsym_wrapper(name, dp, error);

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
#endif
