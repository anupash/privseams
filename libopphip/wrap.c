/*
 * libinet6 wrap.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 * - Miika Komu <miika@iki.fi>
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
#include "libinet6/util.h"
#include "icomm.h"
#include "wrap_db.h"

//static
int db_exist = 0;

// used for dlsym_util
#define NUMBER_OF_DLSYM_FUNCTIONS 10
int (*socket_dlsym)(int domain, int type, int protocol);
int (*bind_dlsym)(int socket, const struct sockaddr *sa, socklen_t sa_len);
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

void *dl_function_filehandles[NUMBER_OF_DLSYM_FUNCTIONS];
void *dl_registered_functions[] =
  {"socket", "bind", "connect", "send", "sendto",
   "sendmsg", "recv", "recvfrom", "recvmsg", "close"};

inline hip_hit_t *get_local_hits_wrapper()
{
  struct gaih_addrtuple *at = NULL;
  struct gaih_addrtuple **pat = &at;
  
  get_local_hits(NULL, pat);
  return (hip_hit_t *)(&at->addr);
}

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

inline int wrapping_is_applicable(const struct sockaddr *sa, int type)
{
  return ((sa->sa_family == AF_INET || sa->sa_family == AF_INET6) &&
	  (type == SOCK_STREAM || type == SOCK_DGRAM) &&
	  !ipv6_addr_is_hit(SA2IP(sa)));
}

void uninit_dlsym_functions()
{
  int i = 0;
  for (i = 0; i < NUMBER_OF_DLSYM_FUNCTIONS; i++) {
    dlclose(dl_function_filehandles[i]);
  }
}

void init_dlsym_functions()
{
  int err = 0, i;
  char *error = NULL;

  for (i = 0; i < NUMBER_OF_DLSYM_FUNCTIONS; i++) {
    dl_function_filehandles[i] = dlopen(SOFILE, RTLD_LAZY);
    HIP_ASSERT(dl_function_filehandles[i]);
    socket_dlsym = dlsym(dl_function_filehandles[i],
			 dl_registered_functions[i]);
  }

  error = dlerror();
  if (err){
    HIP_DIE("dlerror: %s\n", error);
  }
}

void uninitialize_db()
{
  uninit_dlsym_functions();
  hip_uninit_socket_db();
}

void initialize_db_when_not_exist()
{
  if(!db_exist) {
    init_dlsym_functions();
    hip_init_socket_db();
    HIP_DEBUG("socketdb initialized\n");
    // XX FIXME: SHOULD HAVE ALSO SIGNAL HANDLERS?
    atexit(uninitialize_db);
    db_exist = 1;
  }
}

#if 0
inline int any_sa_to_hit_sa(const struct sockaddr *from,
		     const hip_hit_t *use_hit,
		     struct sockaddr_in6 *to) {
  to->sin6_family = AF_INET6;
  ipv6_addr_copy(&to->sin6_addr, use_hit);
  if (from->sa_family == AF_INET)
    to->sin6_port = ((struct sockaddr_in *) from)->sin_port;
  else if (from->sa_family == AF_INET6)
    to->sin6_port = ((struct sockaddr_in6 *) from)->sin6_port;
  else
    return -1;

  return 0;
}
#endif

inline int translate_connected_socket(const int socket, int **translated_socket)
{
  int err = 0, pid = getpid();
  hip_opp_socket_t *entry = hip_socketdb_find_entry(pid, socket);

  HIP_ASSERT(entry);
  HIP_ASSERT(entry->translated_socket);

  *translated_socket = &entry->translated_socket;

  return err;
}

inline int request_peer_hit_from_hipd(const struct in6_addr *ip, 
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
    HIP_DEBUG_HIT("ptr", ptr);
    HIP_ASSERT(ptr);
    memcpy(peer_hit, ptr, sizeof(hip_hit_t));
    HIP_DEBUG_HIT("peer_hit", peer_hit);
  } // end of  if(!ipv6_addr_any(&ip))

 out_err:

  if(msg)
    free(msg);

  return err;
}

inline int translate_disconnected_socket(const int orig_socket,
				  const struct sockaddr *orig_id,
				  int **translated_socket,
				  struct sockaddr **translated_id,
				  int is_peer)
{
  int err = 0, pid = getpid(), port, type;
  hip_opp_socket_t *entry;
  struct sockaddr_in6 mapped_addr;

  entry = hip_socketdb_find_entry(pid, orig_socket);
  HIP_ASSERT(entry);

  /* By default, we don't translate at all */
  entry->orig_socket = orig_socket;
  entry->translated_socket = orig_socket;
  *translated_socket = &entry->translated_socket;
  *translated_id = (struct sockaddr *)
    (is_peer ? &entry->translated_dst_id : &entry->translated_src_id);

  /* Copy identifier to the database even when we are dealing with e.g.
     HIT or SOCK_RAW. The */
  if(!entry->is_translated &&
     !wrapping_is_applicable(orig_id, entry->type)) {
    HIP_DEBUG("Wrapping is not applicable, returning original\n");
    memcpy((is_peer ? &entry->orig_dst_id : &entry->orig_src_id),
	   orig_id, SALEN(orig_id));
    memcpy(*translated_id, orig_id, SALEN(orig_id));
    goto out_err;
  }

  /* hipd requires IPv4 addresses in IPv6 mapped format */
  if (orig_id->sa_family == AF_INET) {
    IPV4_TO_IPV6_MAP(&((struct sockaddr_in *) orig_id)->sin_addr,
		     &mapped_addr.sin6_addr);
    HIP_DEBUG_INADDR("ipv4 addr", SA2IP(orig_id));
    port = ((struct sockaddr_in *)orig_id)->sin_port;
  } else if (orig_id->sa_family == AF_INET6) {
    memcpy(&mapped_addr, orig_id, SALEN(orig_id));
    HIP_DEBUG_IN6ADDR("ipv6 addr\n", SA2IP(orig_id));
    port = ((struct sockaddr_in6 *)orig_id)->sin6_port;
  } else {
    HIP_ASSERT("Not an IPv4/IPv6 socket: wrapping_is_applicable failed?\n");
  }

  mapped_addr.sin6_family = orig_id->sa_family;
  mapped_addr.sin6_port = port;

  _HIP_DEBUG("connect sin_port=%d\n", ntohs(port));
  _HIP_DEBUG_IN6ADDR("sin6_addr ip = ", ip);
  
  /* Now, the socket identifier seems translatable (e.g. not an HIT or a
     RAW_SOCK). */

  /* Optimization: we don't request a HIT from hipd in sendto()
     and sendmsg() unless the application layer id has changed. Note: this
     may have limitations when addressing hosts behind a remote NAT network. */
  if (entry->is_translated &&
      !memcmp((is_peer ? &entry->orig_dst_id : &entry->orig_dst_id), orig_id,
	      SALEN(orig_id))) {
    HIP_DEBUG("entry does not require a request from hipd\n");
    goto skip_request;
  }

  /* Request a HIT of the peer from hipd. This will possibly launch an I1
     with NULL HIT that will block until R1 is received. Called e.g. in
     connect() or sendto(). If opportunistic HIP fails, it can return an
     IP address instead of a HIT */
  if (is_peer) {
    HIP_DEBUG("requesting hit from hipd\n");
    err = request_peer_hit_from_hipd(&mapped_addr.sin6_addr,
	       SA2IP(&entry->translated_dst_id),
	       SA2IP(&entry->translated_src_id));
    // XX FIX: FALLBACK TRANSLATION WITH IPv4 ADDRESSES: MAPPED FORMAT
  } else {
    /* Binding to an interface: assign any HIT */
    memcpy(&entry->translated_src_id, get_local_hits_wrapper(),
	   sizeof(hip_hit_t));
  }

  if (err || !ipv6_addr_is_hit(SA2IP(&entry->translated_dst_id))) {
    HIP_DEBUG("Localhost or peer does not support HIP, falling back to plain IP\n");
    goto out_err;
  }

  ((struct sockaddr_in6 *)(*translated_id))->sin6_family = AF_INET6;
  ((struct sockaddr_in6 *)(*translated_id))->sin6_port = port;

 skip_request:

  /* We have now successfully translated an IP to an HIT. The HIT requires a new socket.
     Also, we need set the return values correctly */

  entry->is_translated = 1;
  entry->translated_socket = socket(AF_INET6, type, 0);
  *translated_socket = &entry->translated_socket;
  if (entry->translated_socket <= 0) {
    err = -1;
    HIP_ERROR("socket allocation failed\n");
  }

 out_err:
  HIP_DEBUG("pid %d, orig socket %d, translated sock %d\n", pid, orig_socket,
	    **translated_socket);
  HIP_DEBUG_IN6ADDR("original id", orig_id);
  HIP_DEBUG_IN6ADDR("translated id", *translated_id);

  return err;
}

#if 0
void dlsym_wrapper(const char *funcName, void *dp, char *err)
{
  if (dp==NULL){
    fputs(dlerror(),stderr);
    exit(1);
  }

  if(!strcmp(funcName, "socket"))
    socket_dlsym = dlsym(dp, funcName);
  else if(!strcmp(funcName, "bind"))
    close_dlsym = dlsym(dp, funcName);
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
    HIP_ASSERT(0);
  }
  
  err = dlerror();
  if (err){
    fputs(err,stderr);
    exit(1);
  }
}
#endif

int socket(int domain, int type, int protocol)
{
  int pid = 0;
  int socket_fd = 0;
  int err = 0;
  hip_opp_socket_t *entry = NULL;

  initialize_db_when_not_exist();

  socket_fd = socket_dlsym(domain, type, protocol);

  if(socket_fd != -1){
    pid = getpid();    
    if(exists_translation(pid, socket_fd)){
      HIP_DEBUG("pid %d, socket_fd %d\n", pid, socket_fd);
    } else{
      err = hip_socketdb_add_entry(pid, socket_fd);
      if(err)
	return err;

      entry = hip_socketdb_find_entry(pid, socket_fd);
      HIP_ASSERT(entry);
      if(entry){
	entry->domain = domain;
	entry->type = type;
	entry->protocol = protocol;
      }

    } 
  }
  else{
    HIP_ASSERT(0);
  }
  HIP_DEBUG("Called socket_dlsym socket_fd=%d\n", socket_fd);  
  return socket_fd;
}

int bind(int osock, const struct sockaddr *olocal_sa, socklen_t osock_len)
{
  // XX TODO: write entry->translated_id_src_port
  return -1;
}

int accept(int osockfd, struct sockaddr *oaddr, socklen_t *oaddrlen)
{
  return -1;
}

int connect(int orig_sock, const struct sockaddr *orig_peer_sa,
	    socklen_t orig_sock_len)
{
  int err = 0, *translated_socket;
  struct sockaddr *translated_peer;

  HIP_DEBUG("\n");

  err = translate_disconnected_socket(orig_sock, orig_peer_sa,
				      &translated_socket, &translated_peer, 1);
  if (err) {
    HIP_ERROR("Translation failed\n");
    goto out_err;
  }

 skip:

  err = connect_dlsym(*translated_socket, translated_peer, SALEN(translated_peer));
  if (err) {
    HIP_PERROR("connect error:");
  }
    
 out_err:
  return err;
}


/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t send(int a, const void * b, size_t c, int flags)
{
  int err, charnum = 0, *translated_socket;

  //  assert(db_exist);
  err = translate_connected_socket(a, &translated_socket);
  if(err){
    HIP_ERROR("t call failed: %s\n", strerror(err));
    return err;
  }
  
  charnum = send_dlsym(*translated_socket, b, c, flags);
  
  HIP_DEBUG("Called send_dlsym with number of returned char=%d\n", charnum);

  return charnum;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 * Untested.
 */
ssize_t sendto(int a, const void * b, size_t c, int flags, 
	       const struct sockaddr  *to, socklen_t tolen)
{
  int err = 0;
  ssize_t charnum = 0;

  return -1; // XX FIXME

  return charnum;

 out_err:

  return err;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t sendmsg(int a, const struct msghdr *msg, int flags)
{
  int err;
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

  return -1; // XX FIXME
  
  err = 0;
  socket = a;
  
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
    int domain = entry->domain;
    int type = entry->type;
    int protocol = entry->protocol;
    
    if( check_domain_type_protocol(domain, type, protocol) ||
	check_msg_name(msg) ||
	(!pktinfo.pktinfo_in4) ){
      charnum = sendmsg_dlsym(socket, msg, flags);
      dlclose(dp);
      HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);
      return charnum;
    }
  }
  HIP_ASSERT(pktinfo.pktinfo_in6);
  HIP_HEXDUMP("pktinfo", &pktinfo.pktinfo_in6->ipi6_addr, sizeof(struct in6_addr));
  HIP_ASSERT(msg->msg_name);
  is = (struct sockaddr *)(msg->msg_name);
  HIP_HEXDUMP("msg->msgname", is, sizeof(struct sockaddr));
 
  local_hit = get_local_hits_wrapper();
  HIP_ASSERT(local_hit);

  //err = cache_translation(&socket, local_hit, id, NULL, is);
  
  if(err){
    HIP_ERROR("sendmsg cache_translation call failed: %s\n", strerror(err));
    return errno;
  }
  charnum = sendmsg_dlsym(socket, msg, flags);
  
  HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);

  return charnum;
}

ssize_t recv(int a, void *b, size_t c, int flags)
{
  int err = 0, charnum = 0, *translated_socket;
  void *dp = NULL;
  char *error = NULL;
  char *name = "recv";

  //  assert(db_exist);
  err = translate_connected_socket(a, &translated_socket);
  if(err){
    HIP_ERROR("translate_socket call failed: %s\n", strerror(err));
    return err;
  }

  charnum = recv_dlsym(*translated_socket, b, c, flags);
  
  HIP_DEBUG("Called recv_dlsym with number of returned char=%d\n", charnum);

  return charnum;
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags, 
		 struct sockaddr *from, socklen_t *fromlen)
{
  int charnum = 0, translated_socket;
  char *error = NULL, *name = "recvfrom";
  void *dp = NULL;

  return -1; // XX TODO

  charnum = recvfrom_dlsym(translated_socket, buf, len, flags, from, fromlen);
  HIP_DEBUG("recvfrom_dlsym dlopen recvfrom\n");
  
  HIP_DEBUG("Called recvfrom_dlsym with number of returned char=%d\n", charnum);

  return charnum;
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
  int err;
  int charnum = 0;  
  int socket = 0;
  void *dp = NULL;
  char *error = NULL;
  char *name = "recvmsg";

  return -1; // XX TODO
  
  charnum = recvmsg_dlsym(socket, msg, flags);

  HIP_DEBUG("Called recvmsg_dlsym with number of returned chars=%d\n", charnum);

  return charnum;
}
int close(int fd)
{
  int err;
  int pid = 0;
  hip_opp_socket_t *entry = NULL;
  void *dp = NULL;
  char *error = NULL;
  char *name = "close";

  err = 0;

  if(db_exist){
    pid = getpid();
    entry = hip_socketdb_find_entry(pid, fd);
    HIP_DEBUG("close() pid %d, fd %d\n", pid, fd);

    if(!entry){
      _HIP_DEBUG("should not happen, dumping socket db\n");
      hip_socketdb_dump();
      goto out_err;
      //assert(0);
    }
    if(entry){

      if (entry->translated_socket) {
	int old_socket = entry->orig_socket;
	int new_socket = entry->translated_socket;
	// close new_socket too
	if(old_socket != new_socket){
	  HIP_DEBUG("old_socket %d new_socket %d\n", 
		    old_socket, new_socket);	  
	  err = close_dlsym(new_socket);
	  if(err){
	    _HIP_DEBUG("close new_socket failed err %d\n", err);
	  } else{
	    _HIP_DEBUG("close new_socket no error\n");
	  }
	}
      }
    }    
  }
  
  err = close_dlsym(fd);
  HIP_DEBUG("close_dlsym called with err %d\n", err);

out_err:
  return err;
}


// used to test socketdb
void test_db(){
  HIP_DEBUG("testing db\n");
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
  entry->translated_socket = socket+100;
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
