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
int hip_db_exist = 0;


// used for dlsym_util
#define NUMBER_OF_DLSYM_FUNCTIONS 10

struct {
	int (*socket_dlsym)(int domain, int type, int protocol);
	int (*bind_dlsym)(int socket, const struct sockaddr *sa,
			  socklen_t sa_len);
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
	int (*accept_dlsym)(int sockfd, struct sockaddr *addr,
			    socklen_t *addrlen);
} dl_function_ptr;

void *dl_function_fd[NUMBER_OF_DLSYM_FUNCTIONS];
void *dl_function_name[] =
{"socket", "bind", "connect", "send", "sendto",
 "sendmsg", "recv", "recvfrom", "recvmsg", "close", "accept"};

int hip_get_local_hit_wrapper(hip_hit_t *hit)
{
	int err = 0;
	struct gaih_addrtuple *at = NULL;
	struct gaih_addrtuple **pat = &at;
	
	err = get_local_hits(NULL, pat);
	if (err)
		HIP_ERROR("getting local hit failed\n");
	else
		memcpy(hit, &at->addr, sizeof(hip_hit_t));
	
	HIP_FREE(*pat);
	
	return err;
}

inline int hip_domain_is_pf_inet6(int domain)
{
	return (domain == PF_INET || domain == PF_INET6);
}

inline int hip_type_is_stream_or_dgram(int type)
{
	return (type == SOCK_STREAM || type == SOCK_DGRAM);
}

inline int hip_check_domain_type_protocol(int domain, int type, int protocol)
{
	return (!hip_domain_is_pf_inet6(domain)) ||
		(!hip_type_is_stream_or_dgram(type)) || 
		(!(protocol == 0));
}

inline int hip_check_msg_name(const struct msghdr *msg)
{
	return ((msg->msg_name != NULL) && \
		(!(((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == PF_INET || \
		   ((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == PF_INET6)));
}

inline int hip_wrapping_is_applicable(const struct sockaddr *sa, hip_opp_socket_t *entry)
{
	HIP_ASSERT(entry);

	if (!(entry->protocol == 0 || entry->protocol == IPPROTO_TCP ||
	      entry->protocol == IPPROTO_UDP))
		return 0;
	
	if (!(entry->domain == PF_INET6 || entry->domain == PF_INET))
		return 0;
	
	if (!(entry->type == SOCK_STREAM || entry->type == SOCK_DGRAM))
		return 0;
	
	if (sa) {
		if (sa->sa_family == AF_INET6 && ipv6_addr_is_hit(SA2IP(sa)))
			return 0;
		if (!(sa->sa_family == AF_INET || sa->sa_family == AF_INET6))
			return 0;
	}
	
	return 1;
}

void hip_uninit_dlsym_functions()
{
	int i = 0;
	for (i = 0; i < NUMBER_OF_DLSYM_FUNCTIONS; i++) {
		dlclose(dl_function_fd[i]);
	}
}

void hip_init_dlsym_functions()
{
	int err = 0, i;
	char *error = NULL;
	
	for (i = 0; i < NUMBER_OF_DLSYM_FUNCTIONS; i++) {
		dl_function_fd[i] = dlopen(SOFILE, RTLD_LAZY);
		HIP_ASSERT(dl_function_fd[i]);
		((int **) (&dl_function_ptr))[i] = dlsym(dl_function_fd[i],
							 dl_function_name[i]);
	}
	
	error = dlerror();
	if (err){
		HIP_DIE("dlerror: %s\n", error);
	}
}

void hip_uninitialize_db()
{
	hip_uninit_dlsym_functions();
	hip_uninit_socket_db();
}

void hip_initialize_db_when_not_exist()
{
	if(!hip_db_exist) {
		hip_init_dlsym_functions();
		hip_init_socket_db();
		HIP_DEBUG("socketdb initialized\n");
		// XX FIXME: SHOULD HAVE ALSO SIGNAL HANDLERS?
		atexit(hip_uninitialize_db);
		hip_db_exist = 1;
	}
}

void hip_store_orig_socket_info(hip_opp_socket_t *entry, int is_peer, const int socket,
			    const struct sockaddr *sa, const socklen_t sa_len)
{
	/* Fill in the information of original socket */
	entry->orig_socket = socket;
	if (is_peer) {
		memcpy(&entry->orig_peer_id, sa, sa_len);
		entry->orig_peer_id_len = sa_len;
	} else {
		memcpy(&entry->orig_local_id, sa, sa_len);
		entry->orig_local_id_len = sa_len;
	}
}

void hip_copy_orig_to_translated(hip_opp_socket_t *entry)
{
	entry->translated_socket = entry->orig_socket;
	memcpy(&entry->translated_peer_id, &entry->orig_peer_id,
	       sizeof(struct sockaddr_storage));
	memcpy(&entry->translated_local_id, &entry->orig_local_id,
	       sizeof(struct sockaddr_storage));
}

inline int hip_request_peer_hit_from_hipd(const struct in6_addr *peer_ip,
				      struct in6_addr *peer_hit,
				      const struct in6_addr *local_hit)
{
	struct hip_common *msg = NULL;
	struct in6_addr *hit_recv = NULL;
	hip_hit_t *ptr = NULL;
	int err = 0;
	int ret = 0;
	
	HIP_IFE(ipv6_addr_any(peer_ip), -1);
	
	HIP_IFE(!(msg = malloc(HIP_MAX_PACKET)), -1);
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)(local_hit),
					  HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_IPV6_ADDR  failed\n");
	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0), -1,
		 "build hdr failed\n");
	
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	HIP_DEBUG("send_recv msg succeed\n");
	
	/* check error value */
	HIP_IFE(hip_get_msg_err(msg), -1);
	
	ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
	HIP_DEBUG_HIT("ptr", ptr);
	HIP_ASSERT(ptr);
	memcpy(peer_hit, ptr, sizeof(hip_hit_t));
	HIP_DEBUG_HIT("peer_hit", peer_hit);
	
 out_err:
	
	if(msg)
		free(msg);
	
	return err;
}

void hip_translate_to_original(hip_opp_socket_t *entry)
{
	/* translated entries correspond to originals   */
	HIP_DEBUG("Translating to original\n");
	hip_copy_orig_to_translated(entry);
	entry->local_id_is_translated = 1;
	entry->peer_id_is_translated = 1;
}

int set_translation(hip_opp_socket_t *entry,
		    struct sockaddr_in6 *hit,
		    int is_peer) {
	int err = 0;
	
	if (!entry->translated_socket) {
		int new_socket = socket(AF_INET6, entry->type, 0);
		if (new_socket <= 0) {
			err = -1;
			HIP_ERROR("socket allocation failed\n");
			goto out_err;
		}
		entry->translated_socket = new_socket;
	}
	
	if (is_peer) {
		memcpy(&entry->translated_peer_id, hit, SALEN(hit));
		entry->translated_peer_id_len = SALEN(hit);
		entry->peer_id_is_translated = 1;
	} else {
		memcpy(&entry->translated_local_id, hit, SALEN(hit));
		entry->translated_local_id_len = SALEN(hit);
		entry->local_id_is_translated = 1;
	}
	
 out_err:
	return err;
	
}

int hip_autobind(hip_opp_socket_t *entry, struct sockaddr_in6 *hit) {
	int err = 0;
	
	do { /* XX FIXME: CHECK UPPER BOUNDARY */
		hit->sin6_port = rand();
	} while(hit->sin6_port < 1024);
	
	HIP_IFE(set_translation(entry, hit, 0), -1);
	err = dl_function_ptr.bind_dlsym(entry->translated_socket,
					 (struct sockaddr *) &entry->translated_local_id,
					 sizeof(struct sockaddr_in6));
	if (err) {
		HIP_ERROR("bind failed\n");
		goto out_err;
	}
	
 out_err:
	return err;
}

int hip_translate_new(hip_opp_socket_t *entry,
		      const int orig_socket,
		      const struct sockaddr *orig_id,
		      const socklen_t orig_id_len,
		      int is_peer, int is_dgram,
		      int is_translated, int wrap_applicable)
{
	int err = 0, pid = getpid(), port;
	struct sockaddr_in6 src_hit, dst_hit,
		*hit = (is_peer ? &dst_hit : &src_hit);
	socklen_t translated_id_len;
	struct sockaddr_in6 mapped_addr;
	
	HIP_DEBUG("Translating new id\n");
	
	HIP_ASSERT(entry->type == SOCK_STREAM || orig_id);
	
	err = hip_get_local_hit_wrapper(&src_hit.sin6_addr);
	if (err) {
		HIP_ERROR("No local HIT: is hipd running?\n");
		src_hit.sin6_family = AF_INET6;
		goto out_err;
	}
	
	if (entry->type == SOCK_STREAM && is_peer &&
	    !entry->local_id_is_translated) {
		HIP_IFE(hip_autobind(entry, &src_hit), -1);
	}
	
	/* hipd requires IPv4 addresses in IPv6 mapped format */
	if (orig_id->sa_family == AF_INET) {
		IPV4_TO_IPV6_MAP(&((struct sockaddr_in *) orig_id)->sin_addr,
				 &mapped_addr.sin6_addr);
		HIP_DEBUG_INADDR("ipv4 addr", SA2IP(orig_id));
		port = ((struct sockaddr_in *)orig_id)->sin_port;
	} else if (orig_id->sa_family == AF_INET6) {
		memcpy(&mapped_addr, orig_id, orig_id_len);
		HIP_DEBUG_IN6ADDR("ipv6 addr\n", SA2IP(orig_id));
		port = ((struct sockaddr_in6 *)orig_id)->sin6_port;
	} else {
		HIP_ASSERT("Not an IPv4/IPv6 socket: wrapping_is_applicable failed?\n");
	}
	mapped_addr.sin6_family = orig_id->sa_family;
	mapped_addr.sin6_port = port;
	
	hit->sin6_port = port;
	
	_HIP_DEBUG("sin_port=%d\n", ntohs(port));
	_HIP_DEBUG_IN6ADDR("sin6_addr ip = ", ip);
	
	if (is_peer) {
		/* Request a HIT of the peer from hipd. This will possibly
		   launch an I1 with NULL HIT that will block until R1 is
		   received. Called e.g. in connect() or sendto(). If
		   opportunistic HIP fails, it can return an IP address
		   instead of a HIT */
		HIP_DEBUG("requesting hit from hipd\n");
		HIP_IFEL(hip_request_peer_hit_from_hipd(&mapped_addr.sin6_addr,
							&dst_hit.sin6_addr,
							&src_hit.sin6_addr),
			 -1, "Request from hipd failed\n");
		dst_hit.sin6_family = AF_INET6;
	} else if (!entry->local_id_is_translated) {
		HIP_DEBUG("Local id already translated\n");
	}
	
	if (err || IN6_IS_ADDR_V4MAPPED(&hit->sin6_addr) ||
	    !ipv6_addr_is_hit(&hit->sin6_addr)) {
		HIP_DEBUG("Localhost/peer does not support HIP, falling back to IP\n");
		goto out_err;
	}
	
	/* We have now successfully translated an IP to an HIT. The HIT
	   requires a new socket. Also, we need set the return values
	   correctly */
	HIP_IFE(set_translation(entry, hit, is_peer), -1);
	
	return err;
	
 out_err:
	hip_translate_to_original(entry);
	return err;
}

int hip_old_translation_is_ok(hip_opp_socket_t *entry,
			  const int orig_socket,
			  const struct sockaddr *orig_id,
			  const socklen_t orig_id_len,
			  int is_peer, int is_dgram,
			  int is_translated, int wrap_applicable)
{
	void *translated_id =
	  (is_peer ? &entry->translated_peer_id : &entry->translated_local_id);

	/*
	 * An entry does not require translation when...
	 *
	 * (1) the entry must be already translated once
	 *
	 * and one of the following:
	 *
	 * (2) connection oriented socket call does not require new translation
	 * (3) original id was not given (e.g. recvfrom with NULL src)
	 * (4) optimization: we don't do a new translation unless the app
	 *     layer id has changed. Note: this optimization may have
	 *     limitations when addressing hosts behind a remote NAT network
	 */
	
	if (is_translated &&                                /* 1 */
	    (!is_dgram ||                                   /* 2 */
	     !orig_id  ||                                   /* 3 */
	     !memcmp(translated_id, orig_id, orig_id_len))) /* 4 */ {
		HIP_DEBUG("Old translation ok\n");
		return 1;
	} else {
		HIP_DEBUG("New translation required\n");
		return 0;
	}
}

int hip_translate_socket(const int *orig_socket,
		     const struct sockaddr *orig_id,
		     const socklen_t *orig_id_len,
		     int **translated_socket,
		     struct sockaddr **translated_id,
		     socklen_t **translated_id_len,
		     int is_peer, int is_dgram)
{
	int err = 0, pid = getpid(), is_translated, wrap_applicable;
	hip_opp_socket_t *entry;
	
	entry = hip_socketdb_find_entry(pid, *orig_socket);
	HIP_ASSERT(entry);
	HIP_ASSERT(orig_socket);
	
	is_translated =
		(is_peer ? entry->peer_id_is_translated :
		 entry->local_id_is_translated);
	wrap_applicable = hip_wrapping_is_applicable(orig_id, entry);

	HIP_DEBUG("orig_id=%p is_dgram=%d wrap_applicable=%d already=%d is_peer=%d\n",
		  orig_id, is_dgram, wrap_applicable, is_translated, is_peer);
	
	if (!is_translated)
		hip_store_orig_socket_info(entry, is_peer, *orig_socket,
					   orig_id, *orig_id_len);
	
	
	if (!wrap_applicable)
		hip_translate_to_original(entry);
	else if (hip_old_translation_is_ok(entry, *orig_socket, orig_id,
					   *orig_id_len, is_peer, is_dgram,
					   is_translated, wrap_applicable))
		HIP_DEBUG("Keeping the existing translation\n");
	else
		err = hip_translate_new(entry, *orig_socket, orig_id,
					*orig_id_len, is_peer, is_dgram,
					is_translated, wrap_applicable);
	
	if (err) {
		HIP_ERROR("Error occurred during translation\n");
	}
	
	if (entry->orig_socket == entry->translated_socket) {
		HIP_DEBUG("No translation occured, returning original socket and id\n");
		*translated_socket = (int *) orig_socket;
		*translated_id = (struct sockaddr *) orig_id;
		*translated_id_len = (socklen_t *) orig_id_len;
	} else {
		HIP_DEBUG("Returning translated socket and id\n");
		*translated_socket = &entry->translated_socket;
		*translated_id = (struct sockaddr *)
			(is_peer ? &entry->translated_peer_id :
			 &entry->translated_local_id);
		*translated_id_len =
			(is_peer ? &entry->translated_peer_id_len :
			 &entry->translated_local_id_len);
	}
	
 out_err:
	
	HIP_DEBUG("translation: pid %p, orig socket %p, translated sock %p\n",
		  pid, orig_socket, *translated_socket);
	HIP_DEBUG("orig_id %p, translated_id %p\n", orig_id, *translated_id);
	
	return err;
}

int socket(int domain, int type, int protocol)
{
	int pid = 0;
	int socket_fd = 0;
	int err = 0;
	hip_opp_socket_t *entry = NULL;
	
	hip_initialize_db_when_not_exist();
	
	socket_fd = dl_function_ptr.socket_dlsym(domain, type, protocol);
	
	if(socket_fd != -1){
		pid = getpid();    
		if(hip_exists_translation(pid, socket_fd)){
			HIP_DEBUG("pid %d, socket_fd %d\n", pid, socket_fd);
		} else {
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

int bind(int orig_socket, const struct sockaddr *orig_id,
	 socklen_t orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	
	err = hip_translate_socket(&orig_socket, orig_id, &orig_id_len,
				   &translated_socket, &translated_id,
				   &translated_id_len, 0, 0);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
 skip:
	
	err = dl_function_ptr.bind_dlsym(*translated_socket, translated_id,
					 *translated_id_len);
	if (err) {
		HIP_PERROR("connect error:");
	}
	
 out_err:
	return err;
}

int accept(int orig_socket, struct sockaddr *orig_id, socklen_t *orig_id_len)
{
	// XX TODO: REMEMBER THAT OADDR CAN BE NULL
	return -1;
}

int connect(int orig_socket, const struct sockaddr *orig_id,
	    socklen_t orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	
	HIP_DEBUG("\n");
	
	err = hip_translate_socket(&orig_socket, orig_id, &orig_id_len,
				   &translated_socket, &translated_id,
				   &translated_id_len, 1, 0);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.connect_dlsym(*translated_socket, translated_id,
					    *translated_id_len);
	if (err) {
		HIP_PERROR("connect error:");
	}
	
 out_err:
	return err;
}


/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 */
ssize_t send(int orig_socket, const void * b, size_t c, int flags)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	
	err = hip_translate_socket(&orig_socket, NULL, &zero,
				   &translated_socket, &translated_id,
				   &translated_id_len, 1, 0);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.send_dlsym(*translated_socket, b, c, flags);
	
	HIP_DEBUG("Called send_dlsym with number of returned char=%d\n", err);
	
 out_err:
	
	return err;
}

/* 
 * The calls return the number of characters sent, or -1 if an error occurred.
 * Untested.
 */
ssize_t sendto(int orig_socket, const void *buf, size_t buf_len, int flags, 
	       const struct sockaddr  *orig_id, socklen_t orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	
	HIP_DEBUG("\n");
	
	err = hip_translate_socket(&orig_socket,
				   orig_id,
				   &orig_id_len,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   1, 1);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.sendto_dlsym(*translated_socket, buf, buf_len,
					   flags,
					   translated_id,
					   *translated_id_len);

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
	hip_hit_t local_hit;
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
	for (cmsg=CMSG_FIRSTHDR(tmp_msg); cmsg;
	     cmsg=CMSG_NXTHDR(tmp_msg,cmsg)){
		if ((cmsg->cmsg_level == cmsg_level) && 
		    (cmsg->cmsg_type == cmsg_type)) {
			/* The structure is a union, so this fills also the
			   pktinfo_in6 pointer */
			pktinfo.pktinfo_in4 =
				(struct in_pktinfo*)CMSG_DATA(cmsg);
			//      gotip = 1;
			break;
		}
	}
	if(!(pktinfo.pktinfo_in4)){ // try ipv6
		cmsg_level = IPPROTO_IPV6;
		cmsg_type = IPV6_PKTINFO; //IPV6_2292PKTINFO;
		for (cmsg=CMSG_FIRSTHDR(tmp_msg); cmsg;
		     cmsg=CMSG_NXTHDR(tmp_msg,cmsg)){
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
		
		if(hip_check_domain_type_protocol(domain, type, protocol) ||
		   hip_check_msg_name(msg) ||
		   (!pktinfo.pktinfo_in4) ){
			charnum = dl_function_ptr.sendmsg_dlsym(socket, msg,
								flags);
			dlclose(dp);
			HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);
			return charnum;
		}
	}
	HIP_ASSERT(pktinfo.pktinfo_in6);
	HIP_HEXDUMP("pktinfo", &pktinfo.pktinfo_in6->ipi6_addr,
		    sizeof(struct in6_addr));
	HIP_ASSERT(msg->msg_name);
	is = (struct sockaddr *)(msg->msg_name);
	HIP_HEXDUMP("msg->msgname", is, sizeof(struct sockaddr));
	
	err = hip_get_local_hit_wrapper(&local_hit);
	HIP_ASSERT(!err);
	
	//err = cache_translation(&socket, &local_hit, id, NULL, is);
	
	if(err){
		HIP_ERROR("sendmsg cache_translation call failed: %s\n", strerror(err));
		return errno;
	}
	charnum = dl_function_ptr.sendmsg_dlsym(socket, msg, flags);
	
	HIP_DEBUG("Called sendmsg_dlsym with number of returned chars=%d\n", charnum);
	
	return charnum;
}

ssize_t recv(int orig_socket, void *b, size_t c, int flags)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len, zero = 0;
	struct sockaddr *translated_id;
	
	HIP_DEBUG("\n");
	
	err = hip_translate_socket(&orig_socket,
				   NULL,
				   &zero,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   0, 0);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.recv_dlsym(*translated_socket, b, c, flags);
	
	HIP_DEBUG("Called recv_dlsym with number of returned char=%d\n", err);
	
 out_err:
	
	return err;
}

ssize_t recvfrom(int orig_socket, void *buf, size_t len, int flags, 
		 struct sockaddr *orig_id, socklen_t *orig_id_len)
{
	int err = 0, *translated_socket;
	socklen_t *translated_id_len;
	struct sockaddr *translated_id;
	
	HIP_DEBUG("\n");
	
	err = hip_translate_socket(&orig_socket,
				   orig_id,
				   orig_id_len,
				   &translated_socket,
				   &translated_id,
				   &translated_id_len,
				   0, 1);
	if (err) {
		HIP_ERROR("Translation failure\n");
		goto out_err;
	}
	
	err = dl_function_ptr.recvfrom_dlsym(*translated_socket, buf, len,
					     flags,
					     translated_id,
					     translated_id_len);
	if (err) {
		HIP_PERROR("connect error:");
	}
	
 out_err:
	return err;
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
	
	charnum = dl_function_ptr.recvmsg_dlsym(socket, msg, flags);
	
	HIP_DEBUG("Called recvmsg_dlsym with number of returned chars=%d\n",
		  charnum);
	
	return charnum;
}
int close(int fd)
{
	int err = 0, pid = 0;
	hip_opp_socket_t *entry = NULL;
	void *dp = NULL;
	char *error = NULL, *name = "close";
	
	if(!hip_db_exist)
		goto out_err;

	pid = getpid();
	entry = hip_socketdb_find_entry(pid, fd);
	HIP_DEBUG("close() pid %d, fd %d\n", pid, fd);
	
	if(!entry){
		_HIP_DEBUG("should not happen, dumping socket db\n");
		hip_socketdb_dump();
		goto out_err;
			//assert(0);
	}

	if (entry->translated_socket) {
		// close new_socket too
		if(entry->orig_socket != entry->translated_socket){
			err = dl_function_ptr.close_dlsym(entry->translated_socket);
			if (err)
				HIP_ERROR("Err %d close trans socket\n", err);
		}
	}
	
	HIP_DEBUG("old_socket %d new_socket %d\n", 
		  entry->orig_socket,
		  entry->translated_socket);	  
 out_err:
	err = dl_function_ptr.close_dlsym(fd);
	HIP_DEBUG("close_dlsym called with err %d\n", err);
	
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
