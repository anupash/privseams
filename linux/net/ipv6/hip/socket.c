/*
 * HIP socket handler - handle PF_HIP type sockets
 *
 * Author:
 * - Miika Komu <miika@iki.fi>
 *
 * Todo:
 * - Do we need separate proto ops for dgrams?
 * - What functions should return just zero?
 *
 */

#include "socket.h"

/*
 * The eid db lock (local or peer) must be obtained before accessing these
 * variables.
 */
static sa_eid_t hip_local_eid_count = 1;
static sa_eid_t hip_peer_eid_count  = 1;

static struct proto_ops hip_socket_ops = {
	family:		PF_HIP,

	release:	hip_socket_release,
	bind:		hip_socket_bind,
	connect:	hip_socket_connect,
	socketpair:	hip_socket_socketpair,
	accept:		hip_socket_accept,
	getname:	hip_socket_getname,
	poll:		hip_socket_poll,
	ioctl:		hip_socket_ioctl,
	listen:		hip_socket_listen,
	shutdown:	hip_socket_shutdown,
	setsockopt:	hip_socket_setsockopt,
	getsockopt:	hip_socket_getsockopt,
	sendmsg:	hip_socket_sendmsg,
	recvmsg:	hip_socket_recvmsg,
	mmap:		hip_socket_mmap,
	sendpage:	hip_socket_sendpage
};

struct net_proto_family hip_family_ops = {
	family:         PF_HIP,
	create:         hip_create_socket
};

sa_eid_t hip_create_unique_local_eid(void)
{
	// XX CHECK OVERFLOWS
	return hip_local_eid_count++;
}

sa_eid_t hip_create_unique_peer_eid(void)
{
	// XX CHECK OVERFLOWS
	return hip_peer_eid_count++;
}

int hip_create_socket(struct socket *sock, int protocol)
{
	int err = 0;

	HIP_DEBUG("\n");

	// XX TODO: REPLACE WITH A SELECTOR
	err = inet6_family_ops.create(sock, protocol);
	if (err) {
		HIP_ERROR("Inet6 creation failed (%d)\n", err);
		goto out_err;
	}

	// XX LOCK AND UNLOCK?
	sock->ops = &hip_socket_ops;
	/* Note: we cannot set sock->sk->family ever to PF_HIP because it
	   simply does not work if we want to use inet6 sockets. */

 out_err:

	return err;
}

int hip_init_socket_handler(void)
{
	int err = 0;

	err = sock_register(&hip_family_ops);
	if (err) {
		HIP_ERROR("HIP socket handler registration failed (%d)\n",
			  err);
	}

	return err;
}

void hip_uninit_socket_handler(void)
{
	int err = 0;

	err = sock_unregister(PF_HIP);
	if (err) {
		HIP_ERROR("HIP socket handler unregistration failed (%d)\n",
			  err);
	}
}

int hip_select_socket_handler(struct socket *sock,
			      struct proto_ops **handler)
{
	int err = 0;
	// XX FIXME: WHEN TO SELECT UDP AND IPV4?
	*handler = &inet6_stream_ops;
	return err;
}

int hip_socket_get_eid_info(struct socket *sock,
			    struct proto_ops **socket_handler,
			    const struct sockaddr_eid *eid,
			    int eid_is_local,
			    struct hip_lhi *lhi)
{
	struct hip_eid_owner_info owner_info;
	int err = 0;

	err = hip_select_socket_handler(sock, socket_handler);
	if (err) {
		HIP_ERROR("Failed to select a socket handler\n");
		goto out_err;
	}

	err = hip_db_get_lhi_by_eid(eid, lhi, &owner_info, eid_is_local);
	if (err) {
		HIP_ERROR("Failed to map %s EID to HIT\n",
			  (eid_is_local ? "local" : "peer"));
		goto out_err;
	}

	/* XX FIXME: CHECK ACCESS RIGHTS FROM OWNER_INFO */

 out_err:

	return err;
}

int hip_socket_release(struct socket *sock)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	if (sock->sk == NULL)
		goto out_err;

	err = socket_handler->release(sock);
	if (err) {
		HIP_ERROR("Socket handler failed (%d)\n", err);
		goto out_err;
	}

	/* XX FIX: RELEASE EID */

	/* XX FIX: DESTROY HI ? */

 out_err:

	return err;
}

int hip_socket_bind(struct socket *sock, struct sockaddr *umyaddr,
		    int sockaddr_len)
{
	int err = 0;
	struct sockaddr_in6 sockaddr_in6;
	struct proto_ops *socket_handler;
	struct sock *sk = sock->sk;
	struct ipv6_pinfo *pinfo = inet6_sk(sk);
	struct hip_lhi lhi;
	struct sockaddr_eid *sockaddr_eid = (struct sockaddr_eid *) umyaddr;

	HIP_DEBUG("\n");

	err = hip_socket_get_eid_info(sock, &socket_handler, sockaddr_eid,
				      1, &lhi);
	if (err) {
		HIP_ERROR("Failed to get socket eid info.\n");
		goto out_err;
	}

	/* Clear out the flowinfo, etc from sockaddr_in6 */
	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));

	/* XX FIXME: select the IP address based on the mappings or interfaces
	   from db and do not use in6_addr_any. */

	/* Use in6_addr_any (= all zeroes) for bind. Offering a HIT to bind
	   does not work without modifications into the bind code because
	   bind_v6 returns an error when it does address type checks. */
	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));
	sockaddr_in6.sin6_family = PF_INET6;
	sockaddr_in6.sin6_port = sockaddr_eid->eid_port;
	
	/* XX FIX: check access permissions from eid_owner_info */

	err = socket_handler->bind(sock, (struct sockaddr *) &sockaddr_in6,
				   sizeof(struct sockaddr_in6));
	if (err) {
		HIP_ERROR("Socket handler failed (%d).\n", err);
		goto out_err;
	}

	memcpy(&pinfo->rcv_saddr, &lhi.hit,
	       sizeof(struct in6_addr));
	memcpy(&pinfo->saddr, &lhi.hit,
	       sizeof(struct in6_addr));

 out_err:

	return err;
}

int hip_socket_connect(struct socket *sock, struct sockaddr *uservaddr,
		       int sockaddr_len, int flags)
{
	int err = 0;
	struct sockaddr_in6 sockaddr_in6;
	struct proto_ops *socket_handler;
	struct hip_lhi lhi;
	struct sockaddr_eid *sockaddr_eid = (struct sockaddr_eid *) uservaddr;

	HIP_DEBUG("\n");

	err = hip_socket_get_eid_info(sock, &socket_handler, sockaddr_eid,
				      0, &lhi);
	if (err) {
		HIP_ERROR("Failed to get socket eid info.\n");
		goto out_err;
	}

	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));
	sockaddr_in6.sin6_family = PF_INET6;
	memcpy(&sockaddr_in6.sin6_addr, &lhi.hit, sizeof(struct in6_addr));
	sockaddr_in6.sin6_port = sockaddr_eid->eid_port;

	/* Note: connect calls autobind if the application has not already
	   called bind manually. */
	
	err = socket_handler->connect(sock, (struct sockaddr *) &sockaddr_in6,
				      sizeof(struct sockaddr_in6), flags);
	if (err) {
		HIP_ERROR("Socket handler failed (%d).\n", err);
		goto out_err;
	}

 out_err:

	return err;
}

int hip_socket_socketpair(struct socket *sock1, struct socket *sock2)
{
	int err = 0;
	HIP_DEBUG("\n");
	err = -ENOSYS;
	return err;
}

int hip_socket_accept(struct socket *sock, struct socket *newsock,
		      int flags)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		HIP_ERROR("Failed to select socket handler.\n");
		goto out_err;
	}

	err = socket_handler->accept(sock, newsock, flags);
	if (err) {
		/* Can return e.g. ERESTARTSYS */
		HIP_DEBUG("Socket handler returned (%d)\n", err);
		goto out_err;
	}

	/* XX FIXME: do something to the newsock? */

 out_err:
	
	return err;
}

int hip_socket_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *usockaddr_len, int peer)
{
	int err = 0;
	struct proto_ops *socket_handler;
	struct hip_lhi lhi;
	struct hip_eid_owner_info owner_info;
	struct sock *sk = sock->sk;
	struct ipv6_pinfo *pinfo = inet6_sk(sk);
	struct inet_opt *inet = inet_sk(sk);
	struct sockaddr_in6 sockaddr_in6_tmp;
	struct sockaddr_eid *sockaddr_eid = (struct sockaddr_eid *) uaddr;
	int sockaddr_in6_tmp_len;

	HIP_DEBUG("\n");

	/* XX CHECK access perms? */

	HIP_DEBUG("getname for %s called\n", (peer ? "peer" : "local"));

	HIP_HEXDUMP("daddr", &pinfo->daddr,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("rcv_saddr", &pinfo->rcv_saddr,
		    sizeof(struct in6_addr));

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		HIP_ERROR("Failed to select a socket handler\n");
		goto out_err;
	}

	HIP_DEBUG("port: %d\n", ntohs((peer ? inet->dport : inet->sport)));

	err = socket_handler->getname(sock,
				      (struct sockaddr *) &sockaddr_in6_tmp,
				      &sockaddr_in6_tmp_len, peer);
	if (err) {
		HIP_ERROR("Socket handler failed (%d)\n", err);
		goto out_err;
	}

	HIP_ASSERT(sockaddr_in6_tmp_len == sizeof(struct sockaddr_in6));
	HIP_DEBUG_IN6ADDR("inet6 getname returned addr",
			  &sockaddr_in6_tmp.sin6_addr);

	owner_info.uid = current->uid;
	owner_info.gid = current->gid;

	memcpy(&lhi.hit, &pinfo->daddr,
	       sizeof(struct in6_addr));
	lhi.anonymous = 0; /* XX FIXME: should be really set to -1 */

	err = hip_db_set_eid(sockaddr_eid, &lhi, &owner_info, !peer);
	if (err) {
		HIP_ERROR("Setting of %s eid failed\n",
			  (peer ? "peer" : "local"));
		goto out_err;
	}

	sockaddr_eid->eid_port = (peer) ? inet->dport : inet->sport;

	*usockaddr_len = sizeof(struct sockaddr_eid);

 out_err:

	return err;
}

unsigned int hip_socket_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	unsigned int mask = 0;
	HIP_DEBUG("\n");
	mask = POLLERR;
	return mask;
}

int hip_socket_ioctl(struct socket *sock, unsigned int cmd,
		     unsigned long arg)
{
	int err = 0;
	HIP_DEBUG("\n");
	err = -ENOSYS;
	return err;
}

int hip_socket_listen(struct socket *sock, int backlog)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->listen(sock, backlog);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:
	
	return err;
}

int hip_socket_shutdown(struct socket *sock, int flags)
{
	int err = 0;
	HIP_DEBUG("\n");
	err = -ENOSYS;
	return err;
}

int hip_socket_set_my_eid(struct hip_common *request,
			  struct hip_common *response)
{
	int err = 0;
	struct sockaddr_eid eid;
	struct hip_tlv_common *param = NULL;
	struct hip_eid_iface *iface;
	struct hip_eid_endpoint *eid_endpoint;
	struct hip_lhi lhi;
	struct hip_eid_owner_info owner_info;
	struct hip_host_id *host_id;
	
	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(request) != HIP_USER_SET_MY_EID) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	eid_endpoint = hip_get_param(request, HIP_PARAM_EID_ENDPOINT);
	if (!eid_endpoint) {
		err = -ENOENT;
		HIP_ERROR("Could not find eid endpoint\n");
		goto out_err;
	}

	if (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_HIT) {
		err = -EAFNOSUPPORT;
		HIP_ERROR("setmyeid does not support HITs, only HIs\n");
		goto out_err;
	}
	
	HIP_DEBUG("hi len %d\n",
		  ntohs((eid_endpoint->endpoint.id.host_id.hi_length)));

	HIP_HEXDUMP("eid endpoint", eid_endpoint,
		    hip_get_param_total_len(eid_endpoint));

	host_id = &eid_endpoint->endpoint.id.host_id;

	owner_info.uid = current->uid;
	owner_info.gid = current->gid;
	
	/*
	 * The resolver sends here only public keys, but it is possible for
	 * the applications to send also their private keys here.
	 */
	if (hip_host_id_contains_private_key(host_id)) {
		err = hip_private_host_id_to_hit(host_id, &lhi.hit,
						 HIP_HIT_TYPE_HASH126);
		if (err) {
			HIP_ERROR("Failed to calculate HIT from HI.");
			goto out_err;
		}
	
		/* XX TODO: check UID/GID permissions before adding */
		err = hip_add_localhost_id(&lhi, host_id);
		if (err) {
			HIP_ERROR("Adding of localhost id failed");
			goto out_err;
		}
	} else {
		/* Only public key */
		err = hip_host_id_to_hit(host_id,
					 &lhi.hit, HIP_HIT_TYPE_HASH126);
	}
	
	HIP_DEBUG_HIT("calculated HIT", &lhi.hit);
	
	/* Iterate through the interfaces */
	while((param = hip_get_next_param(request, param)) != NULL) {
		/* Skip other parameters (only the endpoint should
		   really be there). */
		if (hip_get_param_type(param) != HIP_PARAM_EID_IFACE)
			continue;
		iface = (struct hip_eid_iface *) param;
		/* XX TODO: convert and store the iface somewhere?? */
		/* XX TODO: check also the UID permissions for storing
		   the ifaces before actually storing them */
	}
	
	/* The eid port information will be filled by the resolver. It is not
	   really meaningful in the eid db. */
	eid.eid_port = htons(0);
	
	lhi.anonymous =
	   (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ?
		1 : 0;
	
	/* XX TODO: check UID/GID permissions before adding ? */
	err = hip_db_set_my_eid(&eid, &lhi, &owner_info);
	if (err) {
		HIP_ERROR("Could not set my eid into the db\n");
		goto out_err;
	}

	/* Clear the response (in the case it is the same as the request) and
	   write a return message */
	
	hip_msg_init(response);
	hip_build_user_hdr(response, HIP_USER_SET_MY_EID, err);
	err = hip_build_param_eid_sockaddr(response,
					   (struct sockaddr *) &eid,
					   sizeof(eid));
	if (err) {
		HIP_ERROR("Could not build eid sockaddr\n");
		goto out_err;
	}
	
 out_err:
	return err;
}

int hip_socket_setsockopt(struct socket *sock, int level, int optname,
			  char *optval, int optlen)
{
	int err = 0;
	HIP_DEBUG("\n");

	err = -ENOSYS;
	return err;
}

int hip_socket_getsockopt(struct socket *sock, int level, int optname,
			  char *optval, int *optlen)
{
	int err = 0;
	struct hip_common *msg = (struct hip_common *) optval;
	
	HIP_DEBUG("\n");

	/* XX CHECK: what happens when the the optval buffer is overflowed? */

	/* XX FIX ME: what about normal inet6 socket option queries? */

	err = hip_check_userspace_msg(msg);
	if (err) {
		HIP_ERROR("Userspace msg invalid\n");
		goto out_err;
	}
	
	if (hip_get_msg_total_len(msg) != *optlen) {
		err = -EMSGSIZE;
		HIP_ERROR("Bad message size\n");
		goto out_err;
	}

	/*
	 * Note: there is no HIP_SOCK_OPT_SET_PEER_EID because peer mappings
	 * are not socket specific; they are global and sent using the same
	 * interface that hipconf uses.
	 */
	switch(optname) {
	  /*
	   * XX TODO: setting my eid may be subject to some race conditions
	   *
	   */
	case HIP_SOCK_OPT_SET_MY_EID:
	  err = hip_socket_set_my_eid(msg, msg);
	  if (err) {
		  HIP_ERROR("Setting of my eid failed\n");
		  goto out_err;
	  }
	  break;
	default:
		HIP_ERROR("Unknown optname %d\n", optname);
		err = -ENOSYS;
	}
	
 out_err:
	/* Build an error message in case of an error. Errors caused a goto
	   here in the previous switch-case handler. */
	if (err) {
		hip_hdr_type_t msg_type = hip_get_msg_type(msg);
		hip_msg_init(msg);
		hip_build_user_hdr(msg, msg_type, err);
	}
	
	return err;
}

int hip_socket_sendmsg(struct kiocb *iocb, struct socket *sock, 
		       struct msghdr *m, size_t total_len)

{
	int err = 0;
	struct proto_ops *socket_handler;
	struct sock *sk = sock->sk;
	struct inet_opt *inet = inet_sk(sk);
	struct ipv6_pinfo *pinfo = inet6_sk(sk);

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	HIP_DEBUG("sport=%d dport=%d\n", ntohs(inet->sport), ntohs(inet->dport));

	HIP_HEXDUMP("daddr", &pinfo->daddr,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("rcv_saddr", &pinfo->rcv_saddr,
		    sizeof(struct in6_addr));

	err = socket_handler->sendmsg(iocb, sock, m, total_len);
	if (err) {
		/* The socket handler can return EIO or EINTR which are not
		   "real" errors. */
		HIP_DEBUG("Socket handler returned (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}

int hip_socket_recvmsg(struct kiocb *iocb, struct socket *sock, 
		       struct msghdr *m, size_t total_len,
		       int flags)
{
	int err = 0;
	struct sock *sk = sock->sk;
	struct inet_opt *inet = inet_sk(sk);
	struct ipv6_pinfo *pinfo = inet6_sk(sk);
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	HIP_DEBUG("sport=%d dport=%d\n", ntohs(inet->sport),
		  ntohs(inet->dport));

	HIP_HEXDUMP("daddr", &pinfo->daddr,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("rcv_saddr", &pinfo->rcv_saddr,
		    sizeof(struct in6_addr));

	err = socket_handler->recvmsg(iocb, sock, m, total_len, flags);
	if (err) {
		/* The socket handler can return EIO or EINTR which are not
		   "real" errors. */
		HIP_DEBUG("Socket socket handler returned (%d)\n", err);
		goto out_err;
	}

 out_err:
	
	return err;
}

int hip_socket_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct * vma)
{
	int err = 0;
	HIP_DEBUG("\n");
	err = -ENOSYS;
	return err;
}

ssize_t hip_socket_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags)
{
	int err = 0;
	HIP_DEBUG("\n");
	err = -ENOSYS;
	return err;
}
