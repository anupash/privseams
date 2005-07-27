/*
 * HIP socket handler - handle PF_HIP type sockets
 *
 * Licence: GNU/GPL
 * Authors:
 *          Miika Komu <miika@iki.fi>
 *          Anthony D. Joseph <adj@hiit.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 */

#include "bos.h"
#include "socket.h"


extern struct net_proto_family hip_family_ops;
extern struct proto_ops inet_stream_ops;
extern struct proto_ops inet_dgram_ops;
extern struct proto_ops inet6_stream_ops;
extern struct proto_ops inet6_dgram_ops;
extern int inet6_create(struct socket *sock, int protocol);

/* kernel module unit tests */
extern struct hip_unit_test_suite_list hip_unit_test_suite_list;

#ifndef __KERNEL__
extern int handle_bos_peer_list(int family, struct addrinfo **pai, int msg_len);
#endif

/*
 * Do not access these databases directly: use the accessors.
 */
HIP_INIT_DB(hip_local_eid_db, "local_eid");
HIP_INIT_DB(hip_peer_eid_db, "peer_eid");

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

	HIP_DEBUG("protocol=%d\n", protocol);

	// XX TODO: REPLACE WITH A SELECTOR
	err = inet6_create(sock, protocol);
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

	HIP_ASSERT(sock && sock->sk);

	HIP_DEBUG("sock_type=%d sk_proto=%d\n",
		  sock->sk->sk_type, sock->sk->sk_protocol);

	/* XX FIXME: How to handle IPPROTO_RAW? */
	/* XX FIXME: How to react on IPPROTO_HIP */

	switch (sock->sk->sk_protocol) {
	case IPPROTO_TCP:
	  *handler = &inet6_stream_ops;
	  break;
	case IPPROTO_UDP:
	  *handler = &inet6_dgram_ops;
	  break;
	default:
	  *handler = NULL;
	  err = -EPROTONOSUPPORT;
	  HIP_ERROR("Cannot select protocol handler for proto %d.",
		    sock->sk->sk_protocol);
	  break;
	}

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

	HIP_DEBUG("Querying for eid value %d\n", ntohs(eid->eid_val));

	err = hip_db_get_lhi_by_eid(eid, lhi, &owner_info, eid_is_local);
	if (err) {
		HIP_ERROR("Failed to map %s EID to HIT\n",
			  (eid_is_local ? "local" : "peer"));
		goto out_err;
	}

	/* XX FIXME: CHECK ACCESS RIGHTS FROM OWNER_INFO */

	/* Access control for EDs */
	if(eid_is_local) {
		HIP_DEBUG("current->uid:%d, current->gid:%d,current->pid:%d\n",
			  current->uid, current->gid, current->pid);
		HIP_DEBUG("ED->uid:%d, ED->gid:%d, ED->pid:%d\n",
			  owner_info.uid, owner_info.gid, owner_info.pid);
		HIP_DEBUG("flags:%d\n",owner_info.flags);
		if(owner_info.flags & HIP_HI_REUSE_ANY) {
			HIP_DEBUG("Access control check to ED, REUSE_ANY\n");
			goto out_err;	
			
		} else if((owner_info.flags & HIP_HI_REUSE_GID) && 
			  (current->gid == owner_info.gid)) {
			HIP_DEBUG("Access control check to ED, REUSE_GID\n");
			goto out_err;	
			
		} else if((owner_info.flags & HIP_HI_REUSE_UID) && 
			  (current->uid == owner_info.uid)) {
			HIP_DEBUG("Access control check to ED, REUSE_UID\n");
			goto out_err;
			
		} else if(current->pid == owner_info.pid) {
			HIP_DEBUG("Access control check to ED, PID ok\n");
			goto out_err;
			
		} else {
			err = -EACCES;
			HIP_INFO("Access denied to ED\n");
			goto out_err;
		}
	}
	
 out_err:

	return err;
}

int hip_socket_release(struct socket *sock)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	if (sock->sk == NULL)
		goto out_err;

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->release(sock);
	if (err) {
		HIP_ERROR("Socket handler failed (%d)\n", err);
		goto out_err;
	}

	/* XX FIX: RELEASE EID */
		
	if(sock->local_ed != 0) { 
		hip_db_dec_eid_use_cnt(sock->local_ed, 1);
		sock->local_ed = 0;
	}
	if(sock->peer_ed != 0) { 
		hip_db_dec_eid_use_cnt(sock->peer_ed, 0);
		sock->peer_ed = 0;
	}

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
	HIP_DEBUG_HIT("hip_socket_bind(): HIT", &lhi.hit);
	HIP_DEBUG("binding to eid with value %d\n",
		  ntohs(sockaddr_eid->eid_val));
	sock->local_ed = ntohs(sockaddr_eid->eid_val);
	HIP_DEBUG("socket.local_ed: %d, socket.peer_ed: %d\n",sock->local_ed,
		  sock->peer_ed);

	/* Clear out the flowinfo, etc from sockaddr_in6 */
	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));

	/* XX FIXME: select the IP address based on the mappings or interfaces
	   from db and do not use in6_addr_any. */

	/* Use in6_addr_any (= all zeroes) for bind. Offering a HIT to bind
	   does not work without modifications into the bind code because
	   bind_v6 returns an error when it does address type checks. */
	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));
	memcpy(&sockaddr_in6.sin6_addr, &lhi.hit, sizeof(struct in6_addr));
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

	HIP_DEBUG("connecting to eid with value %d\n",
		  ntohs(sockaddr_eid->eid_val));
	sock->peer_ed = ntohs(sockaddr_eid->eid_val);
	HIP_DEBUG("socket.local_ed: %d, socket.peer_ed: %d\n",sock->local_ed,
		  sock->peer_ed);

	memset(&sockaddr_in6, 0, sizeof(struct sockaddr_in6));
	sockaddr_in6.sin6_family = PF_INET6;
	memcpy(&sockaddr_in6.sin6_addr, &lhi.hit, sizeof(struct in6_addr));
	sockaddr_in6.sin6_port = sockaddr_eid->eid_port;

	/* Note: connect calls autobind if the application has not already
	   called bind manually. */

	/* XX CHECK: what about autobind src eid ? */

	/* XX CHECK: check does the autobind actually bind to an IPv6 address
	   or HIT? Or inaddr_any? Should we do the autobind manually here? */

	err = socket_handler->connect(sock, (struct sockaddr *) &sockaddr_in6,
				      sizeof(struct sockaddr_in6), flags);
	if (err) {
		HIP_ERROR("Socket handler failed (%d).\n", err);
		goto out_err;
	}

 out_err:

	return err;
}

/*
 * untested
 */
int hip_socket_socketpair(struct socket *sock1, struct socket *sock2)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock1, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->socketpair(sock1, sock2);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

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
	struct inet_sock *inet = inet_sk(sk);
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
	owner_info.pid = current->pid;
	owner_info.flags = 0;

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

/*
 * XX TODO: fall back to IPV6 POLL
 */
unsigned int hip_socket_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	int err = 0;
	int mask = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		mask = POLLERR;
		goto out_err;
	}

	mask = socket_handler->poll(file, sock, wait);

 out_err:

	return mask;
}

int hip_socket_ioctl(struct socket *sock, unsigned int cmd,
		     unsigned long arg)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->ioctl(sock, cmd, arg);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

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
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->shutdown(sock, flags);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}

int hip_socket_sendmsg(struct kiocb *iocb, struct socket *sock, 
		       struct msghdr *m, size_t total_len)

{
	int err = 0;
	struct proto_ops *socket_handler;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
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
	struct inet_sock *inet = inet_sk(sk);
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
		    struct vm_area_struct *vma)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->mmap(file, sock, vma);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}

ssize_t hip_socket_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags)
{
	int err = 0;
	struct proto_ops *socket_handler;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	err = socket_handler->sendpage(sock, page, offset, size, flags);
	if (err) {
		HIP_ERROR("Inet socket handler failed (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;
}

/**
 * hip_socket_handle_del_local_hi - handle deletion of a localhost host identity
 * @msg: the message containing the lhi to be deleted
 *
 * This function is currently unimplemented.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_socket_handle_del_local_hi(const struct hip_common *input)
{
	struct hip_work_order *hwo;
	int err = 0;

	HIP_DEBUG("Sending a delete HI msg to the userspace daemon\n");
	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("Failed to insert hi work order (%d)\n",
			  err);
		err = -EFAULT;
		goto out_err;
	}			   

	HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_MSG,
				HIP_WO_SUBTYPE_DELHI, NULL, NULL, NULL,
				0, 0, 0);
	/* override the destructor; socket handler deletes the msg
	   by itself */
	hwo->destructor = NULL;
	hwo->msg = (struct hip_common *) input;
	hip_insert_work_order(hwo);
	
 out_err:
	return err;
}

int hip_handle_peer_map_work_order(const struct in6_addr *hit,
				   const struct in6_addr *ip,
				   int insert, int rvs)
{
	int err = 0, subtype;
	struct hip_work_order *hwo;

	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("No memory for hit <-> ip mapping\n");
		err = -ENOMEM;
		goto out_err;
	}

	subtype = (rvs ? HIP_WO_SUBTYPE_ADDRVS : 
		   (insert ? HIP_WO_SUBTYPE_ADDMAP : HIP_WO_SUBTYPE_DELMAP));

	HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_MSG, subtype,
				ip, hit, NULL, 0, 0, 0);
	hip_insert_work_order(hwo);

 out_err:

	return err;
}

static int hip_add_peer_map(const struct hip_common *input, int rvs)
{
	struct in6_addr *hit, *ip;
	int err = 0;

	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out;
	}

	HIP_DEBUG_HIT("add map HIT", hit);
	HIP_DEBUG_IN6ADDR("add map IP", ip);
	
 	err = hip_handle_peer_map_work_order(hit, ip, 1, rvs);
 	if (err) {
 		HIP_ERROR("Failed to insert peer map work order (%d)\n", err);
	}

 out:

	return err;

}


/**
 * hip_socket_handle_rvs - Handle a case where we want our host to register
 * with rendezvous server.
 * Use this instead off "add map" functionality since we set the special
 * flag... (rvs)
 */
int hip_socket_handle_rvs(const struct hip_common *input)
{
	return hip_add_peer_map(input, 1);
}


/**
 * hip_socket_handle_add_peer_map_hit_ip - handle adding of a HIT-to-IPv6 mapping
 * @msg: the message containing the mapping to be added to kernel databases
 *
 * Add a HIT-to-IPv6 mapping of peer to the mapping database in the kernel
 * module.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_socket_handle_add_peer_map_hit_ip(const struct hip_common *input)
{
	HIP_DEBUG("\n");
	return hip_add_peer_map(input, 0);
}

/**
 * hipd_handle_async_del_map_hit_ip - handle deletion of a mapping
 * @msg: the message containing the mapping to be deleted
 *
 * Currently this function is unimplemented.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_socket_handle_del_peer_map_hit_ip(const struct hip_common *input)
{
	struct in6_addr *hit, *ip;
	int err = 0;

	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out;
	}

	HIP_DEBUG_HIT("hit", hit);
	HIP_DEBUG_IN6ADDR("ip", ip);

 	err = hip_handle_peer_map_work_order(hit, ip, 0, 0);
 	if (err) {
 		HIP_ERROR("Failed to insert peer map work order (%d)\n", err);
	}

 out:

	return err;
}


int hip_socket_handle_rst(const struct hip_common *input)
{
	return -ENOSYS;
}

int hip_socket_bos_wo(const struct hip_common *input)
{
	struct hip_work_order *hwo;
	int err = 0;
	
	HIP_DEBUG("Sending new HI to userspace daemon\n");
	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("Failed to insert hi work order (%d)\n",
			  err);
		err = -EFAULT;
		goto out_err;
	}			   
	
	HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_MSG,
				HIP_WO_SUBTYPE_SEND_BOS, NULL, NULL, NULL,
				0, 0, 0);
	/* override the destructor; socket handler deletes the msg
	   by itself */
	hwo->destructor = NULL;
	hwo->msg = (struct hip_common *) input;
	hip_insert_work_order(hwo);

 out_err:
	return err;
}


/**
 * hipd_handle_async_unit_test - handle unit test message
 * @msg: message containing information about which unit tests to execute
 *
 * Execute unit tests in the kernelspace and return the number of unit tests
 * failed.
 *
 * Returns: the number of unit tests failed
 */
int hip_socket_handle_unit_test(const struct hip_common *msg)
{
	int err = 0;
#if 0 /* XX TODO */
	uint16_t failed_test_cases;
	uint16_t suiteid, caseid;
	struct hip_unit_test *test = NULL;
	char err_log[HIP_UNIT_ERR_LOG_MSG_MAX_LEN] = "";

	test = (struct hip_unit_test *)
		hip_get_param(msg, HIP_PARAM_UNIT_TEST);
	if (!test) {
		HIP_ERROR("No unit test parameter found\n");
		err = -ENOMSG;
		goto out;
	}

	suiteid = hip_get_unit_test_suite_param_id(test);
	caseid = hip_get_unit_test_case_param_id(test);

	HIP_DEBUG("Executing suiteid=%d, caseid=%d\n", suiteid, caseid);

	failed_test_cases = hip_run_unit_test_case(&hip_unit_test_suite_list,
						   suiteid, caseid,
						   err_log, sizeof(err_log));
	if (failed_test_cases)
		HIP_ERROR("\n===Unit Test Summary===\nTotal %d errors:\n%s\n",
			  failed_test_cases, err_log);
	else
		HIP_INFO("\n===Unit Test Summary===\nAll tests passed, no errors!\n");

 out:
	hip_msg_init(msg); /* reuse the same input msg for results */
	hip_build_user_hdr(msg, SO_HIP_RUN_UNIT_TEST, failed_test_cases);
	hip_build_unit_test_log();
#endif

	return err;
}

#if defined(CONFIG_HIP_USERSPACE) && defined(__KERNEL__)
int hip_wrap_handle_add_local_hi(const struct hip_common *input)
{
	struct hip_work_order *hwo;
	int err = 0;
	
	HIP_DEBUG("Sending new HI to userspace daemon\n");
	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("Failed to insert hi work order (%d)\n",
			  err);
		err = -EFAULT;
		goto out_err;
	}			   
	
	HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_MSG,
				HIP_WO_SUBTYPE_ADDHI, NULL, NULL, NULL,
				0, 0, 0);
	/* override the destructor; socket handler deletes the msg
	   by itself */
	hwo->destructor = NULL;
	hwo->msg = (struct hip_common *) input;
	hip_insert_work_order(hwo);

 out_err:
	return err;
}
#endif /* CONFIG_HIP_USERSPACE && __KERNEL__ */

/*
 * This function is similar to hip_socket_handle_add_local_hi but there are
 * three major differences:
 * - this function is used by native HIP sockets (not hipconf)
 * - HIP sockets require EID handling which is done here
 * - this function DOES NOT call hip_precreate_r1, so you need launch
 */
int hip_socket_handle_set_my_eid(struct hip_common *msg)
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
	if (hip_get_msg_type(msg) != SO_HIP_SET_MY_EID) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	eid_endpoint = hip_get_param(msg, HIP_PARAM_EID_ENDPOINT);
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
	owner_info.pid = current->pid;
	owner_info.flags = eid_endpoint->endpoint.flags;
	
	lhi.anonymous =
		(eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ?
		1 : 0;

	if (hip_host_id_contains_private_key(host_id)) {
		err = hip_private_host_id_to_hit(host_id, &lhi.hit,
						 HIP_HIT_TYPE_HASH120);
		if (err) {
			HIP_ERROR("Failed to calculate HIT from HI.");
			goto out_err;
		}


		/* XX FIXME: figure out socket handler - user daemon 
		   interaction */
		/* XX TODO: check UID/GID permissions before adding */
		err = hip_wrap_handle_add_local_hi(msg); 
		if (err == -EEXIST) {
			HIP_INFO("Host id exists already, ignoring\n");
			err = 0;
		} else if (err) {
			HIP_ERROR("Adding of localhost id failed");
			goto out_err;
		}
		
	} else {
		/* Only public key */
		err = hip_host_id_to_hit(host_id,
					 &lhi.hit, HIP_HIT_TYPE_HASH120);
	}
	
	HIP_DEBUG_HIT("calculated HIT", &lhi.hit);
	
	/* Iterate through the interfaces */
	while((param = hip_get_next_param(msg, param)) != NULL) {
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

	HIP_DEBUG("EID value was set to %d\n", ntohs(eid.eid_val));

	/* Clear the msg and reuse it for the result */
	
	hip_msg_init(msg);
	hip_build_user_hdr(msg, SO_HIP_SET_MY_EID, err);
	err = hip_build_param_eid_sockaddr(msg, (struct sockaddr *) &eid,
					   sizeof(struct sockaddr_eid));
	if (err) {
		HIP_ERROR("Could not build eid sockaddr\n");
		goto out_err;
	}
	
 out_err:
	return err;
}


int hip_socket_handle_set_peer_eid(struct hip_common *msg)
{
	int err = 0;
	struct sockaddr_eid eid;
	struct hip_tlv_common *param = NULL;
	struct hip_eid_endpoint *eid_endpoint;
	struct hip_lhi lhi;
	struct hip_eid_owner_info owner_info;

	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(msg) != SO_HIP_SET_PEER_EID) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	eid_endpoint = hip_get_param(msg, HIP_PARAM_EID_ENDPOINT);
	if (!eid_endpoint) {
		err = -ENOENT;
		HIP_ERROR("Could not find eid endpoint\n");
		goto out_err;
	}
	
	if (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_HIT) {
		memcpy(&lhi.hit, &eid_endpoint->endpoint.id.hit,
		       sizeof(struct in6_addr));
		HIP_DEBUG_HIT("Peer HIT: ", &lhi.hit);
	} else {
		HIP_DEBUG("host_id len %d\n",
			 ntohs((eid_endpoint->endpoint.id.host_id.hi_length)));
		err = hip_host_id_to_hit(&eid_endpoint->endpoint.id.host_id,
					 &lhi.hit, HIP_HIT_TYPE_HASH120);
		if (err) {
			HIP_ERROR("Failed to calculate HIT from HI.");
			goto out_err;
		}
	}

	lhi.anonymous =
	       (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ? 1 : 0;

	/* Fill eid owner information in and assign a peer EID */

	owner_info.uid = current->uid;
	owner_info.gid = current->gid;
	
	/* The eid port information will be filled by the resolver. It is not
	   really meaningful in the eid db. */
	eid.eid_port = htons(0);

	err = hip_db_set_peer_eid(&eid, &lhi, &owner_info);
	if (err) {
		HIP_ERROR("Could not set my eid into the db\n");
		goto out_err;
	}
	
	/* Iterate through the addresses */

	while((param = hip_get_next_param(msg, param)) != NULL) {
		struct sockaddr_in6 *sockaddr;

		HIP_DEBUG("Param type=%d\n", hip_get_param_type(param));

		/* Skip other parameters (only the endpoint should
		   really be there). */
		if (hip_get_param_type(param) != HIP_PARAM_EID_SOCKADDR)
			continue;

		HIP_DEBUG("EID sockaddr found in the msg\n");

		sockaddr =
		  (struct sockaddr_in6 *) hip_get_param_contents_direct(param);
		if (sockaddr->sin6_family != AF_INET6) {
			HIP_INFO("sa_family %d not supported, ignoring\n",
				 sockaddr->sin6_family);
			continue;
		}

		HIP_DEBUG_IN6ADDR("Peer IPv6 address", &sockaddr->sin6_addr);

		/* XX FIX: the mapping should be tagged with an uid */

		err = hip_handle_peer_map_work_order(&lhi.hit,
						     &sockaddr->sin6_addr,1,0);
		if (err) {
			HIP_ERROR("Failed to insert map work order (%d)\n",
				  err);
			goto out_err;
		}
	}

	/* Finished. Write a return message with the EID (reuse the msg for
	   result). */

	hip_msg_init(msg);
	hip_build_user_hdr(msg, SO_HIP_SET_PEER_EID, -err);
	err = hip_build_param_eid_sockaddr(msg,
					   (struct sockaddr *) &eid,
					   sizeof(eid));
	if (err) {
		HIP_ERROR("Could not build eid sockaddr\n");
		goto out_err;
	}

 out_err:
	/* XX FIXME: if there were errors, remove eid and hit-ip mappings
	   if necessary */

	return err;
}

#if 0
/**
 * hip_socket_handle_get_peer_list - handle creation of list of known peers
 * @msg: message containing information about which unit tests to execute
 *
 * Process a request for the list of known peers
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_socket_handle_get_peer_list(struct hip_common *msg)
{
	int err = 0;
	hip_peer_opaque_t pr;
	int fail;
	int i, j;
	struct hip_host_id *peer_host_id = NULL;
	struct hip_lhi lhi;
	char buf[46];
        hip_peer_entry_opaque_t *entry, *next;
	hip_peer_addr_opaque_t *addr, *anext;
	
	HIP_DEBUG("\n");

	/* Initialize the data structure for the peer list */
	memset(&pr, 0, sizeof(hip_peer_opaque_t));
	
	/* Extra consistency test */
	if (hip_get_msg_type(msg) != SO_HIP_GET_PEER_LIST) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}

	/* Iterate through the hadb db entries, collecting addresses */
	fail = hip_for_each_ha(hip_hadb_list_peers_func, &pr);
	if (fail) {
		err = -EINVAL;
		HIP_ERROR("Peer list creation failed\n");
		goto out_err;
	}

	HIP_DEBUG("pr.count=%d headp=0x%p end=0x%p\n", pr.count, pr.head, pr.end);
	if (pr.count <= 0) {
		HIP_ERROR("No usable entries found\n");
		err = -EINVAL;
		goto out_err;
	}
	/* Complete the list by iterating through the list and
	   recording the peer host id. This is done separately from
	   list creation because it involves calling a function that
	   may sleep (can't be done while holding locks!) */
	memset(&lhi, 0, sizeof(struct hip_lhi)); /* Zero flags, etc. */
	for (i = 0, entry = pr.head; i < pr.count; i++, entry = entry->next) {
	        /* Get the HIT */
	        memcpy(&(lhi.hit),&(entry->hit),sizeof(struct in6_addr));

		/* Look up HOST ID */
		peer_host_id = hip_get_host_id(HIP_DB_PEER_HID, &lhi, HIP_ANY_ALGO);
		if (peer_host_id == NULL) {
	                hip_in6_ntop(&(lhi.hit), buf);
			HIP_DEBUG("Peer host id for hit (%s) not found!\n",
				  buf);
			err = -EINVAL;
			goto out_err;
		}
		HIP_DEBUG("## Hostname for HOST ID is: %s\n", 
			  hip_get_param_host_id_hostname(peer_host_id));

		/* Save the HOST ID */
	        entry->host_id = peer_host_id;
	}

	/* Finished. Write a return message with the peer list (reuse the
	   msg for result).
	   Format is:
	   <unsigned integer> - Number of entries
	   [<host id> - Host identifier
	    <hit> - HIT
	    <unsigned integer> - Number of addresses
	    [<ipv6 address> - IPv6 address
	     ...]
	   ...]
	*/

	hip_msg_init(msg);
	hip_build_user_hdr(msg, SO_HIP_GET_PEER_LIST, -err);

	/********** PEER LIST COUNT *********/

	err = hip_build_param_contents(msg, &(pr.count), HIP_PARAM_UINT,
				       sizeof(unsigned int));
	if (err) {
		HIP_ERROR("Could not build peer list count\n");
		err = -EINVAL;
		goto out_err;
	}

	for (i = 0, entry = pr.head; i < pr.count; i++, entry = entry->next) {
	        /********** HOST_ID *********/

	        HIP_DEBUG("The HOST ID is: %s\n", 
			  hip_get_param_host_id_hostname(entry->host_id));
	        err = hip_build_param(msg, entry->host_id);
 	        if (err) {
 		        HIP_ERROR("Building of host id failed\n");
			err = -EINVAL;
 		        goto out_err;
 	        }

	        /********** HIT *********/

		err = hip_build_param_contents(msg, &entry->hit,
					       HIP_PARAM_HIT,
					       sizeof(struct in6_addr));
 	        if (err) {
 		        HIP_ERROR("Building of hit failed\n");
			err = -EINVAL;
 		        goto out_err;
 	        }

		/********** IP ADDR LIST COUNT *********/

		err = hip_build_param_contents(msg, &entry->count, 
					       HIP_PARAM_UINT,
					       sizeof(unsigned int));
		if (err) {
		        HIP_ERROR("Could not build peer addr list count\n");
			err = -EINVAL;
			goto out_err;
		}

		addr = entry->addr_list;
		for (j = 0; j < entry->count; j++, addr = addr->next) {
		        /********** IP ADDR *********/

		        err=hip_build_param_contents(msg, &addr->addr,
						     HIP_PARAM_IPV6_ADDR, 
						     sizeof(struct in6_addr));
			if (err) {
 		                HIP_ERROR("Building of IP address failed\n");
				err = -EINVAL;
				goto out_err;
			}
		}
	}

 out_err:
	/* Recurse through structure, freeing memory */
	entry = pr.head;
	_HIP_DEBUG("free mem, pr.head=0x%p\n", pr.head);
	while (entry) {
		_HIP_DEBUG("entry=0x%p\n", entry);
		next = entry->next;
		_HIP_DEBUG("next=0x%p\n", next);
		_HIP_DEBUG("entry->host_id=0x%p\n", entry->host_id);
		if (entry->host_id)
			HIP_FREE(entry->host_id);
		addr = entry->addr_list;
		_HIP_DEBUG("addrlist=0x%p\n", addr);
		while (addr) {
			_HIP_DEBUG("addr=0x%p\n", addr);
			anext = addr->next;
			HIP_FREE(addr);
			addr = anext;
		}
		HIP_FREE(entry);
		entry = next;
	}
	_HIP_DEBUG("done freeing mem, err = %d\n", err);
	return err;
}
#endif

/*
 * The socket options that do not need a return value.
 */
int hip_socket_setsockopt(struct socket *sock, int level, int optname,
			  char *optval, int optlen)
{
	int err = 0;
	struct proto_ops *socket_handler;
	struct hip_common *msg = (struct hip_common *) optval;
	int msg_type;

	HIP_DEBUG("\n");

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	/* The message was destined to TCP or IP - forward */
	if (level != IPPROTO_HIP) {
		err = socket_handler->setsockopt(sock, level, optname, optval,
						 optlen);
		goto out_err;
	}

	if (!(optname == SO_HIP_GLOBAL_OPT || optname == SO_HIP_SOCKET_OPT)) {
		err = -ESOCKTNOSUPPORT;
		HIP_ERROR("optname (%d) was incorrect\n", optname);
		goto out_err;
	}

	err = hip_check_userspace_msg(msg);
	if (err) {
		HIP_ERROR("HIP socket option was invalid\n");
		goto out_err;
	}

	msg_type = hip_get_msg_type(msg);
	switch(msg_type) {
	case SO_HIP_ADD_LOCAL_HI:
		err = hip_wrap_handle_add_local_hi(msg);
		break;
	case SO_HIP_DEL_LOCAL_HI:
		err = hip_socket_handle_del_local_hi(msg);
		break;
	case SO_HIP_ADD_PEER_MAP_HIT_IP:
		err = hip_socket_handle_add_peer_map_hit_ip(msg);
		break;
	case SO_HIP_DEL_PEER_MAP_HIT_IP:
		err = hip_socket_handle_del_peer_map_hit_ip(msg);
		break;
	case SO_HIP_RST:
		err = hip_socket_handle_rst(msg);
		break;
	case SO_HIP_ADD_RVS:
		err = hip_socket_handle_rvs(msg);
		break;
// XX TODO: not supported for now, this message should be moved as
// such to the userspace anyway i.e. create WORKORDER:
// HIP_WO_SUBTYPE_SEND_BOS:
	case SO_HIP_BOS:
		err = hip_socket_bos_wo(msg);
		//err = hip_socket_send_bos(msg);
		break;
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:

	return err;
}

/*
 * The socket options that need a return value.
 */
int hip_socket_getsockopt(struct socket *sock, int level, int optname,
			  char *optval, int *optlen)
{
	int err = 0;
	struct proto_ops *socket_handler;
	struct hip_common *msg = (struct hip_common *) optval;

	if (optname == SO_HIP_GET_HIT_LIST) {
		/* In this case the level corresponds to the port number */
		struct my_addrinfo **pai = (struct my_addrinfo **)optval;
		HIP_DEBUG("Got it\n");
		return (handle_bos_peer_list(AF_INET6, level, pai, *optlen));
	}


	HIP_DEBUG("%d\n", level);

	err = hip_select_socket_handler(sock, &socket_handler);
	if (err) {
		goto out_err;
	}

	/* The message was destined to TCP or IP - forward */
	if (level != IPPROTO_HIP) {
		err = socket_handler->getsockopt(sock, level, optname, optval,
						 optlen);
		goto out_err;
	}

	if (!(optname == SO_HIP_GLOBAL_OPT || optname == SO_HIP_SOCKET_OPT)) {
		err = -ESOCKTNOSUPPORT;
		goto out_err;
	}

	err = hip_check_userspace_msg(msg);
	if (err) {
		HIP_ERROR("HIP socket option was malformed\n");
		goto out_err;
	}

	if (hip_get_msg_total_len(msg) != *optlen) {
		HIP_ERROR("HIP socket option length was incorrect\n");
		err = -EMSGSIZE;
		goto out_err;		
	}

	/* XX FIX: we make the assumtion here that the socket option return
	   value has enough space... */

	switch(hip_get_msg_type(msg)) {
	case SO_HIP_RUN_UNIT_TEST:
		err = hip_socket_handle_unit_test(msg);
		break;
	case SO_HIP_SET_MY_EID:
		err = hip_socket_handle_set_my_eid(msg);
		break;
	case SO_HIP_SET_PEER_EID:
		err = hip_socket_handle_set_peer_eid(msg);
		break;
#if 0  // XX TODO, not supported
	case SO_HIP_GET_PEER_LIST:
		err = hip_socket_handle_get_peer_list(msg);
		break;
#endif
	default:
		err = -ESOCKTNOSUPPORT;
	}


 out_err:

	return err;
}

/**
 * hip_uninit_eid_db - uninitialize local/peer eid db
 * @db: Database structure to delete. 
 *
 * All elements of the @db are deleted.
 */
void hip_uninit_eid_db(struct hip_db_struct *db)
{
	struct list_head *curr, *iter;
	struct hip_host_id_entry *tmp;
	unsigned long lf;

	HIP_WRITE_LOCK_DB(db);

	list_for_each_safe(curr,iter,&db->db_head) {
		tmp = list_entry(curr, struct hip_host_id_entry, next);
		HIP_FREE(tmp);
	}

	HIP_WRITE_UNLOCK_DB(db);
}

void hip_uninit_all_eid_db(void)
{
	hip_uninit_eid_db(&hip_peer_eid_db);
	hip_uninit_eid_db(&hip_local_eid_db);
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_hit_no_lock(struct hip_db_struct *db,
						     const struct hip_lhi *lhi)
{
	struct hip_eid_db_entry *entry;

	HIP_DEBUG("\n");

	list_for_each_entry(entry, &db->db_head, next) {
		/* XX TODO: Skip the anonymous bit. Is it ok? */
		if (!ipv6_addr_cmp(&entry->lhi.hit,
				   (struct in6_addr *) &lhi->hit))
			return entry;
	}

	return NULL;
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_eid_no_lock(struct hip_db_struct *db,
						const struct sockaddr_eid *eid)
{
	struct hip_eid_db_entry *entry;

	list_for_each_entry(entry, &db->db_head, next) {
		HIP_DEBUG("comparing %d with %d\n",
			  ntohs(entry->eid.eid_val), ntohs(eid->eid_val));
		if (entry->eid.eid_val == eid->eid_val)
			    return entry;
	}

	return NULL;
}

/*
 * Decreases the use_cnt entry in the hip_eid_db_entry struct and deletes
 * the entry for the given eid_val if use_cnt drops below one.
 */
void hip_db_dec_eid_use_cnt_by_eid_val(struct hip_db_struct *db, 
					sa_eid_t eid_val) 
{	

	struct hip_eid_db_entry *tmp;
	struct list_head *curr, *iter;
	unsigned long lf;

	HIP_WRITE_LOCK_DB(db);
	
	list_for_each_safe(curr, iter, &db->db_head){
		tmp = list_entry(curr ,struct hip_eid_db_entry, next);
		HIP_DEBUG("comparing %d with %d\n",
			  ntohs(tmp->eid.eid_val), eid_val);
		if (ntohs(tmp->eid.eid_val) == eid_val) {
			tmp->use_cnt--;
			if(tmp->use_cnt < 1) {
				kfree(tmp);
				list_del(curr);
			}
			HIP_WRITE_UNLOCK_DB(db);
			return;
		}
	}
	HIP_WRITE_UNLOCK_DB(db);
}

void hip_db_dec_eid_use_cnt(sa_eid_t eid_val, int is_local) 
{
	struct hip_db_struct *db;
	
	if(eid_val == 0) return;
	
	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;
	hip_db_dec_eid_use_cnt_by_eid_val(db, eid_val);
}

int hip_db_set_eid(struct sockaddr_eid *eid,
		   const struct hip_lhi *lhi,
		   const struct hip_eid_owner_info *owner_info,
		   int is_local)
{
	struct hip_db_struct *db;
	int err = 0;
	unsigned long lf;
	struct hip_eid_db_entry *entry = NULL;

	HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

	HIP_WRITE_LOCK_DB(db);

	entry = hip_db_find_eid_entry_by_hit_no_lock(db, lhi);
	if (!entry) {
		entry = HIP_MALLOC(sizeof(struct hip_eid_db_entry),
				   GFP_KERNEL);
		if (!entry) {
			err = -ENOMEM;
			goto out_err;
		}

		entry->eid.eid_val = ((is_local) ?
			htons(hip_create_unique_local_eid()) :
			htons(hip_create_unique_peer_eid()));
		entry->eid.eid_family = PF_HIP;
		memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));

		HIP_DEBUG("Generated eid val %d\n", entry->eid.eid_val);

		memcpy(&entry->lhi, lhi, sizeof(struct hip_lhi));
		memcpy(&entry->owner_info, owner_info,
		       sizeof(struct hip_eid_owner_info));

		/* Finished. Add the entry to the list. */
		list_add(&entry->next, &db->db_head);
	} else {
		/* XX TODO: Ownership is not changed here; should it? */
		memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));
	}

 out_err:
	HIP_WRITE_UNLOCK_DB(db);

	return err;
}

int hip_db_set_my_eid(struct sockaddr_eid *eid,
		      const struct hip_lhi *lhi,
		      const struct hip_eid_owner_info *owner_info)
{
	return hip_db_set_eid(eid, lhi, owner_info, 1);
}

int hip_db_set_peer_eid(struct sockaddr_eid *eid,
			const struct hip_lhi *lhi,
			const struct hip_eid_owner_info *owner_info)
{
	return hip_db_set_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info,
			  int is_local)
{
	struct hip_db_struct *db;
	int err = 0;
	unsigned long lf;
	struct hip_eid_db_entry *entry = NULL;

	HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

	HIP_READ_LOCK_DB(db);

	entry = hip_db_find_eid_entry_by_eid_no_lock(db, eid);
	if (!entry) {
		err = -ENOENT;
		goto out_err;
	}

	memcpy(lhi, &entry->lhi, sizeof(struct hip_lhi));
	memcpy(owner_info, &entry->owner_info,
	       sizeof(struct hip_eid_owner_info));

 out_err:
	HIP_READ_UNLOCK_DB(db);

	return err;

}

int hip_db_get_peer_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info)
{
	return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_my_lhi_by_eid(const struct sockaddr_eid *eid,
			     struct hip_lhi *lhi,
			     struct hip_eid_owner_info *owner_info)
{
	return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 1);
}

#undef HIP_READ_LOCK_DB
#undef HIP_WRITE_LOCK_DB
#undef HIP_READ_UNLOCK_DB
#undef HIP_WRITE_UNLOCK_DB

