/*
 * HIP socket handler - handle PF_HIP type sockets
 *
 * Licence: GNU/GPL
 * Authors:
 *          Miika Komu <miika@iki.fi>
 *          Anthony D. Joseph <adj@hiit.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 */

#include "socket.h"
#include "debug.h"
#include "db.h"
#include "builder.h"
#include "misc.h"
#include "workqueue.h"
#include "misc.h"
#include "cookie.h"
#include "unit.h"
#include "input.h"
#include "output.h"
#include "debug.h"

#include <linux/net.h>
#include <net/addrconf.h>

extern struct net_proto_family hip_family_ops;
extern struct proto_ops inet_stream_ops;
extern struct proto_ops inet_dgram_ops;
extern struct proto_ops inet6_stream_ops;
extern struct proto_ops inet6_dgram_ops;
extern int inet6_create(struct socket *sock, int protocol);

/* kernel module unit tests */
extern struct hip_unit_test_suite_list hip_unit_test_suite_list;

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

typedef struct hip_peer_addr_opaque {
        struct in6_addr addr;
        struct hip_peer_addr_opaque *next;
} hip_peer_addr_opaque_t;         /* Structure to record peer addresses */

typedef struct hip_peer_entry_opaque {
	unsigned int count;
        struct hip_host_id *host_id;
	hip_hit_t hit;
        hip_peer_addr_opaque_t *addr_list;
        struct hip_peer_entry_opaque *next;
} hip_peer_entry_opaque_t;         /* Structure to record kernel peer entry */

typedef struct hip_peer_opaque {
	unsigned int count;
        struct hip_peer_entry_opaque *head;
        struct hip_peer_entry_opaque *end;
} hip_peer_opaque_t;         /* Structure to record kernel peer list */


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

/*
 * note this function is called by two other functions below.
 */
int hip_socket_add_local_hi(const struct hip_host_id *host_identity,
			  const struct hip_lhi *lhi)
{
	int err = 0;

	err = hip_add_localhost_id(lhi, host_identity);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	/* If adding localhost id failed because there was a duplicate, we
	   won't precreate anything (and void causing dagling memory
	   pointers) */
#if 0	
	HIP_DEBUG("hip: Generating a new R1 now\n");

       	if (!hip_precreate_r1(&lhi->hit)) {
		HIP_ERROR("Unable to precreate R1s... failing\n");
		err = -ENOENT;
		goto out_err;
	}
#endif

 out_err:
	return err;
}

/**
 * hip_socket_handle_local_add_hi - handle adding of a localhost host identity
 * @input: contains the hi parameter in fqdn format (includes private key)
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_socket_handle_add_local_hi(const struct hip_common *input)
{
	int err = 0;
	struct hip_host_id *dsa_host_identity, *rsa_host_identity = NULL;
	struct hip_lhi dsa_lhi, rsa_lhi;
	struct in6_addr hit_our;
	
	HIP_DEBUG("\n");

	if ((err = hip_get_msg_err(input)) != 0) {
		HIP_ERROR("daemon failed (%d)\n", err);
		goto out_err;
	}

	_HIP_DUMP_MSG(response);

	dsa_host_identity = hip_get_nth_param(input, HIP_PARAM_HOST_ID, 1);
        if (!dsa_host_identity) {
		HIP_ERROR("no dsa host identity pubkey in response\n");
		err = -ENOENT;
		goto out_err;
	}

	rsa_host_identity = hip_get_nth_param(input, HIP_PARAM_HOST_ID, 2);
        if (!rsa_host_identity) {
		HIP_ERROR("no rsa host identity pubkey in response\n");
		err = -ENOENT;
		goto out_err;
	}

	_HIP_HEXDUMP("rsa host id\n", rsa_host_identity,
		    hip_get_param_total_len(rsa_host_identity));

	err = hip_private_host_id_to_hit(dsa_host_identity, &dsa_lhi.hit,
					 HIP_HIT_TYPE_HASH126);
	if (err) {
		HIP_ERROR("dsa host id to hit conversion failed\n");
		goto out_err;
	}

	err = hip_private_host_id_to_hit(rsa_host_identity, &rsa_lhi.hit,
					 HIP_HIT_TYPE_HASH126);
	if (err) {
		HIP_ERROR("rsa host id to hit conversion failed\n");
		goto out_err;
	}

	/* XX FIX: Note: currently the order of insertion of host ids makes a
	   difference. */

	err = hip_socket_add_local_hi(rsa_host_identity, &rsa_lhi);
	if (err) {
		HIP_ERROR("Failed to add HIP localhost identity\n");
		goto out_err;
	}

	err = hip_socket_add_local_hi(dsa_host_identity, &dsa_lhi);
	if (err) {
		HIP_ERROR("Failed to add HIP localhost identity\n");
		goto out_err;
	}

	HIP_DEBUG("Adding of HIP localhost identity was successful\n");

	HIP_DEBUG("hip: Generating a new R1 now\n");
	
        /* XX TODO: precreate R1s for both algorithms, not just the default */ 
	if (hip_copy_any_localhost_hit_by_algo(&hit_our, HIP_HI_DEFAULT_ALGO) < 0) {
		HIP_ERROR("Didn't find HIT for R1 precreation\n");
		err = -EINVAL;
		goto out_err;
	}
       	if (!hip_precreate_r1(&hit_our)) {
		HIP_ERROR("Unable to precreate R1s... failing\n");
		err = -ENOENT;
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
	int err = 0;

	HIP_ERROR("Not implemented\n");
	err = -ENOSYS;

        return err;
}

int hip_insert_peer_map_work_order(const struct in6_addr *hit,
					  const struct in6_addr *ip,
					  int insert, int rvs)
{
	int err = 0;
	struct hip_work_order *hwo;
	struct in6_addr *ip_copy;

	hwo = hip_create_job_with_hit(GFP_ATOMIC, hit);
	if (!hwo) {
		HIP_ERROR("No memory for hit <-> ip mapping\n");
		err = -ENOMEM;
		goto out_err;
	}
	
	ip_copy = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
	if (!ip_copy) {
		HIP_ERROR("No memory to copy IP to work order\n");
		err = -ENOMEM;
		goto out_err;
	}
	
	ipv6_addr_copy(ip_copy,ip);
	hwo->arg2 = ip_copy;
	hwo->type = HIP_WO_TYPE_MSG;
	if (rvs)
		hwo->subtype = HIP_WO_SUBTYPE_ADDRVS;
	else {
		if (insert)
			hwo->subtype = HIP_WO_SUBTYPE_ADDMAP;
		else
			hwo->subtype = HIP_WO_SUBTYPE_DELMAP;
	}

	hip_insert_work_order(hwo);

 out_err:

	return err;
}

static int hip_do_work(const struct hip_common *input, int rvs)
{
	struct in6_addr *hit, *ip;
	char buf[46];
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

	hip_in6_ntop(hit, buf);
	HIP_DEBUG("map HIT: %s\n", buf);
	hip_in6_ntop(ip, buf);
	HIP_DEBUG("map IP: %s\n", buf);
	
 	err = hip_insert_peer_map_work_order(hit, ip, 1, rvs);
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
	return hip_do_work(input, 1);
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
	return hip_do_work(input, 0);
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
	char buf[46];
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

	hip_in6_ntop(hit, buf);
	HIP_INFO("map HIT: %s\n", buf);
	hip_in6_ntop(ip, buf);
	HIP_INFO("map IP: %s\n", buf);
	
 	err = hip_insert_peer_map_work_order(hit, ip, 0, 0);
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

/* This is the maximum number of source addresses for sending BOS packets */
#define MAX_SRC_ADDRS 128

/**
 * hip_socket_send_bos - send a BOS packet
 * @msg: input message (should be empty)
 *
 * Generate a signed HIP BOS packet containing our HIT, and send
 * the packet out each network device interface. Note that there
 * is a limit of MAX_SRC_ADDRS (128) total addresses.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_socket_send_bos(const struct hip_common *msg)
{
	int err = 0;
	struct hip_common *bos = NULL;
	struct in6_addr hit_our;
	struct in6_addr daddr;
 	int i, mask;
 	struct hip_host_id  *host_id_pub = NULL;
	struct hip_host_id *host_id_private = NULL;
	u8 signature[HIP_DSA_SIGNATURE_LEN];
	struct net_device *saddr_dev;
	struct inet6_dev *idev;
	struct in6_addr saddr[MAX_SRC_ADDRS];
	int if_idx[MAX_SRC_ADDRS];
	int addr_count = 0;
	struct flowi fl;
	struct inet6_ifaddr *ifa = NULL;

	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(msg) != SO_HIP_BOS) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	/* allocate space for new BOS */
	bos = hip_msg_alloc();
	if (!bos) {
		HIP_ERROR("Allocation of BOS failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* Determine our HIT */
	if (hip_copy_any_localhost_hit(&hit_our) < 0) {
		HIP_ERROR("Our HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Determine our HOST ID public key */
	host_id_pub = hip_get_any_localhost_public_key(0);
	if (!host_id_pub) {
		HIP_ERROR("Could not acquire localhost public key\n");
		goto out_err;
	}

	/* Determine our HOST ID private key */
	host_id_private = hip_get_any_localhost_host_id(0);
	if (!host_id_private) {
		err = -EINVAL;
		HIP_ERROR("No localhost private key found\n");
		goto out_err;
	}

 	/* Ready to begin building the BOS packet */
	/*
	    IP ( HIP ( HOST_ID,
              HIP_SIGNATURE ) )
	 */
	mask = HIP_CONTROL_NONE;

 	hip_build_network_hdr(bos, HIP_BOS, mask, &hit_our, NULL);

	/********** HOST_ID *********/

	_HIP_DEBUG("This HOST ID belongs to: %s\n",
		   hip_get_param_host_id_hostname(host_id_pub));
	err = hip_build_param(bos, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of host id failed\n");
 		goto out_err;
 	}

 	/********** SIGNATURE **********/

	HIP_ASSERT(host_id_private);

	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */

	if (!hip_create_signature(bos, hip_get_msg_total_len(bos), 
				  host_id_private, signature)) {
		HIP_ERROR("Could not create signature\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Only DSA supported currently */
	HIP_ASSERT(hip_get_host_id_algo(host_id_private) == HIP_HI_DSA);

	err = hip_build_param_signature_contents(bos,
					signature,
					HIP_DSA_SIGNATURE_LEN,
					HIP_SIG_DSA);
	if (err) {
		HIP_ERROR("Building of signature failed (%d)\n", err);
		goto out_err;
	}

 	/************** BOS packet ready ***************/
	HIP_DEBUG("sending BOS\n");
	/* Use All Nodes Addresses (link-local) RFC2373
 	   FF02:0:0:0:0:0:0:1 as the destination multicast address */
 	ipv6_addr_all_nodes(&daddr);

	/* Iterate through all the network devices, recording source
	 * addresses for BOS packets */

	/* First lock the devices list */
	read_lock(&dev_base_lock);
        read_lock(&addrconf_lock);

	/* Now, iterate through the list */
        for (saddr_dev = dev_base; saddr_dev; saddr_dev = saddr_dev->next) {
		HIP_DEBUG("Found network interface %d: %s\n", 
			  saddr_dev->ifindex, saddr_dev->name);

		/* Skip down devices */
		if (!(saddr_dev->flags & IFF_UP)) {
		        HIP_DEBUG("Skipping down device\n");
			continue;
		}

		/* Skip non-multicast devices */
		if (!(saddr_dev->flags & IFF_MULTICAST)) {
		        HIP_DEBUG("Skipping non-multicast device\n");
			continue;
		}

		/* Skip loopback devices (as long as we do
		 * not have loopback support). TODO: skip tunnels etc. */
		if (saddr_dev->flags & IFF_LOOPBACK) {
		        HIP_DEBUG("Skipping loopback device\n");
			continue;
		}

		/* Skip non-IPv6 devices (as long as we do
		 * not have IPv4 support). TODO: skip tunnels etc. */
                idev = in6_dev_get(saddr_dev);
                if (!idev) {
                        HIP_DEBUG("Skipping non-IPv6 device\n");
                        continue;
                }
                read_lock(&idev->lock);

                /* test, debug crashing when all IPv6 addresses of 
		 * interface were deleted */
                if (idev->dead) {
                        HIP_DEBUG("dead device\n");
                        goto out_idev_unlock;
                }

		/* Record the interface's non-link local IPv6 addresses */
		for (i=0, ifa=idev->addr_list; ifa; i++, ifa = ifa->if_next) {
		        if (addr_count >= MAX_SRC_ADDRS) {
			        HIP_DEBUG("too many source addresses\n");
				goto out_idev_unlock;
			}
		        spin_lock_bh(&ifa->lock);
			HIP_DEBUG_IN6ADDR("addr", &ifa->addr);
			if (ipv6_addr_type(&ifa->addr) & IPV6_ADDR_LINKLOCAL){
				HIP_DEBUG("not counting link local address\n");
			} else {
				if_idx[addr_count] = saddr_dev->ifindex;
			        ipv6_addr_copy(&(saddr[addr_count]), &ifa->addr);
				addr_count++;
			}
			spin_unlock_bh(&ifa->lock);
		}
		HIP_DEBUG("address list count=%d\n", addr_count);

	out_idev_unlock:
                read_unlock(&idev->lock);
                in6_dev_put(idev);
	}

        read_unlock(&addrconf_lock);
        read_unlock(&dev_base_lock);

	HIP_DEBUG("final address list count=%d\n", addr_count);

	HIP_DEBUG_IN6ADDR("dest mc address", &daddr);

	/* Loop through the saved addresses, sending the BOS packets 
	   out the correct interface */
	for (i = 0; i < addr_count; i++) {
	        /* got a source addresses, send BOS */
	        HIP_DEBUG_IN6ADDR("selected source address", &(saddr[i]));

		/* Set up the routing structure to use the correct
		   interface, source addr, and destination addr */
		fl.proto = IPPROTO_HIP;
		fl.oif = if_idx[i];
		fl.fl6_flowlabel = 0;
		fl.fl6_dst = daddr;
		fl.fl6_src = saddr[i];

		HIP_DEBUG("pre csum totlen=%u\n", hip_get_msg_total_len(bos));
		/* Send it! */
		err = hip_csum_send_fl(&(saddr[i]), &daddr, bos, &fl);
		if (err)
		        HIP_ERROR("sending of BOS failed, err=%d\n", err);
	}
	
	err = 0;

 out_err:
	if (host_id_private)
		kfree(host_id_private);
	if (host_id_pub)
		kfree(host_id_pub);
	if (bos)
		kfree(bos);

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
	
	if (hip_host_id_contains_private_key(host_id)) {
		err = hip_private_host_id_to_hit(host_id, &lhi.hit,
						 HIP_HIT_TYPE_HASH126);
		if (err) {
			HIP_ERROR("Failed to calculate HIT from HI.");
			goto out_err;
		}
	
		/* XX TODO: check UID/GID permissions before adding */
		err = hip_socket_add_local_hi(host_id, &lhi);
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
					 &lhi.hit, HIP_HIT_TYPE_HASH126);
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
					 &lhi.hit, HIP_HIT_TYPE_HASH126);
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

		err = hip_insert_peer_map_work_order(&lhi.hit,
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

/**
* hip_list_peers_add - private function to add an entry to the peer list
* @addr: IPv6 address
* @entry: peer list entry
* @last: pointer to pointer to end of peer list linked list
*
* Add an IPv6 address (if valid) to the peer list and update the tail
* pointer.
*
* Returns: zero on success, or negative error value on failure
*/
static int hip_list_peers_add(struct in6_addr *address,
			      hip_peer_entry_opaque_t *entry,
			      hip_peer_addr_opaque_t **last)
{
	hip_peer_addr_opaque_t *addr;

	HIP_DEBUG_IN6ADDR("## SPI is 0, found bex address:", address);
	
	/* Allocate an entry for the address */
	addr = kmalloc(sizeof(hip_peer_addr_opaque_t), GFP_ATOMIC);
	if (!addr) {
		HIP_ERROR("No memory to create peer addr entry\n");
		return -ENOMEM;
	}
	addr->next = NULL;
	/* Record the peer addr */
	ipv6_addr_copy(&addr->addr, address);
	
	if (*last == NULL) {  /* First entry? Add to head and tail */
		entry->addr_list = addr;
	} else {             /* Otherwise, add to tail */
		(*last)->next = addr;
	}
	*last = addr;
	entry->count++;   /* Increment count in peer entry */
	return 0;
}


/**
 * hip_hadb_list_peers_func - private function to process a hadb entry
 * @entry: hadb table entry
 * @opaque: private data for the function (contains record keeping structure)
 *
 * Process a hadb entry, extracting the HOST ID, HIT, and IPv6 addresses.
 *
 * Returns: zero on success, or negative error value on failure
 */
static int hip_hadb_list_peers_func(hip_ha_t *entry, void *opaque)
{
	hip_peer_opaque_t *op = (hip_peer_opaque_t *)opaque;
	hip_peer_entry_opaque_t *peer_entry = NULL;
	hip_peer_addr_opaque_t *last = NULL;
	struct hip_peer_addr_list_item *s;
	struct hip_spi_out_item *spi_out, *tmp;
	char buf[46];
	struct hip_lhi lhi;
	int err = 0;
	int found_addrs = 0;

	/* Start by locking the entry */
	HIP_LOCK_HA(entry);

	/* Extract HIT */
	hip_in6_ntop(&(entry->hit_peer), buf);
	HIP_DEBUG("## Got an entry for peer HIT: %s\n", buf);
	memset(&lhi, 0, sizeof(struct hip_lhi));
	memcpy(&(lhi.hit),&(entry->hit_peer),sizeof(struct in6_addr));

	/* Create a new peer list entry */
	peer_entry = kmalloc(sizeof(hip_peer_entry_opaque_t),GFP_ATOMIC);
	if (!peer_entry) {
		HIP_ERROR("No memory to create peer list entry\n");
		err = -ENOMEM;
		goto error;
	}
	peer_entry->count = 0;    /* Initialize the number of addrs to 0 */
	peer_entry->host_id = NULL;
	/* Record the peer hit */
	ipv6_addr_copy(&(peer_entry->hit), &(lhi.hit));
	peer_entry->addr_list = NULL;
	peer_entry->next = NULL; 

	if (!op->head) {          /* Save first list entry as head and tail */
		op->head = peer_entry;
		op->end = peer_entry;
	} else {                  /* Add entry to the end */
		op->end->next = peer_entry;
		op->end = peer_entry;
	}

	/* Record each peer address */
	
	if (entry->default_spi_out == 0) {
		if (!ipv6_addr_any(&entry->bex_address)) {
			err = hip_list_peers_add(&entry->bex_address,
						 peer_entry, &last);
			if (err != 0)
				goto error;
			found_addrs = 1;
		}
		goto done;
	}

	list_for_each_entry_safe(spi_out, tmp, &entry->spis_out, list) {
		list_for_each_entry(s, &spi_out->peer_addr_list, list) {
			err = hip_list_peers_add(&(s->address), peer_entry,
						 &last);
			if (err != 0)
				goto error;
			found_addrs = 1;
		}
	}

 done:

	/* Increment count of entries and connect the address list to
	 * peer entry only if addresses were copied */
	if (!found_addrs) {
		err = -ENOMSG;
		HIP_DEBUG("entry has no usable addresses\n");
	}

	op->count++; /* increment count on error also so err handling works */
		
 error:
	//HIP_DEBUG("*** TODO: on error, kfree kmalloced addresses here ? ***\n");
	_HIP_DEBUG("op->end->next=0x%p\n", op->end->next);
	_HIP_DEBUG("op->end=0x%p\n", op->end);

	HIP_UNLOCK_HA(entry);
	return err;
}

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
		peer_host_id = hip_get_host_id(HIP_DB_PEER_HID, &lhi);
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
			kfree(entry->host_id);
		addr = entry->addr_list;
		_HIP_DEBUG("addrlist=0x%p\n", addr);
		while (addr) {
			_HIP_DEBUG("addr=0x%p\n", addr);
			anext = addr->next;
			kfree(addr);
			addr = anext;
		}
		kfree(entry);
		entry = next;
	}
	_HIP_DEBUG("done freeing mem, err = %d\n", err);
	return err;
}

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
		err = hip_socket_handle_add_local_hi(msg);
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
	case SO_HIP_BOS:
		err = hip_socket_send_bos(msg);
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
	case SO_HIP_GET_PEER_LIST:
		err = hip_socket_handle_get_peer_list(msg);
		break;
	default:
		err = -ESOCKTNOSUPPORT;
	}


 out_err:

	return err;
}

