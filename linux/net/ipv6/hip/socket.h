#ifndef HIP_SOCKET_H
#define HIP_SOCKET_H

#include <linux/net.h>
#include <linux/socket.h>
#include <net/hip.h>
#include <asm/poll.h>
#include <linux/random.h>
#include "debug.h"
#include "builder.h"
#include "db.h"
#include "misc.h"

extern struct net_proto_family hip_family_ops;

extern struct proto_ops inet_stream_ops;
extern struct proto_ops inet_dgram_ops;
extern struct proto_ops inet6_stream_ops;
extern struct proto_ops inet6_dgram_ops;
extern struct net_proto_family inet_family_ops;
extern struct net_proto_family inet6_family_ops;

int hip_init_socket_handler(void);
void hip_uninit_socket_handler(void);

sa_eid_t hip_create_unique_local_eid(void);
sa_eid_t hip_create_unique_peer_eid(void);

int hip_create_socket(struct socket *sock, int protocol);

int hip_socket_release(struct socket *sock);
int hip_socket_bind(struct socket *sock, struct sockaddr *umyaddr,
		    int sockaddr_len);
int hip_socket_connect(struct socket *sock, struct sockaddr *uservaddr,
		       int sockaddr_len, int flags);
int hip_socket_socketpair(struct socket *sock1, struct socket *sock2);
int hip_socket_accept(struct socket *sock, struct socket *newsock,
		      int flags);
int hip_socket_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *usockaddr_len, int peer);
unsigned int hip_socket_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait);
int hip_socket_ioctl(struct socket *sock, unsigned int cmd,
		     unsigned long arg);
int hip_socket_listen(struct socket *sock, int len);
int hip_socket_shutdown(struct socket *sock, int flags);
int hip_socket_setsockopt(struct socket *sock, int level, int optname,
			  char *optval, int optlen);
int hip_socket_getsockopt(struct socket *sock, int level, int optname,
			  char *optval, int *optlen);
int hip_socket_sendmsg(struct socket *sock, struct msghdr *m, int total_len,
		       struct scm_cookie *scm);
int hip_socket_recvmsg(struct socket *sock, struct msghdr *m, int total_len,
		       int flags, struct scm_cookie *scm);
int hip_socket_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct * vma);
ssize_t hip_socket_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags);

#endif /* HIP_SOCKET_H */
