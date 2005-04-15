#ifndef HIP_SOCKET_H
#define HIP_SOCKET_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <net/hip.h>
#include <net/ipv6.h>
#include <net/addrconf.h>

#include "debug.h"
#include "hidb.h"
#include "builder.h"
#include "misc.h"
#include "workqueue.h"
#include "misc.h"
#include "cookie.h"
#include "unit.h"
#include "input.h"
#include "output.h"
#include "debug.h"
#include "hadb.h"

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
int hip_socket_sendmsg(struct kiocb *iocb, struct socket *sock, 
		       struct msghdr *m, size_t total_len);
int hip_socket_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, 
		       size_t total_len, int flags);
int hip_socket_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct * vma);
ssize_t hip_socket_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags);
void hip_uninit_all_eid_db(void);
int hip_db_set_eid(struct sockaddr_eid *eid,
		   const struct hip_lhi *lhi,
		   const struct hip_eid_owner_info *owner_info,
		   int is_local);
int hip_db_set_my_eid(struct sockaddr_eid *eid,
		      const struct hip_lhi *lhi,
		      const struct hip_eid_owner_info *owner_info);
int hip_db_set_peer_eid(struct sockaddr_eid *eid,
			const struct hip_lhi *lhi,
			const struct hip_eid_owner_info *owner_info);
int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info,
			  int is_local);
int hip_db_get_peer_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			       struct hip_eid_owner_info *owner_info);
int hip_db_get_my_lhi_by_eid(const struct sockaddr_eid *eid,
			     struct hip_lhi *lhi,
			     struct hip_eid_owner_info *owner_info);

#endif /* __KERNEL__ */
#endif /* HIP_SOCKET_H */
