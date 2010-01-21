#ifndef _HIPD_INIT
#define _HIPD_INIT
#include <sys/types.h>
#include <sys/stat.h> 
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#ifndef ANDROID_CHANGES
#include <linux/icmpv6.h>
#endif
#include "lib/tool/xfrmapi.h"
#include "lib/conf/hipconf.h"
#include "oppipdb.h"
#include "lib/core/debug.h"
#include "hiprelay.h"
#include "tcptimeout.h"
#include "hadb.h"
#include "nsupdate.h"

/*
 * HIP daemon initialization functions.
 *
 */


extern hip_ipsec_func_set_t default_ipsec_func_set;
extern int hip_firewall_sock_fd;
extern int hip_firewall_sock_lsi_fd;

int hip_associate_default_hit_lsi(void);

int hipd_init(int flush_ipsec, int killold);
/**
 * Creates a UDP socket for NAT traversal.
 *
 * @param  hip_nat_sock_udp	a pointer to the UDP socket.
 * @param sockaddr_in           the address that will be used to create the
 *      socket. If NULL is passed, INADDR_ANY is used.
 * @param  is_output		1 if the socket is for output, otherwise 0
 * 
 * @return zero on success, negative error value on error.
 */
int hip_create_nat_sock_udp(int *hip_nat_sock_udp, 
	struct sockaddr_in* addr,
	int is_output);
void hip_close(int signal);
void hip_exit(int signal);
int hip_init_dht(void);
#endif /* _HIP_INIT */

