#ifndef _HIPD_INIT
#define _HIPD_INIT

/*
 * HIP daemon initialization functions.
 *
 */

#include <sys/types.h>
#include <sys/stat.h> 
#include <sys/socket.h>

#include "hipconf.h"

extern char *i3_config;

int hipd_init(int flush_ipsec);
int hip_init_host_ids();
int hip_init_raw_sock_v6(int *hip_raw_sock_v6);
int hip_init_nat_sock_udp(int *hip_nat_sock_udp);
int hip_init_nat_sock_udp_data(int *hip_nat_sock_udp_data);
void hip_close(int signal);
void hip_exit(int signal);
int init_random_seed();
void hip_probe_kernel_modules();


#endif /* _HIP_INIT */

