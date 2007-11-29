#ifndef _HIPD_INIT
#define _HIPD_INIT

/*
 * HIP daemon initialization functions.
 *
 */

/**
 * HIP daemon lock file is used to prevent multiple instances
 * of the daemon to start and to record current daemon pid.
 */ 
#define HIP_DAEMON_LOCK_FILE	"/var/lock/hipd.lock"


#include <sys/types.h>
#include <sys/stat.h> 
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include "xfrmapi.h"
#include "hipconf.h"
#include "oppipdb.h"
#include "hi3.h"

#define USER_NOBODY "nobody"

extern char *hip_i3_config_file;
extern int hip_use_i3;

int hipd_init(int flush_ipsec, int killold);
int hip_init_host_ids();
int hip_init_raw_sock_v6(int *hip_raw_sock_v6);
int hip_init_nat_sock_udp(int *hip_nat_sock_udp);
int hip_init_nat_sock_udp_data(int *hip_nat_sock_udp_data);
void hip_close(int signal);
void hip_exit(int signal);
int init_random_seed();
void hip_probe_kernel_modules();
int hip_init_dht();

#endif /* _HIP_INIT */

