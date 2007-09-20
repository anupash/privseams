#ifndef _HIPD_INIT
#define _HIPD_INIT
#include <sys/types.h>
#include <sys/stat.h> 
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <pwd.h>
#include "xfrmapi.h"
#include "hipconf.h"
#include "oppipdb.h"
#include "debug.h"
#include "rvs.h"
#include "hiprelay.h"
#include "escrow.h"

/*
 * HIP daemon initialization functions.
 *
 */

/**
 * HIP daemon lock file is used to prevent multiple instances
 * of the daemon to start and to record current daemon pid.
 */ 
#define HIP_DAEMON_LOCK_FILE	"/var/lock/hipd.lock"
#define USER_NOBODY "nobody"

extern char *i3_config_file;

int hipd_init(int flush_ipsec, int killold);
int hip_init_host_ids();
int hip_init_raw_sock_v6(int *hip_raw_sock_v6);
int hip_init_nat_sock_udp(int *hip_nat_sock_udp);
int hip_init_nat_sock_udp_data(int *hip_nat_sock_udp_data);
int init_random_seed();
void hip_close(int signal);
void hip_exit(int signal);
void hip_probe_kernel_modules();

#endif /* _HIP_INIT */

