/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_HIPD_INIT_H
#define HIP_HIPD_INIT_H

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include "lib/tool/xfrmapi.h"
#include "lib/core/debug.h"
#include "lib/core/protodefs.h"
#include "lib/conf/conf.h"
#include "oppipdb.h"
#include "hiprelay.h"
#include "hadb.h"
#include "nsupdate.h"

extern hip_ipsec_func_set_t default_ipsec_func_set;
extern int hip_firewall_sock_lsi_fd;

int hipd_init(int flush_ipsec, int killold);

int hip_set_cloexec_flag(int desc, int value);

int hip_create_nat_sock_udp(int *hip_nat_sock_udp,
                            struct sockaddr_in *addr,
                            int is_output);
void hip_close(int signal);
void hip_exit(int signal);

#endif /* HIP_HIPD_INIT_H */
