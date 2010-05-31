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
#include "lib/core/conf.h"
#include "oppipdb.h"
#include "hiprelay.h"
#include "hadb.h"
#include "nsupdate.h"

/* startup flags options to be configured via the command line */
#define HIPD_START_FOREGROUND               (1 << 0)
#define HIPD_START_CREATE_CONFIG_AND_EXIT   (1 << 1)
#define HIPD_START_FLUSH_IPSEC              (1 << 2)
#define HIPD_START_KILL_OLD                 (1 << 3)
#define HIPD_START_FIX_ALIGNMENT            (1 << 4)
#define HIPD_START_LOWCAP                   (1 << 5)
#define HIPD_START_LOAD_KMOD                (1 << 6)

/*
 * HIP daemon initialization functions.
 */
extern int hip_firewall_sock_lsi_fd;

int set_cloexec_flag(int desc, int value);

int hipd_init(const uint64_t flags);
/**
 * Creates a UDP socket for NAT traversal.
 *
 * @param  hip_nat_sock_udp a pointer to the UDP socket.
 * @param addr the address that will be used to create the
 *                 socket. If NULL is passed, INADDR_ANY is used.
 * @param is_output 1 if the socket is for output, otherwise 0
 *
 * @return zero on success, negative error value on error.
 */
int hip_create_nat_sock_udp(int *hip_nat_sock_udp,
                            struct sockaddr_in *addr,
                            int is_output);
void hip_exit(void);

#endif /* HIP_HIPD_INIT_H */
