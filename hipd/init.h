#ifndef HIP_HIPD_INIT_H
#define HIP_HIPD_INIT_H

#include <sys/socket.h>
#include "lib/core/protodefs.h"

extern hip_ipsec_func_set_t default_ipsec_func_set;
extern int hip_firewall_sock_fd;
extern int hip_firewall_sock_lsi_fd;

int hip_associate_default_hit_lsi(void);

int hipd_init(int flush_ipsec, int killold);

int hip_set_cloexec_flag(int desc, int value);

int hip_create_nat_sock_udp(int *hip_nat_sock_udp,
                            struct sockaddr_in *addr,
                            int is_output);
void hip_close(int signal);
void hip_exit(int signal);
#endif /* HIP_HIPD_INIT_H */
