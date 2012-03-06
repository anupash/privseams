/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H
#define HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H

#include <unistd.h>

#include <x509ac.h>
#include <x509ac-supp.h>

#include "modules/signaling/lib/signaling_prot_common.h"

// Netstat format widths (derived from netstat source code)
#define NETSTAT_SIZE_PROTO      7
#define NETSTAT_SIZE_RECV_SEND  7
#define NETSTAT_SIZE_OUTPUT     160
#define NETSTAT_SIZE_STATE      12
#define NETSTAT_SIZE_PROGNAME   20
#define NETSTAT_SIZE_ADDR_v6    50


/**
 * Struct to hold the information from netstat.
 */
struct system_app_context {
    pid_t pid;
    uid_t uid;
    int   inode;
    char  path[PATH_MAX];
    char  proto[NETSTAT_SIZE_PROTO];
    char  recv_q[NETSTAT_SIZE_RECV_SEND];
    char  send_q[NETSTAT_SIZE_RECV_SEND];
    char  local_addr[NETSTAT_SIZE_ADDR_v6];
    char  remote_addr[NETSTAT_SIZE_ADDR_v6];
    char  state[NETSTAT_SIZE_STATE];
    char  progname[NETSTAT_SIZE_PROGNAME];
};

int signaling_verify_application(const char *const app_path);

int signaling_netstat_get_application_system_info_by_ports(const uint16_t src_port,
                                                           const uint16_t dst_port,
                                                           struct system_app_context *const sys_ctx,
                                                           uint8_t endpoint);

int signaling_get_application_context_from_certificate(X509AC *ac,
                                                       struct signaling_application_context *const app_ctx);

int signaling_get_verified_application_context_by_ports(struct signaling_connection *conn,
                                                        struct signaling_connection_context *const ctx,
                                                        uint8_t endpoint);

int signaling_get_verified_host_context(struct signaling_host_context *ctx);

#endif /* HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H */
