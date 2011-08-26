/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * The HIPL main file containing the daemon main loop.
 *
 * @note HIPU: libm.a is not availble on OS X. The functions are present in libSystem.dyld, though
 * @note HIPU: lcap is used by HIPD. It needs to be changed to generic posix functions.
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/conf.h"
#include "lib/core/debug.h"
#include "lib/core/filemanip.h"
#include "lib/core/hashtable.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/performance.h"
#include "lib/core/protodefs.h"
#include "lib/core/straddr.h"
#include "lib/core/util.h"
#include "config.h"
#include "accessor.h"
#include "hip_socket.h"
#include "init.h"
#include "maintenance.h"
#include "netdev.h"
#include "hipd.h"


/** Suppress advertising of none, AF_INET or AF_INET6 address in UPDATEs.
 *  0 = none = default, AF_INET, AF_INET6 */
int suppress_af_family = 0;

/* For sending HIP control messages */
int hip_raw_sock_output_v6 = 0;
int hip_raw_sock_output_v4 = 0;

/* For receiving HIP control messages */
int hip_raw_sock_input_v6 = 0;
int hip_raw_sock_input_v4 = 0;

/** File descriptor of the socket used for sending HIP control packet
 *  NAT traversal on UDP/IPv4
 */
int hip_nat_sock_output_udp = 0;

/** File descriptor of the socket used for receiving HIP control packet
 *  NAT traversal on UDP/IPv4
 */
int hip_nat_sock_input_udp = 0;

int hip_nat_sock_output_udp_v6 = 0;
int hip_nat_sock_input_udp_v6  = 0;

/** Specifies the NAT status of the daemon. This value indicates if the current
 *  machine is behind a NAT. */
hip_transform_suite hip_nat_status = 0;

/* Encrypt host id in I2 */
int hip_encrypt_i2_hi = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock = 0;

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec;

/** For getting/setting routes and adding HITs (it was not possible to use
 *  nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route;

struct sockaddr_in6 hip_firewall_addr;
static int          hip_firewall_sock = 0;

/* used to change the transform order see hipconf usage to see the usage
 * This is set to AES, 3DES, NULL by default see hipconf trasform order for
 * more information.
 */
int hip_transform_order = 123;

/* Tells to the daemon should it build LOCATOR parameters to R1 and I2 */
int hip_locator_status = HIP_MSG_SET_LOCATOR_OFF;

/* We are caching the IP addresses of the host here. The reason is that during
 * in hip_handle_acquire it is not possible to call getifaddrs (it creates
 * a new netlink socket and seems like only one can be open per process).
 * Feel free to experiment by porting the required functionality from
 * iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
 * variable and most of the functions referencing them unnecessary -miika
 */

int            address_count;
HIP_HASHTABLE *addresses;

int address_change_time_counter = -1;

/*Define hip_use_userspace_ipsec variable to indicate whether use
 * userspace ipsec or not. If it is 1, hip uses the user space ipsec.
 * It will not use if hip_use_userspace_ipsec = 0. Added By Tao Wan
 */
int hip_use_userspace_ipsec = 0;

int  esp_prot_active               = 0;
int  esp_prot_num_transforms       = 0;
long esp_prot_num_parallel_hchains = 0;

int hip_shotgun_status = HIP_MSG_SHOTGUN_OFF;

int hip_broadcast_status = HIP_MSG_BROADCAST_OFF;

int hip_wait_addr_changes_to_stabilize = 1;

/**
 * print hipd usage instructions on stderr
 */
static void usage(void)
{
    fprintf(stderr, "Usage: hipd [options]\n\n");
    fprintf(stderr, "  -V print version information and exit\n");
    fprintf(stderr, "  -b run in background\n");
    fprintf(stderr, "  -i <device name> add interface to the white list. " \
                    "Use additional -i for additional devices.\n");
    fprintf(stderr, "  -k kill existing hipd\n");
    fprintf(stderr, "  -N do not flush all IPsec databases during start\n");
    fprintf(stderr, "  -a fix alignment issues automatically(ARM)\n");
    fprintf(stderr, "  -f set debug type format to short\n");
    fprintf(stderr, "  -d set the initial (pre-config) debug level to ALL (default is MEDIUM)\n");
    fprintf(stderr, "  -D <module name> disable this module. " \
                    "Use additional -D for additional modules.\n");
    fprintf(stderr, "  -p disable privilege separation\n");
    fprintf(stderr, "  -m disable the loading/unloading of kernel modules\n");
    fprintf(stderr, "\n");
}

/**
 * send a message to the HIP firewall
 *
 * @param msg the message to send
 * @return zero on success or negative on error
 */
int hip_sendto_firewall(HIPFW const struct hip_common *msg)
{
#ifdef CONFIG_HIP_FIREWALL
    int n = 0;
    HIP_DEBUG("CONFIG_HIP_FIREWALL DEFINED AND STATUS IS %d\n", hip_get_firewall_status());

    n = sendto(hip_firewall_sock,
               msg,
               hip_get_msg_total_len(msg),
               0,
               (struct sockaddr *) &hip_firewall_addr,
               sizeof(hip_firewall_addr));
    return n;
#else
    HIP_DEBUG("Firewall is disabled.\n");
    return 0;
#endif // CONFIG_HIP_FIREWALL
}

/**
 * Parse the command line options
 * @param argc  number of command line parameters
 * @param argv  command line parameters
 * @param flags pointer to the startup flags container
 * @return      nonzero if the caller should exit, 0 otherwise
 */
int hipd_parse_cmdline_opts(int argc, char *argv[], uint64_t *flags)
{
    int c;

    while ((c = getopt(argc, argv, ":bi:kNchafVdD:pm")) != -1) {
        switch (c) {
        case 'b':
            /* run in the "background" */
            *flags &= ~HIPD_START_FOREGROUND;
            break;
        case 'i':
            if (hip_netdev_white_list_add(optarg)) {
                HIP_INFO("Successfully added device <%s> to white list.\n", optarg);
            } else {
                HIP_DIE("Error adding device <%s> to white list. Dying...\n", optarg);
            }
            break;
        case 'k':
            *flags |= HIPD_START_KILL_OLD;
            break;
        case 'N':
            /* do NOT flush IPsec DBs */
            *flags &= ~HIPD_START_FLUSH_IPSEC;
            break;
        case 'c':
            *flags |= HIPD_START_CREATE_CONFIG_AND_EXIT;
            break;
        case 'a':
            *flags |= HIPD_START_FIX_ALIGNMENT;
            break;
        case 'f':
            HIP_INFO("Setting output format to short\n");
            hip_set_logfmt(LOGFMT_SHORT);
            break;
        case 'd':
            hip_set_logdebug(LOGDEBUG_ALL);
            break;
        case 'D':
            if (!lmod_disable_module(optarg)) {
                HIP_DEBUG("Module '%s' disabled.\n", optarg);
            } else {
                HIP_ERROR("Error while disabling module '%s'.\n", optarg);
            }
            break;
        case 'p':
            /* do _not_ use low capabilies ("privilege separation") */
            *flags &= ~HIPD_START_LOWCAP;
            break;
        case 'm':
            /* do _not_ load/unload kernel modules/drivers */
            *flags &= ~HIPD_START_LOAD_KMOD;
            break;
        case 'V':
            hip_print_version("hipd");
            return -1;
        case '?':
        case 'h':
        default:
            usage();
            return -1;
        }
    }

    return 0;
}

/**
 * Daemon "main" function.
 * @param flags startup flags
 * @return      0 on success, negative error code otherwise
 */
int hipd_main(uint64_t flags)
{
    int                       highest_descriptor = 0, err = 0;
    struct timeval            timeout;
    fd_set                    read_fdset;
    struct hip_packet_context ctx = { 0 };

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Creating perf set\n");
    perf_set = hip_perf_create(PERF_MAX);

    check_and_create_dir("results", HIP_DIR_MODE);

    hip_perf_set_name(perf_set, PERF_STARTUP, "results/PERF_STARTUP.csv");
    hip_perf_set_name(perf_set, PERF_I1_SEND, "results/PERF_I1_SEND.csv");
    hip_perf_set_name(perf_set, PERF_I1, "results/PERF_I1.csv");
    hip_perf_set_name(perf_set, PERF_I1_R1, "results/PERF_I1_R1.csv");
    hip_perf_set_name(perf_set, PERF_R1, "results/PERF_R1.csv");

    /* splitting R1 */
    hip_perf_set_name(perf_set, PERF_R1x1, "results/PERF_R1x1.csv");
    hip_perf_set_name(perf_set, PERF_R1x2, "results/PERF_R1x2.csv");
    hip_perf_set_name(perf_set, PERF_R1x3, "results/PERF_R1x3.csv");
    hip_perf_set_name(perf_set, PERF_R1x4, "results/PERF_R1x4.csv");
    hip_perf_set_name(perf_set, PERF_R1x4x1, "results/PERF_R1x4x1.csv");
    hip_perf_set_name(perf_set, PERF_R1x4x2, "results/PERF_R1x4x2.csv");
    hip_perf_set_name(perf_set, PERF_R1x4x3, "results/PERF_R1x4x3.csv");
    hip_perf_set_name(perf_set, PERF_R1x5, "results/PERF_R1x5.csv");

    hip_perf_set_name(perf_set, PERF_R1x5, "results/PERF_R1x5.csv");

    hip_perf_set_name(perf_set, PERF_R1_I2, "results/PERF_R1_I2.csv");
    hip_perf_set_name(perf_set, PERF_I2, "results/PERF_I2.csv");
    hip_perf_set_name(perf_set, PERF_I2_R2, "results/PERF_I2_R2.csv");
    hip_perf_set_name(perf_set, PERF_R2, "results/PERF_R2.csv");
    hip_perf_set_name(perf_set, PERF_R2_I3, "results/PERF_R2_I3.csv");
    hip_perf_set_name(perf_set, PERF_I3, "results/PERF_I3.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE, "results/PERF_UPDATE.csv");
    hip_perf_set_name(perf_set, PERF_NOTIFY, "results/PERF_NOTIFY.csv");
    hip_perf_set_name(perf_set, PERF_DH_CREATE, "results/PERF_DH_CREATE.csv");
    hip_perf_set_name(perf_set, PERF_SIGN, "results/PERF_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY, "results/PERF_VERIFY.csv");
    hip_perf_set_name(perf_set, PERF_BASE, "results/PERF_BASE.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_SEND, "results/PERF_CLOSE_SEND.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE, "results/PERF_HANDLE_CLOSE.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE_ACK, "results/PERF_HANDLE_CLOSE_ACK.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_COMPLETE, "results/PERF_CLOSE_COMPLETE.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY_USER_SIG, "results/PERF_VERIFY_USER_SIG.csv");
    hip_perf_set_name(perf_set, PERF_TRIGGER_CONN, "results/PERF_TRIGGER_CONN.csv");
    hip_perf_set_name(perf_set, PERF_HIPD_R2_FINISH, "results/PERF_HIPD_R2_FINISH.csv");
    hip_perf_set_name(perf_set, PERF_HIPD_I3_FINISH, "results/PERF_HIPD_I3_FINISH.csv");
    hip_perf_set_name(perf_set, PERF_USER_COMM, "results/PERF_USER_COMM.csv");
    hip_perf_set_name(perf_set, PERF_NEW_CONN, "results/PERF_NEW_CONN.csv");
    hip_perf_set_name(perf_set, PERF_PERF, "results/PERF_PERF.csv");

    /* signature verification and generation */
    hip_perf_set_name(perf_set, PERF_R1_VERIFY_HOST_SIG, "results/PERF_R1_VERIFY_HOST_SIG.csv");
    hip_perf_set_name(perf_set, PERF_I2_HOST_SIGN, "results/PERF_I2_HOST_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_I2_USER_SIGN, "results/PERF_I2_USER_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_I2_VERIFY_HOST_SIG, "results/PERF_I2_VERIFY_HOST_SIG.csv");
    hip_perf_set_name(perf_set, PERF_I2_VERIFY_USER_SIG, "results/PERF_I2_VERIFY_USER_SIG.csv");
    hip_perf_set_name(perf_set, PERF_R2_HOST_SIGN, "results/PERF_R2_HOST_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_R2_USER_SIGN, "results/PERF_R2_USER_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_R2_VERIFY_HOST_SIG, "results/PERF_R2_VERIFY_HOST_SIG.csv");
    hip_perf_set_name(perf_set, PERF_R2_VERIFY_USER_SIG, "results/PERF_R2_VERIFY_USER_SIG.csv");
    hip_perf_set_name(perf_set, PERF_I3_HOST_SIGN, "results/PERF_I3_HOST_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_I3_VERIFY_HOST_SIG, "results/PERF_I3_VERIFY_HOST_SIG.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE_HOST_SIGN, "results/PERF_UPDATE_HOST_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE_VERIFY_HOST_SIG, "results/PERF_UPDATE_VERIFY_HOST_SIG.csv");
    hip_perf_set_name(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG, "results/PERF_NOTIFY_VERIFY_HOST_SIG.csv");
    hip_perf_set_name(perf_set, PERF_X509_VERIFY_CERT_CHAIN, "results/PERF_X509_VERIFY_CERT_CHAIN.csv");
    hip_perf_set_name(perf_set, PERF_SEND_CERT_CHAIN, "results/PERF_SEND_CERT_CHAIN.csv");
    hip_perf_set_name(perf_set, PERF_CERTIFICATE_EXCHANGE, "results/PERF_CERTIFICATE_EXCHANGE.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CERT_CHAIN, "results/PERF_HANDLE_CERT_CHAIN.csv");
    hip_perf_set_name(perf_set, PERF_ECDSA_VERIFY_IMPL, "results/PERF_ECDSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_ECDSA_SIGN_IMPL, "results/PERF_ECDSA_SIGN_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_LOAD_USER_KEY, "results/PERF_LOAD_USER_KEY.csv");
    hip_perf_set_name(perf_set, PERF_LOAD_USER_PUBKEY, "results/PERF_LOAD_USER_PUBKEY.csv");

    hip_perf_set_name(perf_set, PERF_TEST1, "results/PERF_TEST1.csv");
    hip_perf_set_name(perf_set, PERF_TEST2, "results/PERF_TEST2.csv");


    hip_perf_open(perf_set);

    HIP_DEBUG("Start PERF_STARTUP\n");
    hip_perf_start_benchmark(perf_set, PERF_STARTUP);
#endif

    /* default is long format */
    hip_set_logfmt(LOGFMT_LONG);

    if (flags & HIPD_START_FIX_ALIGNMENT) {
        HIP_DEBUG("Setting alignment traps to 3(fix+ warn)\n");
        if (system("echo 3 > /proc/cpu/alignment")) {
            HIP_ERROR("Setting alignment traps failed.");
        }
    }

    /* Configuration is valid! Fork a daemon, if so configured */
    if (flags & HIPD_START_FOREGROUND) {
        hip_set_logtype(LOGTYPE_STDERR);
        HIP_DEBUG("foreground\n");
    } else {
        hip_set_logtype(LOGTYPE_SYSLOG);
        if (fork() > 0) {
            return 0;
        }
    }

    HIP_INFO("hipd pid=%d starting\n", getpid());

    /* prepare the one and only hip_packet_context instance */
    HIP_IFEL(!(ctx.input_msg  = hip_msg_alloc()), ENOMEM, "Insufficient memory");
    HIP_IFEL(!(ctx.output_msg = hip_msg_alloc()), ENOMEM, "Insufficient memory");

    /* Default initialization function. */
    HIP_IFEL(hipd_init(flags), 1, "hipd_init() failed!\n");

    if (flags & HIPD_START_CREATE_CONFIG_AND_EXIT) {
        HIP_ERROR("Config files create, exiting...\n");
        return 0;
    }

    highest_descriptor = hip_get_highest_descriptor();

    /* Enter to the select-loop */
    HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT,
                 HIP_DEBUG_LEVEL_INFORMATIVE,
                 "Hipd daemon running. Starting select loop.\n");
    hipd_set_state(HIPD_STATE_EXEC);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_STARTUP\n");
    hip_perf_stop_benchmark(perf_set, PERF_STARTUP);
    hip_perf_write_benchmark(perf_set, PERF_STARTUP);
#endif
    while (hipd_get_state() != HIPD_STATE_CLOSED) {
        hip_prepare_fd_set(&read_fdset);

        hip_firewall_sock = hip_user_sock;

        timeout.tv_sec  = HIP_SELECT_TIMEOUT;
        timeout.tv_usec = 0;

#ifdef CONFIG_HIP_FIREWALL
        if (hip_firewall_status < 0) {
            memset(&hip_firewall_addr, 0, sizeof(hip_firewall_addr));
            hip_firewall_addr.sin6_family = AF_INET6;
            hip_firewall_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
            hip_firewall_addr.sin6_addr   = in6addr_loopback;

            hip_msg_init(ctx.input_msg);
            err = hip_build_user_hdr(ctx.input_msg,
                                     HIP_MSG_FIREWALL_STATUS,
                                     0);
            if (err) {
                HIP_ERROR("hip_build_user_hdr\n");
            } else {
                hip_firewall_status = 0;
                HIP_DEBUG("sent %d bytes to firewall\n",
                          hip_sendto_firewall(ctx.input_msg));
            }
        }
#endif

        err = select(highest_descriptor + 1, &read_fdset, NULL, NULL, &timeout);

        if (err < 0) {
            HIP_ERROR("select() error: %s.\n", strerror(errno));
            goto to_maintenance;
        } else if (err == 0) {
            /* idle cycle - select() timeout */
            goto to_maintenance;
        }

        hip_run_socket_handles(&read_fdset, &ctx);

to_maintenance:
        err = hip_periodic_maintenance();
        if (err) {
            HIP_ERROR("Error (%d) ignoring. %s\n", err,
                      ((errno) ? strerror(errno) : ""));
            err = 0;
        }
    }

out_err:
    /* free allocated resources */
    hip_exit();

    free(ctx.input_msg);
    free(ctx.output_msg);

    HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

    return err;
}
