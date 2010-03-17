/** @file
 * The HIPL main file containing the daemon main loop.
 *
 * @date 28.01.2008
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note HIPU: libm.a is not availble on OS X. The functions are present in libSystem.dyld, though
 * @note HIPU: lcap is used by HIPD. It needs to be changed to generic posix functions.
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "config.h"
#include "hipd.h"
#include "hip_socket.h"
#include "modularization.h"
#include "lib/core/filemanip.h"
#include "lib/core/straddr.h"

#ifdef CONFIG_HIP_PERFORMANCE
#include "lib/performance/performance.h"
#endif

int is_active_mhaddr                 = 1; /**< Which mhaddr to use active or lazy? (default: active) */
int is_hard_handover                 = 0; /**< if hard handover is forced to be used (default: no) */

/** Suppress advertising of none, AF_INET or AF_INET6 address in UPDATEs.
 *  0 = none = default, AF_INET, AF_INET6 */
int suppress_af_family               = 0;

/* For sending HIP control messages */
int hip_raw_sock_output_v6           = 0;
int hip_raw_sock_output_v4           = 0;

/* For receiving HIP control messages */
int hip_raw_sock_input_v6            = 0;
int hip_raw_sock_input_v4            = 0;

/** File descriptor of the socket used for sending HIP control packet
 *  NAT traversal on UDP/IPv4
 */
int hip_nat_sock_output_udp          = 0;

/** File descriptor of the socket used for receiving HIP control packet
 *  NAT traversal on UDP/IPv4
 */
int hip_nat_sock_input_udp           = 0;

int hip_nat_sock_output_udp_v6       = 0;
int hip_nat_sock_input_udp_v6        = 0;

/** Specifies the NAT status of the daemon. This value indicates if the current
 *  machine is behind a NAT. */
hip_transform_suite_t hip_nat_status = 0;

/* Encrypt host id in I2 */
int hip_encrypt_i2_hi                = 0;

/* Communication interface to userspace apps (hipconf etc) */
int hip_user_sock                    = 0;
struct sockaddr_un hip_user_addr;

/** For receiving netlink IPsec events (acquire, expire, etc) */
struct rtnl_handle hip_nl_ipsec      = {0};

/** For getting/setting routes and adding HITs (it was not possible to use
 *  nf_ipsec for this purpose). */
struct rtnl_handle hip_nl_route = { 0 };

struct rtnl_handle hip_nl_generic = { 0 };

struct sockaddr_in6 hip_firewall_addr;
int hip_firewall_sock                    = 0;

/* used to change the transform order see hipconf usage to see the usage
 * This is set to AES, 3DES, NULL by default see hipconf trasform order for
 * more information.
 */
int hip_transform_order                  = 123;

/* Tells to the daemon should it build LOCATOR parameters to R1 and I2 */
int hip_locator_status             = SO_HIP_SET_LOCATOR_OFF;

/* Create /etc/hip stuff and exit (used for binary hipfw packaging) */
int create_configs_and_exit        = 0;

/* We are caching the IP addresses of the host here. The reason is that during
 * in hip_handle_acquire it is not possible to call getifaddrs (it creates
 * a new netlink socket and seems like only one can be open per process).
 * Feel free to experiment by porting the required functionality from
 * iproute2/ip/ipaddrs.c:ipaddr_list_or_flush(). It would make these global
 * variable and most of the functions referencing them unnecessary -miika
 */

int address_count;
HIP_HASHTABLE *addresses;
time_t load_time;

int address_change_time_counter = -1;

/*Define hip_use_userspace_ipsec variable to indicate whether use
 * userspace ipsec or not. If it is 1, hip uses the user space ipsec.
 * It will not use if hip_use_userspace_ipsec = 0. Added By Tao Wan
 */
int hip_use_userspace_ipsec                  = 0;

int hip_use_userspace_data_packet_mode       = 0;

int esp_prot_active                          = 0;
int esp_prot_num_transforms                  = 0;
uint8_t esp_prot_transforms[MAX_NUM_TRANSFORMS];
long esp_prot_num_parallel_hchains           = 0;

int hip_shotgun_status                       = SO_HIP_SHOTGUN_OFF;

int hip_trigger_update_on_heart_beat_failure = 1;
int hip_wait_addr_changes_to_stabilize       = 1;

int hip_use_opptcp                           = 0; // false

static void usage(void)
{
    fprintf(stderr, "Usage: hipd [options]\n\n");
    fprintf(stderr, "  -b run in background\n");
    fprintf(stderr, "  -i <device name> add interface to the white list. Use additional -i for additional devices.\n");
    fprintf(stderr, "  -k kill existing hipd\n");
    fprintf(stderr, "  -N do not flush ipsec rules on exit\n");
    fprintf(stderr, "  -a fix alignment issues automatically(ARM)\n");
    fprintf(stderr, "  -f set debug type format to short\n");
    fprintf(stderr, "\n");
}

/**
 * send a message to the HIP firewall
 *
 * @param msg the message to send
 * @return zero on success or negative on error
 */
int hip_sendto_firewall(const struct hip_common *msg)
{
#ifdef CONFIG_HIP_FIREWALL
    int n          = 0;
    HIP_DEBUG("CONFIG_HIP_FIREWALL DEFINED AND STATUS IS %d\n", hip_get_firewall_status());
    struct sockaddr_in6 hip_firewall_addr;
    socklen_t alen = sizeof(hip_firewall_addr);

    bzero(&hip_firewall_addr, alen);
    hip_firewall_addr.sin6_family = AF_INET6;
    hip_firewall_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    hip_firewall_addr.sin6_addr   = in6addr_loopback;

    n = sendto(hip_firewall_sock,
               msg,
               hip_get_msg_total_len(msg),
               0,
               (struct sockaddr *) &hip_firewall_addr,
               alen);
    return n;
#else
    HIP_DEBUG("Firewall is disabled.\n");
    return 0;
#endif // CONFIG_HIP_FIREWALL
}

/**
 * Daemon "main" function.
 *
 * @param argc number of command line arguments
 * @param argv the command line arguments
 * @return zero on success or negative on error
 */
static int hipd_main(int argc, char *argv[])
{
    int ch, killold = 0;
    // char buff[HIP_MAX_NETLINK_PACKET];
    fd_set read_fdset;
    int foreground = 1, highest_descriptor = 0, err = 0, fix_alignment = 0;
    struct timeval timeout;
    struct hip_packet_context packet_ctx = {0};

    /* The flushing is enabled by default. The reason for this is that
     * people are doing some very experimental features on some branches
     * that may crash the daemon and leave the SAs floating around to
     * disturb further base exchanges. Use -N flag to disable this. */
    int flush_ipsec = 1;


#ifdef CONFIG_HIP_PERFORMANCE
    int bench_set   = 0;
    HIP_DEBUG("Creating perf set\n");
    perf_set = hip_perf_create(PERF_MAX);

    check_and_create_dir("results", DEFAULT_CONFIG_DIR_MODE);

    hip_perf_set_name(perf_set, PERF_I1_SEND, "results/PERF_I1_SEND.csv");
    hip_perf_set_name(perf_set, PERF_I1, "results/PERF_I1.csv");
    hip_perf_set_name(perf_set, PERF_R1, "results/PERF_R1.csv");
    hip_perf_set_name(perf_set, PERF_I2, "results/PERF_I2.csv");
    hip_perf_set_name(perf_set, PERF_R2, "results/PERF_R2.csv");
    hip_perf_set_name(perf_set, PERF_DH_CREATE, "results/PERF_DH_CREATE.csv");
    hip_perf_set_name(perf_set, PERF_SIGN, "results/PERF_SIGN.csv");
    hip_perf_set_name(perf_set, PERF_DSA_SIGN_IMPL, "results/PERF_DSA_SIGN_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY, "results/PERF_VERIFY.csv");
    hip_perf_set_name(perf_set, PERF_BASE, "results/PERF_BASE.csv");
    hip_perf_set_name(perf_set, PERF_ALL, "results/PERF_ALL.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE_SEND, "results/PERF_UPDATE_SEND.csv");
    hip_perf_set_name(perf_set, PERF_VERIFY_UPDATE, "results/PERF_VERIFY_UPDATE.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE_COMPLETE, "results/PERF_UPDATE_COMPLETE.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_ESTABLISHED, "results/PERF_HANDLE_UPDATE_ESTABLISHED.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_REKEYING, "results/PERF_HANDLE_UPDATE_REKEYING.csv");
    hip_perf_set_name(perf_set, PERF_UPDATE_FINISH_REKEYING, "results/PERF_UPDATE_FINISH_REKEYING.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_SEND, "results/PERF_CLOSE_SEND.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE, "results/PERF_HANDLE_CLOSE.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_CLOSE_ACK, "results/PERF_HANDLE_CLOSE_ACK.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_1, "results/PERF_HANDLE_UPDATE_1.csv");
    hip_perf_set_name(perf_set, PERF_HANDLE_UPDATE_2, "results/PERF_HANDLE_UPDATE_2.csv");
    hip_perf_set_name(perf_set, PERF_CLOSE_COMPLETE, "results/PERF_CLOSE_COMPLETE.csv");
    hip_perf_set_name(perf_set, PERF_DSA_VERIFY_IMPL, "results/PERF_DSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_RSA_VERIFY_IMPL, "results/PERF_RSA_VERIFY_IMPL.csv");
    hip_perf_set_name(perf_set, PERF_RSA_SIGN_IMPL, "results/PERF_RSA_SIGN_IMPL.csv");
    hip_perf_open(perf_set);
#endif

    /* default is long format */
    hip_set_logfmt(LOGFMT_LONG);

    /* Parse command-line options */
    while ((ch = getopt(argc, argv, ":bi:kNchaf")) != -1) {
        switch (ch) {
        case 'b':
            foreground = 0;
            break;
        case 'i':
            if (hip_netdev_white_list_add(optarg)) {
                HIP_INFO("Successfully added device <%s> to white list.\n", optarg);
            } else {
                HIP_DIE("Error adding device <%s> to white list. Dying...\n", optarg);
            }
            break;
        case 'k':
            killold                 = 1;
            break;
        case 'N':
            flush_ipsec             = 0;
            break;
        case 'c':
            create_configs_and_exit = 1;
            break;
        case 'a':
            fix_alignment           = 1;
            break;
        case 'f':
            HIP_INFO("Setting output format to short\n");
            hip_set_logfmt(LOGFMT_SHORT);
            break;
        case '?':
        case 'h':
        default:
            usage();
            return err;
        }
    }

    if (fix_alignment) {
        HIP_DEBUG("Setting alignment traps to 3(fix+ warn)\n");
        if (system("echo 3 > /proc/cpu/alignment == -1")) {
            HIP_ERROR("Setting alignment traps failed.");
        }
    }

    /* Configuration is valid! Fork a daemon, if so configured */
    if (foreground) {
        hip_set_logtype(LOGTYPE_STDERR);
        HIP_DEBUG("foreground\n");
    } else {
        hip_set_logtype(LOGTYPE_SYSLOG);
        if (fork() > 0) {
            return 0;
        }
    }

    HIP_INFO("hipd pid=%d starting\n", getpid());
    time(&load_time);

    /* Default initialization function. */
    HIP_IFEL(hipd_init(flush_ipsec, killold), 1, "hipd_init() failed!\n");

    HIP_IFEL(create_configs_and_exit, 0, "Configs created, exiting\n");

    highest_descriptor = hip_get_highest_descriptor();

    /* Allocate user message. */
    HIP_IFE(!(packet_ctx.input_msg = hip_msg_alloc()), 1);
    packet_ctx.output_msg  = NULL;
    packet_ctx.src_addr    = malloc(sizeof(struct in6_addr));
    packet_ctx.dst_addr    = malloc(sizeof(struct in6_addr));
    packet_ctx.msg_ports   = malloc(sizeof(struct hip_stateless_info));
    packet_ctx.hadb_entry  = NULL;
    packet_ctx.drop_packet = 0;
    HIP_DEBUG("Daemon running. Entering select loop.\n");

    /* Enter to the select-loop */
    HIP_DEBUG_GL(HIP_DEBUG_GROUP_INIT,
                 HIP_DEBUG_LEVEL_INFORMATIVE,
                 "Hipd daemon running.\n"
                 "Starting select loop.\n");
    hipd_set_state(HIPD_STATE_EXEC);
    while (hipd_get_state() != HIPD_STATE_CLOSED) {

        hip_prepare_fd_set(&read_fdset);

        hip_firewall_sock = hip_user_sock;

        timeout.tv_sec  = HIP_SELECT_TIMEOUT;
        timeout.tv_usec = 0;

#ifdef CONFIG_HIP_FIREWALL
        if (hip_firewall_status < 0) {
            hip_msg_init(packet_ctx.input_msg);
            err = hip_build_user_hdr(packet_ctx.input_msg, SO_HIP_FIREWALL_STATUS, 0);
            if (err) {
                HIP_ERROR("hip_build_user_hdr\n");
            } else {
                hip_firewall_status = 0;
                HIP_DEBUG("sent %d bytes to firewall\n",
                          hip_sendto_firewall(packet_ctx.input_msg));
            }
        }
#endif

        err = select(highest_descriptor + 1, &read_fdset, NULL, NULL, &timeout);

        if (err < 0) {
            HIP_ERROR("select() error: %s.\n", strerror(errno));
            goto to_maintenance;
        } else if (err == 0) {
            /* idle cycle - select() timeout */
            _HIP_DEBUG("Idle.\n");
            goto to_maintenance;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        if (bench_set) {
            HIP_DEBUG("Stop and write PERF_ALL\n");
            hip_perf_stop_benchmark(perf_set, PERF_ALL);
            hip_perf_write_benchmark(perf_set, PERF_ALL);
            bench_set = 0;
        }
#endif

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_ALL\n");
        bench_set = 1;
        hip_perf_start_benchmark(perf_set, PERF_ALL);
#endif

        hip_run_socket_handles(&read_fdset, &packet_ctx);

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
    hip_exit(err);

    if (packet_ctx.input_msg) {
        HIP_FREE(packet_ctx.input_msg);
    }

    if (packet_ctx.src_addr) {
        HIP_FREE(packet_ctx.src_addr);
    }

    if (packet_ctx.dst_addr) {
        HIP_FREE(packet_ctx.dst_addr);
    }

    if (packet_ctx.msg_ports) {
        HIP_FREE(packet_ctx.msg_ports);
    }

    HIP_INFO("hipd pid=%d exiting, retval=%d\n", getpid(), err);

    return err;
}

/**
 * the main function for hipd
 *
 * @param argc number of command line arguments
 * @param argv the command line arguments
 * @return zero on success or negative on error
 */
int main(int argc, char *argv[])
{
    int err = 0;
    uid_t euid;

    euid = geteuid();
    /* We need to recreate the NAT UDP sockets to bind to the new port. */
    HIP_IFEL((euid != 0), -1, "hipd must be started as root\n");

    HIP_IFE(hipd_main(argc, argv), -1);
    if (hipd_get_flag(HIPD_FLAG_RESTART)) {
        HIP_INFO(" !!!!! HIP DAEMON RESTARTING !!!!! \n");
        hip_handle_exec_application(0, EXEC_LOADLIB_NONE, argc, argv);
    }

out_err:
    return err;
}
