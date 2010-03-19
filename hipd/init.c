/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * This file defines initialization functions for the HIP daemon.
 *
 * @note    HIPU: BSD platform needs to be autodetected in hip_set_lowcapability
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include <netinet/icmp6.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "config.h"
#include "init.h"
#include "esp_prot_light_update.h"
#include "hip_socket.h"
#include "nsupdate.h"
#include "modularization.h"
#include "output.h"
#include "lib/core/common_defines.h"
#include "lib/core/debug.h"
#include "lib/core/hip_capability.h"
#include "lib/core/filemanip.h"
#include "lib/core/hostid.h"
#include "lib/core/hip_udp.h"
#include "lib/core/hostsfiles.h"
#include "lib/performance/performance.h"
#include "lib/tool/xfrmapi.h"
#include "modules/hipd_modules.h"

/**
 * HIP daemon lock file is used to prevent multiple instances
 * of the daemon to start and to record current daemon pid.
 */
#define HIP_DAEMON_LOCK_FILE    HIPL_LOCKDIR "/hipd.lock"

#ifndef ANDROID_CHANGES

/** ICMPV6_FILTER related stuff */
#define BIT_CLEAR(nr, addr) do { ((uint32_t *) (addr))[(nr) >> 5] &= ~(1U << ((nr) & 31)); } while (0)
#define BIT_SET(nr, addr) do { ((uint32_t *) (addr))[(nr) >> 5] |= (1U << ((nr) & 31)); } while (0)
#define BIT_TEST(nr, addr) do { (uint32_t *) (addr))[(nr) >> 5] & (1U << ((nr) & 31)); } while (0)

#ifndef ICMP6_FILTER_WILLPASS
#define ICMP6_FILTER_WILLPASS(type, filterp) \
    (BIT_TEST((type), filterp) == 0)

#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
    BIT_TEST((type), filterp)

#define ICMP6_FILTER_SETPASS(type, filterp) \
    BIT_CLEAR((type), filterp)

#define ICMP6_FILTER_SETBLOCK(type, filterp) \
    BIT_SET((type), filterp)

#define ICMP6_FILTER_SETPASSALL(filterp) \
    memset(filterp, 0, sizeof(struct icmp6_filter));

#define ICMP6_FILTER_SETBLOCKALL(filterp) \
    memset(filterp, 0xFF, sizeof(struct icmp6_filter));
#endif
/** end ICMPV6_FILTER related stuff */

#endif /* ANDROID_CHANGES */

/**
 * Catch SIGCHLD.
 *
 * @param signum the signal number to catch
 */
static void hip_sig_chld(int signum)
{
#ifdef ANDROID_CHANGES
    int status;
#else
    union wait status;
#endif

    int pid;

    signal(signum, hip_sig_chld);

    /* Get child process status, so it wont be left as zombie for long time. */
    while ((pid = wait3(&status, WNOHANG, 0)) > 0) {
        /* Maybe do something.. */
        _HIP_DEBUG("Child quit with pid %d\n", pid);
    }
}

#ifndef CONFIG_HIP_OPENWRT
#ifdef CONFIG_HIP_DEBUG
/**
 * print information about underlying the system for bug reports
 */
static void hip_print_sysinfo(void)
{
    FILE *fp    = NULL;
    char str[256];
    int current = 0;
    int pipefd[2];
    int stdout_fd;
    int ch;

    fp = fopen("/etc/debian_version", "r");
    if (!fp) {
        fp = fopen("/etc/redhat-release", "r");
    }

    if (fp) {
        while (fgets(str, sizeof(str), fp)) {
            HIP_DEBUG("version=%s", str);
        }
        if (fclose(fp)) {
            HIP_ERROR("Error closing version file\n");
        }
        fp = NULL;
    }

    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        HIP_DEBUG("Printing /proc/cpuinfo\n");

        /* jk: char != int !!! */
        while ((ch = fgetc(fp)) != EOF) {
            str[current] = ch;
            /* Tabs end up broken in syslog: remove */
            if (str[current] == '\t') {
                continue;
            }
            if (str[current++] == '\n' || current == sizeof(str) - 1) {
                str[current] = '\0';
                HIP_DEBUG(str);
                current      = 0;
            }
        }

        if (fclose(fp)) {
            HIP_ERROR("Error closing /proc/cpuinfo\n");
        }
        fp = NULL;
    } else {
        HIP_ERROR("Failed to open file /proc/cpuinfo\n");
    }

    /* Route stdout into a pipe to capture lsmod output */

    stdout_fd = dup(1);
    if (stdout_fd < 0) {
        HIP_ERROR("Stdout backup failed\n");
        return;
    }
    if (pipe(pipefd)) {
        HIP_ERROR("Pipe creation failed\n");
        return;
    }
    if (dup2(pipefd[1], 1) < 0) {
        HIP_ERROR("Stdout capture failed\n");
        if (close(pipefd[1])) {
            HIP_ERROR("Error closing write end of pipe\n");
        }
        if (close(pipefd[0])) {
            HIP_ERROR("Error closing read end of pipe\n");
        }
        return;
    }

    if (system("lsmod") == -1) {
        HIP_ERROR("lsmod failed");
    }
    ;

    if (dup2(stdout_fd, 1) < 0) {
        HIP_ERROR("Stdout restore failed\n");
    }
    if (close(stdout_fd)) {
        HIP_ERROR("Error closing stdout backup\n");
    }
    if (close(pipefd[1])) {
        HIP_ERROR("Error closing write end of pipe\n");
    }

    fp = fdopen(pipefd[0], "r");
    if (fp) {
        HIP_DEBUG("Printing lsmod output\n");
        while (fgets(str, sizeof(str), fp)) {
            HIP_DEBUG(str);
        }
        if (fclose(fp)) {
            HIP_ERROR("Error closing read end of pipe\n");
        }
    } else {
        HIP_ERROR("Error opening pipe for reading\n");
        if (close(pipefd[0])) {
            HIP_ERROR("Error closing read end of pipe\n");
        }
    }
}

#endif
#endif

/**
 * Create a file with the given contents unless it already exists
 *
 * @param path the file with its path
 * @param contents a string to write to the file
 */
static void hip_create_file_unless_exists(const char *path, const char *contents)
{
    struct stat status;
    if (stat(path, &status)  == 0) {
        return;
    }

    FILE *fp     = fopen(path, "w");
    HIP_ASSERT(fp);
    size_t items = fwrite(contents, strlen(contents), 1, fp);
    HIP_ASSERT(items > 0);
    fclose(fp);
}

/**
 * load hipd configuration files
 */
static void hip_load_configuration(void)
{
    const char *cfile = "default";

    /* HIPL_CONFIG_FILE, HIPL_CONFIG_FILE_EX and so on are defined in
     * the auto-generated config.h */

    hip_create_file_unless_exists(HIPL_CONFIG_FILE, HIPL_CONFIG_FILE_EX);

    hip_create_file_unless_exists(HIPL_HOSTS_FILE, HIPL_HOSTS_FILE_EX);

    hip_create_file_unless_exists(HIPL_NSUPDATE_CONF_FILE, HIPL_NSUPDATE_CONF_FILE_EX);

    /* Load the configuration. The configuration is loaded as a sequence
     * of hipd system calls. Assumably the user socket buffer is large
     * enough to buffer all of the hipconf commands.. */

    hip_conf_handle_load(NULL, ACTION_LOAD, &cfile, 1, 1);
}

/**
 * initialize OS-dependent variables
 */
static void hip_set_os_dep_variables(void)
{
    struct utsname un;
    int rel[4] = {0};

    uname(&un);

    HIP_DEBUG("sysname=%s nodename=%s release=%s version=%s machine=%s\n",
              un.sysname, un.nodename, un.release, un.version, un.machine);

    sscanf(un.release, "%d.%d.%d.%d", &rel[0], &rel[1], &rel[2], &rel[3]);

    /*
     * 2.6.19 and above introduced some changes to kernel API names:
     * - XFRM_BEET changed from 2 to 4
     * - crypto algo names changed
     */

#ifndef CONFIG_HIP_PFKEY
    if (rel[0] <= 2 && rel[1] <= 6 && rel[2] < 19) {
        hip_xfrm_set_beet(2);
        hip_xfrm_set_algo_names(0);
    } else {
        //hip_xfrm_set_beet(1); /* TUNNEL mode */
        hip_xfrm_set_beet(4);         /* BEET mode */
        hip_xfrm_set_algo_names(1);
    }
#endif

#ifndef CONFIG_HIP_PFKEY
    /* This requires new kernel versions (the 2.6.18 patch) - jk */
    hip_xfrm_set_default_sa_prefix_len(128);
#endif
}

/**
 * Initialize raw ipv4 socket.
 */
static int hip_init_raw_sock_v4(int *hip_raw_sock_v4, int proto)
{
    int on  = 1, err = 0;
    int off = 0;

    *hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW, proto);
    hip_set_cloexec_flag(*hip_raw_sock_v4, 1);
    HIP_IFEL(*hip_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Probe kernel modules.
 */

#ifndef CONFIG_HIP_OPENWRT
#ifndef ANDROID_CHANGES
static void hip_probe_kernel_modules(void)
{
    int count, err, status;
    char cmd[40];
    int mod_total;
    char *mod_name[] =
    {
        "xfrm6_tunnel",    "xfrm4_tunnel",
        "ip6_tunnel",      "ipip",           "ip4_tunnel",
        "xfrm_user",       "dummy",          "esp6", "esp4",
        "ipv6",            "crypto_null",    "cbc",
        "blkcipher",       "des",            "aes",
        "xfrm4_mode_beet", "xfrm6_mode_beet","sha1",
        "capability"
    };

    mod_total = sizeof(mod_name) / sizeof(char *);

    HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);

    for (count = 0; count < mod_total; count++) {
        snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe", mod_name[count]);
        HIP_DEBUG("%s\n", cmd);
        err = fork();
        if (err < 0) {
            HIP_ERROR("Failed to fork() for modprobe!\n");
        } else if (err == 0) {
            /* Redirect stderr, so few non fatal errors wont show up. */
            if (freopen("/dev/null", "w", stderr) == NULL) {
                HIP_ERROR("freopen if /dev/null failed.");
            }
            ;
            execlp("/sbin/modprobe", "/sbin/modprobe", mod_name[count], (char *) NULL);
        } else {waitpid(err, &status, 0);
        }
    }

    HIP_DEBUG("Probing completed\n");
}

#endif /* ANDROID_CHANGES */
#endif /* CONFIG_HIP_OPENWRT */

/**
 * Initialize random seed.
 */
static int init_random_seed(void)
{
    struct timeval tv;
    struct timezone tz;
    struct {
        struct timeval tv;
        pid_t          pid;
        long int       rand;
    } rand_data;
    int err = 0;

    err            = gettimeofday(&tv, &tz);
    srandom(tv.tv_usec);

    memcpy(&rand_data.tv, &tv, sizeof(tv));
    rand_data.pid  = getpid();
    rand_data.rand = random();

    RAND_seed(&rand_data, sizeof(rand_data));

    return err;
}

/**
 * Init raw ipv6 socket.
 */
static int hip_init_raw_sock_v6(int *hip_raw_sock_v6, int proto)
{
    int on = 1, off = 0, err = 0;

    *hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, proto);
    hip_set_cloexec_flag(*hip_raw_sock_v6, 1);
    HIP_IFEL(*hip_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

static struct hip_host_id_entry *hip_return_first_rsa(void)
{
    hip_list_t *curr, *iter;
    struct hip_host_id_entry *tmp = NULL;
    int c;
    uint16_t algo                 = 0;

    HIP_READ_LOCK_DB(hip_local_hostid_db);

    list_for_each_safe(curr, iter, hip_local_hostid_db, c) {
        tmp  = (struct hip_host_id_entry *) list_entry(curr);
        HIP_DEBUG_HIT("Found HIT", &tmp->lhi.hit);
        algo = hip_get_host_id_algo(tmp->host_id);
        HIP_DEBUG("hits algo %d HIP_HI_RSA = %d\n",
                  algo, HIP_HI_RSA);
        if (algo == HIP_HI_RSA) {
            goto out_err;
        }
    }

out_err:
    HIP_READ_UNLOCK_DB(hip_local_hostid_db);
    if (algo == HIP_HI_RSA) {
        return tmp;
    }
    return NULL;
}

/**
 * Initialize host IDs.
 */
static int hip_init_host_ids(void)
{
    int err                     = 0;
    struct stat status;
    struct hip_common *user_msg = NULL;
    hip_hit_t default_hit;
    hip_lsi_t default_lsi;

    /* We are first serializing a message with HIs and then
     * deserializing it. This building and parsing causes
     * a minor overhead, but as a result we can reuse the code
     * with hipconf. */

    HIP_IFE(!(user_msg = hip_msg_alloc()), -1);

    /* Create default keys if necessary. */

    if (stat(DEFAULT_CONFIG_DIR "/" DEFAULT_HOST_RSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX, &status) && errno == ENOENT) {
        //hip_msg_init(user_msg); already called by hip_msg_alloc()

        HIP_IFEL(hip_serialize_host_id_action(user_msg, ACTION_NEW, 0, 1,
                                              NULL, NULL, RSA_KEY_DEFAULT_BITS, DSA_KEY_DEFAULT_BITS),
                 1, "Failed to create keys to %s\n", DEFAULT_CONFIG_DIR);
    }

    /* Retrieve the keys to hipd */
    /* Three steps because multiple large keys will not fit in the same message */

    /* DSA keys and RSA anonymous are not loaded by default until bug id
     * 522 is properly solved. Run hipconf add hi default if you want to
     * enable non-default HITs. */
#if 0
    /* dsa anon and pub */
    hip_msg_init(user_msg);
    if (err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
                                           0, 1, "dsa", NULL, 0, 0)) {
        HIP_ERROR("Could not load default keys (DSA)\n");
        goto out_err;
    }
    if (err = hip_handle_add_local_hi(user_msg)) {
        HIP_ERROR("Adding of keys failed (DSA)\n");
        goto out_err;
    }

    /* rsa anon */
    hip_msg_init(user_msg);
    if (err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
                                           1, 1, "rsa", NULL, 0, 0)) {
        HIP_ERROR("Could not load default keys (RSA anon)\n");
        goto out_err;
    }
    if (err = hip_handle_add_local_hi(user_msg)) {
        HIP_ERROR("Adding of keys failed (RSA anon)\n");
        goto out_err;
    }
#endif

    /* rsa pub */
    hip_msg_init(user_msg);
    if ((err = hip_serialize_host_id_action(user_msg, ACTION_ADD,
                                            0, 1, "rsa", NULL, 0, 0))) {
        HIP_ERROR("Could not load default keys (RSA pub)\n");
        goto out_err;
    }

    if ((err = hip_handle_add_local_hi(user_msg))) {
        HIP_ERROR("Adding of keys failed (RSA pub)\n");
        goto out_err;
    }

    HIP_DEBUG("Keys added\n");
    hip_get_default_hit(&default_hit);
    hip_get_default_lsi(&default_lsi);

    HIP_DEBUG_HIT("default_hit ", &default_hit);
    HIP_DEBUG_LSI("default_lsi ", &default_lsi);
    hip_hidb_associate_default_hit_lsi(&default_hit, &default_lsi);

    /*Initializes the hadb with the information contained in /etc/hip/hosts*/
    //hip_init_hadb_hip_host();

out_err:

    if (user_msg) {
        HIP_FREE(user_msg);
    }

    return err;
}

static int hip_init_certs(void)
{
    int err = 0;
    char hit[41];
    FILE *conf_file;
    struct hip_host_id_entry *entry;
    char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];

    memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
    HIP_IFEL(gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1), -1,
             "gethostname failed\n");

    conf_file = fopen(HIP_CERT_CONF_PATH, "r");
    if (!conf_file) {
        HIP_DEBUG("Configuration file did NOT exist creating it and "
                  "filling it with default information\n");
        HIP_IFEL(!memset(hit, '\0', sizeof(hit)), -1,
                 "Failed to memset memory for hit presentation format\n");
        /* Fetch the first RSA HIT */
        entry = hip_return_first_rsa();
        if (entry == NULL) {
            HIP_DEBUG("Failed to get the first RSA HI");
            goto out_err;
        }
        hip_in6_ntop(&entry->lhi.hit, hit);
        conf_file = fopen(HIP_CERT_CONF_PATH, "w+");
        fprintf(conf_file,
                "# Section containing SPKI related information\n"
                "#\n"
                "# issuerhit = what hit is to be used when signing\n"
                "# days = how long is this key valid\n"
                "\n"
                "[ hip_spki ]\n"
                "issuerhit = %s\n"
                "days = %d\n"
                "\n"
                "# Section containing HIP related information\n"
                "#\n"
                "# issuerhit = what hit is to be used when signing\n"
                "# days = how long is this key valid\n"
                "\n"
                "[ hip_x509v3 ]\n"
                "issuerhit = %s\n"
                "days = %d\n"
                "\n"
                "#Section containing the name section for the x509v3 issuer name"
                "\n"
                "[ hip_x509v3_name ]\n"
                "issuerhit = %s\n"
                "\n"
                "# Uncomment this section to add x509 extensions\n"
                "# to the certificate\n"
                "#\n"
                "# DO NOT use subjectAltName, issuerAltName or\n"
                "# basicConstraints implementation uses them already\n"
                "# All other extensions are allowed\n"
                "\n"
                "# [ hip_x509v3_extensions ]\n",
                hit, HIP_CERT_INIT_DAYS,
                hit, HIP_CERT_INIT_DAYS,
                hit /* TODO SAMU: removed because not used:*/  /*, hostname*/);
        fclose(conf_file);
    } else {
        HIP_DEBUG("Configuration file existed exiting hip_init_certs\n");
    }
out_err:
    return err;
}

static void hip_init_packet_types(void)
{
    lmod_register_packet_type(HIP_I1,        "HIP_I1");
    lmod_register_packet_type(HIP_R1,        "HIP_R1");
    lmod_register_packet_type(HIP_I2,        "HIP_I2");
    lmod_register_packet_type(HIP_R2,        "HIP_R2");
    lmod_register_packet_type(HIP_CER,       "HIP_CER");
    lmod_register_packet_type(HIP_BOS,       "HIP_BOS");
    lmod_register_packet_type(HIP_NOTIFY,    "HIP_NOTIFY");
    lmod_register_packet_type(HIP_CLOSE,     "HIP_CLOSE");
    lmod_register_packet_type(HIP_CLOSE_ACK, "HIP_CLOSE_ACK");
    lmod_register_packet_type(HIP_HDRR,      "HIP_HDRR");
    lmod_register_packet_type(HIP_PSIG,      "HIP_PSIG");
    lmod_register_packet_type(HIP_TRIG,      "HIP_TRIG");
    lmod_register_packet_type(HIP_LUPDATE,   "HIP_LUPDATE");
    lmod_register_packet_type(HIP_DATA,      "HIP_DATA");
    lmod_register_packet_type(HIP_PAYLOAD,   "HIP_PAYLOAD");
}

static int hip_init_handle_functions(void)
{
    int err = 0;

    HIP_DEBUG("Initialize handle functions.\n");

    hip_register_handle_function(HIP_I1, HIP_STATE_UNASSOCIATED, &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_UNASSOCIATED, &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_I1_SENT,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_I1_SENT,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_I2_SENT,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_I2_SENT,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_R2_SENT,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_R2_SENT,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_ESTABLISHED,  &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_ESTABLISHED,  &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_CLOSING,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_CLOSING,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_CLOSED,       &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_CLOSED,       &hip_send_r1, 1100);
    hip_register_handle_function(HIP_I1, HIP_STATE_NONE,         &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_I1, HIP_STATE_NONE,         &hip_send_r1, 1100);

    hip_register_handle_function(HIP_DATA, HIP_STATE_UNASSOCIATED, &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_UNASSOCIATED, &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_I1_SENT,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_I1_SENT,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_I2_SENT,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_I2_SENT,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_R2_SENT,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_R2_SENT,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_ESTABLISHED,  &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_ESTABLISHED,  &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_CLOSING,      &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_CLOSING,      &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_CLOSED,       &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_CLOSED,       &hip_send_r1, 1100);
    hip_register_handle_function(HIP_DATA, HIP_STATE_NONE,         &hip_handle_i1, 1000);
    hip_register_handle_function(HIP_DATA, HIP_STATE_NONE,         &hip_send_r1, 1100);

    hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED, &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_UNASSOCIATED, &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,      &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_I1_SENT,      &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,      &hip_handle_i2_in_i2_sent, 900);
    hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,      &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_I2_SENT,      &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,      &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_R2_SENT,      &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_ESTABLISHED,  &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_ESTABLISHED,  &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_CLOSING,      &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_CLOSING,      &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_CLOSED,       &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_CLOSED,       &hip_send_r2, 1100);
    hip_register_handle_function(HIP_I2, HIP_STATE_NONE,         &hip_handle_i2, 1000);
    hip_register_handle_function(HIP_I2, HIP_STATE_NONE,         &hip_send_r2, 1100);

    hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT, &hip_handle_r1, 1000);
    hip_register_handle_function(HIP_R1, HIP_STATE_I1_SENT, &hip_send_i2, 1100);
    hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT, &hip_handle_r1, 1000);
    hip_register_handle_function(HIP_R1, HIP_STATE_I2_SENT, &hip_send_i2, 1100);
    hip_register_handle_function(HIP_R1, HIP_STATE_CLOSING, &hip_handle_r1, 1000);
    hip_register_handle_function(HIP_R1, HIP_STATE_CLOSING, &hip_send_i2, 1100);
    hip_register_handle_function(HIP_R1, HIP_STATE_CLOSED,  &hip_handle_r1, 1000);
    hip_register_handle_function(HIP_R1, HIP_STATE_CLOSED,  &hip_send_i2, 1100);

    hip_register_handle_function(HIP_R2, HIP_STATE_I2_SENT, &hip_handle_r2, 1000);

    hip_register_handle_function(HIP_NOTIFY, HIP_STATE_I1_SENT,     &hip_handle_notify, 1000);
    hip_register_handle_function(HIP_NOTIFY, HIP_STATE_I2_SENT,     &hip_handle_notify, 1000);
    hip_register_handle_function(HIP_NOTIFY, HIP_STATE_R2_SENT,     &hip_handle_notify, 1000);
    hip_register_handle_function(HIP_NOTIFY, HIP_STATE_ESTABLISHED, &hip_handle_notify, 1000);
    hip_register_handle_function(HIP_NOTIFY, HIP_STATE_CLOSING,     &hip_handle_notify, 1000);
    hip_register_handle_function(HIP_NOTIFY, HIP_STATE_CLOSED,      &hip_handle_notify, 1000);

    hip_register_handle_function(HIP_CLOSE, HIP_STATE_ESTABLISHED,  &hip_handle_close, 1000);
    hip_register_handle_function(HIP_CLOSE, HIP_STATE_CLOSING,      &hip_handle_close, 1000);

    hip_register_handle_function(HIP_CLOSE_ACK, HIP_STATE_CLOSING, &hip_handle_close_ack, 1000);
    hip_register_handle_function(HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_handle_close_ack, 1000);

    hip_register_handle_function(HIP_CLOSE_ACK, HIP_STATE_CLOSED,  &hip_handle_close_ack, 1000);

    hip_register_handle_function(HIP_BOS, HIP_STATE_UNASSOCIATED, &hip_handle_bos, 1000);
    hip_register_handle_function(HIP_BOS, HIP_STATE_I1_SENT,      &hip_handle_bos, 1000);
    hip_register_handle_function(HIP_BOS, HIP_STATE_I2_SENT,      &hip_handle_bos, 1000);

    hip_register_handle_function(HIP_LUPDATE, HIP_STATE_ESTABLISHED, &esp_prot_handle_light_update, 1000);
    hip_register_handle_function(HIP_LUPDATE, HIP_STATE_R2_SENT,     &esp_prot_handle_light_update, 1000);

    return err;
}

/**
 * Main initialization function for HIP daemon.
 *
 * @param flush_ipsec one if ipsec should be flushed or zero otherwise
 * @param killold one if an existing hipd process should be killed or
 *                zero otherwise
 * @return zero on success or negative on failure
 */
int hipd_init(int flush_ipsec, int killold)
{
    int err              = 0, certerr = 0, hitdberr = 0, i;
    unsigned int mtu_val = HIP_HIT_DEV_MTU;
    char str[64];
    char mtu[16];
    struct sockaddr_in6 daemon_addr;

    memset(str, 0, 64);
    memset(mtu, 0, 16);

    /* Make sure that root path is set up correcly (e.g. on Fedora 9).
     * Otherwise may get warnings from system() commands.
     * @todo: should append, not overwrite  */
    setenv("PATH", HIP_DEFAULT_EXEC_PATH, 1);

    /* Open daemon lock file and read pid from it. */
    HIP_IFEL(hip_create_lock_file(HIP_DAEMON_LOCK_FILE, killold), -1,
             "locking failed\n");

    hip_init_hostid_db(NULL);

    hip_set_os_dep_variables();

    hip_init_packet_types();

    hip_init_handle_functions();

    hip_register_maint_function(&hip_nat_refresh_port,         10000);
    hip_register_maint_function(&hip_relht_maintenance,        20000);
    hip_register_maint_function(&hip_registration_maintenance, 30000);

#ifndef CONFIG_HIP_OPENWRT
#ifdef CONFIG_HIP_DEBUG
    hip_print_sysinfo();
#endif
#ifndef ANDROID_CHANGES
    hip_probe_kernel_modules();
#endif
#endif

    /* Register signal handlers */
    signal(SIGINT, hip_close);
    signal(SIGTERM, hip_close);
    signal(SIGCHLD, hip_sig_chld);

#ifdef CONFIG_HIP_OPPORTUNISTIC
    HIP_IFEL(hip_init_oppip_db(), -1,
             "Cannot initialize opportunistic mode IP database for " \
             "non HIP capable hosts!\n");
#endif
    HIP_IFEL((hip_init_cipher() < 0), 1, "Unable to init ciphers.\n");

    HIP_IFE(init_random_seed(), -1);

    hip_init_hadb();
    /* hip_init_puzzle_defaults just returns, removed -samu  */
#if 0
    hip_init_puzzle_defaults();
#endif

#ifdef CONFIG_HIP_OPPORTUNISTIC
    hip_init_opp_db();
#endif


    /* Resolve our current addresses, afterwards the events from kernel
     * will maintain the list This needs to be done before opening
     * NETLINK_ROUTE! See the comment about address_count global var. */
    HIP_DEBUG("Initializing the netdev_init_addresses\n");

    hip_netdev_init_addresses(&hip_nl_ipsec);

    if (rtnl_open_byproto(&hip_nl_route,
                          RTMGRP_LINK | RTMGRP_IPV6_IFADDR | IPPROTO_IPV6
                          | RTMGRP_IPV4_IFADDR | IPPROTO_IP,
                          NETLINK_ROUTE) < 0) {
        err = 1;
        HIP_ERROR("Routing socket error: %s\n", strerror(errno));
        goto out_err;
    }

    /* Open the netlink socket for address and IF events */
    if (rtnl_open_byproto(&hip_nl_ipsec, XFRMGRP_ACQUIRE, NETLINK_XFRM) < 0) {
        HIP_ERROR("Netlink address and IF events socket error: %s\n",
                  strerror(errno));
        err = 1;
        goto out_err;
    }

#ifndef CONFIG_HIP_PFKEY
    hip_xfrm_set_nl_ipsec(&hip_nl_ipsec);
#endif

#if 0
    {
        int ret_sockopt            = 0, value = 0;
        socklen_t value_len        = sizeof(value);
        int ipsec_buf_size         = 200000;
        socklen_t ipsec_buf_sizeof = sizeof(ipsec_buf_size);
        ret_sockopt    = getsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_RCVBUF,
                                    &value, &value_len);
        if (ret_sockopt != 0) {
            HIP_DEBUG("Getting receive buffer size of hip_nl_ipsec.fd failed\n");
        }
        ipsec_buf_size = value * 2;
        HIP_DEBUG("Default setting of receive buffer size for hip_nl_ipsec was %d.\n"
                  "Setting it to %d.\n", value, ipsec_buf_size);
        ret_sockopt    = setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_RCVBUF,
                                    &ipsec_buf_size, ipsec_buf_sizeof);
        if (ret_sockopt != 0) {
            HIP_DEBUG("Setting receive buffer size of hip_nl_ipsec.fd failed\n");
        }
        ret_sockopt    = 0;
        ret_sockopt    = setsockopt(hip_nl_ipsec.fd, SOL_SOCKET, SO_SNDBUF,
                                    &ipsec_buf_size, ipsec_buf_sizeof);
        if (ret_sockopt != 0) {
            HIP_DEBUG("Setting send buffer size of hip_nl_ipsec.fd failed\n");
        }
    }
#endif

    HIP_IFEL(hip_init_raw_sock_v6(&hip_raw_sock_output_v6, IPPROTO_HIP), -1, "raw sock output v6\n");
    HIP_IFEL(hip_init_raw_sock_v4(&hip_raw_sock_output_v4, IPPROTO_HIP), -1, "raw sock output v4\n");
    /* hip_nat_sock_input should be initialized after hip_nat_sock_output
       because for the sockets bound to the same address/port, only the last socket seems
       to receive the packets. NAT input socket is a normal UDP socket where as
       NAT output socket is a raw socket. A raw output socket support better the "shotgun"
       extension (sending packets from multiple source addresses). */
    HIP_IFEL(hip_init_raw_sock_v4(&hip_nat_sock_output_udp, IPPROTO_UDP), -1, "raw sock output udp\n");
    HIP_IFEL(hip_init_raw_sock_v6(&hip_raw_sock_input_v6, IPPROTO_HIP), -1, "raw sock input v6\n");
    HIP_IFEL(hip_init_raw_sock_v4(&hip_raw_sock_input_v4, IPPROTO_HIP), -1, "raw sock input v4\n");
    HIP_IFEL(hip_create_nat_sock_udp(&hip_nat_sock_input_udp, 0, 0), -1, "raw sock input udp\n");

    HIP_DEBUG("hip_raw_sock_v6 input = %d\n", hip_raw_sock_input_v6);
    HIP_DEBUG("hip_raw_sock_v6 output = %d\n", hip_raw_sock_output_v6);
    HIP_DEBUG("hip_raw_sock_v4 input = %d\n", hip_raw_sock_input_v4);
    HIP_DEBUG("hip_raw_sock_v4 output = %d\n", hip_raw_sock_output_v4);
    HIP_DEBUG("hip_nat_sock_udp input = %d\n", hip_nat_sock_input_udp);
    HIP_DEBUG("hip_nat_sock_udp output = %d\n", hip_nat_sock_output_udp);

    if (flush_ipsec) {
        hip_flush_all_sa();
        hip_flush_all_policy();
    }

    HIP_DEBUG("Setting SP\n");
    hip_delete_default_prefix_sp_pair();
    HIP_IFE(hip_setup_default_sp_prefix_pair(), -1);

    HIP_DEBUG("Setting iface %s\n", HIP_HIT_DEV);
    set_up_device(HIP_HIT_DEV, 0);
    HIP_IFE(set_up_device(HIP_HIT_DEV, 1), 1);
    HIP_DEBUG("Lowering MTU of dev " HIP_HIT_DEV " to %u\n", mtu_val);
    sprintf(mtu, "%u", mtu_val);
    strcpy(str, "ifconfig dummy0 mtu ");
    strcat(str, mtu);
    /* MTU is set using system call rather than in do_chflags to avoid
     * chicken and egg problems in hipd start up. */
    if (system(str) == -1) {
        HIP_ERROR("Exec %s failed", str);
    }


    HIP_IFE(hip_init_host_ids(), 1);

    hip_user_sock           = socket(AF_INET6, SOCK_DGRAM, 0);
    HIP_IFEL((hip_user_sock < 0), 1,
             "Could not create socket for user communication.\n");
    bzero(&daemon_addr, sizeof(daemon_addr));
    daemon_addr.sin6_family = AF_INET6;
    daemon_addr.sin6_port   = htons(HIP_DAEMON_LOCAL_PORT);
    daemon_addr.sin6_addr   = in6addr_loopback;
    hip_set_cloexec_flag(hip_user_sock, 1);

    HIP_IFEL(bind(hip_user_sock, (struct sockaddr *) &daemon_addr,
                  sizeof(daemon_addr)), -1,
             "Bind on daemon addr failed\n");

    hip_load_configuration();

    certerr = 0;
    certerr = hip_init_certs();
    if (certerr < 0) {
        HIP_DEBUG("Initializing cert configuration file returned error\n");
    }

    hitdberr = 0;

    /* Service initialization. */
    hip_init_services();

#ifdef CONFIG_HIP_RVS
    HIP_INFO("Initializing HIP relay / RVS.\n");
    hip_relay_init();
#endif

#ifdef CONFIG_HIP_PRIVSEP
    HIP_IFEL(hip_set_lowcapability(0), -1, "Failed to set capabilities\n");
#endif /* CONFIG_HIP_PRIVSEP */

    hip_firewall_sock_lsi_fd = hip_user_sock;

    if (hip_get_nsupdate_status()) {
        nsupdate(1);
    }

    /* Initialize modules */
    HIP_INFO("Initializing modules.\n");
    for (i = 0; i < num_modules_hipd; i++) {
        HIP_DEBUG("module: %s\n", modules_hipd[i]);
        if (lmod_module_disabled(modules_hipd[i])) {
            HIP_DEBUG("state:  DISABLED\n");
            continue;
        } else {
            HIP_DEBUG("state:  ENABLED\n");
            HIP_IFEL(hipd_init_functions[i](),
                     -1,
                     "Module initialization failed.\n");
        }
    }

    hip_init_sockets();

out_err:
    return err;
}

int hip_set_cloexec_flag(int desc, int value)
{
    int oldflags = fcntl(desc, F_GETFD, 0);
    /* If reading the flags failed, return error indication now.*/
    if (oldflags < 0) {
        return oldflags;
    }
    /* Set just the flag we want to set. */

    if (value != 0) {
        oldflags |= FD_CLOEXEC;
    } else {
        oldflags &= ~FD_CLOEXEC;
    }
    /* Store modified flag word in the descriptor. */
    return fcntl(desc, F_SETFD, oldflags);
}

/**
 * Creates a UDP socket for NAT traversal.
 *
 * @param  hip_nat_sock_udp a pointer to the UDP socket.
 * @param sockaddr_in the address that will be used to create the
 *                 socket. If NULL is passed, INADDR_ANY is used.
 * @param is_output 1 if the socket is for output, otherwise 0
 *
 * @return zero on success, negative error value on error.
 */
int hip_create_nat_sock_udp(int *hip_nat_sock_udp,
                            struct sockaddr_in *addr,
                            int is_output)
{
    int on  = 1, err = 0;
    int off = 0;
    struct sockaddr_in myaddr;
    int type, protocol;

    if (is_output) {
        type     = SOCK_RAW;
        protocol = IPPROTO_UDP;
    } else {
        type     = SOCK_DGRAM;
        protocol = 0;
    }

    HIP_DEBUG("\n");

    if ((*hip_nat_sock_udp = socket(AF_INET, type, protocol)) < 0) {
        HIP_ERROR("Can not open socket for UDP\n");
        return -1;
    }
    hip_set_cloexec_flag(*hip_nat_sock_udp, 1);
    err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp pktinfo failed\n");
    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp recverr failed\n");
        #ifndef CONFIG_HIP_OPENWRT
    if (!is_output) {
        int encap_on = HIP_UDP_ENCAP_ESPINUDP;
        err = setsockopt(*hip_nat_sock_udp, SOL_UDP, HIP_UDP_ENCAP, &encap_on, sizeof(encap_on));
    }
    HIP_IFEL(err, -1, "setsockopt udp encap failed\n");
        #endif
    err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");
    err = setsockopt(*hip_nat_sock_udp, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt udp reuseaddr failed\n");

    if (is_output) {
        err = setsockopt(*hip_nat_sock_udp, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on));
    }
    HIP_IFEL(err, -1, "setsockopt hdr include failed\n");

    if (addr) {
        memcpy(&myaddr, addr, sizeof(struct sockaddr_in));
    } else {
        myaddr.sin_family      = AF_INET;
        /** @todo Change this inaddr_any -- Abi */
        myaddr.sin_addr.s_addr = INADDR_ANY;

        myaddr.sin_port        = htons(hip_get_local_nat_udp_port());
    }

    err = bind(*hip_nat_sock_udp, (struct sockaddr *) &myaddr, sizeof(myaddr));
    if (err < 0) {
        HIP_PERROR("Unable to bind udp socket to port\n");
        err = -1;
        goto out_err;
    }

    HIP_DEBUG_INADDR("UDP socket created and bound to addr", (struct in_addr *) &myaddr.sin_addr.s_addr);

out_err:
    return err;
}

/**
 * exit gracefully by sending CLOSE to all peers
 *
 * @param signal the signal hipd received from OS
 */
void hip_close(int signal)
{
    static int terminate = 0;

    HIP_ERROR("Signal: %d\n", signal);
    terminate++;

    /* Close SAs with all peers */
    if (terminate == 1) {
        hip_send_close(NULL, FLUSH_HA_INFO_DB);
        hipd_set_state(HIPD_STATE_CLOSING);
        HIP_DEBUG("Starting to close HIP daemon...\n");
    } else if (terminate == 2) {
        HIP_DEBUG("Send still once this signal to force daemon exit...\n");
    } else if (terminate > 2) {
        HIP_DEBUG("Terminating daemon.\n");
        hip_exit(signal);
        exit(signal);
    }
}

/**
 * Cleanup and signal handler to free userspace and kernel space
 * resource allocations.
 *
 * @param signal the signal hipd received
 */
void hip_exit(int signal)
{
    HIP_ERROR("Signal: %d\n", signal);

    hip_delete_default_prefix_sp_pair();
    /* Close SAs with all peers */
    // hip_send_close(NULL);

    hip_delete_all_sp();

    hip_delete_all_addresses();

    set_up_device(HIP_HIT_DEV, 0);

    /* Next line is needed only if RVS or hiprelay is in use. */
    hip_uninit_services();

    hip_uninit_handle_functions();

    hip_uninit_maint_functions();

    lmod_uninit_packet_types();

#ifdef CONFIG_HIP_OPPORTUNISTIC
    hip_oppdb_uninit();
#endif

#ifdef CONFIG_HIP_RVS
    HIP_INFO("Uninitializing RVS / HIP relay database and whitelist.\n");
    hip_relay_uninit();
#endif

    if (hip_raw_sock_input_v6) {
        HIP_INFO("hip_raw_sock_input_v6\n");
        close(hip_raw_sock_input_v6);
    }

    if (hip_raw_sock_output_v6) {
        HIP_INFO("hip_raw_sock_output_v6\n");
        close(hip_raw_sock_output_v6);
    }

    if (hip_raw_sock_input_v4) {
        HIP_INFO("hip_raw_sock_input_v4\n");
        close(hip_raw_sock_input_v4);
    }

    if (hip_raw_sock_output_v4) {
        HIP_INFO("hip_raw_sock_output_v4\n");
        close(hip_raw_sock_output_v4);
    }

    if (hip_nat_sock_input_udp) {
        HIP_INFO("hip_nat_sock_input_udp\n");
        close(hip_nat_sock_input_udp);
    }

    if (hip_nat_sock_output_udp) {
        HIP_INFO("hip_nat_sock_output_udp\n");
        close(hip_nat_sock_output_udp);
    }

    if (hip_nat_sock_input_udp_v6) {
        HIP_INFO("hip_nat_sock_input_udp_v6\n");
        close(hip_nat_sock_input_udp_v6);
    }

    if (hip_nat_sock_output_udp_v6) {
        HIP_INFO("hip_nat_sock_output_udp_v6\n");
        close(hip_nat_sock_output_udp_v6);
    }

    hip_uninit_hadb();
    hip_uninit_host_id_dbs();

    if (hip_user_sock) {
        HIP_INFO("hip_user_sock\n");
        close(hip_user_sock);
    }
    if (hip_nl_ipsec.fd) {
        HIP_INFO("hip_nl_ipsec.fd\n");
        rtnl_close(&hip_nl_ipsec);
    }
    if (hip_nl_route.fd) {
        HIP_INFO("hip_nl_route.fd\n");
        rtnl_close(&hip_nl_route);
    }

    hip_remove_lock_file(HIP_DAEMON_LOCK_FILE);

#ifdef CONFIG_HIP_PERFORMANCE
    /* Deallocate memory of perf_set after finishing all of tests */
    hip_perf_destroy(perf_set);
#endif

    hip_dh_uninit();

    lmod_uninit_disabled_modules();

    return;
}
