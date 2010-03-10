/** @file lib/conf/hipconf
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This library is used to configure HIP daemon (hipd) dynamically
 * with the hipconf command line tool. Hipd uses this library also to
 * parse the static configuration from @c /etc/hip/hipd_config (the file
 * has same syntax as hipconf).
 *
 * All new messages have to be registered into the action_handler
 * array defined in the end of this file. You will have to register
 * also action and type handlers. See hip_conf_get_action(),
 * hip_conf_check_action_argc() and hip_conf_get_type()
 *
 * @brief This file defines functions for configuring the the Host Identity
 * Protocol daemon (hipd).
 *
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @author  Tao Wan  <twan@cc.hut.fi>
 * @author  Teresa Finez <tfinezmo_cc.hut.fi> Modifications
 * @author  Samu Varjonen
 * @todo    del map
 * @todo    fix the rst kludges
 * @todo    read the output message from send_msg?
 * @todo    adding of new extensions should be made simpler
 */

/* required for ifreq */
#define _BSD_SOURCE

#include <sys/ioctl.h>

#include "config.h"
#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/straddr.h"
#include "hipconf.h"
#include "lib/core/prefix.h"
#include "lib/dht/libhipdht.h"
#include "lib/core/hostid.h"
#include "lib/core/message.h"
#include "lib/core/crypto.h"

/**
 * TYPE_ constant list, as an index for each action_handler function.
 *
 * @note Important! These values are used as array indexes, so keep these
 *       in order. If you add a constant TYPE_NEWTYPE here, the value of
 *       TYPE_NEWTYPE must be a correct index for looking up its corresponding
 *       handler function in action_handler[]. Add values after the last value
 *       and increment TYPE_MAX.
 */
/* 0 is reserved */
#define TYPE_HI            1
#define TYPE_MAP           2
#define TYPE_RST           3
#define TYPE_SERVER        4
#define TYPE_BOS           5
#define TYPE_PUZZLE        6
#define TYPE_NAT           7
#define TYPE_OPP           EXEC_LOADLIB_OPP /* Should be 8 */
#define TYPE_BLIND         9
#define TYPE_SERVICE       10
#define TYPE_CONFIG        11
#define TYPE_RUN           EXEC_LOADLIB_HIP /* Should be 12 */
#define TYPE_TTL           13
#define TYPE_GW            14
#define TYPE_GET           15
#define TYPE_HA            16
#define TYPE_MHADDR        17
#define TYPE_DEBUG         18
#define TYPE_DAEMON        19
#define TYPE_LOCATOR       20
#define TYPE_SET           21 /* DHT set <name> */
#define TYPE_DHT           22
#define TYPE_OPPTCP        23
#define TYPE_ORDER         24
#define TYPE_TCPTIMEOUT    25 /* add By Tao Wan, on 04.01.2008*/
#define TYPE_HIPPROXY      26
#define TYPE_HEARTBEAT     27
#define TYPE_HI3           28
/* free slot (was for TYPE_GET_PEER_LSI  29) */
#define TYPE_BUDDIES       30
/* free slot */
#define TYPE_NSUPDATE      32
#define TYPE_HIT_TO_IP     33
#define TYPE_HIT_TO_IP_SET 34
#define TYPE_HIT_TO_LSI    35
#define TYPE_NAT_LOCAL_PORT 36
#define TYPE_NAT_PEER_PORT 37
#define TYPE_DATAPACKET    38 /*support for data packet mode-- Prabhu */
#define TYPE_SHOTGUN       39
#define TYPE_ID_TO_ADDR    40
#define TYPE_LSI_TO_HIT    41
#define TYPE_HANDOVER      42
#define TYPE_MANUAL_UPDATE 43
#define TYPE_MAX           44 /* exclusive */

/* #define TYPE_RELAY         22 */

/**
 * A help string containing the usage of @c hipconf and also
 * @c /etc/hip/hipd_config.
 *
 * @note If you added a new action, do not forget to add a brief usage below
 *       for the action.
 */
const char *hipconf_usage =
    "add|del map <hit> <ipv6> [lsi]\n"
    "del hi <hit>|all\n"
    "get hi default|all\n"
    "new|add hi anon|pub rsa|dsa filebasename\n"
    "new hi anon|pub rsa|dsa filebasename keylen\n"
    "new|add hi default (HI must be created as root)\n"
    "new hi default rsa_keybits dsa_keybits\n"
    "get|inc|dec|new puzzle all\n"
    "set puzzle all new_value\n"
    "bos all\n"
    "nat none|plain-udp\n"
    "nat port local <port>\n"
    "nat port peer <port>\n"
    "rst all|peer_hit <peer_HIT>\n"
    "load config default\n"
    "mhaddr mode lazy|active\n"
    "handover mode hard|soft\n"
    "Server side:\n"
    "\tadd|del service rvs|relay|full-relay\n"
    "\treinit service rvs|relay|full-relay\n"
    "Client side:\n"
    "\tadd server rvs|relay|full-relay [HIT] <IP|hostname> <lifetime in seconds>\n"
    "\tdel server rvs|relay|full-relay [HIT] <IP|hostname>\n"
#ifdef CONFIG_HIP_BLIND
    "set blind on|off\n"
#endif
#ifdef CONFIG_HIP_OPPORTUNISTIC
    "set opp normal|advanced|none\n"
#endif
    "heartbeat <seconds> (0 seconds means off)\n"
    "get ha all|HIT\n"
    "opendht on|off\n"
    "dht gw <IPv4|hostname> <port (OpenDHT default = 5851)> <TTL>\n"
    "dht get <fqdn/hit>\n"
    "dht set <name>\n"
    "locator on|off|get\n"
    "debug all|medium|none\n"
    "restart daemon\n"
    "set tcptimeout on|off\n" /*added by Tao Wan*/
    "transform order <integer> "
    " (1=AES, 2=3DES, 3=NULL and place them to order\n"
    "  like 213 for the order 3DES, AES and NULL)\n"
#ifdef CONFIG_HIP_HIPPROXY
    "hipproxy on|off\n"
#endif
    "manual-update <interface>\n"
    "hi3 on|off\n"
    "nsupdate on|off\n"
    "hit-to-ip on|off\n"
    "hit-to-ip-zone <hit-to-ip.zone.>\n"
    "buddies on|off\n"
    "datapacket on|off\n"
    "shotgun on|off\n"
    "id-to-addr hit|lsi\n"
;

/**
 * Query hipd for the HITs of the local host
 *
 * @param msg input/output message for the query/response for hipd
 * @param opt "all" to query for all HITs or "default" for the default
 * @param optc currently 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_get_hits(hip_common_t *msg, const char *opt, int optc, int send_only)
{
    int err                              = 0;
    struct hip_tlv_common *current_param = NULL;
    struct hip_hit_info *data;
    struct in_addr *deflsi               = NULL;
    in6_addr_t *defhit                   = NULL;
    hip_tlv_type_t param_type            = 0;
    char hit_s[INET6_ADDRSTRLEN], lsi_s[INET_ADDRSTRLEN];

    if (strcmp(opt, "all") == 0) {
        /* Build a HIP message with socket option to get default HIT. */
        HIP_IFE(hip_build_user_hdr(msg, SO_HIP_GET_HITS, 0), -1);
        /* Send the message to the daemon. The daemon fills the
         * message. */
        HIP_IFE(hip_send_recv_daemon_info(msg, send_only, 0), -ECOMM);

        /* Loop through all the parameters in the message just filled. */
        while ((current_param =
                    hip_get_next_param(msg, current_param)) != NULL) {
            param_type = hip_get_param_type(current_param);

            if (param_type == HIP_PARAM_HIT_INFO) {
                data = (struct hip_hit_info *)
                       hip_get_param_contents_direct(
                    current_param);
                inet_ntop(AF_INET6, &data->lhi.hit, hit_s,
                          INET6_ADDRSTRLEN);

                if (data->lhi.anonymous) {
                    HIP_INFO("Anonymous");
                } else {
                    HIP_INFO("Public   ");
                }

                if (data->lhi.algo == HIP_HI_RSA) {
                    HIP_INFO(" RSA ");
                } else if (data->lhi.algo == HIP_HI_DSA) {
                    HIP_INFO(" DSA ");
                } else {
                    HIP_INFO(" Unknown algorithm (%d) ",
                             data->lhi.algo);
                }
                HIP_INFO("%s", hit_s);

                inet_ntop(AF_INET, &data->lsi, lsi_s,
                          INET_ADDRSTRLEN);

                HIP_INFO("     LSI %s\n", lsi_s);
            } else {
                HIP_ERROR("Unrelated parameter in user " \
                          "message.\n");
            }
        }
    } else if (strcmp(opt, "default") == 0) {
        /* Build a HIP message with socket option to get default HIT. */
        HIP_IFE(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT, 0), -1);
        /* Send the message to the daemon. The daemon fills the
         * message. */
        HIP_IFE(hip_send_recv_daemon_info(msg, send_only, 0), -ECOMM);

        /* Loop through all the parameters in the message just filled. */
        while ((current_param =
                    hip_get_next_param(msg, current_param)) != NULL) {
            param_type = hip_get_param_type(current_param);

            if (param_type == HIP_PARAM_HIT) {
                defhit = (struct in6_addr *)
                         hip_get_param_contents_direct(
                    current_param);
                inet_ntop(AF_INET6, defhit, hit_s,
                          INET6_ADDRSTRLEN);
            } else if (param_type == HIP_PARAM_LSI) {
                deflsi = (struct in_addr *)
                         hip_get_param_contents_direct(
                    current_param);
                inet_ntop(AF_INET, deflsi, lsi_s,
                          INET_ADDRSTRLEN);
            } else {
                HIP_ERROR("Unrelated parameter in user " \
                          "message.\n");
            }
        }

        HIP_INFO("Default HIT: %s\nDefault LSI: %s\n", hit_s, lsi_s);
    } else {
        HIP_ERROR("Invalid argument \"%s\". Use \"default\" or " \
                  "\"all\".\n", opt);
        err = -EINVAL;
        goto out_err;
    }

out_err:
    hip_msg_init(msg);

    return err;
}

/**
 * Flush all run-time host identities from hipd
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt currently unused
 * @param optc currently unused
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @note this does not flush the host identities from disk
 */
static int hip_conf_handle_hi_del_all(hip_common_t *msg,
                                      int action,
                                      const char *opt[],
                                      int optc,
                                      int send_only)
{
    int err                      = 0;
    struct hip_tlv_common *param = NULL;
    struct hip_hit_info *data;
    hip_common_t *msg_tmp        = NULL;

    msg_tmp = hip_msg_alloc();
    HIP_IFEL(!msg_tmp, -ENOMEM, "Malloc for msg_tmp failed\n");

    HIP_IFEL(hip_build_user_hdr(msg_tmp, SO_HIP_GET_HITS, 0),
             -1, "Failed to build user message header\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg_tmp, send_only, 0), -1,
             "Sending msg failed.\n");

    while ((param = hip_get_next_param(msg_tmp, param)) != NULL) {
        data = (struct hip_hit_info *) hip_get_param_contents_direct(param);
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEL_LOCAL_HI, 0),
                 -1, "Failed to build user message header\n");

        HIP_IFEL(hip_build_param_contents(msg, (void *) &data->lhi.hit,
                                          HIP_PARAM_HIT, sizeof(in6_addr_t)),
                 -1, "Failed to build HIT param\n");

        HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
                 "Sending msg failed.\n");

        hip_msg_init(msg);
    }

    /** @todo deleting HITs from the interface isn't working, so we
        restart it */
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_RESTART_DUMMY_INTERFACE, 0),
             -1, "Failed to build message header\n");

    HIP_INFO("All HIs deleted.\n");

out_err:
    if (msg_tmp) {
        free(msg_tmp);
    }
    return err;
}

/**
 * Handles the hipconf commands where the type is @c del.
 *
 * @param msg    input/output message for the query/response for hipd
 * @öaram action currently unused
 * @param opt    "all" or a specific HIT
 * @param optc   1
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_hi_del(hip_common_t *msg,
                                  int action,
                                  const char *opt[],
                                  int optc,
                                  int send_only)
{
    int err = 0;
    int ret;
    in6_addr_t hit;

    HIP_IFEL(optc != 1, -EINVAL, "Invalid number of arguments\n");

    if (!strcmp(opt[0], "all")) {
        return hip_conf_handle_hi_del_all(msg, action, opt, optc, send_only);
    }

    ret = inet_pton(AF_INET6, opt[0], &hit);
    HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -EAFNOSUPPORT,
             "inet_pton: not a valid address family\n");
    HIP_IFEL((ret == 0), -EINVAL,
             "inet_pton: %s: not a valid network address\n", opt[0]);

    HIP_HEXDUMP("HIT to delete: ", &hit, sizeof(in6_addr_t));

    if ((err = hip_build_user_hdr(msg, SO_HIP_DEL_LOCAL_HI, 0))) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }

    if ((err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
                                        sizeof(in6_addr_t)))) {
        HIP_ERROR("build param HIT failed: %s\n", strerror(err));
        goto out_err;
    }

out_err:
    return err;
}

/**
 * print a hip_hadb_user_info_state structure
 *
 * @param ha hip_hadb_user_info_state (partial information of hadb)
 * @return zero for success and negative on error
 */
static int hip_conf_print_info_ha(struct hip_hadb_user_info_state *ha)
{
    _HIP_HEXDUMP("HEXHID ", ha, sizeof(struct hip_hadb_user_info_state));

    HIP_INFO("HA is %s\n", hip_state_str(ha->state));
    if (ha->shotgun_status == SO_HIP_SHOTGUN_ON) {
        HIP_INFO(" Shotgun mode is on.\n");
    } else {
        HIP_INFO(" Shotgun mode is off.\n");
    }

    HIP_INFO_HIT(" Local HIT", &ha->hit_our);
    HIP_INFO_HIT(" Peer  HIT", &ha->hit_peer);
    HIP_DEBUG_LSI(" Local LSI", &ha->lsi_our);
    HIP_DEBUG_LSI(" Peer  LSI", &ha->lsi_peer);
    HIP_INFO_IN6ADDR(" Local IP", &ha->ip_our);
    HIP_INFO(" Local NAT traversal UDP port: %d\n", ha->nat_udp_port_local);
    HIP_INFO_IN6ADDR(" Peer  IP", &ha->ip_peer);
    HIP_INFO(" Peer  NAT traversal UDP port: %d\n", ha->nat_udp_port_peer);
    HIP_INFO(" Peer  hostname: %s\n", &ha->peer_hostname);
    if (ha->heartbeats_on > 0 && ha->state == HIP_STATE_ESTABLISHED) {
        HIP_DEBUG(" Heartbeat %.3f ms mean RTT, "
                  "%.3f ms std dev,\n"
                  " %d packets sent,"
                  " %d packets received,"
                  " %d packet lost\n",
                  (ha->heartbeats_mean),
                  (ha->heartbeats_variance),
                  ha->heartbeats_sent,
                  ha->heartbeats_received,
                  (ha->heartbeats_sent - ha->heartbeats_received));
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_RELAY) {
        HIP_INFO(" Peer has granted us relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_FULLRELAY) {
        HIP_INFO(" Peer has granted us full relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_RVS) {
        HIP_INFO(" Peer has granted us rendezvous service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_GRANTED_UNSUP) {
        HIP_DEBUG(" Peer has granted us an unknown service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_RELAY) {
        HIP_INFO(" Peer has refused to grant us relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_FULLRELAY) {
        HIP_INFO(" Peer has refused to grant us full relay service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_RVS) {
        HIP_INFO(" Peer has refused to grant us RVS service\n");
    }
    if (ha->peer_controls & HIP_HA_CTRL_PEER_REFUSED_UNSUP) {
        HIP_DEBUG(" Peer has refused to grant us an unknown service\n");
    }

    return 0;
}

/* Non-static functions -> global scope */

/**
 * Map a symbolic hipconf action (=add/del) into a number
 *
 * @param argv an array of strings (command line args to hipconf)
 * @return the numeric action id correspoding to the symbolic text
 * @note If you defined a constant ACTION_NEWACT in hipconf.h,
 *       you also need to add a proper sentence in the strcmp() series,
 *       like that:
 *       ...
 *       else if (!strcmp("newaction", text))
 *           ret = ACTION_NEWACT;
 *       ...
 */
int hip_conf_get_action(char *argv[])
{
    int ret = -1;

    if (!strcmp("add", argv[1])) {
        ret = ACTION_ADD;
    } else if (!strcmp("del", argv[1])) {
        ret = ACTION_DEL;
    } else if (!strcmp("new", argv[1])) {
        ret = ACTION_NEW;
    } else if (!strcmp("get", argv[1])) {
        ret = ACTION_GET;
    } else if (!strcmp("set", argv[1])) {
        ret = ACTION_SET;
    } else if (!strcmp("inc", argv[1])) {
        ret = ACTION_INC;
    } else if (!strcmp("dec", argv[1])) {
        ret = ACTION_DEC;
    } else if (!strcmp("bos", argv[1])) {
        ret = ACTION_BOS;
    } else if (!strcmp("rst", argv[1])) {
        ret = ACTION_RST;
    } else if (!strcmp("run", argv[1])) {
        ret = ACTION_RUN;
    } else if (!strcmp("load", argv[1])) {
        ret = ACTION_LOAD;
    } else if (!strcmp("dht", argv[1])) {
        ret = ACTION_DHT;
    } else if (!strcmp("opendht", argv[1])) {
        ret = ACTION_OPENDHT;
    } else if (!strcmp("heartbeat", argv[1])) {
        ret = ACTION_HEARTBEAT;
    } else if (!strcmp("locator", argv[1])) {
        ret = ACTION_LOCATOR;
    } else if (!strcmp("debug", argv[1])) {
        ret = ACTION_DEBUG;
    } else if (!strcmp("mhaddr", argv[1])) {
        ret = ACTION_MHADDR;
    } else if (!strcmp("handover", argv[1])) {
        ret = ACTION_HANDOVER;
    } else if (!strcmp("transform", argv[1])) {
        ret = ACTION_TRANSORDER;
    } else if (!strcmp("restart", argv[1])) {
        ret = ACTION_RESTART;
    } else if (!strcmp("tcptimeout", argv[1])) { /*added by Tao Wan, 08.Jan.2008 */
        ret = ACTION_TCPTIMEOUT;
    } else if (!strcmp("reinit", argv[1])) {
        ret = ACTION_REINIT;
    } else if (!strcmp("hi3", argv[1])) {
        ret = ACTION_HI3;
    }
#ifdef CONFIG_HIP_HIPPROXY
    else if (!strcmp("hipproxy", argv[1])) {
        ret = ACTION_HIPPROXY;
    }
#endif
    else if (!strcmp("manual-update", argv[1])) {
        ret = ACTION_MANUAL_UPDATE;
    } else if (!strcmp("hit-to-lsi", argv[1])) {
        ret = ACTION_HIT_TO_LSI;
    } else if (!strcmp("buddies", argv[1])) {
        ret = ACTION_BUDDIES;
    } else if (!strcmp("nsupdate", argv[1])) {
        ret = ACTION_NSUPDATE;
    } else if (!strcmp("hit-to-ip-set", argv[1])) {
        ret = ACTION_HIT_TO_IP_SET;
    } else if (!strcmp("hit-to-ip", argv[1])) {
        ret = ACTION_HIT_TO_IP;
    } else if (!strcmp("shotgun", argv[1])) {
        ret = ACTION_SHOTGUN;
    } else if (!strcmp("lsi-to-hit", argv[1])) {
        ret = ACTION_LSI_TO_HIT;
    } else if (!strcmp("nat", argv[1])) {
        if (!strcmp("port", argv[2])) {
            if (!strcmp("local", argv[3])) {
                ret = ACTION_NAT_LOCAL_PORT;
            } else if (!strcmp("peer", argv[3])) {
                ret = ACTION_NAT_PEER_PORT;
            }
        } else {
            ret = ACTION_NAT;
        }
    } else if (!strcmp("datapacket", argv[1]))    {
        ret = ACTION_DATAPACKET;
    }

    return ret;
}

/**
 * Get the minimum amount of arguments needed to be given to the action.
 *
 * @note If you defined a constant ACTION_NEWACT in hipconf.h,
 *       you also need to add a case block for the constant
 *       here in the switch(action) block.
 * @param  action action type
 * @return how many arguments needs to be given at least
 */
int hip_conf_check_action_argc(int action)
{
    int count = 0;

    switch (action) {
    case ACTION_NEW:
    case ACTION_NAT:
    case ACTION_DEC:
    case ACTION_RST:
    case ACTION_BOS:
    case ACTION_LOCATOR:
    case ACTION_OPENDHT:
    case ACTION_HEARTBEAT:
    case ACTION_HIT_TO_LSI:
    case ACTION_DATAPACKET:
    case ACTION_MAP_ID_TO_ADDR:
    case ACTION_LSI_TO_HIT:
        count = 1;
        break;
    case ACTION_DEBUG:
    case ACTION_RESTART:
    case ACTION_REINIT:
    case ACTION_TCPTIMEOUT:
    case ACTION_NSUPDATE:
    case ACTION_HIT_TO_IP:
    case ACTION_HIT_TO_IP_SET:
    case ACTION_MANUAL_UPDATE:
        count = 1;
        break;
    case ACTION_ADD:
    case ACTION_DEL:
    case ACTION_SET:
    case ACTION_INC:
    case ACTION_GET:
    case ACTION_RUN:
    case ACTION_LOAD:
    case ACTION_DHT:
    case ACTION_HA:
    case ACTION_MHADDR:
    case ACTION_TRANSORDER:
    case ACTION_NAT_LOCAL_PORT:
    case ACTION_NAT_PEER_PORT:
    case ACTION_HANDOVER:
        count = 2;
        break;
#ifdef CONFIG_HIP_HIPPROXY
    case ACTION_HIPPROXY:
        count = 1;
        break;
#endif
    default:
        break;
    }

    return count;
}

/**
 * map a symbolic hipconf type (=lhi/map/etc) name to numeric type
 *
 * @param  text the type as a string
 * @return the numeric type id correspoding to the symbolic text
 */
int hip_conf_get_type(char *text, char *argv[])
{
    int ret = -1;

    if (!strcmp("hi", text)) {
        ret = TYPE_HI;
    } else if (!strcmp("map", text)) {
        ret = TYPE_MAP;
    } else if (!strcmp("rst", text)) {
        ret = TYPE_RST;
    } else if (!strcmp("server", text)) {
        ret = TYPE_SERVER;
    } else if (!strcmp("puzzle", text)) {
        ret = TYPE_PUZZLE;
    } else if (!strcmp("service", text)) {
        ret = TYPE_SERVICE;
    } else if (!strcmp("normal", text)) {
        ret = TYPE_RUN;
    } else if (!strcmp("ha", text)) {
        ret = TYPE_HA;
    } else if ((!strcmp("all", text)) && (strcmp("rst", argv[1]) == 0)) {
        ret = TYPE_RST;
    } else if ((!strcmp("peer_hit", text)) && (strcmp("rst", argv[1]) == 0)) {
        ret = TYPE_RST;
    } else if (strcmp("nat", argv[1]) == 0) {
        if (argv[2] && strcmp("port", argv[2]) == 0) {
            if (argv[3] && strcmp("local", argv[3]) == 0) {
                ret = TYPE_NAT_LOCAL_PORT;
            } else if (argv[3] && strcmp("peer", argv[3]) == 0) {
                ret = TYPE_NAT_PEER_PORT;
            }
        } else {
            ret = TYPE_NAT;
        }
    } else if (strcmp("locator", argv[1]) == 0)     {
        ret = TYPE_LOCATOR;
    } else if (!strcmp("tcptimeout", text)) {
        ret = TYPE_TCPTIMEOUT;
    } else if ((!strcmp("all", text)) && (strcmp("bos", argv[1]) == 0)) {
        ret = TYPE_BOS;
    } else if (!strcmp("debug", text)) {
        ret = TYPE_DEBUG;
    } else if ((!strcmp("mode", text)) && (strcmp("mhaddr", argv[1]) == 0)) {
        ret = TYPE_MHADDR;
    } else if (!strcmp("daemon", text)) {
        ret = TYPE_DAEMON;
    } else if ((!strcmp("mode", text)) && (strcmp("handover", argv[1]) == 0)) {
        ret = TYPE_HANDOVER;
    }
#ifdef CONFIG_HIP_OPPORTUNISTIC
    else if (!strcmp("opp", text)) {
        ret = TYPE_OPP;
    }
#endif
#ifdef CONFIG_HIP_BLIND
    else if (!strcmp("blind", text)) {
        ret = TYPE_BLIND;
    }
#endif
    else if (!strcmp("order", text)) {
        ret = TYPE_ORDER;
    } else if (strcmp("opendht", argv[1]) == 0) {
        ret = TYPE_DHT;
    } else if (strcmp("heartbeat", argv[1]) == 0) {
        ret = TYPE_HEARTBEAT;
    } else if (!strcmp("ttl", text)) {
        ret = TYPE_TTL;
    } else if (!strcmp("gw", text)) {
        ret = TYPE_GW;
    } else if (!strcmp("get", text)) {
        ret = TYPE_GET;
    } else if (!strcmp("set", text)) {
        ret = TYPE_SET;
    } else if (!strcmp("config", text)) {
        ret = TYPE_CONFIG;
    }
#ifdef CONFIG_HIP_HIPPROXY
    else if (strcmp("hipproxy", argv[1]) == 0) {
        ret = TYPE_HIPPROXY;
    }
#endif
    else if (strcmp("manual-update", argv[1]) == 0) {
        ret = TYPE_MANUAL_UPDATE;
    } else if (strcmp("hi3", argv[1]) == 0) {
        ret = TYPE_HI3;
    } else if (strcmp("hit-to-lsi", argv[1]) == 0) {
        ret = TYPE_HIT_TO_LSI;
    } else if (strcmp("buddies", argv[1]) == 0) {
        ret = TYPE_BUDDIES;
    } else if (strcmp("nsupdate", argv[1]) == 0) {
        ret = TYPE_NSUPDATE;
    } else if (strcmp("hit-to-ip-set", argv[1]) == 0) {
        ret = TYPE_HIT_TO_IP_SET;
    } else if (strcmp("hit-to-ip", argv[1]) == 0) {
        ret = TYPE_HIT_TO_IP;
    } else if (strcmp("datapacket", argv[1]) == 0) {
        ret = TYPE_DATAPACKET;
    } else if (strcmp("shotgun", argv[1]) == 0) {
        ret = TYPE_SHOTGUN;
    } else if (strcmp("lsi-to-hit", argv[1]) == 0) {
        ret = TYPE_LSI_TO_HIT;
    } else {
        HIP_DEBUG("ERROR: NO MATCHES FOUND \n");
    }

    return ret;
}

/**
 * Get a type argument index, in argv[].
 *
 * @note If you defined a constant ACTION_NEWACT in hipconf.h,
 *       you also need to add a case block for the constant
 *       here in the switch(action) block.
 * @param  integer value for an action
 * @return an index for argv[], which indicates the type argument.
 *         Usually either 1 or 2.
 */
int hip_conf_get_type_arg(int action)
{
    int type_arg = -1;

    switch (action) {
    case ACTION_ADD:
    case ACTION_DEL:
    case ACTION_NEW:
    case ACTION_NAT:
    case ACTION_NAT_LOCAL_PORT:
    case ACTION_NAT_PEER_PORT:
    case ACTION_INC:
    case ACTION_DEC:
    case ACTION_SET:
    case ACTION_GET:
    case ACTION_RUN:
    case ACTION_LOAD:
    case ACTION_DHT:
    case ACTION_OPENDHT:
    case ACTION_BUDDIES:
    case ACTION_HEARTBEAT:
    case ACTION_LOCATOR:
    case ACTION_RST:
    case ACTION_BOS:
    case ACTION_MHADDR:
    case ACTION_HANDOVER:
    case ACTION_TCPTIMEOUT:
    case ACTION_TRANSORDER:
    case ACTION_REINIT:
#ifdef CONFIG_HIP_HIPPROXY
    case ACTION_HIPPROXY:
#endif
    case ACTION_HI3:
    case ACTION_RESTART:
    case ACTION_NSUPDATE:
    case ACTION_HIT_TO_IP:
    case ACTION_HIT_TO_IP_SET:
    case ACTION_DATAPACKET:
    case ACTION_SHOTGUN:
        type_arg = 2;
        break;
    case ACTION_MANUAL_UPDATE:
    case ACTION_HIT_TO_LSI:
    case ACTION_LSI_TO_HIT:
    case ACTION_DEBUG:
        type_arg = 1;
        break;
    default:
        break;
    }

    return type_arg;
}

/**
 * Resolve a given hostname to a HIT/LSI or IP address depending on match_hip flag
 *
 * @param msg input/output message for the query/response for hipd
 * @param opt options arguments as strings
 * @param optc number of arguments
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
int resolve_hostname_to_id(const char *hostname, struct in6_addr *id,
                           int match_hip)
{
    int err              = 1;
    struct addrinfo *res = NULL, *rp;
    struct in_addr *in4;
    struct in6_addr *in6;

    HIP_IFEL(getaddrinfo(hostname, NULL, NULL, &res), -1,
             "getaddrinfo failed\n");
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        in4 = &((struct sockaddr_in *) rp->ai_addr)->sin_addr;
        in6 = &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr;
        if (rp->ai_family == AF_INET6) {
            _HIP_DEBUG_IN6ADDR("addr", in6);
            _HIP_DEBUG("hit=%s\n",
                       (ipv6_addr_is_hit(in6) ? "yes" : "no"));
        }

        if (rp->ai_family == AF_INET) {
            _HIP_DEBUG_INADDR("addr", in4);
            _HIP_DEBUG("lsi=%s\n",
                       (IS_LSI32(in4->s_addr) ? "yes" : "no"));
        }

        if (rp->ai_family == AF_INET6 &&
            (ipv6_addr_is_hit(in6) ? match_hip : !match_hip)) {
            ipv6_addr_copy(id, in6);
            err = 0;
            _HIP_DEBUG("Match\n");
            break;
        } else if (rp->ai_family == AF_INET &&
                   (IS_LSI32(in4->s_addr) ? match_hip : !match_hip)) {
            IPV4_TO_IPV6_MAP(in4, id);
            err = 0;
            break;
            _HIP_DEBUG("Match\n");
        }
    }

out_err:
    if (res) {
        freeaddrinfo(res);
    }

    return err;
}

/**
 * Handles the hipconf commands where the type is @c server. Creates a user
 * message from the function parameters @c msg, @c action and @c opt[]. The
 * command line that this function parses is of type:
 * <code>tools/hipconf <b>add</b> server &lt;SERVICES&gt; &lt;SERVER HIT&gt;
 * &lt;SERVER IP ADDRESS&gt; &lt;LIFETIME&gt;</code> or
 * <code>tools/hipconf <b>del</b> server &lt;SERVICES&gt; &lt;SERVER HIT&gt;
 * &lt;SERVER IP ADDRESS&gt;</code>, where <code>&lt;SERVICES&gt;</code> is a list of
 * the services to which we want to register or cancel or registration. The
 * list can consist of any number of the strings @c rvs, @c relay,
 * or any number of service type numbers between 0 and 255. The list can be a
 * combination of these with repetitions allowed. At least one string or
 * service type number must be provided.
 *
 * @param msg    a pointer to a target buffer where the message for HIP daemon
 *               is to put
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in array @c opt.
 * @return       zero on success, or negative error value on error.
 * @note         Currently only action @c add is supported.
 * @todo         If the current machine has more than one IP address
 *               there should be a way to choose which of the addresses
 *               to register to the server.
 * @todo         There are currently four different HITs at the @c dummy0
 *               interface. There should be a way to choose which of the HITs
 *               to register to the server.
 */
static int hip_conf_handle_server(hip_common_t *msg,
                                  int action,
                                  const char *opt[],
                                  int optc,
                                  int send_only)
{
    hip_hit_t hit;
    in6_addr_t ipv6;
    int err = 0, seconds = 0, i = 0, number_of_regtypes = 0, reg_type = 0;
    int index_of_hit = 0, index_of_ip = 0, opp_mode = 0;;
    uint8_t lifetime             = 0, *reg_types = NULL;
    time_t seconds_from_lifetime = 0;
    char lowercase[30];

    _HIP_DEBUG("hip_conf_handle_server() invoked.\n");

    memset(&hit, 0, sizeof(hit));
    memset(&ipv6, 0, sizeof(ipv6));

    if (action != ACTION_ADD && action != ACTION_DEL) {
        HIP_ERROR("Only actions \"add\" and \"del\" are supported for " \
                  "\"server\".\n");
        err = -1;
        goto out_err;
    } else if (action == ACTION_ADD) {
        if (optc < 4) {
            if (optc < 3) {
                HIP_ERROR("Missing arguments.\n");
                err = -1;
                goto out_err;
            } else {
                HIP_DEBUG("Opportunistic mode or direct HIT registration \n");
                opp_mode = 1;
            }
        }

        if (!opp_mode) {
            number_of_regtypes = optc - 3;
            index_of_hit       = optc - 3;
            index_of_ip        = optc - 2;
        } else {
            number_of_regtypes = optc - 2;
            index_of_ip        = optc - 2;
        }

        HIP_IFEL(hip_string_is_digit(opt[optc - 1]), -1,
                 "Invalid lifetime value \"%s\" given.\n"       \
                 "Please give a lifetime value between 1 and "  \
                 "15384774 seconds.\n", opt[optc - 1]);

        seconds = atoi(opt[optc - 1]);

        if (seconds <= 0 || seconds > 15384774) {
            HIP_ERROR("Invalid lifetime value \"%s\" given.\n"    \
                      "Please give a lifetime value between 1 and " \
                      "15384774 seconds.\n", opt[optc - 1]);
            goto out_err;
        }

        HIP_IFEL(hip_get_lifetime_value(seconds, &lifetime), -1,
                 "Unable to convert seconds to a lifetime value.\n");

        hip_get_lifetime_seconds(lifetime, &seconds_from_lifetime);
    } else if (action == ACTION_DEL) {
        if (optc < 3) {
            HIP_ERROR("Missing arguments.\n");
            err = -1;
            goto out_err;
        }
        number_of_regtypes = optc - 2;
        index_of_hit       = optc - 2;
        index_of_ip        = optc - 1;
    }

    if (!opp_mode) {
        /* Check the HIT value. */
        if (inet_pton(AF_INET6, opt[index_of_hit], &hit) <= 0) {
            if (resolve_hostname_to_id(opt[index_of_hit], &hit, 1)) {
                HIP_ERROR("'%s' is not a valid HIT.\n", opt[index_of_hit]);
                err = -1;
                goto out_err;
            }
        }
    }
    /* Check the IPv4 or IPV6 value. */

    if (inet_pton(AF_INET6, opt[index_of_ip], &ipv6) <= 0) {
        struct in_addr ipv4;
        if (inet_pton(AF_INET, opt[index_of_ip], &ipv4) <= 0) {
            int i;
            /* First try to find an IPv4 or IPv6 address. Second,
             * settle for HIT if no routable address found.
             * The second step is required with dnsproxy
             * (see bug id 880) */
            for (i = 0; i < 2; i++) {
                err = resolve_hostname_to_id(opt[index_of_ip], &ipv6, i);
                if (err == 0) {
                    break;
                }
            }

            if (err) {
                HIP_ERROR("'%s' is not a valid IPv4 or IPv6 address.\n",
                          opt[index_of_ip]);
                err = -1;
                goto out_err;
            }
        } else {
            IPV4_TO_IPV6_MAP(&ipv4, &ipv6);
        }
    }

    reg_types = malloc(number_of_regtypes * sizeof(uint8_t));

    if (reg_types == NULL) {
        err = -1;
        HIP_ERROR("Unable to allocate memory for registration " \
                  "types.\n");
        goto out_err;
    }

    if (optc > 13) {
        HIP_ERROR("Too many services requested.\n");
        err = -1;
        goto out_err;
    }

    /* Every commandline argument in opt[] from '0' to 'optc - 4' should
     * be either one of the predefined strings or a number between
     * 0 and 255 (inclusive). */
    for (; i < number_of_regtypes; i++) {
        if (strlen(opt[i]) > 30) {
            HIP_ERROR("'%s' is not a valid service name.\n", opt[i]);
            err = -1;
            goto out_err;
        }

        hip_string_to_lowercase(lowercase, opt[i], strlen(opt[i]) + 1);
        if (strcmp("rvs", lowercase) == 0) {
            reg_types[i] = HIP_SERVICE_RENDEZVOUS;
        } else if (strcmp("relay", lowercase) == 0) {
            reg_types[i] = HIP_SERVICE_RELAY;
        } else if (strcmp("full-relay", lowercase) == 0)  {
            reg_types[i] = HIP_SERVICE_FULLRELAY;
        }         /* To cope with the atoi() error value we handle the 'zero'
                   * case here. */
        else if (strcmp("0", lowercase) == 0) {
            reg_types[i] = 0;
        } else {
            reg_type = atoi(lowercase);
            if (reg_type <= 0 || reg_type > 255) {
                HIP_ERROR("'%s' is not a valid service name " \
                          "or service number.\n", opt[i]);
                err = -1;
                goto out_err;
            } else {
                reg_types[i] = reg_type;
            }
        }
    }

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_DEL_SERVER, 0), -1,
             "Failed to build hipconf user message header.\n");

    if (!opp_mode) {
        HIP_IFEL(hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
                                          sizeof(in6_addr_t)), -1,
                 "Failed to build HIT parameter to hipconf user message.\n");
    }

    /* Routable address or dnsproxy returning transparently
     * HITs (bug id 880) */
    HIP_IFEL(hip_build_param_contents(msg, &ipv6,
                                      HIP_PARAM_IPV6_ADDR,
                                      sizeof(in6_addr_t)), -1,
             "Failed to build IPv6 parameter to hipconf user message.\n");

    HIP_IFEL(hip_build_param_reg_request(msg, lifetime, reg_types,
                                         number_of_regtypes), -1,
             "Failed to build REG_REQUEST parameter to hipconf user " \
             "message.\n");

    if (action == ACTION_ADD) {
        HIP_INFO("Requesting %u service%s for %d seconds "
                 "(lifetime 0x%x) from %s " \
                 "%s.\n", number_of_regtypes,
                 (number_of_regtypes > 1) ? "s" : "",
                 seconds_from_lifetime, lifetime, opt[index_of_hit],
                 opt[index_of_ip]);
    } else {
        HIP_INFO("Requesting the cancellation of %u service%s from\n" \
                 "HIT %s located at\nIP address %s.\n",
                 number_of_regtypes,
                 (number_of_regtypes > 1) ? "s" : "", opt[index_of_hit],
                 opt[index_of_ip]);
    }
out_err:
    if (reg_types != NULL) {
        free(reg_types);
    }

    return err;
}

/**
 * Handles the hipconf commands where the type is @c hi.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_hi(hip_common_t *msg, int action, const char *opt[],
                       int optc, int send_only)
{
    int err          = 0, anon = 0, use_default = 0, rsa_key_bits = 0;
    int dsa_key_bits = 0;
    const char *fmt  = NULL, *file = NULL;

    if (action == ACTION_DEL) {
        return hip_conf_handle_hi_del(msg, action, opt, optc, send_only);
    } else if (action == ACTION_GET) {
        HIP_IFEL((optc < 1), -1, "Missing arguments.\n");
        HIP_IFEL((optc > 1), -1, "Too many arguments.\n");

        return hip_get_hits(msg, opt[0], 1, send_only);
    } else if (action != ACTION_ADD && action != ACTION_NEW) {
        HIP_ERROR("Only actions \"add\", \"new\", \"del\" and \"get\" " \
                  "are supported for \"hi\".\n");
        err = -1;
        goto out_err;
    }

    HIP_IFEL((optc < 1), -1, "Missing arguments.\n");
    HIP_IFEL((optc > 4), -1, "Too many arguments.\n");

    if (strcmp(opt[0], "pub") == 0) {
        anon = 0;
    } else if (strcmp(opt[0], "anon") == 0) {
        anon = 1;
    } else if (strcmp(opt[OPT_HI_TYPE], "default") == 0) {
        use_default = 1;
    } else {
        HIP_ERROR("Bad HI type %s. Please use \"pub\", \"anon\" or " \
                  "\"default\".\n", opt[0]);
        err = -EINVAL;
        goto out_err;
    }

    if (use_default && action == ACTION_ADD) {
        /* Add default keys in three steps: dsa, rsa anon, rsa pub.
         * Necessary for large keys. */

        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
                                                "dsa", NULL, 0, 0))) {
            goto out_err;
        }
        HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
                 "Sending msg failed.\n");

        hip_msg_init(msg);
        if ((err = hip_serialize_host_id_action(msg, ACTION_ADD, 1, 1,
                                                "rsa", NULL, 0, 0))) {
            goto out_err;
        }
        HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
                 "Sending msg failed.\n");

        hip_msg_init(msg);
        err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
                                           "rsa", NULL, 0, 0);

        goto out_err;
    }

    if (use_default) {
        if (optc == 3) {
            rsa_key_bits = atoi(opt[1]);
            dsa_key_bits = atoi(opt[2]);
        } else {
            HIP_IFEL(optc != 1, -EINVAL, "Invalid number of arguments\n");
        }
    } else {
        if (optc == 4) {
            rsa_key_bits = dsa_key_bits = atoi(opt[OPT_HI_KEYLEN]);
        } else {
            HIP_IFEL(optc != 3, -EINVAL, "Invalid number of arguments\n");
        }

        fmt  = opt[OPT_HI_FMT];
        file = opt[OPT_HI_FILE];
    }

    if (rsa_key_bits < 384 || rsa_key_bits > HIP_MAX_RSA_KEY_LEN ||
        rsa_key_bits % 64 != 0) {
        rsa_key_bits = RSA_KEY_DEFAULT_BITS;
    }
    if (dsa_key_bits < 512 || dsa_key_bits > HIP_MAX_DSA_KEY_LEN ||
        dsa_key_bits % 64 != 0) {
        dsa_key_bits = DSA_KEY_DEFAULT_BITS;
    }

    err = hip_serialize_host_id_action(msg, action, anon, use_default,
                                       fmt, file, rsa_key_bits, dsa_key_bits);
out_err:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c map.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type. (should be the HIT and the corresponding
 *               IPv6 address).
 * @param optc   the number of elements in the array (@b 2).
 * @return       zero on success, or negative error value on error.
 * @note         Does not support @c del action.
 */
static int hip_conf_handle_map(hip_common_t *msg, int action, const char *opt[],
                               int optc, int send_only)
{
    int err = 0;
    struct in_addr lsi, aux;
    in6_addr_t hit, ip6;

    HIP_DEBUG("action=%d optc=%d\n", action, optc);

    HIP_IFEL((optc != 2 && optc != 3), -1, "Missing arguments\n");

    HIP_IFEL(convert_string_to_address(opt[0], &hit), -1,
             "string to address conversion failed\n");

    HIP_IFEL((err = convert_string_to_address(opt[1], &ip6)), -1,
             "string to address conversion failed\n");

    if ((err && !convert_string_to_address_v4(opt[1], &aux))) {
        HIP_IFEL(IS_LSI32(aux.s_addr), -1, "Missing ip address before lsi\n");
    }

    switch (action) {
    case ACTION_ADD:
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_PEER_MAP_HIT_IP,
                                    0), -1, "add peer map failed\n");

        break;
    case ACTION_DEL:
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEL_PEER_MAP_HIT_IP,
                                    0), -1, "del peer map failed\n");
        break;
    default:
        err = -1;
        goto out_err;
        break;
    }

    HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
                                      sizeof(in6_addr_t)), -1,
             "build param hit failed\n");

    HIP_IFEL(hip_build_param_contents(msg, (void *) &ip6,
                                      HIP_PARAM_IPV6_ADDR,
                                      sizeof(in6_addr_t)), -1,
             "build param hit failed\n");

    if (optc == 3) {
        HIP_IFEL(convert_string_to_address_v4(opt[2], &lsi), -1,
                 "string to address conversion failed\n");
        HIP_IFEL(!IS_LSI32(lsi.s_addr), -1, "Wrong LSI value\n");
        HIP_IFEL(hip_build_param_contents(msg, (void *) &lsi,
                                          HIP_PARAM_LSI,
                                          sizeof(struct in_addr)), -1,
                 "build param lsi failed\n");
    }

out_err:
    return err;
}

/**
 * Handles the hipconf command heartbeat <seconds>.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_heartbeat(hip_common_t *msg, int action,
                                     const char *opt[], int optc, int send_only)
{
    int err = 0, seconds = 0;

    seconds = atoi(opt[0]);
    if (seconds < 0) {
        HIP_ERROR("Invalid argument\n");
        err = -EINVAL;
        goto out_err;
    }

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_HEARTBEAT, 0),
             -1, "Failed to build user message header\n");

    HIP_IFEL(hip_build_param_heartbeat(msg, seconds),
             -1, "Failed to build param heartbeat\n");

out_err:
    return err;
}

/**
 * Handles the hipconf transform order command.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_trans_order(hip_common_t *msg, int action,
                                       const char *opt[], int optc, int send_only)
{
    int err = 0, transorder = 0, i = 0, k = 0;

    if (optc != 1) {
        HIP_ERROR("Missing arguments\n");
        err = -EINVAL;
        goto out;
    }

    transorder = atoi(opt[0]);

    /* has to be over 100 three options (and less than 321) */
    if (transorder < 100 && transorder > 322) {
        HIP_ERROR("Invalid argument\n");
        err = -EINVAL;
        goto out;
    }

    /* Check individual numbers has to be in range 1 to 3 (3 options) */
    for (i = 0; i < 3; i++) {
        k  = (int) opt[0][i];
        k -= 48;         // easy way to remove junk
        if (k < 0 || k > 3) {
            HIP_ERROR("Invalid argument\n");
            err = -EINVAL;
            goto out;
        }
    }

    err = hip_build_user_hdr(msg, SO_HIP_TRANSFORM_ORDER, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out;
    }

    err = hip_build_param_transform_order(msg, transorder);
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out;
    }

out:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c rst.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_rst(hip_common_t *msg, int action,
                               const char *opt[], int optc, int send_only)
{
    int err;
    int ret;
    in6_addr_t hit;

    if (!strcmp("all", opt[0])) {
        memset(&hit, 0, sizeof(in6_addr_t));
    } else {
        ret = inet_pton(AF_INET6, opt[0], &hit);
        if (ret < 0 && errno == EAFNOSUPPORT) {
            HIP_PERROR("inet_pton: not a valid address family\n");
            err = -EAFNOSUPPORT;
            goto out;
        } else if (ret == 0) {
            HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
            err = -EINVAL;
            goto out;
        }
    }

    err = hip_build_user_hdr(msg, SO_HIP_RST, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out;
    }

    err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
                                   sizeof(in6_addr_t));
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out;
    }

out:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c debug.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_debug(hip_common_t *msg, int action,
                                 const char *opt[], int optc, int send_only)
{
    int err    = 0;
    int status = 0;
    in6_addr_t hit;

    if (optc != 0) {
        HIP_IFEL(1,
                 -EINVAL,
                 "Wrong amount of arguments. Usage:\nhipconf debug all|medium|none\n");
    }

    if (!strcmp("all", opt[0])) {
        HIP_INFO("Displaying all debugging messages\n");
        memset(&hit, 0, sizeof(in6_addr_t));
        status = SO_HIP_SET_DEBUG_ALL;
    } else if (!strcmp("medium", opt[0])) {
        HIP_INFO("Displaying ERROR and INFO debugging messages\n");
        memset(&hit, 0, sizeof(in6_addr_t));
        status = SO_HIP_SET_DEBUG_MEDIUM;
    } else if (!strcmp("none", opt[0])) {
        HIP_INFO("Displaying no debugging messages\n");
        memset(&hit, 0, sizeof(in6_addr_t));
        status = SO_HIP_SET_DEBUG_NONE;
    } else {
        HIP_IFEL(1, -EINVAL, "Unknown argument\n");
    }

    HIP_IFEL(hip_build_user_hdr(msg, status, 0),
             -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c bos.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_bos(hip_common_t *msg, int action,
                        const char *opt[], int optc, int send_only)
{
    int err;

    /* Check that there are no extra args */
    if (optc != 0) {
        HIP_ERROR("Extra arguments\n");
        err = -EINVAL;
        goto out;
    }

    /* Build the message header */
    err = hip_build_user_hdr(msg, SO_HIP_BOS, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out;
    }

out:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c trigger-update.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_manual_update(hip_common_t *msg, int action,
                                         const char *opt[], int optc, int send_only)
{
    int err = 0, s = 0;
    unsigned int ifidx;
    struct ifreq ifr;

    HIP_IFEL(optc != 0, -1, "Too many parameters for manual-update.\n");

    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, opt[0], sizeof(ifr.ifr_name));

    HIP_IFEL((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1, -1,
             "Failed to open socket.\n");
    HIP_IFEL(ioctl(s, SIOCGIFINDEX, &ifr) == -1, -1,
             "Failed to find interface %s.\n", opt[0]);
    ifidx = ifr.ifr_ifindex;

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_MANUAL_UPDATE_PACKET, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

    err = hip_build_param_contents(msg, (void *) &ifidx, HIP_PARAM_UINT,
                                   sizeof(unsigned int));

out_err:
    if (s != 0) {
        close(s);
    }
    return err;
}

/**
 * Handles the hipconf commands where the type is @c nat port.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */

static int hip_conf_handle_nat_port(hip_common_t *msg, int action,
                                    const char *opt[], int optc, int send_only)
{
    int err        = 0;

    in_port_t port = (in_port_t) atoi(opt[1]);

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_SET_NAT_PORT, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

    if (action == ACTION_NAT_LOCAL_PORT) {
        HIP_IFEL(hip_build_param_nat_port(msg, port, HIP_PARAM_LOCAL_NAT_PORT), -1,
                 "Failed to build nat port parameter.: %s\n", strerror(err));
    } else {
        HIP_IFEL(hip_build_param_nat_port(msg, port, HIP_PARAM_PEER_NAT_PORT), -1,
                 "Failed to build nat port parameter.: %s\n", strerror(err));
    }

    goto out_err;

    HIP_ERROR("Invalid argument\n");
    err = -EINVAL;

out_err:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c nat.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_nat(hip_common_t *msg, int action,
                               const char *opt[], int optc, int send_only)
{
    int err    = 0;
    int status = 0;
    in6_addr_t hit;

    if (!strcmp("plain-udp", opt[0])) {
        memset(&hit, 0, sizeof(in6_addr_t));
        status = SO_HIP_SET_NAT_PLAIN_UDP;
    } else if (!strcmp("none", opt[0])) {
        memset(&hit, 0, sizeof(struct in6_addr));
        status = SO_HIP_SET_NAT_NONE;
    } else if (!strcmp("ice-udp", opt[0])) {
        memset(&hit, 0, sizeof(struct in6_addr));
        status = SO_HIP_SET_NAT_ICE_UDP;
    }

    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

#if 0 /* Not used currently */
    else {
        ret = inet_pton(AF_INET6, opt[0], &hit);
        if (ret < 0 && errno == EAFNOSUPPORT) {
            HIP_PERROR("inet_pton: not a valid address family\n");
            err = -EAFNOSUPPORT;
            goto out_err;
        } else if (ret == 0) {
            HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
            err = -EINVAL;
            goto out_err;
        }
        status = SO_HIP_SET_NAT_ON;
    }

    HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
                                      sizeof(in6_addr_t)), -1,
             "build param hit failed: %s\n", strerror(err));
#endif

out_err:
    return err;
}

/**
 * Handles the hipconf commands where type is @c datapacket. This mode swithces the Hip Firewall to work in data packet mode , meaning it can communicate without establishing BEX with peer node.
 *
 */

static int hip_conf_handle_datapacket(hip_common_t *msg,
                                      int action,
                                      const char *opt[],
                                      int optc,
                                      int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SET_DATAPACKET_MODE_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SET_DATAPACKET_MODE_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }

    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:

    return 0;
}

/**
 * Handles the hipconf commands where the type is @c locator. You can turn
 * locator sending in BEX on or query the set of local locators with this
 * function.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_locator(hip_common_t *msg, int action,
                                   const char *opt[], int optc, int send_only)
{
    int err                     = 0, status = 0;
    struct hip_locator *locator = NULL;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SET_LOCATOR_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SET_LOCATOR_OFF;
    } else if (!strcmp("get", opt[0])) {
        status = SO_HIP_LOCATOR_GET;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));
    if (status == SO_HIP_LOCATOR_GET) {
        HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
                 "Send recv daemon info failed\n");
        locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
        if (locator) {
            hip_print_locator_addresses(msg);
        } else {
            HIP_DEBUG("No LOCATOR found from daemon msg\n");
        }
    }
out_err:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c puzzle.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_puzzle(hip_common_t *msg,
                                  int action,
                                  const char *opt[],
                                  int optc,
                                  int send_only)
{
    int err = 0, ret = 0, msg_type = 0, all, *diff = NULL, newVal = 0;
    hip_hit_t hit, all_zero_hit;
    struct hip_tlv_common *current_param = NULL;
    hip_tlv_type_t param_type            = 0;
    char hit_s[INET6_ADDRSTRLEN];

    memset(&hit, 0, sizeof(hip_hit_t));
    memset(&all_zero_hit, 0, sizeof(hip_hit_t));

    if (action == ACTION_SET) {
        if (optc != 2) {
            HIP_ERROR("Missing arguments\n");
            err = -EINVAL;
            goto out_err;
        }
    } else if (optc != 1)   {
        HIP_ERROR("Missing arguments\n");
        err = -EINVAL;
        goto out_err;
    }

    switch (action) {
    case ACTION_NEW:
        msg_type = SO_HIP_CONF_PUZZLE_NEW;
        break;
    case ACTION_INC:
        msg_type = SO_HIP_CONF_PUZZLE_INC;
        break;
    case ACTION_DEC:
        msg_type = SO_HIP_CONF_PUZZLE_DEC;
        break;
    case ACTION_SET:
        msg_type = SO_HIP_CONF_PUZZLE_SET;
        break;
    case ACTION_GET:
        msg_type = SO_HIP_CONF_PUZZLE_GET;
        break;
    default:
        err      = -1;
    }

    if (err) {
        HIP_ERROR("Action (%d) not supported yet\n", action);
        goto out_err;
    }

    all = !strcmp("all", opt[0]);

    if (!all) {
        ret = inet_pton(AF_INET6, opt[0], &hit);
        if (ret < 0 && errno == EAFNOSUPPORT) {
            HIP_PERROR("inet_pton: not a valid address family\n");
            err = -EAFNOSUPPORT;
            goto out_err;
        } else if (ret == 0) {
            HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
            err = -EINVAL;
            goto out_err;
        }
    }

    /* obtain the new value for set */
    if ((msg_type == SO_HIP_CONF_PUZZLE_SET) && (optc == 2)) {
        newVal = atoi(opt[1]);
    }

    /* Build a HIP message with socket option to get puzzle difficulty. */
    HIP_IFE(hip_build_user_hdr(msg, msg_type, 0), -1);

    /* attach the hit into the message */
    err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
                                   sizeof(in6_addr_t));
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out_err;
    }

    /* obtain the result for the get action */
    if (msg_type == SO_HIP_CONF_PUZZLE_GET) {
        /* Send the message to the daemon. The daemon fills the message. */
        HIP_IFE(hip_send_recv_daemon_info(msg, send_only, 0), -ECOMM);

        /* Loop through all the parameters in the message just filled. */
        while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
            param_type = hip_get_param_type(current_param);
            if (param_type == HIP_PARAM_HIT) {
                //no need to get the hit from msg
            } else if (param_type == HIP_PARAM_INT)   {
                diff = (int *) hip_get_param_contents_direct(current_param);
            } else {
                HIP_ERROR("Unrelated parameter in user " \
                          "message.\n");
            }
        }

        HIP_INFO("Puzzle difficulty is: %d\n", *diff);

        if (ipv6_addr_cmp(&all_zero_hit, &hit) != 0) {
            inet_ntop(AF_INET6, &hit, hit_s, INET6_ADDRSTRLEN);
            HIP_INFO("for peer hit: %s\n", hit_s);
        }
    }

    /* attach new val for the set action */
    if (msg_type == SO_HIP_CONF_PUZZLE_SET) {
        err = hip_build_param_contents(msg, (void *) &newVal, HIP_PARAM_INT,
                                       sizeof(int));
        if (err) {
            HIP_ERROR("build param int failed: %s\n", strerror(err));
            goto out_err;
        }
    }

    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }

    if ((msg_type == SO_HIP_CONF_PUZZLE_GET)
        || (msg_type == SO_HIP_CONF_PUZZLE_SET)) {
        goto out_err;
    }

    if (all) {
        HIP_INFO("New puzzle difficulty effective immediately\n");
    } else {
        HIP_INFO("New puzzle difficulty is effective in %d seconds\n",
                 HIP_R1_PRECREATE_INTERVAL);
    }

out_err:
    if (msg_type == SO_HIP_CONF_PUZZLE_GET) {
        hip_msg_init(msg);
    }
    return err;
}

/**
 * Handles the hipconf commands where the type is @c opp.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_opp(hip_common_t *msg,
                               int action,
                               const char *opt[],
                               int optc,
                               int send_only)
{
    unsigned int oppmode = 0;
    int err              = 0;

    if (action == ACTION_RUN) {
        return hip_handle_exec_application(0, EXEC_LOADLIB_OPP, optc, (char **) &opt[0]);
    }
    if (optc != 1) {
        HIP_ERROR("Incorrect number of arguments\n");
        err = -EINVAL;
        goto out;
    }

    if (!strcmp("normal", opt[0])) {
        oppmode = 1;
    } else if (!strcmp("advanced", opt[0])) {
        oppmode = 2;
    } else if (!strcmp("none", opt[0])) {
        oppmode = 0;
    } else {
        HIP_ERROR("Invalid argument\n");
        err = -EINVAL;
        goto out;
    }

    /* Build the message header */
    err = hip_build_user_hdr(msg, SO_HIP_SET_OPPORTUNISTIC_MODE, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out;
    }

    err = hip_build_param_contents(msg, (void *) &oppmode, HIP_PARAM_UINT,
                                   sizeof(unsigned int));
    if (err) {
        HIP_ERROR("build param oppmode failed: %s\n", strerror(err));
        goto out;
    }

out:
    return err;
}

/**
 * turn blind support on or off
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt an array containing a single string "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_blind(hip_common_t *msg, int action,
                                 const char *opt[], int optc, int send_only)
{
    int err    = 0;
    int status = 0;

    HIP_DEBUG("hipconf: using blind\n");

    if (optc != 1) {
        HIP_ERROR("Missing arguments\n");
        err = -EINVAL;
        goto out;
    }

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SET_BLIND_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SET_BLIND_OFF;
    } else {
        HIP_PERROR("not a valid blind mode\n");
        err = -EAFNOSUPPORT;
        goto out;
    }

    err = hip_build_user_hdr(msg, status, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out;
    }

out:
    return err;
}

/**
 * Function that is used to set the name sent to DHT in name/fqdn -> HIT -> IP mappings
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt hostname
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_set(hip_common_t *msg,
                               int action,
                               const char *opt[],
                               int optc,
                               int send_only)
{
    int err      = 0;
    int len_name = 0;
    len_name = strlen(opt[0]);
    HIP_DEBUG("Name received from user: %s (len = %d (max 256))\n", opt[0], len_name);
    HIP_IFEL((len_name > 255), -1, "Name too long, max 256\n");

    err      = hip_build_user_hdr(msg, SO_HIP_DHT_SET, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }

    err = hip_build_param_opendht_set(msg, opt[0]);
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out_err;
    }
out_err:
    return err;
}

/**
 * Function that is used to set the used gateway addr port and ttl with DHT
 * e.g. hipconf dht gw <hostname|HIT|IP> 5851 600
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt hostname|HIT|IP, port and ttl (as strings)
 * @param optc 3
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero on success, or negative error value on error.
 */
static int hip_conf_handle_gw(hip_common_t *msg,
                              int action,
                              const char *opt[],
                              int optc,
                              int send_only)
{
    int err;
    int ret_HIT = 0, ret_IP = 0, ret_HOSTNAME = 0;
    struct in_addr ip_gw;
    struct in6_addr ip_gw_mapped;
    char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];

    HIP_INFO("Resolving new gateway for openDHT %s\n", opt[0]);

    memset(hostname, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX);

    if (optc != 3) {
        HIP_ERROR("Missing arguments\n");
        err = -EINVAL;
        goto out_err;
    }

    if (strlen(opt[0]) > 39) { //address longer than size of ipv6 address
        HIP_ERROR("Address longer than maximum allowed\n");
        err = -EINVAL;
        goto out_err;
    }

    ret_IP  = inet_pton(AF_INET, opt[0], &ip_gw);
    ret_HIT = inet_pton(AF_INET6, opt[0], &ip_gw_mapped);

    if (!(ret_IP || ret_HIT)) {
        //HIP_ERROR("Gateway address not correct\n");
        //goto out_err;
        memcpy(hostname, opt[0], HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
        hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX - 1] = '\0';
        ret_HOSTNAME                               = 1;
    }

    if (ret_IP) {
        IPV4_TO_IPV6_MAP(&ip_gw, &ip_gw_mapped);
    }

    if (ret_IP || ret_HIT) {
        HIP_DEBUG_IN6ADDR("Address ", &ip_gw_mapped);
    } else {
        HIP_DEBUG("Host name : %s\n", hostname);
    }

    err = hip_build_user_hdr(msg, SO_HIP_DHT_GW, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }

    err = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped,
                                          atoi(opt[2]), atoi(opt[1]), hostname);
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out_err;
    }

out_err:
    return err;
}

/**
 * Function that gets data from DHT
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt hostname or HIT as a string
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_get(hip_common_t *msg,
                               int action,
                               const char *opt[],
                               int optc,
                               int send_only)
{
#ifdef CONFIG_HIP_DHT
    int err = 0, is_hit = 0, socket = 0;
    hip_hit_t hit;
    unsigned char dht_response[HIP_MAX_PACKET];
    struct addrinfo *serving_gateway;
    struct hip_opendht_gw_info *gw_info;
    struct hip_host_id *hid;
    struct in_addr tmp_v4;
    struct in6_addr reply6;
    char tmp_ip_str[INET_ADDRSTRLEN];
    int tmp_ttl, tmp_port;
    const char *pret;

    memset(&hit, 0, sizeof(hip_hit_t));

    /* ASK THIS INFO FROM DAEMON */
    HIP_INFO("Asking serving gateway info from daemon...\n");
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DHT_SERVING_GW, 0), -1,
             "Building daemon header failed\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "Send recv daemon info failed\n");
    HIP_IFEL(!(gw_info = hip_get_param(msg, HIP_PARAM_OPENDHT_GW_INFO)), -1,
             "No gw struct found\n");

    /* Check if DHT was on */
    if ((gw_info->ttl == 0) && (gw_info->port == 0)) {
        HIP_INFO("DHT is not in use\n");
        goto out_err;
    }
    memset(&tmp_ip_str, '\0', sizeof(tmp_ip_str));
    tmp_ttl  = gw_info->ttl;
    tmp_port = htons(gw_info->port);
    IPV6_TO_IPV4_MAP(&gw_info->addr, &tmp_v4);
    pret     = inet_ntop(AF_INET, &tmp_v4, tmp_ip_str, 20);
    HIP_INFO("Got address %s, port %d, TTL %d from daemon\n",
             tmp_ip_str, tmp_port, tmp_ttl);

    is_hit   = inet_pton(AF_INET6, opt[0], &hit);

    /* If this is 1 then it is hit (actually any ipv6 would do), if 0 then hostname */
    if (is_hit < 0 && errno == EAFNOSUPPORT) {
        HIP_PERROR("inet_pton: not a valid address family\n");
        err = -EAFNOSUPPORT;
        goto out_err;
    }

    HIP_DEBUG("Resolve the gateway address\n");
    HIP_IFEL(resolve_dht_gateway_info(tmp_ip_str, &serving_gateway, tmp_port, AF_INET), 0,
             "Resolve error!\n");

    HIP_DEBUG("Initialize socket\n");
    socket = init_dht_gateway_socket_gw(socket, serving_gateway);

    _HIP_DEBUG("Connect the DHT socket\n");
    err    = connect_dht_gateway(socket, serving_gateway, 1);

    HIP_DEBUG("Send get msg\n");
    HIP_IFEL((err = opendht_get(socket, (unsigned char *) opt[0],
                                (unsigned char *) tmp_ip_str, tmp_port)), 0, "DHT get error\n");

    HIP_DEBUG("Read response\n");
    HIP_IFE((err = opendht_read_response(socket, dht_response)), -1);

    _HIP_DEBUG("is_hit %d err %d\n", is_hit, err);

    if (is_hit == 1 && err >= 0) {
        _HIP_DUMP_MSG(dht_response);
        _HIP_DEBUG("Returned locators above\n");
        /* hip_print_locator_addresses((struct hip_common *)dht_response); */
        /* Verify signature */
        HIP_IFEL(!(hid = hip_get_param((struct hip_common *) dht_response,
                                       HIP_PARAM_HOST_ID)), -ENOENT,
                 "No HOST_ID found in DHT response\n");

        HIP_IFEL((err = hip_verify_packet_signature((struct hip_common *) dht_response,
                                                    hid)), -1,
                 "Failed to verify the signature in HDRR\n");
        HIP_DEBUG("HDRR signature successfully verified\n");
    } else if (is_hit == 0 && err >= 0)   {
        memcpy(&((&reply6)->s6_addr), dht_response, sizeof(reply6.s6_addr));
        HIP_DEBUG_HIT("Returned HIT", &reply6);
    }
    hip_msg_init(msg);
out_err:
    return err;
#else /* CONFIG_HIP_DHT */
    return -1;
#endif /* CONFIG_HIP_DHT */
}

/**
 * Function that is used to set DHT on or off
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_dht_toggle(hip_common_t *msg,
                                      int action,
                                      const char *opt[],
                                      int optc,
                                      int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_DHT_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_DHT_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Set BUDDIES extension on or off
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt options arguments as strings
 * @param optc number of arguments
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_buddies_toggle(hip_common_t *msg,
                                          int action,
                                          const char *opt[],
                                          int optc,
                                          int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_BUDDIES_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_BUDDIES_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Set SHOTGUN extension on or off
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_shotgun_toggle(hip_common_t *msg,
                                          int action,
                                          const char *opt[],
                                          int optc,
                                          int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SHOTGUN_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SHOTGUN_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }

    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Translate a HIT to an LSI
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt remote hit as a string
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_get_peer_lsi(hip_common_t *msg,
                                        int action,
                                        const char *opt[],
                                        int optc,
                                        int send_only)
{
    int err = 0;
    hip_hit_t hit;
    hip_tlv_common_t *param;
    hip_lsi_t *lsi;
    char lsi_str[INET_ADDRSTRLEN];
    const char *hit_str = opt[0];

    HIP_IFEL((inet_pton(AF_INET6, hit_str, &hit) <= 0), 1,
             "Not an IPv6 address\n");
    HIP_IFEL(!ipv6_addr_is_hit(&hit), -1, "Not a HIT\n");

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_LSI_PEER, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

    HIP_IFE(hip_build_param_contents(msg, &hit, HIP_PARAM_HIT, sizeof(hit)), -1);

    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "send recv daemon info\n");

    param = hip_get_param(msg, HIP_PARAM_LSI);
    HIP_IFEL(!param, -1, "No LSI in msg\n");
    lsi   = hip_get_param_contents_direct(param);
    HIP_IFEL(!inet_ntop(AF_INET, lsi, lsi_str, sizeof(lsi_str)), -1,
             "LSI string conversion failed\n");
    HIP_INFO("HIT %s maps to LSI %s\n", hit_str, lsi_str);

out_err:
    return err;
}


/**
 * Handles @c service commands received from @c hipconf.
 *
 * Create a message to the kernel module from the function parameters @c msg,
 * @c action and @c opt[].
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed on
 *               the given mapping.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type (pointer to @b "rvs" or @b "relay").
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_service(hip_common_t *msg,
                                   int action,
                                   const char *opt[],
                                   int optc,
                                   int send_only)
{
    int err = 0;

    HIP_IFEL((action != ACTION_ADD && action != ACTION_REINIT
              && action != ACTION_DEL), -1,
             "Only actions \"add\", \"del\" and \"reinit\" are supported " \
             "for \"service\".\n");

    HIP_IFEL((optc < 1), -1, "Missing arguments.\n");
    HIP_IFEL((optc > 1), -1, "Too many arguments.\n");

    if (action == ACTION_ADD) {
        if (strcmp(opt[0], "rvs") == 0) {
            HIP_INFO("Adding rendezvous service.\n");
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_RVS, 0), -1,
                     "Failed to build user message header.\n");
        } else if (strcmp(opt[0], "relay") == 0) {
            HIP_INFO("Adding HIP UDP relay service.\n");
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_HIPRELAY, 0), -1,
                     "Failed to build user message header.\n");
        } else if (strcmp(opt[0], "full-relay") == 0) {
            HIP_INFO("Adding HIP_FULLRELAY service.\n");
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_FULLRELAY, 0), -1,
                     "Failed to build user message header.\n");
        } else {
            HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
        }
    } else if (action == ACTION_REINIT) {
        if (strcmp(opt[0], "rvs") == 0) {
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_REINIT_RVS, 0), -1,
                     "Failed to build user message header.\n");
        } else if (strcmp(opt[0], "relay") == 0) {
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_REINIT_RELAY, 0), -1,
                     "Failed to build user message header.\n");
        } else if (strcmp(opt[0], "full-relay") == 0) {
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_REINIT_FULLRELAY, 0), -1,
                     "Failed to build user message header.\n");
        } else {
            HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
        }
    } else if (action == ACTION_DEL) {
        if (strcmp(opt[0], "rvs") == 0) {
            HIP_INFO("Deleting rendezvous service.\n");
            HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CANCEL_RVS, 0),
                     -1, "Failed to build user message header.\n");
        } else if (strcmp(opt[0], "relay") == 0) {
            HIP_INFO("Deleting HIP UDP relay service.\n");
            HIP_IFEL(hip_build_user_hdr(
                         msg, SO_HIP_CANCEL_HIPRELAY, 0), -1,
                     "Failed to build user message header.\n");
        } else if (strcmp(opt[0], "full-relay") == 0) {
            HIP_INFO("Deleting HIP full relay service.\n");
            HIP_IFEL(hip_build_user_hdr(
                         msg, SO_HIP_CANCEL_FULLRELAY, 0), -1,
                     "Failed to build user message header.\n");
        } else {
            HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
        }
    }

out_err:
    return err;
}

/**
 * Handle e.g. "hipconf run normal firefox". Enables HIP support
 * for the given application using LD_PRELOAD. This means that
 * all getaddrinfo() calls go through the modified libinet6 library.
 * This function is depracated.
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt a string containing the name of the application to LD_PRELOAD
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @todo remove this and related constants
 */
static int hip_conf_handle_run_normal(hip_common_t *msg,
                                      int action,
                                      const char *opt[],
                                      int optc,
                                      int send_only)
{
    HIP_ERROR("Unsupported\n");
    return -1;
}


/**
 * query and print information on host associations from hipd
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt an array of string containing one string "all"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_ha(hip_common_t *msg,
                              int action,
                              const char *opt[],
                              int optc,
                              int send_only)
{
    struct hip_tlv_common *current_param = NULL;
    int err                              = 0;
    in6_addr_t hit1;

    HIP_IFEL(optc > 1, -1, "Too many arguments\n");

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0), -1,
             "Building of daemon header failed\n");

    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "send recv daemon info\n");

    while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
        struct hip_hadb_user_info_state *ha =
            hip_get_param_contents_direct(current_param);

        if (!strcmp("all", opt[0])) {
            hip_conf_print_info_ha(ha);
        } else {
            HIP_IFE(convert_string_to_address(opt[0], &hit1), -1);

            if ((ipv6_addr_cmp(&hit1, &ha->hit_our) == 0) ||
                (ipv6_addr_cmp(&hit1, &ha->hit_peer) == 0))
            {
                hip_conf_print_info_ha(ha);
            }
        }
    }

out_err:
    hip_msg_init(msg);

    return err;
}

/**
 * set mobility to lazy or active mode for mhaddr extension
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "lazy" or "active"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_mhaddr(hip_common_t *msg,
                                  int action,
                                  const char *opt[],
                                  int optc,
                                  int send_only)
{
    int err = 0;

    if (strcmp("active", opt[0]) == 0) {
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_MHADDR_ACTIVE, 0), -1,
                 "Building of daemon header failed\n");
        HIP_INFO("mhaddr mode set to active successfully\n");
    } else {
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_MHADDR_LAZY, 0), -1,
                 "Building of daemon header failed\n");
        HIP_INFO("mhaddr mode set to lazy successfully\n");
    }

    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "send recv daemon info\n");

out_err:
    return err;
}

/**
 * prefer hard or soft handovers
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "hard" or "soft"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_handover(hip_common_t *msg,
                                    int action,
                                    const char *opt[],
                                    int optc,
                                    int send_only)
{
    int err = 0;

    if (strcmp("hard", opt[0]) == 0) {
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_HANDOVER_HARD, 0), -1,
                 "Building of daemon header failed\n");
        HIP_INFO("handover mode set to hard successfully\n");
    } else {
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_HANDOVER_SOFT, 0), -1,
                 "Building of daemon header failed\n");
        HIP_INFO("handover mode set to soft successfully\n");
    }

    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "send recv daemon info\n");

out_err:
    hip_msg_init(msg);

    return err;
}

/**
 * creates the string intended to set the environmental variable
 * LD_PRELOAD. The function required the required libraries, and then
 * includes the prefix (path where these libraries are located) to
 * each one. Finally it appends all of the them to the same string.
 *
 * @param libs            an array of pointers to the required libraries
 * @param lib_all         a pointer to the string to store the result
 * @param lib_all_length  length of the string lib_all
 * @return                zero on success, or -1 overflow in string lib_all
 */

static int hip_append_pathtolib(char **libs, char *lib_all, int lib_all_length)
{
    int c_count   = lib_all_length, err = 0;
    char *lib_aux = lib_all;
    char *prefix  = HIPL_DEFAULT_PREFIX; /* translates to "/usr/local" etc */

    while (*libs != NULL) {
        /* Copying prefix to lib_all */
        HIP_IFEL(c_count < strlen(prefix), -1, "Overflow in string lib_all\n");
        strncpy(lib_aux, prefix, c_count);
        while (*lib_aux != '\0') {
            lib_aux++;
            c_count--;
        }

        /* Copying "/lib/" to lib_all */
        HIP_IFEL(c_count < 5, -1, "Overflow in string lib_all\n");
        strncpy(lib_aux, "/lib/", c_count);
        c_count -= 5;
        lib_aux += 5;

        /* Copying the library name to lib_all */
        HIP_IFEL(c_count < strlen(*libs), -1, "Overflow in string lib_all\n");
        strncpy(lib_aux, *libs, c_count);
        while (*lib_aux != '\0') {
            lib_aux++;
            c_count--;
        }

        /* Adding ':' to separate libraries */
        *lib_aux = ':';
        c_count--;
        lib_aux++;

        /* Next library */
        libs++;
    }

    /* Delete the last ':' */
    *--lib_aux = '\0';

out_err:
    return err;
}

/**
 * Handle the hipconf commands where the type is @c run. Execute new
 * application and set environment variable "LD_PRELOAD" to as type
 * says.
 *
 * @param do_fork Whether to fork or not.
 * @param type   the numeric action identifier for the action to be performed.
 * @param argc   the number of elements in the array.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @return       zero on success, or negative error value on error.
 * @note In order to this function to work properly, "make install"
 *       must be executed to install libraries to right paths. Also library
 *       paths must be set right.
 * @see exec_app_types EXEC_LOADLIB_OPP, EXEC_LOADLIB_HIP and
 *      EXEC_LOADLIB_NONE
 *
 */
int hip_handle_exec_application(int do_fork, int type, int argc, char *argv[])
{
    /* Variables. */
    char lib_all[LIB_LENGTH];
    int err = 0;
    char *libs[5];


    if (do_fork) {
        err = fork();
    }
    if (err < 0) {
        HIP_ERROR("Failed to exec new application.\n");
    } else if (err > 0)   {
        err = 0;
    } else if (err == 0)    {
        HIP_DEBUG("Exec new application.\n");
        if (type == EXEC_LOADLIB_HIP) {
            libs[0] = "libhiptool.so";
            libs[1] = NULL;
            libs[2] = NULL;
            libs[3] = "libhipopendht.so";
        } else if (type == EXEC_LOADLIB_OPP)   {
            libs[0] = "libopphip.so";
            libs[1] = "libhiptool.so";
            libs[2] = NULL;
            libs[3] = "libhipopendht.so";
        }

#if 0
        if (type != EXEC_LOADLIB_NONE) {
            setenv("LD_PRELOAD", libs, 1);
            HIP_DEBUG("LD_PRELOADing\n");
        }
#endif

        hip_append_pathtolib(libs, lib_all, LIB_LENGTH);
        setenv("LD_PRELOAD", lib_all, 1);
        HIP_DEBUG("LD_PRELOADing: %s\n", lib_all);
        err = execvp(argv[0], argv);

        if (err != 0) {
            HIP_DEBUG("Executing new application failed!\n");
            exit(1);
        }
    }

    return err;
}

/**
 * trigger HIP CLOSE to close all SAs and HAs
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt ignored
 * @param optc ignored
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_restart(hip_common_t *msg,
                                   int type,
                                   const char *opt[],
                                   int optc,
                                   int send_only)
{
    int err = 0;

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_RESTART, 0), -1,
             "hip_build_user_hdr() failed!");

out_err:
    return err;
}

/**
 * turn on or off opportunistic TCP extension
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_opptcp(hip_common_t *msg,
                                  int action,
                                  const char *opt[],
                                  int optc,
                                  int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SET_OPPTCP_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SET_OPPTCP_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0),
             -1,
             "Failed to build user message header.: %s\n",
             strerror(err));

out_err:
    return err;
}

/**
 * Handles the hipconf commands where the type is @ tcptimeout. Experimental.
 * Tries to pimp up TCP using /proc file system to tolerate mobility better.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
static int hip_conf_handle_tcptimeout(struct hip_common *msg,
                                      int action,
                                      const char *opt[],
                                      int optc,
                                      int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        HIP_INFO("tcptimeout set on\n");
        status = SO_HIP_SET_TCPTIMEOUT_ON;
    } else if (!strcmp("off", opt[0])) {
        HIP_INFO("tcptimeout set off\n");
        status = SO_HIP_SET_TCPTIMEOUT_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
        // err = -1;
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "build hdr failed: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Function that is used to set HIP PROXY on or off
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_hipproxy(struct hip_common *msg,
                                    int action,
                                    const char *opt[],
                                    int optc,
                                    int send_only)
{
    int err = 0;
#ifdef CONFIG_HIP_HIPPROXY
    int status = 0;
#endif

    HIP_DEBUG("hip_conf_handle_hipproxy()\n");

#ifdef CONFIG_HIP_HIPPROXY
    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SET_HIPPROXY_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SET_HIPPROXY_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "build hdr failed: %s\n", strerror(err));

out_err:
#endif
    return err;
}

/**
 * Handles the hipconf commands where the type is @c locator. Turns on
 * locators for the base exchange. Currently this functionality does not work
 * and is disabled by default.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_hi3(hip_common_t *msg,
                        int action,
                        const char *opt[],
                        int optc, int send_only)
{
    int err = 0, status = 0;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_SET_HI3_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_SET_HI3_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Turn nsupdate extension on or off. The nsupdate extension publishes
 * the HIT and IP address of the host on a given DNS server (as an alternative
 * to DHT). Useful especially with mobility.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action ignored
 * @param opt    "on" or "off"
 * @param optc   1
 * @return       zero on success, or negative error value on error.
 * @see hip_conf_handle_hit_to_ip()
 */
static int hip_conf_handle_nsupdate(hip_common_t *msg,
                                    int action,
                                    const char *opt[],
                                    int optc, int send_only)
{
    int err = 0, status;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_NSUPDATE_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_NSUPDATE_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * ask hipd to map a HIT or LSI to a locator
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt a HIT or LSI
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_map_id_to_addr(struct hip_common *msg,
                                          int action,
                                          const char *opt[],
                                          int optc,
                                          int send_only)
{
    int err = 0;
    struct in6_addr hit;
    struct in_addr lsi;
    struct in6_addr *ip;
    struct in_addr ip4;
    struct hip_tlv_common *param = NULL;
    char addr_str[INET6_ADDRSTRLEN];

    if (inet_pton(AF_INET6, opt[0], &hit) != 1) {
        HIP_IFEL(inet_pton(AF_INET, opt[0], &lsi) != 1, -1,
                 "inet_pton failed\n");
        IPV4_TO_IPV6_MAP(&lsi, &hit);
    }

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_MAP_ID_TO_ADDR, 0), -1,
             "Failed to build message header\n");
    HIP_IFEL(hip_build_param_contents(msg, &hit, HIP_PARAM_IPV6_ADDR,
                                      sizeof(hit)), -1,
             "Failed to build message contents\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "Sending message failed\n");

    while ((param = hip_get_next_param(msg, param))) {
        if (hip_get_param_type(param) != HIP_PARAM_IPV6_ADDR) {
            continue;
        }
        ip = hip_get_param_contents_direct(param);
        if (IN6_IS_ADDR_V4MAPPED(ip)) {
            IPV6_TO_IPV4_MAP(ip, &ip4);
            HIP_IFEL(!inet_ntop(AF_INET, &ip4, addr_str,
                                INET_ADDRSTRLEN), -1, "inet_ntop() failed\n");
        } else {
            HIP_IFEL(!inet_ntop(AF_INET6, ip, addr_str,
                                INET6_ADDRSTRLEN), -1, "inet_ntop() failed\n");
        }

        HIP_INFO("Found IP: %s\n", addr_str);
    }

    hip_msg_init(msg);

out_err:
    return err;
}

/**
 * Set hit-to-ip extension on of off. The extension "subscribes" the host
 * to DNS resolution for HITs from the configured DNS server.
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt "on" or "off"
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @see hip_conf_handle_nsupdate
 * @see hip_conf_handle_hit_to_ip_set
 */
static int hip_conf_handle_hit_to_ip(hip_common_t *msg,
                                     int action,
                                     const char *opt[],
                                     int optc, int send_only)
{
    int err = 0, status;

    if (!strcmp("on", opt[0])) {
        status = SO_HIP_HIT_TO_IP_ON;
    } else if (!strcmp("off", opt[0])) {
        status = SO_HIP_HIT_TO_IP_OFF;
    } else {
        return hip_conf_handle_map_id_to_addr(msg, action, opt, optc, send_only);
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1,
             "Failed to build user message header.: %s\n", strerror(err));

out_err:
    return err;
}

/**
 * Set the HIT-to-IP server
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt the ip address of the HIT-to-IP server
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 * @see hip_conf_handle_hit_to_ip
 */
static int hip_conf_handle_hit_to_ip_set(hip_common_t *msg,
                                         int action,
                                         const char *opt[],
                                         int optc,
                                         int send_only)
{
    int err      = 0;
    int len_name = 0;
    len_name = strlen(opt[0]);
    HIP_DEBUG("hit-to-ip zone received from user: %s (len = %d (max %d))\n", opt[0], len_name, HIT_TO_IP_ZONE_MAX_LEN);
    HIP_IFEL((len_name >= HIT_TO_IP_ZONE_MAX_LEN), -1, "Name too long (max %s)\n", HIT_TO_IP_ZONE_MAX_LEN);

    err      = hip_build_user_hdr(msg, SO_HIP_HIT_TO_IP_SET, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }
    err = hip_build_param_hit_to_ip_set(msg, opt[0]);
    if (err) {
        HIP_ERROR("build param failed: %s\n", strerror(err));
        goto out_err;
    }
out_err:
    return err;
}

/**
 * translate a remote LSI to a HIT
 *
 * @param msg input/output message for the query/response for hipd
 * @param action unused
 * @param opt the LSI as a string
 * @param optc 1
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
static int hip_conf_handle_lsi_to_hit(struct hip_common *msg,
                                      int action,
                                      const char *opt[],
                                      int optc,
                                      int send_only)
{
    int err                      = 0;
    hip_lsi_t lsi;
    struct in6_addr *hit;
    struct hip_tlv_common *param = NULL;

    HIP_IFEL(inet_pton(AF_INET, opt[0], &lsi) != 1, -1, "inet_pton()\n");
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_LSI_TO_HIT, 0), -1,
             "Failed to build message header\n");
    HIP_IFEL(hip_build_param_contents(msg, &lsi, HIP_PARAM_LSI, sizeof(lsi)),
             -1, "Failed to build message contents\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "Sending message failed\n");

    while ((param = hip_get_next_param(msg, param))) {
        if (hip_get_param_type(param) != HIP_PARAM_IPV6_ADDR) {
            continue;
        }
        hit = hip_get_param_contents_direct(param);
        HIP_INFO_HIT("Found HIT: ", hit);
    }

    hip_msg_init(msg);

out_err:
    return err;
}

/**
 * Handles the hipconf commands where the type is @c load.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_load(struct hip_common *msg,
                         int action,
                         const char *opt[],
                         int optc,
                         int send_only)
{
    int err          = 0, i, len;
    FILE *hip_config = NULL;

    List list;
    char *c, line[128], *hip_arg, str[128], *fname, *args[64],
    *comment, *nl;

    HIP_IFEL((optc != 1), -1, "Missing arguments\n");

    if (!strcmp(opt[0], "default")) {
        fname = HIPL_CONFIG_FILE;
    } else {
        fname = (char *) opt[0];
    }


    HIP_IFEL(!(hip_config = fopen(fname, "r")), -1,
             "Error: can't open config file %s.\n", fname);

    while (err == 0 && fgets(line, sizeof(line), hip_config) != NULL) {
        _HIP_DEBUG("line %s\n", line);
        /* Remove whitespace */
        c = line;
        while (*c == ' ' || *c == '\t') {
            c++;
        }

        /* Line is a comment or empty */
        if (c[0] == '#' || c[0] == '\n' || c[0] == '\0') {
            continue;
        }

        /* Terminate before (the first) trailing comment */
        comment = strchr(c, '#');
        if (comment) {
            *comment = '\0';
        }

        /* prefix the contents of the line with" hipconf"  */
        memset(str, '\0', sizeof(str));
        strcpy(str, "hipconf");
        str[strlen(str)] = ' ';
        hip_arg          = strcat(str, c);
        /* replace \n with \0  */
        nl               = strchr(hip_arg, '\n');
        if (nl) {
            *nl = '\0';
        }

        /* split the line into an array of strings and feed it
         * recursively to hipconf */
        initlist(&list);
        extractsubstrings(hip_arg, &list);
        len = length(&list);
        for (i = 0; i < len; i++) {
            /* the list is backwards ordered */
            args[len - i - 1] = getitem(&list, i);
        }
        err = hip_do_hipconf(len, args, 1);
        if (err) {
            HIP_ERROR("Error on the following line: %s\n", line);
            HIP_ERROR("Ignoring error on hipd configuration\n");
            err = 0;
        }

        destroy(&list);
    }

out_err:
    if (hip_config) {
        fclose(hip_config);
    }

    return err;
}

/**
 * Function pointer array containing pointers to handler functions.
 * Add a handler function for your new action in the action_handler[] array.
 * If you added a handler function here, do not forget to define that function
 * somewhere in this source file. The API for the array is as follows:
 *
 * - Input/output message describes the query message to be sent to hipd. The
 *   message may be overwritten by hipd with a response message from hipd.
 * - The action to take
 * - Arguments for the action
 * - Number of arguments
 * - Wait for a response message from hipd
 *
 * @note You will have to register also action and type handlers. See
 *       hip_conf_get_action(), hip_conf_check_action_argc() and
 *       hip_conf_get_type()
 * @note Keep the elements in the same order as the @c TYPE values are defined
 *       in hipconf.h because type values are used as @c action_handler array
 *       index. Locations and order of these handlers are important.
 */
int (*action_handler[])(hip_common_t *,
                        int action,
                        const char *opt[],
                        int optc,
                        int send_only) =
{
    NULL,     /* reserved */
    hip_conf_handle_hi,                 /* 1: TYPE_HI */
    hip_conf_handle_map,                /* 2: TYPE_MAP */
    hip_conf_handle_rst,                /* 3: TYPE_RST */
    hip_conf_handle_server,             /* 4: TYPE_SERVER */
    /* Any client side registration action. */
    hip_conf_handle_bos,                /* 5: TYPE_BOS */
    hip_conf_handle_puzzle,             /* 6: TYPE_PUZZLE */
    hip_conf_handle_nat,                /* 7: TYPE_NAT */
    hip_conf_handle_opp,                /* 8: TYPE_OPP */
    hip_conf_handle_blind,              /* 9: TYPE_BLIND */
    hip_conf_handle_service,            /* 10: TYPE_SERVICE */
    /* Any server side registration action. */
    hip_conf_handle_load,               /* 11: TYPE_CONFIG */
    hip_conf_handle_run_normal,         /* 12: TYPE_RUN */
    NULL,                               /* was 13: TYPE_TTL */
    hip_conf_handle_gw,                 /* 14: TYPE_GW */
    hip_conf_handle_get,                /* 15: TYPE_GET */
    hip_conf_handle_ha,                 /* 16: TYPE_HA */
    hip_conf_handle_mhaddr,             /* 17: TYPE_MHADDR */
    hip_conf_handle_debug,              /* 18: TYPE_DEBUG */
    hip_conf_handle_restart,            /* 19: TYPE_DAEMON */
    hip_conf_handle_locator,            /* 20: TYPE_LOCATOR */
    hip_conf_handle_set,                /* 21: TYPE_SET */
    hip_conf_handle_dht_toggle,         /* 22: TYPE_DHT */
    hip_conf_handle_opptcp,             /* 23: TYPE_OPPTCP */
    hip_conf_handle_trans_order,        /* 24: TYPE_ORDER */
    hip_conf_handle_tcptimeout,         /* 25: TYPE_TCPTIMEOUT */
    hip_conf_handle_hipproxy,           /* 26: TYPE_HIPPROXY */
    hip_conf_handle_heartbeat,          /* 27: TYPE_HEARTBEAT */
    hip_conf_handle_hi3,                /* 28: TYPE_HI3 */
    NULL,                               /* 29: unused */
    hip_conf_handle_buddies_toggle,     /* 30: TYPE_BUDDIES */
    NULL,     /* 31: unused */
    hip_conf_handle_nsupdate,           /* 32: TYPE_NSUPDATE */
    hip_conf_handle_hit_to_ip,          /* 33: TYPE_HIT_TO_IP */
    hip_conf_handle_hit_to_ip_set,      /* 34: TYPE_HIT_TO_IP_SET */
    hip_conf_handle_get_peer_lsi,       /* 35: TYPE_MAP_GET_PEER_LSI */
    hip_conf_handle_nat_port,           /* 36: TYPE_NAT_LOCAL_PORT */
    hip_conf_handle_nat_port,           /* 37: TYPE_PEER_LOCAL_PORT */
    hip_conf_handle_datapacket,         /* 38:TYPE_DATAPACKET*/
    hip_conf_handle_shotgun_toggle,     /* 39: TYPE_SHOTGUN */
    hip_conf_handle_map_id_to_addr,      /* 40: TYPE_ID_TO_ADDR */
    hip_conf_handle_lsi_to_hit,          /* 41: TYPE_LSI_TO_HIT */
    hip_conf_handle_handover,           /* 42: TYPE_HANDOVER */
    hip_conf_handle_manual_update,      /* 43: TYPE_MANUAL_UPDATE */

    NULL     /* TYPE_MAX, the end. */
};

/**
 * hipconf stub used by the hipconf tool and hipd (to read conf file)
 *
 * @param msg input/output message for the query/response for hipd
 * @param opt options arguments as strings
 * @param optc number of arguments
 * @param send_only 1 if no response from hipd should be requrested, or 0 if
 *                  should block for a response from hipd
 * @return zero for success and negative on error
 */
int hip_do_hipconf(int argc, char *argv[], int send_only)
{
    int err           = 0, type_arg = 0;
    long int action   = 0, type = 0;
    hip_common_t *msg = NULL;
    //char *text = NULL;

    /* Check that we have at least one command line argument. */
    HIP_IFEL((argc < 2), -1, "Invalid arguments.\n\n%s usage:\n%s\n",
             argv[0], hipconf_usage);

    /* Get a numeric value representing the action. */
    action = hip_conf_get_action(argv);

    HIP_IFEL((action == -1), -1,
             "Invalid action argument '%s'\n", argv[1]);

    /* Check that we have at least the minumum number of arguments
     * for the given action. */
    HIP_IFEL((argc < hip_conf_check_action_argc(action) + 2), -1,
             "Not enough arguments given for the action '%s'\n",
             argv[1]);

    /* Is this redundant? What does it do? -Lauri 19.03.2008 19:46. */
    HIP_IFEL(((type_arg = hip_conf_get_type_arg(action)) < 0), -1,
             "Could not parse type\n");

    _HIP_DEBUG("ARGV[TYPE_ARG] = %s ", argv[type_arg]);
    type = hip_conf_get_type(argv[type_arg], argv);
    HIP_IFEL((type <= 0 || type > TYPE_MAX), -1,
             "Invalid type argument '%s' %d\n", argv[type_arg], type);

    /* Get the type argument for the given action. */
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
    hip_msg_init(msg);

    HIP_IFEL((*action_handler[type] == NULL), 0, "Unhandled action, ignore\n");

    /* Call handler function from the handler function pointer
     * array at index "type" with given commandline arguments.
     * The functions build a hip_common message. */
    if (argc == 3) {
        err = (*action_handler[type])(msg, action, (const char **) &argv[2], argc - 3, send_only);
    } else {
        err = (*action_handler[type])(msg, action, (const char **) &argv[3], argc - 3, send_only);
    }

    if (err != 0) {
        HIP_ERROR("Failed to send a message to the HIP daemon.\n");
        goto out_err;
    }

    /* hipconf new hi does not involve any messages to hipd */
    if (hip_get_msg_type(msg) == 0) {
        goto out_err;
    }

    /* Send message to hipd */
    HIP_IFEL(hip_send_recv_daemon_info(msg, send_only, 0), -1,
             "Failed to send user message to the HIP daemon.\n");

    HIP_INFO("User message was sent successfully to the HIP daemon.\n");

out_err:
    if (msg != NULL) {
        free(msg);
    }

    if (err) {
        HIP_ERROR("(Check syntax for hipconf. Is hipd running or root privilege needed?)\n");
    }

    return err;
}
