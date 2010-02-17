/** @file
 * A header file for hipconf.c
 *
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @author  Tao Wan <twan@cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIPCONF_H
#define HIPCONF_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include "lib/core/protodefs.h"

/*
 * DO NOT TOUCH THESE, unless you know what you are doing.
 * These values are used for TYPE_xxx macros.
 */

/**
 * @addtogroup exec_app_types
 * @{
 */
/**
 * Execute application with opportunistic library preloaded.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_OPP        8

/**
 * Execute application with hip-libraries preloaded.
 * Overides example getaddrinfo().
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_HIP        12

/**
 * Execute application,no preloading of libraries.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_NONE       13

/**
 * Maximum length of the string for that stores all libraries.
 * @see handle_exec_application()
 */
#define LIB_LENGTH      200
/** @} addtogroup exec_app_types */

/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2
#define OPT_HI_KEYLEN 3


#define HIPL_CONFIG_FILE_EX \
    "# Format of this file is as with hipconf, but without hipconf prefix\n\
# add hi default    # add all four HITs (see bug id 522)\n\
# add map HIT IP    # preload some HIT-to-IP mappings to hipd\n\
# add service rvs   # the host acts as HIP rendezvous (see also /etc/hip/relay_config)\n\
# add server rvs [RVS-HIT] <RVS-IP-OR-HOSTNAME> <lifetime-secs> # register to rendezvous server\n\
# add server relay [RELAY-HIT] <RVS-IP-OR-HOSTNAME> <lifetime-secs> # register to relay server\n\
# add server full-relay [RELAY-HIT] <RVS-IP-OR-HOSTNAME> <lifetime-secs> # register to relay server\n\
hit-to-ip on # resolve HITs to locators in dynamic DNS zone\n\
# hit-to-ip set hit-to-ip.infrahip.net. # resolve HITs to locators in dynamic DNS zone\n\
nsupdate on # send dynamic DNS updates\n\
# add server rvs hiprvs.infrahip.net 50000 # Register to free RVS at infrahip\n\
opendht on # turn DHT support on (use /etc/hip/dhtservers to define the used server)\n\
# heartbeat 10 # send ICMPv6 messages inside HIP tunnels\n\
# locator on        # host sends all of its locators in base exchange\n\
# datapacket on # experimental draft hiccups extensions\n\
# shotgun on # use all possible src/dst IP combinations to send I1/UPDATE\n\
# opp normal|advanced|none\n\
# transform order 213 # crypto preference order (1=AES, 2=3DES, 3=NULL)\n\
nat plain-udp       # use UDP capsulation (for NATted environments)\n\
debug medium        # debug verbosity: all, medium or none\n"

#define HOSTS_FILE "/etc/hosts"
#define HIPL_HOSTS_FILE_EX \
    "# This file stores the HITs of the hosts, in a similar fashion to /etc/hosts.\n\
# The aliases are optional.  Examples:\n\
#2001:1e:361f:8a55:6730:6f82:ef36:2fff kyle kyle.com # This is a HIT with alias\n\
#2001:17:53ab:9ff1:3cba:15f:86d6:ea2e kenny       # This is a HIT without alias\n"

#define HIPL_NSUPDATE_CONF_FILE     HIPL_SYSCONFDIR "/nsupdate.conf"

#define HIPL_NSUPDATE_CONF_FILE_EX \
    "##########################################################\n" \
    "# configuration examples\n" \
    "##########################################################\n" \
    "# update records for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net.\n" \
    "# $HIT_TO_IP_ZONE = 'hit-to-ip.infrahip.net.';\n" \
    "# or in some other zone\n" \
    "# $HIT_TO_IP_ZONE = 'hit-to-ip.example.org.';\n" \
    "\n" \
    "# update is sent to SOA if server empty\n" \
    "# $HIT_TO_IP_SERVER = '';\n" \
    "# or you may define it \n" \
    "# $HIT_TO_IP_SERVER = 'ns.example.net.';\n" \
    "\n" \
    "# name of key if you configured it on the server\n" \
    "# please also chown this file to nobody and chmod 400\n" \
    "# $HIT_TO_IP_KEY_NAME='key.hit-to-ip';\n" \
    "# $HIT_TO_IP_KEY_NAME = '';\n" \
    "\n" \
    "# secret of that key\n" \
    "# $HIT_TO_IP_KEY_SECRET='Ousu6700S9sfYSL4UIKtvnxY4FKwYdgXrnEgDAu/rmUAoyBGFwGs0eY38KmYGLT1UbcL/O0igGFpm+NwGftdEQ==';\n" \
    "# $HIT_TO_IP_KEY_SECRET = '';\n" \
    "\n" \
    "# TTL inserted for the records\n" \
    "# $HIT_TO_IP_TTL = 1;\n" \
    "###########################################################\n" \
    "# domain with ORCHID prefix \n" \
    "# $REVERSE_ZONE = '1.0.0.1.0.0.2.ip6.arpa.'; \n" \
    "# \n" \
    "# $REVERSE_SERVER = 'ptr-soa-hit.infrahip.net.'; # since SOA 1.0.0.1.0.0.2.ip6.arpa. is dns1.icann.org. now\n" \
    "# $REVERSE_KEY_NAME = '';\n" \
    "# $REVERSE_KEY_SECRET = '';\n" \
    "# $REVERSE_TTL = 86400;\n" \
    "# System hostname is used if empty\n" \
    "# $REVERSE_HOSTNAME = 'stargazer-hit.pc.infrahip.net';\n" \
    "###########################################################\n"

/**
 * hipconf tool actions. These are numerical values for the first commandline
 * argument. For example in "tools/hipconf get hi default" -command "get"
 * is the action. If you want a new action named as 'NEWACT', define a
 * constant variable which has value between 0 and ACTION_MAX.
 * Probably you also need to increase the value of ACTION_MAX.
 * @see hip_conf_get_action()
 */

/* 0 is reserved */
#define ACTION_ADD 1
#define ACTION_DEL 2
#define ACTION_NEW 3
#define ACTION_NAT 4
#define ACTION_HIP 5
#define ACTION_SET 6
#define ACTION_INC 7
#define ACTION_DEC 8
#define ACTION_GET 9
#define ACTION_RUN 10
#define ACTION_LOAD 11
/* unused, was ACTION_DHT 12 */
#define ACTION_HA  13
#define ACTION_RST 14
#define ACTION_BOS 15
#define ACTION_DEBUG 16
#define ACTION_MHADDR 17
#define ACTION_RESTART 18
#define ACTION_LOCATOR 19
/* unused, was ACTION_OPENDHT 20 */
/* free slot (was for ACTION_OPPTCP  21) */
#define ACTION_TRANSORDER 22
#define ACTION_TCPTIMEOUT 23 /* add By Tao Wan, on 04.01.2008 */
/* unused, was ACTION_HIPPROXY 24 */
#define ACTION_REINIT 25
#define ACTION_HEARTBEAT 26
/* unused, was ACTION_HI3 27 */
#define ACTION_HIT_TO_LSI 28
#define ACTION_BUDDIES 29
#define ACTION_NSUPDATE 30
#define ACTION_HIT_TO_IP 31
#define ACTION_HIT_TO_IP_SET 32
#define ACTION_NAT_LOCAL_PORT 33
#define ACTION_NAT_PEER_PORT 34
#define ACTION_DATAPACKET 35  /*Support for datapacket--Prabhu */
#define ACTION_SHOTGUN 36
#define ACTION_MAP_ID_TO_ADDR 37
#define ACTION_LSI_TO_HIT 38
#define ACTION_HANDOVER 39
#define ACTION_MANUAL_UPDATE 40
#define ACTION_MAX 41 /* exclusive */

int hip_handle_exec_application(int fork, int type, int argc, char **argv);
int hip_do_hipconf(int argc, char *argv[], int send_only);

/* Externally used handler functions */
/* TODO: Is there a clean way to get rid of this external use? */
int hip_conf_handle_load(hip_common_t *msg,
                         int type,
                         const char *opt[],
                         int optc,
                         int send_only);
int hip_conf_handle_bos(hip_common_t *msg,
                        int type,
                        const char *opt[],
                        int optc,
                        int send_only);
int hip_conf_handle_hi(hip_common_t *msg,
                       int type,
                       const char *opt[],
                       int optc,
                       int send_only);
#endif /* HIPCONF */
