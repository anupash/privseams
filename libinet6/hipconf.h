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
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 */
#ifndef HIPCONF_H
#define HIPCONF_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sysexits.h>
#include <assert.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "debug.h"
#include "crypto.h"
#include "builder.h"
#include "hipd.h"

#include "util.h"
#include "libhipopendht.h"

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
#define EXEC_LOADLIB_OPP	8

/**
 * Execute application with hip-libraries preloaded.
 * Overides example getaddrinfo().
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_HIP	12

/**
 * Execute application,no preloading of libraries.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_NONE	13

/**
 * Maximum length of the string for that stores all libraries.
 * @see handle_exec_application()
 */
#define LIB_LENGTH	200
/** @} addtogroup exec_app_types */

/* hipconf tool actions. These are numerical values for the first commandline
   argument. For example in "tools/hipconf get hi default" -command "get"
   is the action. */


/* Important! These values are used as array indexes, so keep in this order.
   Add values after the last value and increment TYPE_MAX. */
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
#define ACTION_DHT 12
#define ACTION_HA  13
#define ACTION_RST 14
#define ACTION_BOS 15
#define ACTION_DEBUG 16
#define ACTION_HANDOFF 17
#define ACTION_RESTART 18
#define ACTION_LOCATOR 19
#define ACTION_OPENDHT 20
#define ACTION_OPPTCP  21
#define ACTION_TRANSORDER 22
#define ACTION_MAX 23 /* exclusive */

/* 0 is reserved */
#define TYPE_HI      	1
#define TYPE_MAP     	2
#define TYPE_RST     	3
#define TYPE_RVS     	4
#define TYPE_BOS     	5
#define TYPE_PUZZLE  	6
#define TYPE_NAT     	7
#define TYPE_OPP     	EXEC_LOADLIB_OPP /* Should be 8 */
#define TYPE_ESCROW  	9
#define TYPE_SERVICE 	10
#define TYPE_CONFIG     11
#define TYPE_RUN     	EXEC_LOADLIB_HIP /* Should be 12 */
#define TYPE_TTL        13
#define TYPE_GW         14
#define TYPE_GET        15
#define TYPE_BLIND      16
#define TYPE_HA         17
#define TYPE_MODE       18
#define TYPE_DEBUG      19
#define TYPE_DAEMON     20
#define TYPE_LOCATOR    21
#define TYPE_RELAY_UDP_HIP 22
#define TYPE_SET        23 /* DHT set <name> */
#define TYPE_DHT        24
#define TYPE_OPPTCP		25
#define TYPE_ORDER      26
#define TYPE_MAX    	27 /* exclusive */

/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2

#define HIPD_CONFIG_FILE     "/etc/hip/hipd_config"
#define HIPD_CONFIG_FILE_EX \
"# Format of this file is as with hipconf, but without hipconf prefix.\n\
# add map HIT IP    # preload some HIT-to-IP mappings to hipd \n\
# add service rvs   # the host acts as HIP rendezvous\n\
# nat on            # the host is behind a NAT\n\
# dht gw host port port TTL # set dht gw hostname|ip port default=5851\n\
# locator on # host sends all of its locators in base exchange \n\
opendht off # Jan 2007: OpenDHT infrastructure is flaky -Samu/Miika\n\
debug medium        # debug verbosity: all, medium or none\n"

#define HIPD_HOSTS_FILE     "/etc/hip/hosts"
#define HOSTS_FILE "/etc/hosts"
#define HIPD_HOSTS_FILE_EX \
"# This file stores the HITs of the hosts, in a similar fashion to /etc/hosts.\n\
# The aliases are optional.  Examples:\n\
#2001:1e:361f:8a55:6730:6f82:ef36:2fff kyle kyle.com # This is a HIT with alias\n\
#2001:17:53ab:9ff1:3cba:15f:86d6:ea2e kenny       # This is a HIT without alias\n"

int hip_handle_exec_application(int fork, int type, int argc, char **argv);
int hip_conf_handle_restart(struct hip_common *, int type, const char *opt[], int optc);
int hip_append_pathtolib(char **libs, char *lib_all, int lib_all_length);
int hip_conf_handle_hi(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_map(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_rst(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_debug(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_bos(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_rvs(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_hipudprelay(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_del(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_nat(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_locator(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_puzzle(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_opp(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_blind(struct hip_common *, int type, const char **opt, int optc);
int hip_conf_handle_escrow(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_service(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_load(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_ttl(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_gw(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_trans_order(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_get(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_set(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_dht_toggle(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_run_normal(struct hip_common *msg, int action,
			       const char *opt[], int optc);
int hip_get_all_hits(struct hip_common *msg,char *argv[]);
int hip_get_action(char *action);
int hip_get_type(char *type);
int hip_conf_handle_ha(struct hip_common *msg, int action,const char *opt[], int optc);
int hip_conf_handle_handoff(struct hip_common *msg, int action,const char *opt[], int optc);
int hip_do_hipconf(int argc, char *argv[], int send_only);
int hip_conf_handle_opptcp(struct hip_common *, int type, const char *opt[], int optc);
#endif /* HIPCONF */
