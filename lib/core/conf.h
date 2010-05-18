/** @file
 * A header file for conf.c
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

#ifndef HIP_LIB_CONF_HIPCONF_H
#define HIP_LIB_CONF_HIPCONF_H

#include <stdlib.h>

#include "config.h"
#include "lib/core/protodefs.h"

/*
 * DO NOT TOUCH THESE, unless you know what you are doing.
 * These values are used for TYPE_xxx macros.
 */

/** @defgroup exec_app_types Execute application types
 * @{
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
/* @} */

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
/* free slot */
#define ACTION_HA  13
#define ACTION_RST 14
/* free slot */
#define ACTION_DEBUG 16
#define ACTION_MHADDR 17
#define ACTION_RESTART 18
#define ACTION_LOCATOR 19
/* free slot */
/* free slot (was for ACTION_OPPTCP  21) */
#define ACTION_TRANSORDER 22
#define ACTION_TCPTIMEOUT 23 /* add By Tao Wan, on 04.01.2008 */
#define ACTION_HIPPROXY 24
#define ACTION_REINIT 25
#define ACTION_HEARTBEAT 26

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

int hip_handle_exec_app(int fork, int type, int argc, char **argv);
int hip_do_hipconf(int argc, char *argv[], int send_only);

/* Externally used handler functions */
/* TODO: Is there a clean way to get rid of this external use? */
int hip_conf_handle_load(hip_common_t *msg,
                         int type,
                         const char *opt[],
                         int optc,
                         int send_only);

#endif /* HIP_LIB_CONF_HIPCONF_H */
