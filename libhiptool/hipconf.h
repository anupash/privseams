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

/** @} addtogroup exec_app_types */

/* 0 is reserved */
#define ACTION_ADD 1
#define ACTION_DEL 2
#define ACTION_NEW 3
#define ACTION_HIP 4
#define ACTION_SET 5
#define ACTION_INC 6
#define ACTION_DEC 7
#define ACTION_GET 8
#define ACTION_RUN 9
#define ACTION_LOAD 10
#define ACTION_DHT 11

#define ACTION_MAX 12 /* exclusive */

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
/* 3 points below for DHT TTL/GET/GW */
#define TYPE_TTL        13
#define TYPE_GW         14
#define TYPE_GET        15
#define TYPE_BLIND      16
#define TYPE_MAX    	17 /* exclusive */


/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2

#define HIPD_CONFIG_FILE     "/etc/hip/hipd_config"
#define HIPD_CONFIG_FILE_EX \
"# Format of this file is as with hipconf, but without hipconf prefix.\n\
# Example: add map HIT IP\n"

int hip_handle_exec_application(int fork, int type, char **argv, int argc);
int hip_conf_handle_hi(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_map(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_rst(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_bos(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_rvs(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_del(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_nat(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_puzzle(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_opp(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_blind(struct hip_common *, int type, const char **opt, int optc);
int hip_conf_handle_escrow(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_service(struct hip_common *msg, int action, const char *opt[], int optc);
int hip_conf_handle_load(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_ttl(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_gw(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_get(struct hip_common *, int type, const char *opt[], int optc);
int hip_conf_handle_run_normal(struct hip_common *msg, int action,
			       const char *opt[], int optc);
int hip_get_action(char *action);
int hip_get_type(char *type);
int hip_do_hipconf(int argc, char *argv[]);

#endif /* HIPCONF */
