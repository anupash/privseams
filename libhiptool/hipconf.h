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

#define ACTION_MAX 11 /* exclusive */

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
#define TYPE_RESERVED	EXEC_LOADLIB_NONE /* Should be 13 */
#define TYPE_MAX    	14 /* exclusive */

/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2

#define HIPD_CONFIG_FILE "/etc/hip/hipd_config"

int handle_exec_application(int fork, int type, char **argv, int argc);


#endif /* HIPCONF */
