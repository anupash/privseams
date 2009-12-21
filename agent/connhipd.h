/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef CONNHIPD_H
#define CONNHIPD_H

/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
//#include <socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif

#include "libhipcore/icomm.h"

#include "agent.h"
#include "libhipcore/debug.h"
#include "tools.h"
#include "hitdb.h"
#include "gui_interface.h"
#include "libhipcore/message.h"
#include "libhipcore/builder.h"

/******************************************************************************/
/* DEFINES */

/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/

/******************************************************************************/
/* FUNCTION DEFINITIONS */
int connhipd_init_sock(void);
int connhipd_run_thread(void);
void connhipd_quit(void);

/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*CONNHIPD_H */ 

