/*
    HIP Agent
*/

#ifndef CONNHIPD_H
#define CONNHIPD_H

/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
#include <socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "hip.h"
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "workqueue.h"
#include "agent_tools.h"
#include "hit_db.h"
#include "gui_interface.h"


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int connhipd_init(void);
int connhipd_thread(void *);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

