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


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int connhipd_init(void);
int connhipd_thread(void *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

