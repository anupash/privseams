/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef AGENT_H
#define AGENT_H

/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
//#include <socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <signal.h>

#include "hip.h"
#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
//#include "workqueue.h"
#include "agent_tools.h"
#include "gui_interface.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */



#endif /* END OF HEADER FILE */
/******************************************************************************/

