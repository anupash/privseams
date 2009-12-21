/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef AGENT_H
#define AGENT_H


/******************************************************************************/
/* DEFINES */

/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wait.h> 
#include <unistd.h>
#include <time.h>

#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif

#include "tools.h"
#include "libhipgui/hipgui.h"
#include "gui_interface.h"
#include "connhipd.h"
#include "libhipcore/hip_capability.h"

/******************************************************************************/
/* FUNCTION DEFINITIONS */



#endif /* END OF HEADER FILE */
/******************************************************************************/

