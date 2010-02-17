/*
 *  HIP Agent
 *
 *  License: GNU/GPL
 *  Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#ifndef HIP_AGENT_GUI_INTERFACE_H
#define HIP_AGENT_GUI_INTERFACE_H

#include "hitdb.h"

/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif

/* FUNCTION DEFINITIONS */
int check_hit(HIT_Remote *, int);

/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif

#endif /* HIP_AGENT_GUI_INTERFACE_H */
