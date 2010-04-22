/*
 *  HIP Agent
 *
 *  License: GNU/GPL
 *  Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#ifndef HIP_AGENT_CONNHIPD_H
#define HIP_AGENT_CONNHIPD_H

/* FUNCTION DEFINITIONS */
int connhipd_init_sock(void);
int connhipd_run_thread(void);
void connhipd_quit(void);

#endif /* HIP_AGENT_CONNHIPD_H */
