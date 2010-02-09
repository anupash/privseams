/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef CONNHIPD_H
#define CONNHIPD_H

/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif

/* FUNCTION DEFINITIONS */
int connhipd_init_sock(void);
int connhipd_run_thread(void);
void connhipd_quit(void);

/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*CONNHIPD_H */ 

