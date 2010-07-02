/** @file
 * A header file for conf.c
 *
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @author  Tao Wan <twan@cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_CONF_H
#define HIP_LIB_CORE_CONF_H

#include <stdlib.h>

#include "config.h"
#include "protodefs.h"

/*
 * DO NOT TOUCH THESE, unless you know what you are doing.
 * These values are used for TYPE_xxx macros.
 */

/** @defgroup exec_app_types Execute application types
 * @{
 * Execute application with opportunistic library preloaded.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_OPP        8

/**
 * Execute application with hip-libraries preloaded.
 * Overides example getaddrinfo().
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_HIP        12

/**
 * Execute application,no preloading of libraries.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_NONE       13
/* @} */

/* hipconf tool actions also used outside of conf.c */
#define ACTION_ADD 1
#define ACTION_NEW 3

int hip_handle_exec_app(int fork, int type, int argc, char **argv);
int hip_do_hipconf(int argc, char *argv[], int send_only);

/* Externally used handler functions */
/* TODO: Is there a clean way to get rid of this external use? */
int hip_conf_handle_load(hip_common_t *msg,
                         int type,
                         const char *opt[],
                         int optc,
                         int send_only);

#endif /* HIP_LIB_CORE_CONF_H */
