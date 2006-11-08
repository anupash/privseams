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
#ifndef HIPCONFTOOL_H
#define HIPCONFTOOL_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "hipconf.h"


int handle_hi(struct hip_common *, int type, const char *opt[], int optc);
int handle_map(struct hip_common *, int type, const char *opt[], int optc);
int handle_rst(struct hip_common *, int type, const char *opt[], int optc);
int handle_bos(struct hip_common *, int type, const char *opt[], int optc);
int handle_rvs(struct hip_common *msg, int action, const char *opt[], int optc);
int handle_del(struct hip_common *, int type, const char *opt[], int optc);
int handle_nat(struct hip_common *, int type, const char *opt[], int optc);
int handle_puzzle(struct hip_common *, int type, const char *opt[], int optc);
int handle_opp(struct hip_common *msg, int action, const char *opt[], int optc);
int handle_escrow(struct hip_common *msg, int action, const char *opt[], int optc);
int handle_service(struct hip_common *msg, int action, const char *opt[], int optc);
int get_action(char *action);
int get_type(char *type);

#endif /* HIPCONFTOOL_H */
