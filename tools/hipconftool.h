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

int callback_sendto_hipd(int * sock, void *msg, size_t len);

int callback_recvfrom_hipd(int sock, void *msg, size_t len);

#endif /* HIPCONFTOOL_H */
