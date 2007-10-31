/** @file
 * A header file for user.c.
 * 
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#ifndef HIP_WORKQUEUE
#define HIP_WORKQUEUE

#include <stdio.h>
//#include <asm/byteorder.h>   // use instead #include <endian.h>
#include "list.h"
//#include "debug.h"
#include "timer.h"
#include "bos.h"
#include "close.h"
#include "accessor.h"

extern struct addrinfo * opendht_serving_gateway;
extern int opendht_serving_gateway_port;
extern int opendht_serving_gateway_ttl;
extern int hip_opendht_fqdn_sent;
extern int hip_opendht_hit_sent;
extern int we_are_relay;
extern int hip_interfamily_status;

#endif /* HIP_WORKQUEUE */
