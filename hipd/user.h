/** @file
 * A header file for user.c.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Tao Wan <taow_cc.hut.fi>
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_WORKQUEUE
#define HIP_WORKQUEUE

#include <stdio.h>
#include <stdint.h> // For uint8_t
#include <stdlib.h>
//#include <asm/byteorder.h>   // use instead #include <endian.h>
#include "list.h"
//#include "debug.h"
#include "close.h"
#include "accessor.h"
#include "hidb.h"
#include "cert.h"
/* added by Tao Wan, 10.Jan.2008*/
#include "registration.h"
#include "esp_prot_hipd_msg.h"

extern int hip_locator_status;
extern int hip_tcptimeout_status; /* Tao added, 09.Jan.2008 for tcp timeout*/
extern int hip_hit_to_ip_inuse;
extern int hip_buddies_inuse;
extern int heartbeat_counter;
extern int hip_encrypt_i2_hi;

int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst);
int hip_handle_user_msg(hip_common_t *msg, struct sockaddr_in6 *src);

int hip_handle_netlink_msg (const struct nlmsghdr *msg, int len, void *arg);

#endif /* HIP_WORKQUEUE */
