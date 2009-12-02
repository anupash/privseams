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
#ifndef HIP_USER_H
#define HIP_USER_H 

#include <stdio.h>
#include <stdint.h> // For uint8_t
#include <stdlib.h>
#include "list.h"
#include "bos.h"
#include "close.h"
#include "accessor.h"
#include "hidb.h"
#include "cert.h"
#include "tcptimeout.h"
#include "registration.h"
#include "esp_prot_hipd_msg.h"
#include "user_ipsec_hipd_msg.h"

int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst);
int hip_handle_user_msg(hip_common_t *msg, struct sockaddr_in6 *src);

int hip_handle_netlink_msg (const struct nlmsghdr *msg, int len, void *arg);

#endif /* HIP_USER_H
*/
