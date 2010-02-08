/** @file
 * A header file for nat.c
 *  
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    27.10.2006
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-02.txt">
 *          draft-schmitt-hip-nat-traversal-02</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    All Doxygen comments have been added in version 1.1.
 */
#ifndef __NAT_H__
#define __NAT_H__

#include "lib/core/state.h"

/** Time interval between consecutive NAT Keep-Alive packets in seconds.
    @note According to [draft-schmitt-hip-nat-traversal-02], the default
    keep-alive interval for control channels must be 20 seconds. However, for
    debugging purposes a smaller value is used here.
    @todo Change this value. */
#define HIP_NAT_KEEP_ALIVE_INTERVAL 20
/** Port number for NAT traversal of hip control packets. */
#define HIP_NAT_UDP_PORT 10500
#define HIP_NAT_TURN_PORT 10500

/** For setting socket to listen for beet-udp packets. */
#define HIP_UDP_ENCAP 100
/** UDP encapsulation type. */
#define HIP_UDP_ENCAP_ESPINUDP 2
/** UDP encapsulation type. */ 
#define HIP_UDP_ENCAP_ESPINUDP_NONIKE 1 

extern HIP_HASHTABLE *hadb_hit;
hip_transform_suite_t hip_get_nat_mode(hip_ha_t *entry);
int hip_nat_refresh_port(void);
int hip_nat_send_keep_alive(hip_ha_t *, void *);
hip_transform_suite_t hip_nat_set_control(hip_ha_t *entry, hip_transform_suite_t mode);
int hip_user_nat_mode(int nat_mode);
hip_transform_suite_t hip_nat_get_control(hip_ha_t *entry);
#endif /* __NAT_H__ */

