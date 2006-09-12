/** @file
 * A header file for nat.c
 *  
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    07.09.2006
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-01.txt">
 *          draft-schmitt-hip-nat-traversal-01</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @note    All Doxygen comments have been added in version 1.1.
 */
#ifndef __NAT_H__
#define __NAT_H__

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "user.h"
#include "debug.h"
#include "state.h"

/** Maximum length of a UDP packet. */
#define HIP_MAX_LENGTH_UDP_PACKET 2000
/** Time interval between consecutive NAT Keep-Alive packets in seconds.
    @note According to [draft-schmitt-hip-nat-traversal-01], the default
    keep-alive interval for control channels must be 20 seconds. However, for
    debugging purposes we use a smaller value here.
    @todo Change this value. */
#define HIP_NAT_KEEP_ALIVE_INTERVAL 3
/** Number of retransmissions to try if hip_nat_send_udp() fails. */
#define HIP_NAT_NUM_RETRANSMISSION 1
/** Amount of time to sleep between transmission and retransmissions. */
#define HIP_NAT_SLEEP_TIME 2
/** Port number for NAT traversal of hip control packets. */
#define HIP_NAT_UDP_PORT 50500
/** Port number for NAT travelsal of UDP data traffic. */
#define HIP_UDP_DATA_PORT 54500
/** For setting socket to listen for beet-udp packets. */
#define HIP_UDP_ENCAP 100
/** UDP encapsulation type. */
#define HIP_UDP_ENCAP_ESPINUDP 2
/** UDP encapsulation type. */ 
#define HIP_UDP_ENCAP_ESPINUDP_NONIKE 1 

/** File descriptor of socket used for hip control packet NAT traversal on
    UDP/IPv4. Defined in hipd.c */
extern int hip_nat_sock_udp;
/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. Defined in hipd.c */
extern int hip_nat_status;

int hip_nat_on();
int hip_nat_off();
int hip_nat_off_for_ha(hip_ha_t *, void *);
int hip_nat_on_for_ha(hip_ha_t *, void *);
int hip_nat_receive_udp_control_packet(struct hip_common *, struct in6_addr *,
				       struct in6_addr *,
				       struct hip_stateless_info *);
int hip_nat_send_udp(struct in6_addr *, struct in6_addr *, in_port_t, in_port_t,
		     struct hip_common*, hip_ha_t *, int);
int hip_nat_refresh_port();
int hip_nat_send_keep_alive(hip_ha_t *, void *);
#endif /* __NAT_H__ */

