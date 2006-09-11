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

#define HIP_MAX_LENGTH_UDP_PACKET 2000
#define HIP_NAT_KEEP_ALIVE_TIME 5
#define HIP_NAT_NUM_RETRANSMISSION 2
#define HIP_NAT_UDP_PORT 50500 /* For NAT traversal */
#define HIP_NAT_UDP_DATA_PORT 54500 /* For data traffic*/
#define UDP_ENCAP 100 /* For setting socket to listen for beet-udp packets*/
#define UDP_ENCAP_ESPINUDP 2 
#define UDP_ENCAP_ESPINUDP_NONIKE 1 

extern int hip_nat_sock_udp;
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

int hip_nat_keep_alive();
int hip_handle_keep_alive(hip_ha_t *entry, void *not_used);
#endif //__NAT_H__

