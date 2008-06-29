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


//add by santtu
#include "pjnath.h"
#include "pjlib.h"
#include "pjlib-util.h"

//end add

//add by santtu
#define HIP_USE_ICE
#define ICE_ROLE_CONTROLLING  PJ_ICE_SESS_ROLE_CONTROLLING
#define ICE_ROLE_CONTROLLED  PJ_ICE_SESS_ROLE_CONTROLLED
//end add
#define HIP_NAT_SLEEP_TIME 2
/** Maximum length of a UDP packet. */
#define HIP_MAX_LENGTH_UDP_PACKET 2000
/** Time interval between consecutive NAT Keep-Alive packets in seconds.
    @note According to [draft-schmitt-hip-nat-traversal-02], the default
    keep-alive interval for control channels must be 20 seconds. However, for
    debugging purposes a smaller value is used here.
    @todo Change this value. */
#define HIP_NAT_KEEP_ALIVE_INTERVAL 20
/** Number of retransmissions to try if hip_send_udp() fails. */
#define HIP_NAT_NUM_RETRANSMISSION 2
/** Port number for NAT traversal of hip control packets. */
#define HIP_NAT_UDP_PORT 50500
/** For setting socket to listen for beet-udp packets. */
#define HIP_UDP_ENCAP 100
/** UDP encapsulation type. */
#define HIP_UDP_ENCAP_ESPINUDP 2
/** UDP encapsulation type. */ 
#define HIP_UDP_ENCAP_ESPINUDP_NONIKE 1 
/** Boolean which indicates if random port simulation is on.
    <ul>
    <li>0: port randomizing is off.</li>
    <li>1: port randomizing is on.</li>
    </ul>
    @note Not used currently.
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_UDP_PORT_RANDOMIZING 0
/** Boolean to indicate if a NATed network is simulated.
    <ul>
    <li>0: NATed network is not simulated, real life NATs exist in the network.
    </li>
    <li>1: NATed network is simulated, real life NATs do not exist in the
    network, but UDP encapsulation is still used.</li>
    </ul>
    @note This has no effect if HIP_UDP_PORT_RANDOMIZING is off 
    @note Not used currently.
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_SIMULATE_NATS 0
/** Minimum port number a NAT can randomize.
    Has to be float as it is used in rand().
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_UDP_PORT_RAND_MIN 49152.0
/** Maximum port number a NAT can randomize.
    Has to be float as it is used in rand().
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_UDP_PORT_RAND_MAX 65535.0
/** File descriptor of socket used for hip control packet NAT traversal on
    UDP/IPv4. Defined in hipd.c */
extern int hip_nat_sock_udp;
/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. Defined in hipd.c */
extern int hip_nat_status;
/*
int hip_nat_on();
int hip_nat_off();
int hip_nat_is();
int hip_nat_off_for_ha(hip_ha_t *, void *);
int hip_nat_on_for_ha(hip_ha_t *, void *);
*/

int hip_ha_set_nat_mode(hip_ha_t *entry, void *mode);
int hip_get_nat_mode();
void hip_set_nat_mode(int mode);


void hip_nat_randomize_nat_ports();
int hip_nat_refresh_port();
int hip_nat_send_keep_alive(hip_ha_t *, void *);

int hip_nat_handle_transform_in_client(struct hip_common *msg , hip_ha_t *entry);
int hip_nat_handle_transform_in_server(struct hip_common *msg , hip_ha_t *entry);
uint16_t hip_nat_get_control();
#endif /* __NAT_H__ */

