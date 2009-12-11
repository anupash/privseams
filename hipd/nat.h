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

#include "state.h"

#define HIP_USE_ICE

#define HIP_REFLEXIVE_LOCATOR_ITEM_AMOUNT_MAX 1

#define ICE_ROLE_CONTROLLING  	PJ_ICE_SESS_ROLE_CONTROLLING
#define ICE_ROLE_CONTROLLED  	PJ_ICE_SESS_ROLE_CONTROLLED

#define ICE_CAND_TYPE_HOST 	PJ_ICE_CAND_TYPE_HOST
#define ICE_CAND_TYPE_SRFLX 	PJ_ICE_CAND_TYPE_SRFLX
#define ICE_CAND_TYPE_PRFLX 	PJ_ICE_CAND_TYPE_PRFLX
#define ICE_CAND_TYPE_RELAYED 	PJ_ICE_CAND_TYPE_RELAYED

#define ICE_CAND_PRE_HOST 65535 
#define ICE_CAND_PRE_SRFLX 65534
#define ICE_CAND_PRE_RELAYED 65533

/** Time interval between consecutive NAT Keep-Alive packets in seconds.
    @note According to [draft-schmitt-hip-nat-traversal-02], the default
    keep-alive interval for control channels must be 20 seconds. However, for
    debugging purposes a smaller value is used here.
    @todo Change this value. */
#define HIP_NAT_KEEP_ALIVE_INTERVAL 20
/** Number of retransmissions to try if hip_send_udp() fails. */
#define HIP_NAT_NUM_RETRANSMISSION 2
/** Port number for NAT traversal of hip control packets. */
#define HIP_NAT_UDP_PORT 10500
#define HIP_NAT_TURN_PORT 10500

/** default value for ICE pacing, unit is 0.001 s**/
#define HIP_NAT_RELAY_LATENCY  200
#define HIP_NAT_PACING_DEFAULT 200

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
extern HIP_HASHTABLE *hadb_hit;
int hip_ha_set_nat_mode(hip_ha_t *entry, void *mode);
hip_transform_suite_t hip_select_nat_transform(
		hip_ha_t *entry, hip_transform_suite_t *suite, int suite_count);
int hip_nat_start_ice(hip_ha_t *entry, struct hip_context *ctx);
hip_transform_suite_t hip_get_nat_mode();
int hip_nat_refresh_port();
int hip_nat_send_keep_alive(hip_ha_t *, void *);
int hip_nat_handle_pacing(struct hip_common *msg , hip_ha_t *entry);
hip_transform_suite_t hip_nat_get_control(hip_ha_t *entry);
hip_transform_suite_t hip_nat_set_control(hip_ha_t *entry, hip_transform_suite_t mode);
int hip_external_ice_receive_pkt_all(void* msg, int len, in6_addr_t * src_addr,in_port_t port);
int hip_user_nat_mode(int nat_mode);
uint32_t ice_calc_priority(uint32_t type, uint16_t pref, uint8_t comp_id);
int hip_poll_ice_event_all();
#endif /* __NAT_H__ */

