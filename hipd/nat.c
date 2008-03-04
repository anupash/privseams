/** @file
 * This file defines extensions to Host Identity Protocol (HIP) to support
 * traversal of Network Address Translator (NAT) middleboxes.
 * 
 * The traversal mechanism tunnels HIP control and data traffic over UDP
 * and enables HIP initiators which may be behind NATs to contact HIP
 * responders which may be behind another NAT. Three basic cases exist for NAT
 * traversal. In the first case, only the initiator of a HIP base exchange is
 * located behind a NAT. In the second case, only the responder of a HIP base
 * exchange is located behind a NAT. In the third case, both parties are
 * located behind (different) NATs. The use rendezvous server is mandatory
 * when the responder is behind a NAT.
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
#include "nat.h"
#include "pjnath.h"
#include "pjlib.h"

/** A transmission function set for NAT traversal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
/** A transmission function set for sending raw HIP packets. */
extern hip_xmit_func_set_t default_xmit_func_set;
/** Port used for NAT travelsal random port simulation.
    If random port simulation is of, 50500 is used.
    @note This is needed only for simulation purposes and can be removed from
    released versions of HIPL. */
in_port_t hip_nat_rand_port1 = HIP_NAT_UDP_PORT;
/** Port used for NAT travelsal random port simulation.
    If random port simulation is of, 50500 is used.
    @note This is needed only for simulation purposes and can be removed from
    released versions of HIPL. */
in_port_t hip_nat_rand_port2 = HIP_NAT_UDP_PORT;

/**
 * Sets NAT status "on".
 * 
 * Sets NAT status "on" for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */ 
int hip_nat_on()
{
	int err = 0;
	_HIP_DEBUG("hip_nat_on() invoked.\n");
#if HIP_UDP_PORT_RANDOMIZING 
	hip_nat_randomize_nat_ports();
#endif
	hip_nat_status = 1;
	
	HIP_IFEL(hip_for_each_ha(hip_nat_on_for_ha, NULL), 0,
	         "Error from for_each_ha().\n");

out_err:
	return err;
}

/**
 * Sets NAT status "off".
 *
 * Sets NAT status "off" for each host association in the host association
 * database.
 * 
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */
int hip_nat_off()
{
	int err = 0;

	hip_nat_status = 0;
	HIP_IFEL(hip_for_each_ha(hip_nat_off_for_ha, NULL), 0,
		 "Error from for_each_ha().\n");
 out_err:
	return err;
}


/**
 * Get HIP NAT status.
 */
int hip_nat_is()
{
	return hip_nat_status;
}


/**
 * Sets NAT status "on" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_nat_on_for_ha(hip_ha_t *entry, void *not_used)
{
	/* Parameter not_used is needed because this function is called from
	   hip_nat_on() which calls hip_for_each_ha(). hip_for_each_ha()
	   requires a function pointer as parameter which in turn has two
	   parameters. */
	int err = 0;
	HIP_DEBUG("hip_nat_on_for_ha() invoked.\n");

	if(entry)
	{
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		entry->nat_mode = 1;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat_mode);
	}
 out_err:
	return err;
}

/**
 * Sets NAT status "off" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_nat_off_for_ha(hip_ha_t *entry, void *not_used)
{
	/* Check hip_nat_on_for_ha() for further explanation on "not_used". */
	int err = 0;
	_HIP_DEBUG("hip_nat_off_for_ha() invoked.\n");

	if(entry)
	{
		entry->nat_mode = 0;
		hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set);
	}
 out_err:
	return err;
}

/**
 * Refreshes the port state of all NATs related to this host.
 *
 * Refreshes the port state of all NATs between current host and all its peer
 * hosts by calling hip_nat_send_keep_alive() for each host association in
 * the host association database.
 *
 * @return zero on success, or negative error value on error.
 */ 
int hip_nat_refresh_port()
{
	int err = 0 ;
	
	HIP_DEBUG("Sending Keep-Alives to NAT.\n");
	HIP_IFEL(hip_for_each_ha(hip_nat_send_keep_alive, NULL),
		 -1, "for_each_ha() err.\n");
	
 out_err:
	return err;
}

/**
 * Sends an NAT Keep-Alive packet.
 *
 * Sends an UPDATE packet with nothing but @c HMAC parameter in it to the peer's
 * preferred address. If the @c entry is @b not in state ESTABLISHED or if there
 * is no NAT between this host and the peer (@c entry->nat_mode = 0), then no
 * packet is sent. The packet is send on UDP with source and destination ports
 * set as @c HIP_NAT_UDP_PORT.
 * 
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero on success, or negative error value on error.
 * @note           If the state of @c entry is not ESTABLISHED or if
 *                 @c entry->nat_mode = 0 this function still returns zero
 *                 because these conditions are not errors. Negative error
 *                 value is only returned when the creation of the new UPDATE
 *                 message fails in some way.
 */
int hip_nat_send_keep_alive(hip_ha_t *entry, void *not_used)
{
	int err = 0;
	struct hip_common update_packet;
	
	_HIP_DEBUG("hip_nat_send_keep_alive() invoked.\n");
	_HIP_DEBUG("entry @ %p, entry->nat_mode %d.\n",
		  entry, entry->nat_mode);
	_HIP_DEBUG_HIT("&entry->hit_our", &entry->hit_our);

	/* Check that the host association is in correct state and that there is
	   a NAT between this host and the peer. Note, that there is no error
	   (err is set to zero) if the condition does not hold. We just don't
	   send the packet in that case. */
	if (entry->state != HIP_STATE_ESTABLISHED) {
		HIP_DEBUG("Not sending NAT keepalive state=%s\n", hip_state_str(entry->state));
		goto out_err;
        }

	if (!(entry->nat_mode)) {
		HIP_DEBUG("No nat between the localhost and the peer\n");
		goto out_err;
	}

	if (!IN6_IS_ADDR_V4MAPPED(&entry->local_address)) {
		HIP_DEBUG("Not IPv4 address, skip NAT keepalive\n");
		goto out_err;
	}

	memset(&update_packet, 0, sizeof(update_packet)); 

	entry->hadb_misc_func->
		hip_build_network_hdr(&update_packet, HIP_NOTIFY,
				      0, &entry->hit_our,
				      &entry->hit_peer);
	
	/* Calculate the HIP header length */
	hip_calc_hdr_len(&update_packet);

	/* Send the UPDATE packet using 50500 as source and destination ports.
	   Only outgoing traffic acts refresh the NAT port state. We could
	   choose to use other than 50500 as source port, but we must use 50500
	   as destination port. However, because it is recommended to use
	   50500 as source port also, we choose to do so here. */
	entry->hadb_xmit_func->
		hip_send_pkt(&entry->local_address, &entry->preferred_address,
			     HIP_NAT_UDP_PORT, HIP_NAT_UDP_PORT, &update_packet,
			     entry, 0);

 out_err:
	return err;
}

#if HIP_UDP_PORT_RANDOMIZING
/**
 * Randomizes @b source ports 11111 and 22222.
 *
 * This function randomizes ports @c hip_nat_rand_port1 and
 * @c hip_nat_rand_port2 used in NAT-travelsal. NATs choose randomly a port
 * when HIP control traffic goes through them. Internet Draft 
 * [draft-schmitt-hip-nat-traversal-02] defines these random chosen ports as
 * 11111 and 22222. This function serves as a helper function to simulate
 * these random chosen ports in a non-NATed environment where UPD encapsulation
 * is used.
 *
 * @note According to [draft-schmitt-hip-nat-traversal-02] HIP daemons use
 *       one random port and NATs use two random ports. The value of
 *       @c hip_nat_rand_port1 can be considered as the random port of
 *       HIP daemon also. A scenario where HIP daemons use random source port
 *       and real life NATs randomize the NAT-P and NAT-P' ports is achieved by
 *       removing the @c hip_nat_rand_port2 randomization from this function.
 * @note Not used currently.
 * @note This is needed only for simulation purposes and can be removed from
 *       released versions of HIPL.
 */ 
void hip_nat_randomize_nat_ports()
{
	unsigned int secs_since_epoch = (unsigned int) time(NULL);
	HIP_DEBUG("Randomizing UDP ports to be used.\n");
	srand(secs_since_epoch);
	hip_nat_rand_port1 = HIP_UDP_PORT_RAND_MIN + (int)
		(((HIP_UDP_PORT_RAND_MAX - HIP_UDP_PORT_RAND_MIN + 1) * 
		  rand()) / (RAND_MAX + 1.0));
#if HIP_SIMULATE_NATS
	hip_nat_rand_port2 = HIP_UDP_PORT_RAND_MIN + (int)
		(((HIP_UDP_PORT_RAND_MAX - HIP_UDP_PORT_RAND_MIN + 1) *
		  rand()) / (RAND_MAX + 1.0));
#else
	hip_nat_rand_port2 = hip_nat_rand_port1;
#endif
	HIP_DEBUG("Randomized ports are NAT-P: %u, NAT-P': %u.\n",
		  hip_nat_rand_port1, hip_nat_rand_port2);
}
#endif

//TODO
pj_ice_sess **  	p_ice;
pj_caching_pool cp;
pj_status_t status;
pj_pool_t *pool = 0;

#define PJ_COM_ID 1 

/***
 * this the call back interface when check complete.
 * */
void  hip_on_ice_complete (pj_ice_sess *ice, pj_status_t status){
	HIP_DEBUG("hip_on_ice_complete");
	
	// the verified list is in ice->verified_check_list
	
	
	//read all the element from the list
	
	//we set the flag in the peer list to verified.
	
	//TODO decide if we should save the paired local address also.
	
}

/**
 * this is the call back interface to send package.
 * */
pj_status_t hip_on_tx_pkt(pj_ice_sess *ice, unsigned comp_id, const void *pkt, pj_size_t size, const pj_sockaddr_t *dst_addr, unsigned dst_addr_len){
	HIP_DEBUG("hip_on_tx_pkt");
	
	
	//use sendto send the UDP packet.


	return 0;
}
/**
 * 
 * this is the call back interface when the received packet is not strun.
 * we ignire here.
 * */
void hip_on_rx_data(pj_ice_sess *ice, unsigned comp_id, void *pkt, pj_size_t size, const pj_sockaddr_t *src_addr, unsigned src_addr_len){
	HIP_DEBUG("hip_on_rx_data");
}






/***
 * this function is added to create the ice seesion
 * currently we suppport only one session at one time.
 * only one component in the seesion. 
 * */

int hip_external_ice_init(int role){
	
	//init for PJproject
	status = pj_init();
	pjlib_util_init();
	
	
    if (status != PJ_SUCCESS) {
        HIP_DEBUG("Error initializing PJLIB", status);
        return 1;
    }
	//init for memery pool factroy
    // using default pool policy.
    pj_caching_pool_init(&cp, &pj_pool_factory_default_policy,0 );  
    
    pjnath_init();
    
	
	pj_stun_config  stun_cfg;
	
	const char *  name = "hip_ice";
	pj_ice_sess_role   	 ice_role;
	if(role)
		ice_role = PJ_ICE_SESS_ROLE_CONTROLLING;
	else
		ice_role = PJ_ICE_SESS_ROLE_CONTROLLED;
	
	struct pj_ice_sess_cb cb;
	
	//hip_ice_sess_cb.
	//DOTO tobe reset
 	unsigned   	 comp_cnt = 1;
 	
 	const pj_str_t *   	 local_ufrag ;
 	const pj_str_t *  	local_passwd ;
 	
	//copy from test
	  	pj_pool_t *pool;
	    pj_ioqueue_t *ioqueue;
	    pj_timer_heap_t *timer_heap;
	   //end copy
 	
 	//configure the call back handle
 	cb.on_ice_complete = &hip_on_ice_complete;
 	cb.on_tx_pkt = &hip_on_tx_pkt;
 	cb.on_rx_data= &hip_on_rx_data;
 
 	//copy from test
 	    
 	    pj_ioqueue_create(pool, 12, &ioqueue);
 	    pj_timer_heap_create(pool, 100, &timer_heap);
 	    
 	    pj_stun_config_init(&stun_cfg, &cp.factory, 0, ioqueue, timer_heap);
 	    pool = pj_pool_create(stun_cfg.pf, NULL, 4000, 4000, NULL);
 	//end copy
 	    
 	    
 	//check if there is already a session
 	if(!p_ice)
 	 return pj_ice_sess_create( 
 			&stun_cfg,
 			name,
 			ice_role,
 			comp_cnt,
 			&cb,
 			local_ufrag,
 			local_passwd,
 			p_ice	 
 		) ;
 	/**/
 	return 0;
 	
}

/***
 * this function is called to add local candidates for the only component
 *  
 * */
int hip_external_ice_add_local_candidates(void* session, in6_addr_t * hip_addr, in_port_t port, int addr_type){
	
	 pj_ice_sess *   	 ice;
	 unsigned  	comp_id;
	 pj_ice_cand_type  	type;
	 pj_uint16_t  	local_pref;
	 pj_str_t   	foundation;
	 const pj_sockaddr_t *  	base_addr;
	 const pj_sockaddr_t *  	rel_addr;
	 int  	addr_len;
	 unsigned *  	p_cand_id;
	 pj_sockaddr_in pj_addr;
	 pj_status_t pj_status;
	 
	 
	 ice = session;
	 comp_id = PJ_COM_ID;
	 type = addr_type;
	 foundation = pj_str("ice");
//for preference calculation
	// local_pref = 65536;
	 
	 //TODO  this is only for IPv4
	 pj_sockaddr_in_set_port(&pj_addr, 
	 					port); 
	 //TODO check if HIP address is unit 32
	 pj_sockaddr_in_set_addr(&pj_addr,
			 hip_addr->s6_addr32);
	 
	 addr_len = sizeof(pj_sockaddr_in);
	 
	 
	 //pj_sockaddr_t is a void point. we need pj_sockaddr struct.
	 
	 /*
		pj_sockaddr_in addr;

		pj_sockaddr_in_init(&addr, pj_cstr(&a, cand[i].addr), (pj_uint16_t)cand[i].port);
		status = pj_ice_strans_add_cand(ice_st, cand[i].comp_id, cand[i].type,
					    65535, &addr, PJ_FALSE);
	 */
	 
	 /**
	PJ_ICE_CAND_TYPE_HOST 	ICE host candidate. A host candidate represents the actual local transport address in the host.
	PJ_ICE_CAND_TYPE_SRFLX 	ICE server reflexive candidate, which represents the public mapped address of the local address, and is obtained by sending STUN Binding request from the host candidate to a STUN server.
	PJ_ICE_CAND_TYPE_PRFLX 	ICE peer reflexive candidate, which is the address as seen by peer agent during connectivity check.
	PJ_ICE_CAND_TYPE_RELAYED 	ICE relayed candidate, which represents the address allocated in TURN server.
	  * */
	
	
	pj_status =  pj_ice_sess_add_cand  	(   ice,
			comp_id,
			type,
			65535,
			&foundation,
			&pj_addr,
			base_addr,
			rel_addr,
			addr_len,
			p_cand_id	 
		) ;
	
		
	return pj_status;
}


/*****
*  
*this function is called after the local candidates are added. 
* the check list will created inside the seesion object. 
*/
int hip_external_ice_add_remote_candidates( void * session, int num, struct hip_peer_addr_list_item* list){
	
	pj_ice_sess *   	 ice = session;
	const pj_str_t *  	rem_ufrag;
	const pj_str_t *  	rem_passwd;
	unsigned  	rem_cand_cnt;
	pj_ice_sess_cand *  	rem_cand;	
	int i;
	
	rem_cand_cnt = num;
	//reserve space for the cand
	
	
	for(i = 0; i< num; i ++){
		//(rem_cand+i)->
	}
	
	
	/*
	 * 
	 *
	pj_status_t pj_ice_sess_create_check_list  	(  	pj_ice_sess *   	 ice,
		const pj_str_t *  	rem_ufrag,
		const pj_str_t *  	rem_passwd,
		unsigned  	rem_cand_cnt,
		const pj_ice_sess_cand  	rem_cand[]	 
	) 
	*/
	return 0;
}
/**
 * 
 * called after check list is created
 * */

int hip_ice_start_check(void* ice){
	
	pj_status_t result;
	
	result = pj_ice_sess_start_check  	(  ice  	 ) ;  
	if(result == PJ_SUCCESS) return 1;
	else return 0;
			
}

int hip_external_ice_end(){
	//destory the pool
	if(pool)
		pj_pool_release(pool);
    //destory the pool factory
    pj_caching_pool_destroy(&cp);
}


/*
pj_ice_sess_add_cand()

pj_ice_sess_start_check() 

*/




