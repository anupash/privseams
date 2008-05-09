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

extern HIP_HASHTABLE *hadb_hit;
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














hip_ha_t * hip_get_entry_from_ice(void * ice){ 

	hip_ha_t *ha_n, *entry;
	hip_list_t *item = NULL, *tmp = NULL;
	int i;
	
	entry = NULL;
	// found the right entry. 
	
	list_for_each_safe(item, tmp, hadb_hit, i) {
	    ha_n = list_entry(item);
	    if(ha_n->ice_session == ice){
	    	entry = ha_n;
	    }
	}
	
	return entry;
}



pj_caching_pool cp;
pj_status_t status;
pj_pool_t *pool = 0;

#define PJ_COM_ID 1 

/***
 * this the call back interface when check complete.
 * */
void  hip_on_ice_complete (pj_ice_sess *ice, pj_status_t status){
	HIP_DEBUG("hip_on_ice_complete\n");
	pj_ice_sess_checklist *	valid_list;
	int err = 0;
	int i =0, j =0, k=0;
	pj_ice_sess_cand	*rcand;
	pj_sockaddr		 addr;
    hip_ha_t *ha_n, *entry;
    hip_list_t *item = NULL, *tmp = NULL;
    hip_list_t *item1 = NULL, *tmp1 = NULL;
	struct hip_peer_addr_list_item * peer_addr_list_item;
	struct hip_spi_out_item* spi_out;
    
    
	// found the right entry. 
	/*
    list_for_each_safe(item, tmp, hadb_hit, i) {
        ha_n = list_entry(item);
        if(ha_n->ice_session == ice){
        	entry = ha_n;
        }
    }
    */
    
    
    entry = hip_get_entry_from_ice(ice);
    if(entry == NULL)
    	HIP_DEBUG("hip_on_ice_complete, entry found");
    
	// the verified list 
	//if(status == PJ_TRUE){
		valid_list = &ice->valid_list;
	//}
	
	HIP_DEBUG("there are %d pairs in valid list\n", valid_list->count);
	HIP_DEBUG("there are %d pairs in valid list\n", ice->valid_list.count);
	//read all the element from the list
	if(valid_list->count > 0){
		for(i = 0; i< valid_list->count; i++){
			if (valid_list->checks[i].nominated == PJ_TRUE){
				//set the prefered peer
				HIP_DEBUG("find a nominated candiate\n");
				rcand = valid_list->checks[i].rcand;
				addr = rcand->addr;
				
				hip_print_lsi("set prefered the peer_addr : ", &addr.ipv4.sin_addr.s_addr );
				HIP_DEBUG("set prefered the peer_addr port: %d\n", addr.ipv4.sin_port );
				k= 0;
				list_for_each_safe(item1, tmp1, entry->spis_out, k) {
					spi_out = list_entry(item1);
					j=0;
					list_for_each_safe(item, tmp, spi_out->peer_addr_list, j) {
						peer_addr_list_item = list_entry(item);
						
						HIP_DEBUG_HIT(" peer_addr : ", &peer_addr_list_item->address );
						HIP_DEBUG(" peer_addr port: %d\n", peer_addr_list_item->port );
						
						if((*((pj_uint32_t *) &peer_addr_list_item->address.s6_addr32[3])
								== addr.ipv4.sin_addr.s_addr) && 
								peer_addr_list_item->port == addr.ipv4.sin_port){
							HIP_DEBUG_HIT("found & set prefered the peer_addr : ", &peer_addr_list_item->address );
							peer_addr_list_item->address_state = PEER_ADDR_STATE_ACTIVE;
							peer_addr_list_item->is_preferred = 1;
							memcpy(&entry->preferred_address, &peer_addr_list_item->address, sizeof(struct in6_addr));
							entry->peer_udp_port = peer_addr_list_item->port;
						}
						
					}
				}
				//
			}
			else{/*
				if(valid_list->checks[i].state == PJ_ICE_SESS_CHECK_STATE_SUCCEEDED){
						rcand = valid_list->checks[i].rcand;
						j= 0;
						
						HIP_DEBUG("find a valid candiate\n");
						
						list_for_each_safe(item, tmp, entry->spis_out, j) {
							peer_addr_list_item = list_entry(item);

							
							if(*((pj_uint32_t *) &peer_addr_list_item->address.s6_addr32[3])
									==addr.ipv4.sin_addr.s_addr && 
									peer_addr_list_item->port == addr.ipv4.sin_port){
								HIP_DEBUG_HIT("set active the peer_addr : ", &peer_addr_list_item->address );
								peer_addr_list_item->address_state = PEER_ADDR_STATE_ACTIVE;
							}
						}	
					
				}*/
			}
				
			
		}

		int err;
		uint32_t spi_in, spi_out;
		if (entry->state == HIP_STATE_ESTABLISHED)
					spi_in = hip_hadb_get_latest_inbound_spi(entry);
		
		err =hip_add_sa(&entry->local_address, &entry->preferred_address,
						 &entry->hit_our, &entry->hit_peer,
						 &entry->default_spi_out, entry->esp_transform,
						 &entry->esp_out, &entry->auth_out, 1,
						 HIP_SPI_DIRECTION_OUT, 0, 50500, entry->peer_udp_port,1);
		if (err) {
			HIP_ERROR("Failed to setup outbound SA with SPI=%d\n",
					entry->default_spi_out);
			hip_hadb_delete_inbound_spi(entry, 0);
			hip_hadb_delete_outbound_spi(entry, 0);
			}
		
		err =hip_add_sa(&entry->preferred_address,&entry->local_address, 
						&entry->hit_peer,&entry->hit_our, 
						&spi_in,
						entry->esp_transform,
						 &entry->esp_in, &entry->auth_in, 1,
						 HIP_SPI_DIRECTION_IN, 0, entry->peer_udp_port, 50500,1 );
		if (err) {
				HIP_ERROR("Failed to setup inbound SA with SPI=%d\n", spi_in);
				/* if (err == -EEXIST)
				   HIP_ERROR("SA for SPI 0x%x already exists, this is perhaps a bug\n",
				   spi_in); */
				err = -1;
				hip_hadb_delete_inbound_spi(entry, 0);
				hip_hadb_delete_outbound_spi(entry, 0);
				//goto out_err;
		}
		
		
	
		err = hip_setup_hit_sp_pair(&entry->hit_peer, &entry->hit_our,
						&entry->preferred_address,
						 &entry->local_address,  IPPROTO_ESP, 1, 1);
		if(err) 
			HIP_DEBUG("Setting up SP pair failed\n");
		
		
		
		
	}
	//we set the flag in the peer list to verified.
	
	//TODO decide if we should save the paired local address also.

	
	
	// out_err:
	 // HIP_DEBUG("err\n");
		//return err;
}







/**
 * this is the call back interface to send package.
 * */
pj_status_t hip_on_tx_pkt(pj_ice_sess *ice, unsigned comp_id, const void *pkt, pj_size_t size, const pj_sockaddr_t *dst_addr, unsigned dst_addr_len){
	struct hip_common *msg = NULL;
	pj_status_t err = PJ_SUCCESS;
	hip_ha_t *entry;
//	int error = 0;
	
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");
	
	entry = hip_get_entry_from_ice(ice);
	if(entry==NULL) {
		err = -1;
		goto out_err;
	}
	
	hip_build_network_hdr(msg, 0, 0, &entry->hit_our, &entry->hit_peer);
//	hip_set_msg_total_len(msg,sizeof(struct hip_common) + size);
	msg->payload_len = sizeof(struct hip_common) + size;
	memcpy(msg +1, pkt, size );  
	
	
	
	HIP_DEBUG("hip_on_tx_pkt : \n");
	
	HIP_DEBUG("hip_on_tx_pkt ice current valid number: %d\n", ice->valid_list.count);
	
	
	
	struct in6_addr *local_addr = 0;
	struct in6_addr peer_addr;
	in_port_t src_port = 50500; 
	in_port_t dst_port ;
	pj_sockaddr_in *addr;
	
	addr =(pj_sockaddr_in *) dst_addr;
	//only IP_V4 is supported
	//peer_addr  = (struct in6_addr * )&addr->sin_addr;
	peer_addr.in6_u.u6_addr32[0] = (uint32_t)0;
	peer_addr.in6_u.u6_addr32[1] = (uint32_t)0;
	peer_addr.in6_u.u6_addr32[2] = (uint32_t)htonl (0xffff);
	peer_addr.in6_u.u6_addr32[3] = (uint32_t)addr->sin_addr.s_addr;
	//memcpy(peer_addr.in6_u.u6_addr32+3, &addr->sin_addr.s_addr, 4);
	hip_print_lsi("address is in stun send 2:" , &addr->sin_addr.s_addr );
	hip_print_hit("address is in stun send 3:" , &peer_addr );
	HIP_DEBUG("length of the stun package is %d\n", size );
	dst_port = addr->sin_port;
	
	int msg_len ;
	int retransmit = 0;
	
	if(err = hip_send_stun(local_addr, &peer_addr, src_port,dst_port, msg, msg->payload_len,0) )
		goto out_err;
	//TODO check out what should be returned
	else return PJ_SUCCESS;
	
out_err:
		//	if (host_id_pub)
		//	HIP_FREE(host_id_pub);
	 	if (msg)
	 		HIP_FREE(msg);


	  	return err;
}
/**
 * 
 * this is the call back interface when the received packet is not strun.
 * we ignire here.
 * */
void hip_on_rx_data(pj_ice_sess *ice, unsigned comp_id, void *pkt, pj_size_t size, const pj_sockaddr_t *src_addr, unsigned src_addr_len){
	HIP_DEBUG("hip_on_rx_data Len:%d \ndata: ", size);
	HIP_DEBUG("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
	
}






/***
 * this function is added to create the ice seesion
 * currently we suppport only one session at one time.
 * only one component in the seesion.
 * 
 * return the pointer of the ice session 
 * */

void* hip_external_ice_init(pj_ice_sess_role role){
	pj_ice_sess *  	p_ice;
	pj_status_t status;
	
	//init for PJproject
	status = pj_init();
	pjlib_util_init();
	
	
    if (status != PJ_SUCCESS) {
        HIP_DEBUG("Error initializing PJLIB", status);
        return 0;
    }
    pj_log_set_level(3);
	//init for memery pool factroy
    // using default pool policy.

    pj_dump_config();
    pj_caching_pool_init(&cp, NULL, 6024*1024 );  
    

    pjnath_init();
    
	
	pj_stun_config  stun_cfg;
	
	const char *  name = "hip_ice";
	pj_ice_sess_role   	 ice_role = role;
	
	
	struct pj_ice_sess_cb cb;
	
	//hip_ice_sess_cb.
	//DOTO tobe reset
 	unsigned   	 comp_cnt = 1;
 	
 	const pj_str_t    	 local_ufrag = pj_str("user");
 	const pj_str_t   	local_passwd = pj_str("pass");
 	
	//copy from test
	  //	pj_pool_t *pool;
	    pj_ioqueue_t *ioqueue;
	    pj_timer_heap_t *timer_heap;
	   //end copy
 	
 	//configure the call back handle
 	cb.on_ice_complete = &hip_on_ice_complete;
 	cb.on_tx_pkt = &hip_on_tx_pkt;
 	cb.on_rx_data= &hip_on_rx_data;
 
 	//copy from test
 
 	   
 	  
 	   
 	   pool = pj_pool_create(&cp.factory, NULL, 4000, 4000, NULL);
 	   pj_ioqueue_create(pool, 12, &ioqueue);
 	   pj_timer_heap_create(pool, 100, &timer_heap);
 	   
 	  pj_stun_config_init(&stun_cfg, &cp.factory, 0, ioqueue, timer_heap);
 	//end copy
 	     
 	//check if there is already a session
 	   
 	  status =  pj_ice_sess_create( 
 	 			&stun_cfg,
 	 			name,
 	 			ice_role,
 	 			comp_cnt,
 	 			&cb,
 	 			&local_ufrag,
 	 			&local_passwd,
 	 			&p_ice	 
 	 		);
 	   
 	   
 	 if(PJ_SUCCESS ==  status){
 		 HIP_DEBUG("santtu ice 6 \n"); 
 		 return p_ice;
 	  }
 	 else HIP_DEBUG("santtu ice 7 %d \n", status); 
 	

 	return 0;
 	
}

/***
 * this function is called to add local candidates for the only component
 *  
 * */
int hip_external_ice_add_local_candidates(void* session, in6_addr_t * hip_addr, in_port_t port, int addr_type){
	
	 pj_ice_sess *   	 ice ;
	 unsigned  	comp_id;
	 pj_ice_cand_type  	type;
	 pj_uint16_t  	local_pref;
	 pj_str_t   	foundation;
	 const pj_sockaddr_t *  	base_addr = NULL;
	 const pj_sockaddr_t *  	rel_addr= NULL;
	 int  	addr_len;
	 unsigned   	p_cand_id;
	 pj_sockaddr_in pj_addr;
	 pj_status_t pj_status;
	 
	 /***debug area**/
	 HIP_DEBUG_HIT("coming address ",hip_addr);
	 
	 
	 
	 ice = session;
	 pool = pj_pool_create(&cp.factory, NULL, 4000, 4000, NULL);
	 comp_id = PJ_COM_ID;
	 type = addr_type;
	 foundation = pj_str("ice");
//for preference calculation
	// local_pref = 65536;
	 
	 //TODO  this is only for IPv4
	 /*
	 pj_sockaddr_in_set_port(&pj_addr, 
	 					port); 


	 //TODO check if HIP address is unit 32
	 pj_sockaddr_in_set_addr(&pj_addr,
			(pj_uint32_t) hip_addr->s6_addr32);
	
	*/
	 
	 pj_addr.sin_family=PJ_AF_INET;
	 pj_addr.sin_port = port;
	 pj_addr.sin_addr.s_addr =*((pj_uint32_t*) &hip_addr->s6_addr32[3]);
	 
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
			&pj_addr,
			NULL,
			addr_len,
			&p_cand_id	 
		) ;
	HIP_DEBUG("santtu add 4 %d\n", pj_status);
	if(pj_status == PJ_SUCCESS)	{

		return 1;
	}
	else return 0;
}


/*****
*  
*this function is called after the local candidates are added. 
* the check list will created inside the seesion object. 
*/
int hip_external_ice_add_remote_candidates( void * session, HIP_HASHTABLE*  list, pj_ice_cand_type type){
	
	pj_ice_sess *   	 ice = session;
	const pj_str_t *  	rem_ufrag;
	const pj_str_t *  	rem_passwd;
	unsigned  	rem_cand_cnt;
	pj_ice_sess_cand *      temp_cand;
	pj_ice_sess_cand *  	rem_cand;
	struct hip_peer_addr_list_item * peer_addr_list_item;
	int i;
	hip_list_t *item, *tmp;
	const pj_str_t    	 local_ufrag = pj_str("user");
 	const pj_str_t   	local_passwd = pj_str("pass");
	
	
	
	HIP_DEBUG("ICE add remote function\n");
	
	rem_cand_cnt = 0;
	HIP_DEBUG("ICE add remote: node number in list %d\n", list->num_nodes);
	//reserve space for the cand
	rem_cand = pj_pool_calloc(pool,rem_cand_cnt, sizeof(pj_ice_sess_cand));
	
	i=0;
	
	temp_cand = rem_cand;
	
	list_for_each_safe(item, tmp, list, i) {
		peer_addr_list_item = list_entry(item);
		if(peer_addr_list_item->port == 0) peer_addr_list_item->port = 50500;
		HIP_DEBUG_HIT("add Ice remote address:", &peer_addr_list_item->address);
		hip_print_lsi("add Ice remote address 1: ", ((int *) (&peer_addr_list_item->address)+3));
		HIP_DEBUG("add Ice remote port: %d \n", peer_addr_list_item->port);
		if (ipv6_addr_is_hit(&peer_addr_list_item->address))
		    continue;
		//HIP_DEBUG_HIT("add Ice remote", &peer_addr_list_item->address);
		if (IN6_IS_ADDR_V4MAPPED(&peer_addr_list_item->address)) {
			
			temp_cand->comp_id = 1;

		
			temp_cand->addr.ipv4.sin_family = PJ_AF_INET;
			temp_cand->addr.ipv4.sin_port = peer_addr_list_item->port;
			temp_cand->addr.ipv4.sin_addr.s_addr = *((pj_uint32_t *) &peer_addr_list_item->address.s6_addr32[3]) ;
			HIP_DEBUG("add remote address in integer is : %d \n", temp_cand->addr.ipv4.sin_addr.s_addr);
			
			temp_cand->base_addr.ipv4.sin_family = 4;
			temp_cand->base_addr.ipv4.sin_port = peer_addr_list_item->port;
			temp_cand->base_addr.ipv4.sin_addr.s_addr = *((pj_uint32_t*) &peer_addr_list_item->address.s6_addr32[3]);
						
			
			
			temp_cand->comp_id = 1;
			temp_cand->type = type;
			temp_cand->foundation = pj_str("ice");
			//TODO we use the max for all the candidate for now, but it is saved into peer_list already, 
			temp_cand->prio = 65535;
	
			temp_cand++;
			rem_cand_cnt++;
		}
	}
	
	HIP_DEBUG("complete remote list\n");
	/*
	
	for(i = 0; i< rem_cand_cnt; i ++){
		peer_addr_list_item = (struct hip_peer_addr_list_item * )list->b[i]->data;
		
		//(rem_cand+i)->
		rem_cand = PJ_POOL_ZALLOC_T(pool, pj_ice_sess_cand);
		rem_cand->comp_id = 1;
		
		//rem_cand.type = 
	//	foundation
		//rem_cand.prio= 
		//memcpy(&rem_cand->addr.pj_sockaddr_in.sin_family, &peer_addr_list_item->address sizeof(struct in6_addr));
	//	rem_cand->addr.pj_sockaddr_in.sin_family = peer_addr_list_item->address ;
		pj_sockaddr_in_set_port(&rem_cand->addr.ipv4, peer_addr_list_item->port);
		memcpy(&(rem_cand->addr.ipv4.sin_addr),&peer_addr_list_item->address, sizeof(struct in6_addr) );
	}                          
	*/
	pj_status_t t;
	HIP_DEBUG("add remote number: %d \n", rem_cand_cnt);
	if(rem_cand_cnt > 0 )
	t= pj_ice_sess_create_check_list  	(  	session,
	    &local_ufrag,
		 &local_passwd,
		rem_cand_cnt,
		rem_cand 
	) ;
	HIP_DEBUG("add remote result: %d \n", t);
	
	return 0;
}
/**
 * 
 * called after check list is created
 * */

int hip_ice_start_check(void* ice){
	
	pj_ice_sess * session = ice;
	
	HIP_DEBUG("start checking\n");
	HIP_DEBUG("ice: %s \n", session->obj_name);
	HIP_DEBUG("ice: local c number %d \n", session->lcand_cnt);
	HIP_DEBUG("ice: r c number %d \n", session->rcand_cnt);
	HIP_DEBUG("ice: local c number %d \n", session->lcand_cnt);
	HIP_DEBUG("Ice: check list number: %d \n\n", session->clist.count);
		
	
	
	int j;
	
	for(j= 0; j< session->lcand_cnt; j++ ){
		HIP_DEBUG("Ice: check local candidate : %d \n" , j);
		HIP_DEBUG("candidate 's foundation %s \n" , session->lcand[j].foundation.ptr );
		HIP_DEBUG("candidate 's 	prio %d \n" , session->lcand[j].prio );
		hip_print_lsi("candidate 's 	base addr:" , &(session->lcand[j].addr.ipv4.sin_addr.s_addr ));
		HIP_DEBUG("ca 's 	base addr port: %d \n" , (session->lcand[j].addr.ipv4.sin_port ));
	}
	int i;
	for(i= 0; i< session->rcand_cnt; i++ ){
		HIP_DEBUG("Ice: check r ca : %d \n" , i);
		HIP_DEBUG("ca 's foundation %s \n" , session->rcand[i].foundation.ptr );
		HIP_DEBUG("ca 's 	prio %d \n" , session->rcand[i].prio );
		hip_print_lsi("ca 's 	base addr:" , &(session->rcand[i].addr.ipv4.sin_addr.s_addr ));
		HIP_DEBUG("ca 's 	base addr port: %d \n" , (session->rcand[i].addr.ipv4.sin_port ));
	}
					
	pj_status_t result;
	HIP_DEBUG("Ice: check dump end\n");
	pj_log_set_level(4);
	result = pj_ice_sess_start_check  	(  session  	 ) ; 
	HIP_DEBUG("Ice: check  end: check list number: %d \n", session->clist.count);
	
	
	if(result == PJ_SUCCESS) return 0;
	else return -1;
			
}

int hip_external_ice_end(){
	//destory the pool
	if(pool)
		pj_pool_release(pool);
    //destory the pool factory
    pj_caching_pool_destroy(&cp);
}

int hip_external_ice_receive_pkt(struct hip_common * msg, int pkt_size, in6_addr_t * src_addr,in_port_t port ){
    hip_ha_t  *entry;
    int i, addr_len;
    pj_sockaddr_in pj_addr;
   
    
    HIP_DEBUG("receive a stun  len:  %d\n" ,pkt_size);
    HIP_DEBUG_HIT("receive a stun  from:  " ,src_addr );
    HIP_DEBUG("receive a stun  port:  %d\n" ,port);
    //TODO filter out ipv6
	 pj_addr.sin_family=PJ_AF_INET;
	 pj_addr.sin_port = port;
	 pj_addr.sin_addr.s_addr =*((pj_uint32_t*) &src_addr->s6_addr32[3]);
	 
	 addr_len = sizeof(pj_sockaddr_in);
    
	// found the right entry. 
	entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
    if(entry == NULL) return -1;
    if(entry->ice_session){
    	pj_ice_sess_on_rx_pkt(entry->ice_session,1,msg+1, pkt_size-sizeof(struct hip_common), &pj_addr,addr_len);
    }
    else{
    	HIP_DEBUG("ice is not init in entry.\n");
    }
    
	
	return 0;
}

uint8_t hip_get_nat_control(){
#ifdef HIP_USE_ICE
	 if(hip_we_are_relay())
		 return 0;
	 else 
		 return 1;
#else
	return 0;
#endif

}




