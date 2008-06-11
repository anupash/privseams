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
//add by santtu
/** the database for all the ha */
extern HIP_HASHTABLE *hadb_hit;
/** the constant value of the reflexive address amount,
 *  since there is only one RVS server, we use 1 here */
#define HIP_REFEXIVE_LOCATOR_ITEM_AMOUNT_MAX 1
//end add
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
	struct hip_common *msg = NULL;

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "Alloc\n");
	
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


	entry->hadb_misc_func->
		hip_build_network_hdr(msg, HIP_NOTIFY,
				      0, &entry->hit_our,
				      &entry->hit_peer);
	
	/* Calculate the HIP header length */
	hip_calc_hdr_len(msg);

	/* Send the UPDATE packet using 50500 as source and destination ports.
	   Only outgoing traffic acts refresh the NAT port state. We could
	   choose to use other than 50500 as source port, but we must use 50500
	   as destination port. However, because it is recommended to use
	   50500 as source port also, we choose to do so here. */
	entry->hadb_xmit_func->
		hip_send_pkt(&entry->local_address, &entry->preferred_address,
			     HIP_NAT_UDP_PORT, HIP_NAT_UDP_PORT, msg,
			     entry, 0);

 out_err:
	if (msg)
		free(msg);

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


//add by santtu from here

int hip_nat_handle_transform_in_client(struct hip_common *msg , hip_ha_t *entry){
	int err = 0;
	struct hip_nat_transform *nat_transform  = NULL;
	
	
    nat_transform = hip_get_param(msg, HIP_PARAM_NAT_TRANSFORM);
    if(nat_transform){
    	// in the furtue, we should check all the transform type and pick only one
    	// but now, we have only one choice, which is ICE, so the code is the same as
    	//in the server side.
    	entry->nat_control = (ntohs(nat_transform->suite_id[0])) & hip_nat_get_control();
    }
out_err:
	return err;
	  
}

int hip_nat_handle_transform_in_server(struct hip_common *msg , hip_ha_t *entry){
	int err = 0;
	struct hip_nat_transform *nat_transform  = NULL;
	
	
    nat_transform = hip_get_param(msg, HIP_PARAM_NAT_TRANSFORM);
    if(nat_transform){
    	// check if the requested tranform is also supported in the server.
    	entry->nat_control = (ntohs(nat_transform->suite_id[0])) & hip_nat_get_control();
    }
out_err:
	return err;
	  
}

uint16_t hip_nat_get_control(){
#ifdef HIP_USE_ICE
	 if(hip_relay_get_status() == HIP_RELAY_ON)
		 return 0;
	 // comment out before the ice mode is added
	 else //if(hip_nat_get_mode()== SO_HIP_SET_NAT_ICE_UDP)
		 	return 1;
		 // else return 0;
#else
	return 0;
#endif

}
/**
 * handles locator parameter in msg and in entry.
 * 
 * 
 * */
int hip_nat_handle_locator_parameter(hip_common_t *msg,hip_ha_t *entry,struct hip_esp_info *esp_info){
	int err = 0;
	struct hip_locator *locator = NULL;
	
    locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
    if (locator){   
    	HIP_IFEL(hip_update_locator_parameter(entry, 
    	                locator, esp_info),
    	                -1, "hip_update_handle_locator_parameter from msg failed\n");
        }
    if (entry->locator){   
    	HIP_IFEL(hip_update_locator_parameter(entry, 
        			 	entry->locator, esp_info),
        	            -1, "hip_update_handle_locator_parameter from entry failed\n");
            }
    
   
out_err:
   	return err;
}
/**
 * Builds udp and raw locator items into locator list to msg
 * this is the extension of hip_build_locators in output.c
 * type2 locators are collected also
 *
 * @param msg          a pointer to hip_common to append the LOCATORS
 * @return             len of LOCATOR2 on success, or negative error value on error
 */
int hip_nat_build_locators(struct hip_common *msg) 
{
    int err = 0, i = 0, ii = 0;
    struct netdev_address *n;
    hip_ha_t *ha_n;
    hip_list_t *item = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item2 *locs2 = NULL;
    struct hip_locator_info_addr_item *locs1 = NULL;
    int addr_count1 = 0,addr_count2 = 0 ;
    int UDP_relay_count = 0;
    
    
    //TODO count the number of UDP relay servers.
    // check the control state of every hatb_state. 

#ifdef CONFIG_HIP_HI3 // we need addresses for HI3 in any case (if they exist)
    if (address_count > 0) {
#else
    	//check if nat mode is on, or ....
    if (address_count > 0) {
#endif

		//TODO check out the count for UDP and hip raw.
		addr_count1 = address_count;
		// type 2 locator number is the 
		/**wrong impemetation
		 *  hip_relht_size() is the size of relay client in server side*/
		//addr_count2 = hip_relht_size();
		//let's put 10 here for now. anyhow 10 additional type 2 addresses should be enough
		addr_count2 = HIP_REFEXIVE_LOCATOR_ITEM_AMOUNT_MAX;
		
		
		
        HIP_IFEL(!(locs1 = malloc(addr_count1 * 
                                 sizeof(struct hip_locator_info_addr_item))), 
                 -1, "Malloc for LOCATORS type1 failed\n");
        HIP_IFEL(!(locs2 = malloc(addr_count2 * 
                                 sizeof(struct hip_locator_info_addr_item2))), 
                 -1, "Malloc for LOCATORS type2 failed\n");
                 
                 
        memset(locs1,0,(addr_count1 * 
                       sizeof(struct hip_locator_info_addr_item)));
                       
        memset(locs2,0,(addr_count2 *  
                       sizeof(struct hip_locator_info_addr_item2)));  
        
        HIP_DEBUG("there are %d type 1 locator item" , addr_count1);
        //starting
         list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
            if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
                continue;
            if (!IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr))) {
                memcpy(&locs1[ii].address, hip_cast_sa_addr(&n->addr), 
                       sizeof(struct in6_addr));
                locs1[ii].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
                locs1[ii].locator_type = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
                locs1[ii].locator_length = sizeof(struct in6_addr) / 4;
                locs1[ii].reserved = 0;
                HIP_DEBUG_HIT("create one locator item, address: ", &locs1[ii].address);
                ii++;
               
            }
        }
        list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
            if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
                continue;
            if (IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr))) {
                memcpy(&locs1[ii].address, hip_cast_sa_addr(&n->addr), 
                       sizeof(struct in6_addr));
                locs1[ii].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
                locs1[ii].locator_type = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
                locs1[ii].locator_length = sizeof(struct in6_addr) / 4;
                locs1[ii].reserved = 0;
                HIP_DEBUG_HIT("create one locator item, address: ", &locs1[ii].address);
                ii++;
            }
        }
        
        //ending
        /***for reflexive locator
         * retreive the whole entry list
         * if there is a reflexive  **/
        HIP_DEBUG("\n santtu: start looking for reflexive address\n");
        ii = 0;             
        i = 0;  
        
        list_for_each_safe(item, tmp, hadb_hit, i) {
            ha_n = list_entry(item);
            // if there are more addresses than we can take, just break it.
            if (ii>= addr_count2)
                break;
            // check if the reflexive udp port. if it not 0. it means addresses found
            HIP_DEBUG_HIT("santtu: look for reflexive, prefered addres  : ",&ha_n->preferred_address );
            HIP_DEBUG_HIT("santtu: look for reflexive, local addres  : ",&ha_n->local_address );
            HIP_DEBUG("santtu: look for reflexive port: %d \n",ha_n->local_reflexive_udp_port);
            HIP_DEBUG_HIT("santtu: look for reflexive addr: ",&ha_n->local_reflexive_address);
            HIP_DEBUG("santtu: the entry address is %d \n", ha_n);
            if(ha_n->local_reflexive_udp_port){
            	memcpy(&locs2[ii].address, &ha_n->local_reflexive_address, 
            	                       sizeof(struct in6_addr));
                locs2[ii].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
                locs2[ii].locator_type = HIP_LOCATOR_LOCATOR_TYPE_UDP;
                locs2[ii].locator_length = sizeof(struct in6_addr) / 4;
                locs2[ii].reserved = 0;
                // for IPv4 we add UDP information
                locs2[ii].port = htons(ha_n->local_reflexive_udp_port);
                locs2[ii].transport_protocol = 0;
                locs2[ii].kind = 0;
                locs2[ii].spi = 1;
                //TODO change into constant
                locs2[ii].priority = htonl(HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY);
                ii++;
                // if there are more addresses than we can take, just break it.
               if (ii>= addr_count2)
                   break;
            }
            
            // check turn server
    
            
        }
        HIP_DEBUG("hip_build_locators: find relay address account:%d \n", ii);
        //ii is the real amount of type2 locator.addr_count2 is the max value we can accept
        err = hip_build_param_locator2(msg, locs1,locs2, addr_count1,ii);
        //err = hip_build_param_locator2(msg, locs1,locs2, addr_count1,addr_count2);
    }
    else
        HIP_DEBUG("Host has only one or no addresses no point "
                  "in building LOCATOR2 parameters\n");
 out_err:

    if (locs1) free(locs1);
    if (locs2) free(locs2);
    return err;
}

/**
 * Sets NAT status
 * 
 * Sets NAT mode for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 *
int hip_user_nat_mode(int nat_mode)
{
	int err = 0, nat;
	HIP_DEBUG("hip_user_nat_mode() invoked. mode: %d\n", nat_mode);
#if HIP_UDP_PORT_RANDOMIZING 
	hip_nat_randomize_nat_ports();
#endif
	
	nat = nat_mode;
	switch (nat) {
	case SO_HIP_SET_NAT_PLAIN_UDP:
		nat = HIP_NAT_MODE_PLAIN_UDP;
		break;
	case SO_HIP_SET_NAT_NONE:
		nat = HIP_NAT_MODE_NONE;
		break;
	case SO_HIP_SET_NAT_ICE_UDP:
		nat = HIP_NAT_MODE_ICE_UDP;
		break;
	default:
		err = -1;
		HIP_IFEL(1, -1, "Unknown nat mode %d\n", nat_mode);
	} 
	HIP_IFEL(hip_for_each_ha(hip_ha_set_nat_mode, &nat), 0,
	         "Error from for_each_ha().\n");
	//set the nat mode for the host
	hip_set_nat_mode(nat);
	
	HIP_DEBUG("hip_user_nat_mode() end. mode: %d\n", hip_nat_status);

out_err:
	return err;
}
*/