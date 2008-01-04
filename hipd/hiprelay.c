/** @file
 * This file defines the rendezvous extension and the UDP relay for HIP packets
 * for the Host Identity Protocol (HIP). See header file for usage
 * instructions.
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    27.09.2007
 * @note    Related drafts:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-rvs-05.txt">
 *          draft-ietf-hip-rvs-05</a>
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-02.txt">
 *          draft-ietf-hip-nat-traversal-02</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */ 
#include "hiprelay.h"

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_relht_hash, const hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_relht_compare, const hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relht_rec_free, hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relht_free_expired, hip_relrec_t *)

/** The hashtable storing the relay records. */
//static LHASH *hiprelay_ht = NULL;
 LHASH *hiprelay_ht = NULL;
/** 
 * A dummy boolean to indicate the machine has relay capabilities.
 * This is only here for testing and development purposes. It allows the same
 * code to be used at the relay and at endhosts without C precompiler #ifdefs
 */
int we_are_relay = 0;

LHASH *hip_relht_init()
{
     return hiprelay_ht = lh_new(LHASH_HASH_FN(hip_relht_hash),
				 LHASH_COMP_FN(hip_relht_compare));
}

void hip_relht_uninit()
{
     if(hiprelay_ht == NULL)
	  return;

     lh_doall(hiprelay_ht, LHASH_DOALL_FN(hip_relht_rec_free));
     lh_free(hiprelay_ht);
}

unsigned long hip_relht_hash(const hip_relrec_t *rec)
{
     if(rec == NULL || &(rec->hit_r) == NULL)
	  return 0;

     uint8_t hash[HIP_AH_SHA_LEN];
     hip_build_digest(HIP_DIGEST_SHA1, &(rec->hit_r), sizeof(rec->hit_r), hash);
     return *((unsigned long *)hash);
}

int hip_relht_compare(const hip_relrec_t *rec1, const hip_relrec_t *rec2)
{
     if(rec1 == NULL || &(rec1->hit_r) == NULL ||
	rec2 == NULL || &(rec2->hit_r) == NULL)
	  return 1;

     return (hip_relht_hash(rec1) != hip_relht_hash(rec2));
}

void hip_relht_put(hip_relrec_t *rec)
{
     if(hiprelay_ht == NULL || rec == NULL)
	  return;
     
     /* If we are trying to insert a duplicate element (same HIT), we have to
	delete the previous entry. If we do not do so, only the pointer in the
	hash table is replaced and the refrence to the previous element is
	lost resulting in a memory leak. */
     hip_relrec_t dummy;
     memcpy(&(dummy.hit_r), &(rec->hit_r), sizeof(rec->hit_r));
     hip_relht_rec_free(&dummy);
     
     /* lh_insert returns always NULL, we cannot return anything from this function. */
     lh_insert(hiprelay_ht, rec);
}

hip_relrec_t *hip_relht_get(const hip_relrec_t *rec)
{
     if(hiprelay_ht == NULL || rec == NULL)
	  return NULL;

     return (hip_relrec_t *)lh_retrieve(hiprelay_ht, rec);
}

void hip_relht_rec_free(hip_relrec_t *rec)
{
     if(hiprelay_ht == NULL || rec == NULL)
	  return;

     /* Check if such element exist, and delete the pointer from the hashtable. */
     hip_relrec_t *deleted_rec = lh_delete(hiprelay_ht, rec);

     /* Free the memory allocated for the element. */
     if(deleted_rec != NULL)
     {
	  memset(deleted_rec, '\0', sizeof(*deleted_rec));
	  free(deleted_rec);
	  HIP_DEBUG("Relay record deleted.\n");
     }
}

void hip_relht_free_expired(hip_relrec_t *rec)
{
     if(rec == NULL)
	  return;

     if((double)(time(NULL)) - rec->last_contact > HIP_RELREC_LIFETIME)
     {
	  HIP_INFO("Relay record expired, deleting.\n");
	  hip_relht_rec_free(rec);
     }
}

unsigned long hip_relht_size()
{
     if(hiprelay_ht == NULL)
	  return 0;

     return hiprelay_ht->num_items;
}

void hip_relht_maintenance()
{
     if(hiprelay_ht == NULL)
	  return;
     
     unsigned int tmp = hiprelay_ht->down_load;
     hiprelay_ht->down_load = 0;
     lh_doall(hiprelay_ht, LHASH_DOALL_FN(hip_relht_free_expired));
     hiprelay_ht->down_load = tmp;
}

hip_relrec_t *hip_relrec_alloc(const hip_relrec_type_t type,
			       const uint8_t lifetime,
			       const in6_addr_t *hit_r, const hip_hit_t *ip_r,
			       const in_port_t port,
			       const hip_crypto_key_t *hmac,
			       const hip_xmit_func_t func)
{
     if(hit_r == NULL || ip_r == NULL || hmac == NULL || func == NULL)
	  return NULL;

     hip_relrec_t *rec = (hip_relrec_t*) malloc(sizeof(hip_relrec_t));
     
     if(rec == NULL)
     {
	  HIP_ERROR("Error allocating memory for HIP relay record.\n");
	  return NULL;
     }
     rec->type = type;
     memcpy(&(rec->hit_r), hit_r, sizeof(*hit_r));
     memcpy(&(rec->ip_r), ip_r, sizeof(*ip_r));
     rec->udp_port_r = port;
     memcpy(&(rec->hmac_relay), hmac, sizeof(*hmac));
     rec->send_fn = func;
     hip_relrec_set_lifetime(rec, lifetime);
     rec->last_contact = time(NULL);
     
     return rec;
}

void hip_relrec_set_mode(hip_relrec_t *rec, const hip_relrec_type_t type)
{
     if(rec != NULL)
	  rec->type = type;
}

void hip_relrec_set_lifetime(hip_relrec_t *rec, const uint8_t lifetime)
{
     if(rec != NULL)
     {
	  rec->lifetime = pow(2, ((double)(lifetime-64)/8));
     }
}

void hip_relrec_set_udpport(hip_relrec_t *rec, const in_port_t port)
{
     if(rec != NULL)
	  rec->udp_port_r = port;
}

void hip_relrec_info(const hip_relrec_t *rec)
{
     if(rec == NULL)
	  return;
     
     char status[1024];
     char *cursor = status;
     cursor += sprintf(cursor, "Relay record info:\n");
     cursor += sprintf(cursor, " Record type: ");
     cursor += sprintf(cursor, (rec->type == HIP_FULLRELAY) ?
		       "Full relay of HIP packets\n" :
		       (rec->type == HIP_RVSRELAY) ?
		       "RVS relay of I1 packet\n" : "undefined\n");
     cursor += sprintf(cursor, " Record lifetime: %.2f seconds\n",
		       rec->lifetime);
     cursor += sprintf(cursor, " Last contact: %lu seconds ago\n",
		       time(NULL) - rec->last_contact);
     cursor += sprintf(cursor, " HIT of R: %04x:%04x:%04x:%04x:"\
		       "%04x:%04x:%04x:%04x\n",
		       ntohs(rec->hit_r.s6_addr16[0]),
		       ntohs(rec->hit_r.s6_addr16[1]),
		       ntohs(rec->hit_r.s6_addr16[2]),
		       ntohs(rec->hit_r.s6_addr16[3]),
		       ntohs(rec->hit_r.s6_addr16[4]),
		       ntohs(rec->hit_r.s6_addr16[5]),
		       ntohs(rec->hit_r.s6_addr16[6]),
		       ntohs(rec->hit_r.s6_addr16[7]));
     cursor += sprintf(cursor, " IP of R:  %04x:%04x:%04x:%04x:"\
		       "%04x:%04x:%04x:%04x\n",
		       ntohs(rec->ip_r.s6_addr16[0]),
		       ntohs(rec->ip_r.s6_addr16[1]),
		       ntohs(rec->ip_r.s6_addr16[2]),
		       ntohs(rec->ip_r.s6_addr16[3]),
		       ntohs(rec->ip_r.s6_addr16[4]),
		       ntohs(rec->ip_r.s6_addr16[5]),
		       ntohs(rec->ip_r.s6_addr16[6]),
		       ntohs(rec->ip_r.s6_addr16[7]));

     HIP_INFO("\n%s", status);
}

int hip_we_are_relay()
{
     return we_are_relay;
}

int hip_relay_rvs(const hip_common_t *i1, const in6_addr_t *i1_saddr,
		  const in6_addr_t *i1_daddr, hip_relrec_t *rec,
		  const hip_portpair_t *i1_info)
{
     struct hip_common *i1_to_be_relayed = NULL;
     struct hip_tlv_common *current_param = NULL;
     int err = 0, from_added = 0;
     hip_tlv_type_t param_type = 0;
     /* A function pointer to either hip_build_param_from() or
	hip_build_param_relay_from(). */
     int (*builder_function) (struct hip_common *msg,
			      const struct in6_addr *addr,
			      const in_port_t port);

     HIP_DEBUG("hip_relay_rvs() invoked.\n");
     HIP_DEBUG_IN6ADDR("hip_relay_rvs():  I1 source address", i1_saddr);
     HIP_DEBUG_IN6ADDR("hip_relay_rvs():  I1 destination address", i1_daddr);
     HIP_DEBUG_HIT("hip_relay_rvs(): Relay record hit",
		   &rec->hit_r);
     HIP_DEBUG("Relay record port: %d.\n", rec->udp_port_r);
     HIP_DEBUG("I1 source port: %u, destination port: %u\n",
	       i1_info->src_port, i1_info->dst_port);
		
     /* If the incoming I1 packet was destined to port 50500, we know that
	there is a NAT between (I->NAT->RVS->R). */
     if(i1_info->dst_port == HIP_NAT_UDP_PORT) {
	  builder_function = hip_build_param_relay_from;
	  param_type = HIP_PARAM_RELAY_FROM;
     }
     else {
	  builder_function = hip_build_param_from;
	  param_type = HIP_PARAM_FROM;
     }

     HIP_IFEL(!(i1_to_be_relayed = hip_msg_alloc()), -ENOMEM,
	      "No memory to copy original I1\n");	

     /* I1 packet forwarding is achieved by rewriting the source and
	destination IP addresses. */
     hip_build_network_hdr(i1_to_be_relayed, HIP_I1, 0,
			   &(i1->hits), &(i1->hitr));

     /* Adding FROM (RELAY_FROM) parameter. Loop through all the parameters in
	the received I1 packet, and insert a new FROM (RELAY_FROM) parameter
	after the last found FROM (RELAY_FROM) parameter. Notice that in most
	cases the incoming I1 has no paramaters at all, and this "while" loop
	is skipped. Multiple rvses en route to responder is one (and only?)
	case when the incoming I1 packet has parameters. */
     while ((current_param = hip_get_next_param(i1, current_param)) != NULL){
		
	  HIP_DEBUG("Found parameter in I1.\n");
	  /* Copy while type is smaller than or equal to FROM (RELAY_FROM)
	     or a new FROM (RELAY_FROM) has already been added. */
	  if (from_added || hip_get_param_type(current_param) <= param_type)
	  {
	       HIP_DEBUG("Copying existing parameter to I1 packet "\
			 "to be relayed.\n");
	       hip_build_param(i1_to_be_relayed,current_param);
	       continue;
	  }
	  /* Parameter under inspection has greater type than FROM
	     (RELAY_FROM) parameter: insert a new FROM (RELAY_FROM) parameter
	     between the last found FROM (RELAY_FROM) parameter and
	     "current_param". */
	  else
	  {
	       HIP_DEBUG("Created new %s and copied "\
			 "current parameter to relayed I1.\n",
			 hip_param_type_name(param_type));
	       builder_function(i1_to_be_relayed, i1_saddr,
				i1_info->src_port);
	       hip_build_param(i1_to_be_relayed, current_param);
	       from_added = 1;
	  }
     }

     /* If the incoming I1 had no parameters after the existing FROM (RELAY_FROM)
	parameters, new FROM (RELAY_FROM) parameter is not added until here. */
     if (!from_added)
     {
	  HIP_DEBUG("No parameters found, adding a new %s.\n",
		    hip_param_type_name(param_type));
	  builder_function(i1_to_be_relayed, i1_saddr, i1_info->src_port);
     }

     /* Zero message HIP checksum. */
     hip_zero_msg_checksum(i1_to_be_relayed);

     /* Adding RVS_HMAC parameter as the last parameter of the relayed
	packet. Notice, that this presumes that there are no parameters
	whose type value is greater than RVS_HMAC in the incoming I1
	packet. */
     HIP_DEBUG("Adding a new RVS_HMAC parameter as the last parameter.\n");
     HIP_IFEL(hip_build_param_rvs_hmac_contents(i1_to_be_relayed,
						&(rec->hmac_relay)), -1,
	      "Building of RVS_HMAC failed.\n");
	
     /* If the client is behind NAT the I1 packet is relayed on UDP. If
	there is no NAT the packet is relayed on raw HIP. We don't have to
	take care of which send-function to use, as the rec->send_fn was
	initiated with correct value when the relay relay was created. Note
	that we use NULL as source IP address instead of
	i1_daddr. A source address is selected in the corresponding
	send-function. */
     HIP_IFEL(rec->send_fn(NULL, &(rec->ip_r), HIP_NAT_UDP_PORT,
			   rec->udp_port_r, i1_to_be_relayed, NULL, 0),
	      -ECOMM, "Relaying I1 failed.\n");

     /* Once we have relayed the I1 packet successfully, we update the time of
	last contact. */
     rec->last_contact = time(NULL);

     HIP_DEBUG_HIT("hip_relay_rvs(): Relayed I1 to", &(rec->ip_r));

 out_err:
     if(i1_to_be_relayed != NULL)
     {
	  HIP_FREE(i1_to_be_relayed);
     }
     return err;
}

/**
 * 
 * this relay full function is to use to relay package from i or r.
 * 
 * 
 * 
 * */

int hip_relay_full(const hip_common_t *i1, const in6_addr_t *i1_saddr,
		  const in6_addr_t *i1_daddr, hip_relrec_t *rec,
		  const hip_portpair_t *i1_info,
		  const uint8_t type_hdr)
{
     struct hip_common *i1_to_be_relayed = NULL;
     struct hip_tlv_common *current_param = NULL;
     int err = 0, from_added = 0;
     hip_tlv_type_t param_type = 0;
     /* A function pointer to either hip_build_param_from() or
	hip_build_param_relay_from(). */
     int (*builder_function) (struct hip_common *msg,
			      const struct in6_addr *addr,
			      const in_port_t port);

     HIP_DEBUG("hip_relay_full() invoked.\n");
     HIP_DEBUG_IN6ADDR("hip_relay_full():  source address", i1_saddr);
     HIP_DEBUG_IN6ADDR("hip_relay_full():  destination address", i1_daddr);
     HIP_DEBUG_HIT("hip_relay_full: Relay record hit",
		   &rec->hit_r);
     HIP_DEBUG("Relay record port: %d.\n", rec->udp_port_r);
     HIP_DEBUG("I1 source port: %u, destination port: %u\n",
	       i1_info->src_port, i1_info->dst_port);
		
     /* If the incoming I1 packet was destined to port 50500, we know that
	there is a NAT between (I->NAT->RVS->R). */
     // if(i1_info->dst_port == HIP_NAT_UDP_PORT) {
     builder_function = hip_build_param_relay_from;
     param_type = HIP_PARAM_RELAY_FROM;
	  /*	}
	else {
	  builder_function = hip_build_param_from;
	  param_type = HIP_PARAM_FROM;
	  }*/

     HIP_IFEL(!(i1_to_be_relayed = hip_msg_alloc()), -ENOMEM,
	      "No memory to copy original I1\n");	

     /* I1 packet forwarding is achieved by rewriting the source and
	destination IP addresses. */
     hip_build_network_hdr(i1_to_be_relayed, type_hdr, 0,
			   &(i1->hits), &(i1->hitr));

     /* Adding FROM (RELAY_FROM) parameter. Loop through all the parameters in
	the received I1 packet, and insert a new FROM (RELAY_FROM) parameter
	after the last found FROM (RELAY_FROM) parameter. Notice that in most
	cases the incoming I1 has no paramaters at all, and this "while" loop
	is skipped. Multiple rvses en route to responder is one (and only?)
	case when the incoming I1 packet has parameters. */
     while ((current_param = hip_get_next_param(i1, current_param)) != NULL){
		
	  HIP_DEBUG("Found parameter in I1.\n");
	  /* Copy while type is smaller than or equal to FROM (RELAY_FROM)
	     or a new FROM (RELAY_FROM) has already been added. */
	  if (from_added || hip_get_param_type(current_param) <= param_type)
	  {
	       HIP_DEBUG("Copying existing parameter to I1 packet "\
			 "to be relayed.\n");
	       hip_build_param(i1_to_be_relayed,current_param);
	       continue;
	  }
	  /* Parameter under inspection has greater type than FROM
	     (RELAY_FROM) parameter: insert a new FROM (RELAY_FROM) parameter
	     between the last found FROM (RELAY_FROM) parameter and
	     "current_param". */
	  else
	  {
	       HIP_DEBUG("Created new %s and copied "\
			 "current parameter to relayed I1.\n",
			 hip_param_type_name(param_type));
	       builder_function(i1_to_be_relayed, i1_saddr,
				i1_info->src_port);
	       hip_build_param(i1_to_be_relayed, current_param);
	       from_added = 1;
	  }
     }

     /* If the incoming I1 had no parameters after the existing FROM (RELAY_FROM)
	parameters, new FROM (RELAY_FROM) parameter is not added until here. */
     if (!from_added)
     {
	  HIP_DEBUG("No parameters found, adding a new %s.\n",
		    hip_param_type_name(param_type));
	  builder_function(i1_to_be_relayed, i1_saddr, i1_info->src_port);
     }

     /* Zero message HIP checksum. */
     hip_zero_msg_checksum(i1_to_be_relayed);

     /* Adding RVS_HMAC parameter as the last parameter of the relayed
	packet. Notice, that this presumes that there are no parameters
	whose type value is greater than RVS_HMAC in the incoming I1
	packet. */
     HIP_DEBUG("Adding a new RELAY_HMAC parameter as the last parameter.\n");
     HIP_IFEL(hip_build_param_full_relay_hmac_contents(i1_to_be_relayed,
						&(rec->hmac_relay)), -1,
	      "Building of RVS_HMAC failed.\n");
	
     /* If the client is behind NAT the I1 packet is relayed on UDP. If
	there is no NAT the packet is relayed on raw HIP. We don't have to
	take care of which send-function to use, as the rec->send_fn was
	initiated with correct value when the relay relay was created. Note
	that we use NULL as source IP address instead of
	i1_daddr. A source address is selected in the corresponding
	send-function. */
     HIP_IFEL(rec->send_fn(NULL, &(rec->ip_r), HIP_NAT_UDP_PORT,
			   rec->udp_port_r, i1_to_be_relayed, NULL, 0),
	      -ECOMM, "Relaying I1 failed.\n");

     /* Once we have relayed the I1 packet successfully, we update the time of
	last contact. */
     rec->last_contact = time(NULL);

     HIP_DEBUG_HIT("hip_relay_full(): Relayed I1 to", &(rec->ip_r));

 out_err:
     if(i1_to_be_relayed != NULL)
     {
	  HIP_FREE(i1_to_be_relayed);
     }
     return err;
}



/**
 * 
 * 
 * 
 */
int hip_relay_response(const hip_common_t *r,const uint8_t type_hdr, const in6_addr_t *r_saddr,
		  const in6_addr_t *r_daddr , const hip_portpair_t *r_info , 
		  const in6_addr_t *relay_to_addr,const in_port_t relay_to_port)
{
     struct hip_common *r_to_be_relayed = NULL;
     struct hip_tlv_common *current_param = NULL;
     int err = 0;
     hip_tlv_type_t param_type = 0;



     HIP_DEBUG("hip_relay_response() invoked.\n");
     HIP_DEBUG_IN6ADDR("hip_relay_response():  source address", r_saddr);
     HIP_DEBUG_IN6ADDR("hip_relay_response():  destination address", r_daddr);
     HIP_DEBUG_IN6ADDR("hip_relay_response():  relay to address", relay_to_addr);
     //HIP_DEBUG_HIT("hip_relay_full: Relay record hit", &rec->hit_r);
     HIP_DEBUG("Relay_to port: %d.\n", relay_to_port);




     HIP_IFEL(!(r_to_be_relayed = hip_msg_alloc()), -ENOMEM,
	      "No memory to copy original I1\n");	


     hip_build_network_hdr(r_to_be_relayed, type_hdr, 0,
			   &(r->hits), &(r->hitr));


     while ((current_param = hip_get_next_param(r, current_param)) != NULL){
		
		HIP_DEBUG("Found parameter in R.\n");

		HIP_DEBUG("Copying existing parameter to R packet "\
		 "to be relayed.\n");
		hip_build_param(r_to_be_relayed,current_param);

     }


     hip_zero_msg_checksum(r_to_be_relayed);

     

     HIP_IFEL(hip_send(NULL, relay_to_addr, HIP_NAT_UDP_PORT,
			   relay_to_port, r_to_be_relayed, NULL, 0),
	      -ECOMM, "Relaying I1 failed.\n");



     HIP_DEBUG_HIT("hip_relay_response(): Relayed  to", relay_to_addr);

 out_err:
     if(r_to_be_relayed != NULL)
     {
	  HIP_FREE(r_to_be_relayed);
     }
     return err;
}


int hip_relay_handle_from(hip_common_t *source_msg,
			  in6_addr_t *rvs_ip,
			  in6_addr_t *dest_ip, in_port_t *dest_port, hip_tlv_type_t *param_type)
{
     struct hip_relay_from *relay_from = NULL;
     struct hip_from *from = NULL;
     hip_ha_t *rvs_ha_entry = NULL;

     /* Check if the incoming I1 packet has a FROM or RELAY_FROM parameters. */
     relay_from = (struct hip_relay_from *)
	  hip_get_param(source_msg, HIP_PARAM_RELAY_FROM);
     from = (struct hip_from *)
	  hip_get_param(source_msg, HIP_PARAM_FROM);
     
     /* Copy parameter data to target buffers. */
     if(relay_from == NULL && from == NULL)
     {
		  HIP_DEBUG("No FROM or RELAY_FROM parameters found in I1.\n");
		  return 0;
     } else if(from != NULL)
     {
		  
		  *param_type = HIP_PARAM_FROM;
		  memcpy(dest_ip, &from->address, sizeof(from->address));
     } else 
     {
	  HIP_DEBUG("Found RELAY_FROM parameter in I.\n");
	  // set the relay ip and port to the destination address and port.
		  *param_type = HIP_PARAM_RELAY_FROM;
		  
		  memcpy(dest_ip, &relay_from->address, sizeof(relay_from->address));
		  	*dest_port = ntohs(relay_from->port);
		//	*dest_port = relay_from->port;
			HIP_DEBUG("RELAY_FROM port in I. %d \n", *dest_port);
     }
     
     /* The relayed I1 packet has the initiator's HIT as source HIT, and the
	responder HIT as destination HIT. We would like to verify the HMAC
	against the host association that was created when the responder
	registered to the rvs. That particular host association has the
	responder's HIT as source HIT and the rvs' HIT as destination HIT.
	Because we do not have the HIT of RVS in the incoming I1 message, we
	have to get the host association using the responder's HIT and the IP
	address of the RVS as search keys. */
     rvs_ha_entry =
	  hip_hadb_find_rvs_candidate_entry(&source_msg->hitr, rvs_ip);
     
     if (rvs_ha_entry == NULL)
     {
	  HIP_DEBUG("The I1 packet was received from RVS, but the host "\
		    "association created during registration is not found. "
		    "RVS_HMAC cannot be verified.\n");
	  return -1;
     }

     HIP_DEBUG("RVS host or relay host association found.\n");
     
     /* Verify the RVS hmac. */
     if(from != NULL&&hip_verify_packet_rvs_hmac(source_msg, &rvs_ha_entry->hip_hmac_out)
	!= 0)
     {
	  HIP_INFO("RVS_HMAC verification failed.\n");
	  return -1;
     }
     
     if(relay_from != NULL&& hip_verify_packet_full_relay_hmac(source_msg, &rvs_ha_entry->hip_hmac_out)
	!= 0)
     {
	  HIP_INFO("Full_Relay_HMAC verification failed.\n");
	  return -1;
     }
     
     HIP_DEBUG("RVS_HMAC or Full_Relay verified.\n");

     return 0;
}
