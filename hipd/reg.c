/** @file
 * This file defines a service registration functions for the Host Identity
 * Protocol (HIP).
 * 
 * @author  Anu Markkola
 * @date    17.08.2006
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#include "reg.h"

/** A linked list for storing the supported services. */
HIP_HASHTABLE *services;

void hip_init_services(void)
{
     services = hip_ht_init(NULL, NULL);
}

void hip_uninit_services(void)
{       
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s;
     int c;
     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  list_del(s, services);
     }	
}

/**
 * Adds a service to supported services list.
 *  
 * Adds a service to the supported services linked list @c services. Each
 * service can be added only once. An attempt to add a duplicate service
 * results to a negative return value and the service not being added to
 * the list.
 *
 * @param service_type the service type to add.
 * @return             zero on success, or negative on error.
 */ 
int hip_services_add(int service_type)
{
     int err = 0;
     hip_service_t *tmp = NULL;
     hip_service_t *service = NULL;
        
     HIP_DEBUG("Adding service.\n");
	
     /* Check if the service is already supported. */
     tmp = hip_get_service((uint8_t)service_type);
     if(tmp) {
	  HIP_ERROR("Trying to add duplicate service: %s. " \
		    "Current service state is: %s\n", tmp->name,
		    (tmp->state) ? "inactive" : "active");
	  err = -1;
	  goto out_err;
     }
	
     HIP_IFEL(!(service = HIP_MALLOC(sizeof(struct hip_reg_service), 0)), -1, 
	      "malloc\n");
		
     service->state = HIP_SERVICE_INACTIVE;
	
     if (service_type == HIP_SERVICE_ESCROW)
     {
	  service->service_type = HIP_SERVICE_ESCROW;
	  HIP_INFO("Adding escrow service.\n");
	  strncpy(service->name, "ESCROW_SERVICE", 20);
	  service->handle_registration = hip_handle_escrow_registration;
	  service->cancel_registration = hip_cancel_escrow_registration;
	  service->cancel_service = hip_cancel_escrow_service;
		
     } else if (service_type == HIP_SERVICE_RENDEZVOUS)
     {
	  service->service_type = HIP_SERVICE_RENDEZVOUS;
	  HIP_INFO("Adding rendezvous service.\n");
	  strncpy(service->name, "RENDEZVOUS", 20); 
	  service->handle_registration = hip_handle_registration;
	  service->cancel_registration = hip_cancel_registration;
	  service->cancel_service = hip_cancel_service;
     } else if (service_type == HIP_SERVICE_RELAY_UDP_HIP)
     {
	  service->service_type = HIP_SERVICE_RELAY_UDP_HIP;
	  HIP_INFO("Adding UDP relay service for HIP packets.\n");
	  strncpy(service->name, "RELAYUDPHIP_SERVICE", 20); 
	  service->handle_registration = hip_handle_registration;
	  service->cancel_registration = hip_cancel_registration;
	  service->cancel_service = hip_cancel_service;
	  
	  if(hip_relht_init() == NULL)
	  {
	       err = -1;
	  }
	  else
	  {
	       HIP_DEBUG("HIP UDP RELAY service initiated.\n");
	  }
     } else {
	  HIP_ERROR("Unknown service type.\n");
	  err = -1;
	  free(service);
	  goto out_err;
     }
	
     list_add(service, services);
	
     //TODO: Send information about new service
        
 out_err:
     return err;	
}

int hip_services_set_active(int service)
{
     int err = 0, c;
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s;
	
     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->service_type == service) {
	       HIP_DEBUG("Activating service.\n");
	       s->state = HIP_SERVICE_ACTIVE;
	  }
     }
 out_err:
     return err;        
}

int hip_services_set_inactive(int service)
{
     int err = 0, c;
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s = NULL;

     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->service_type == service) {
	       HIP_DEBUG("Inactivating service.\n");
	       s->state = HIP_SERVICE_INACTIVE;
	  }
     }
 out_err:
     return err;        
}

int hip_services_remove(int service)
{
     int err = 0, c;
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s = NULL;
	
     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->service_type == service) {
	       HIP_DEBUG("Removing service %d.\n", service);
	       HIP_IFEL(s->cancel_service(), -1, 
			"Error cancelling service\n");
	       list_del(s, services);
	       HIP_FREE(s);
	  }
     }
        
 out_err:
     return err;
}

/**
 * @return a HIP service if found, NULL otherwise.
 */
hip_service_t *hip_get_service(uint8_t service_type)
{
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s = NULL;
     int c;

     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->service_type == service_type) {
	       return s;
	  }
     } 
     return NULL;
}

/***/

int hip_get_services_list(int **service_types)
{
     hip_service_t *s = NULL, *s2 = NULL;
     hip_list_t *item = NULL, *item2 = NULL, *tmp = NULL, *tmp2 = NULL;
     int counter1 = 0, c;
     int counter2 = 0;
	
     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->state == HIP_SERVICE_ACTIVE)
	       counter1++;
     }

     if (counter1 == 0) {
	  return 0;
     }

     *service_types = HIP_MALLOC((counter1 * sizeof(int)), GFP_KERNEL);	
	
     list_for_each_safe(item2, tmp2, services, c) {
	  s2 = list_entry(item2);
	  if (counter2 < counter1) {
	       if (s2->state == HIP_SERVICE_ACTIVE) {
		    (*service_types)[counter2] = s2->service_type;
		    counter2++;
	       }
	  }
     }
	
     return counter2;
}


int hip_get_service_count()
{
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s = NULL;
     int count = 0, c;
     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->state == HIP_SERVICE_ACTIVE)
	       count++;
     }
	
     return count;
}

int hip_services_is_active(int service)
{
     hip_list_t *item = NULL, *tmp = NULL;
     hip_service_t *s = NULL;
     int c;

     list_for_each_safe(item, tmp, services, c) {
	  s = list_entry(item);
	  if (s->service_type == service && s->state == HIP_SERVICE_ACTIVE)
	       return 1;
     }
     return 0;
}

int hip_check_service_requests(struct in6_addr *hit, uint8_t *requests, int request_count, 
			       int **accepted_requests, int **rejected_requests, int *accepted_count, int *rejected_count)
{
     int err = 0;
     int i;
     int accept_count = 0;
     int reject_count = 0;
     int count = 0;
     hip_service_t *s = NULL;
     int *a_req, *r_req;
     count = hip_get_service_count();
	
     HIP_DEBUG("Service request count: %d.\n", request_count);

     for (i = 0; i < request_count; i++) {
	  s = hip_get_service(requests[i]);
	  if (s) {
	       if (s->state == HIP_SERVICE_ACTIVE) {
		    if (s->handle_registration(hit)) {	
			 HIP_DEBUG("Accepting service request %d.\n", (int)requests[i]);	
			 *accepted_requests[accept_count] = (int)requests[i];
			 accept_count++;
		    }
		    else {
			 HIP_DEBUG("Rejecting service request %d.\n", (int)requests[i]);	
			 *rejected_requests[reject_count] = (int)requests[i];
			 reject_count++;
		    }
	       }
	       else {
		    HIP_DEBUG("Service inactive.\n");
	       }
	  }
     }
	
     if ((accept_count + reject_count) != request_count)
	  HIP_ERROR("Amount of rejected and accepted services does not match the requests.\n");
     else 
	  HIP_DEBUG("Accepted %d and rejected %d service requests.\n", accept_count, reject_count);
	
     *accepted_count = accept_count;
     *rejected_count = reject_count;
 out_err:	
        
     return err;	
}

int hip_handle_regrequest(hip_ha_t *entry, hip_common_t *source_msg,
			  hip_common_t *target_msg)
{
	struct hip_reg_request *reg_request = NULL;
	hip_service_t *service = NULL;
	int err = 0, accepted_count = 0, rejected_count = 0, type_count = 0;
	int request_got_rejected = 0;
	uint8_t lifetime = 0;
	uint8_t *values = NULL;
     
	HIP_DEBUG("hip_handle_regrequest() invoked.\n");

	/* Check if the incoming I2 has a REG_REQUEST parameter at all. */
	reg_request = hip_get_param(source_msg, HIP_PARAM_REG_REQUEST);
	if(reg_request == NULL) {
		HIP_DEBUG("No REG_REQUEST parameter found.\n");
		err = 1;
		return err;
	}
     
	/* Get the registration lifetime and count of registration types. */
	lifetime = reg_request->lifetime;
	type_count = hip_get_param_contents_len(reg_request) -
		sizeof(reg_request->lifetime);
	values = hip_get_param_contents_direct(reg_request) +
		sizeof(reg_request->lifetime);

	/* Arrays for storing accepted and failed request types. */
	uint8_t accepted_requests[type_count], rejected_requests[type_count];
	memset(accepted_requests, '\0', sizeof(accepted_requests));
	memset(rejected_requests, '\0', sizeof(rejected_requests));

	HIP_DEBUG("REG_REQUEST lifetime: %u, number of types: %d.\n",
		  lifetime, type_count);
     
	/* Check if we already have an relay record for the given HIT. */
	hip_relrec_t dummy, *fetch_record = NULL;
	memcpy(&(dummy.hit_r), &(entry->hit_peer), sizeof(entry->hit_peer));
	fetch_record = hip_relht_get(&dummy);

	/* Cancelling a service. draft-ietf-hip-registration-02:
	   "A zero lifetime is reserved for canceling purposes. .. A registrar
	   SHOULD respond and grant a registration with a zero lifetime."
	   Not a word about failed cancellations, but let's generate REG_FAILED
	   parameters for those. -Lauri 21.09.2007 21:23*/

	/* Cancellation is not tested! */
	if(lifetime == 0) {
		HIP_DEBUG("Client is cancelling registration.\n");
		int i = 0;
		
		for(; i < type_count; i++) {
			/* Check if we have the requested service in our services. */
			service = hip_get_service(values[i]);
			if(service == NULL) {
				HIP_INFO("Client is trying to cancel an "\
					 "service (%u) that we do not have in "\
					 "our services database. "\
					 "Cancellation REJECTED.\n", values[i]);
				rejected_requests[rejected_count] = values[i];
				rejected_count++;
				continue;
			}
			
			/* We could do the cancellation via each services
			   cancel_registration functionpointer inside the above
			   else branch. However, since the registration
			   extension is unfinished in this respect, we handle
			   the cancellation using the switch below.
			   -Lauri 21.09.2007 21:32 */
			request_got_rejected = 0;
			
			switch(values[i]) {
			case HIP_SERVICE_RENDEZVOUS:
				HIP_INFO("Client is cancelling rendezvous "\
					 "service.\n");
				
				if(fetch_record != NULL &&
				   fetch_record->type == HIP_RVSRELAY) {
					hip_relht_rec_free(&dummy);
					/* Check that the element really got
					   deleted. */
					if(hip_relht_get(&dummy) == NULL) {
						HIP_DEBUG("Deleted a relay "\
							  "record.\n");
					} else {
						request_got_rejected = 1;
					}
				} else {
					request_got_rejected = 1;
				}
				break;
			case HIP_SERVICE_ESCROW:
				HIP_INFO("Client is cancelling registration "\
					 "to escrow service.\n");
				if(service->cancel_registration(
					   &entry->hit_peer) == 0) {
					HIP_DEBUG("Cancelled escrow "\
						  "service.\n");
				} else {
					request_got_rejected = 1;
				}
				break;
			case HIP_SERVICE_RELAY_UDP_HIP:
				HIP_INFO("Client is cancelling registration "\
					 "to UDP relay for HIP packets "\
					 "service.\n");
				if(fetch_record != NULL &&
				   fetch_record->type == HIP_RVSRELAY) {
					hip_relht_rec_free(&dummy);
					/* Check that the element really got
					   deleted. */
					if(hip_relht_get(&dummy) == NULL) {
						HIP_DEBUG("Deleted a relay "\
							  "record.\n");
					} else {
						request_got_rejected = 1;
					}
				} else {
					request_got_rejected = 1;
				}
				break;
			case HIP_SERVICE_RELAY_UDP_ESP:
				HIP_INFO("Client is cancelling registration "\
					 "to UDP relay for ESP packets "\
					 "service.\n");
				/* Alas, we do not support UDP ESP relay yet. */
				request_got_rejected = 1;
				break;
			default:
				/* We should never come here, since the
				   registration database check should fail for
				   unsupported services. */
				HIP_ERROR("Client is trying to cancel an "\
					  "service (%u) that we do not "\
					  "support. Cancellation REJECTED.\n",
					  values[i]);
				request_got_rejected = 1;
			}
			/* By this far we know whether the request got accepted
			   or rejected. Lets store the type value. */
			if(!request_got_rejected)
			{
				accepted_requests[accepted_count] = values[i];
				accepted_count++;
			}
			else
			{
				rejected_requests[rejected_count] = values[i];
				rejected_count++;
			}
		}
	}
     
	/* Adding a service. */
	else
	{
		HIP_DEBUG("Client is registrating for new services.\n");
		/* Since the RVS and HIP relay services cannot co-exist for a
		   single client HIT, we must accept only one of those services
		   per REG_REQUEST. Also, if there already is a RVS service and
		   client tries to register to UDP relay (or vice versa), we
		   must not allow the registration. The client is required to
		   cancel the previous service first. If the client tries to
		   re-register to an existing service, we delete the old entry
		   and insert a new one. */
		int i = 0, rr_already_inserted = 0;
		lifetime = hip_get_acceptable_lifetime(lifetime);
		hip_relrec_t *relay_record = NULL;
		
		for(; i < type_count; i++) {
			/* Check if we have the requested service in our
			   services. */
			service = hip_get_service(values[i]);
			if(service == NULL) {
				HIP_INFO("Client is trying to register to a "\
					 "service (%u) that we do not have in "\
					 "our services database. Registration "\
					 "REJECTED.\n", values[i]);
				rejected_requests[rejected_count] = values[i];
				rejected_count++;
				continue;
			}
			
			/** @todo Handle registration using each services
			    handle_registration functionpointer (as now done in
			    escrow). Or alternatively remove the whole
			    registration database, and create a state in each
			    individual service indicating the state of the
			    registration process.
			    -Lauri 21.09.2007 22:25 */
			request_got_rejected = 0;

			switch(values[i]) {
			case HIP_SERVICE_RENDEZVOUS:
				HIP_INFO("Client is registering to rendezvous "\
					 "service.\n");
				/* Check if a relay record already exists. If it
				   exists, we must not replace a FULLRELAY to
				   RVS. The client must cancel the RVS first. */
				if(fetch_record != NULL &&
				   fetch_record->type == HIP_FULLRELAY) {
					request_got_rejected = 1;
					HIP_INFO("Client is trying to "\
						 "register to RVS service "\
						 "without first canceling "\
						 "existing UDP relay for HIP "\
						 "packets service. "\
						 "Registration rejected.\n");
				}
				/* Check that the client's HIT is on the
				   whitelist. */
				else if (hip_relwl_get(&source_msg->hits)
					 == NULL) {
					request_got_rejected = 1;    
					HIP_INFO("Client is trying to "\
						 "register to RVS service, "\
						 "but client's HIT is not "\
						 "listed on the whitelist. "\
						 "Registration rejected.\n");
				}
				/* Check that we have not inserted a service
				   for this REG_REQUEST. This is needed, if the
				   client sends a request with multiple equal
				   type values. */
				else if(rr_already_inserted == 0) {
					relay_record = hip_relrec_alloc(
						HIP_RVSRELAY, lifetime,
						&(entry->hit_peer),
						&(entry->preferred_address),
						entry->peer_udp_port,
						&(entry->hip_hmac_in),
						entry->hadb_xmit_func->hip_send_pkt);
					hip_relht_put(relay_record);
					
					/* Check that the element really is in
					   the hashtable. */
					if(hip_relht_get(relay_record)
					   != NULL) {
						rr_already_inserted = 1;
						HIP_INFO("Registration accepted.\n");
					} else { /* The put was unsuccessful. */
						if(relay_record != NULL) {
							free(relay_record);
						}
						request_got_rejected = 1;
						HIP_INFO("Unable to store new "\
							 "service RVS. "\
							 "Registration rejected.\n");
					}
				} else { /* We have already inserted one service. */
					request_got_rejected = 1;
					HIP_INFO("Client is trying to "\
						 "register multiple times to "\
						 "RVS service using one "\
						 "request. Duplicate "\
						 "registration attempt "\
						 "rejected.\n");
				}
				break;
			case HIP_SERVICE_ESCROW:
				HIP_INFO("Client is registering to escrow service.\n");
				if (service->state == HIP_SERVICE_ACTIVE)
				{
					if(service->handle_registration(&entry->hit_peer) == 0)
					{
						request_got_rejected = 0;
					} else
					{
						request_got_rejected = 1;
					}
				} else
				{
					request_got_rejected = 1;
					HIP_DEBUG("Service inactive.\n");
				}
				break;
			case HIP_SERVICE_RELAY_UDP_HIP:
				HIP_INFO("Client is registering to UDP relay for HIP "\
					 "packets service.\n");
				/* Check if a relay record already exists. If it exists,
				   we must not replace an RVS with FULLRELAY. The client must
				   cancel the RVS first*/
				if(fetch_record != NULL && fetch_record->type == HIP_RVSRELAY)
				{
					request_got_rejected = 1;
					HIP_DEBUG("Registration rejected (1).\n");
				}
				/* Check that we have not inserted a service for this
				   REG_REQUEST. This is needed, if the client sends a
				   request with multiple equal type values. */
				else if(rr_already_inserted == 0){
					relay_record =
						hip_relrec_alloc(HIP_FULLRELAY,
								 lifetime,
								 &(entry->hit_peer),
								 &(entry->preferred_address),
								 entry->peer_udp_port,
								 &(entry->hip_hmac_in),
								 entry->hadb_xmit_func->hip_send_pkt);
					hip_relht_put(relay_record);
					/* Check that the element really is in the hashtable. */
					if(hip_relht_get(relay_record) != NULL)
					{
						rr_already_inserted = 1;
						HIP_DEBUG("Registration accepted.\n");
					}else /* The put was unsuccessful. */
					{    
						if(relay_record != NULL)
						{
							free(relay_record);
						}
						request_got_rejected = 1;
						HIP_DEBUG("Registration rejected (2).\n");
					}
				} else /* We have already inserted one service. */
				{    
					request_got_rejected = 1;
					HIP_DEBUG("Registration rejected (3).\n");
				}
				break;
			case HIP_SERVICE_RELAY_UDP_ESP:
				HIP_INFO("Client is registering to UDP relay for ESP "\
					 "packets service.\n");
				/* Alas, we do not support UDP ESP relay yet. :( */
				request_got_rejected = 1;
				break;
			default:
				/* We should never come here, since the registration
				   database check should fail for unsupported services. */
				HIP_ERROR("Client is trying to register to an service (%u) "\
					  "that we do not support. "\
					  "Registration REJECTED.\n", values[i]);
				request_got_rejected = 1;
			}
			/* By this far we know whether the request got accepted or
			   rejected. Lets store the type value. */
			if(!request_got_rejected)
			{
				accepted_requests[accepted_count] = values[i];
				accepted_count++;
			}
			else
			{
				rejected_requests[rejected_count] = values[i];
				rejected_count++;
			}
		}
	}

	HIP_DEBUG("Accepted requests (%d), rejected requests (%d)\n",
		  accepted_count, rejected_count);
	/* Building REG_RESPONSE and REG_FAILED parameters. */
	if(accepted_count > 0)
	{
		hip_build_param_reg_request(target_msg, lifetime, accepted_requests,
					    accepted_count, 0);
	}
	/** @todo Determine failure type using some indicator. */
	if(rejected_count > 0)
	{
		hip_build_param_reg_failed(target_msg, HIP_REG_TYPE_UNAVAILABLE,
					   rejected_requests, rejected_count);
	}
     
 out_err:
	return err;        
}

int hip_handle_registration_attempt(hip_ha_t *entry, hip_common_t *msg, 
				    struct hip_reg_request *reg_request,
				    uint8_t *requests, int request_count)
{
     int err = 0, accepted_count = 0, rejected_count = 0;
     int *accepted_requests = NULL, *rejected_requests = NULL;
     uint8_t lifetime;
                
     HIP_DEBUG("handle_registration_attempt\n");    
        
     /* If reg_request parameter is NULL, the server itself is cancelling
	registration. -> send reg_response with zero lifetime */
     if (!reg_request) {
	  lifetime = 0;
	  HIP_DEBUG("Building REG_RESPONSE parameter with zero lifetime.\n");
	  HIP_IFEL(hip_build_param_reg_request(
			msg, lifetime, requests, request_count, 0), -1,
		   "Building of REG_RESPONSE failed\n");
     }
     
     /* This is a cancel message (lifetime = 0) */
     else if (reg_request->lifetime == 0)
     {
	  int i = 0;
	  int accept_count = 0;
	  hip_service_t *s;
	  /* Client is cancelling registration 
	   *      - remove client's kea entry
	   *      - tell firewall to remove client-data
	   *      - respond with reg_response (lifetime = 0)
	   */
	  HIP_DEBUG("Client is cancelling registration!\n");
	  accepted_requests = HIP_MALLOC(request_count, 0);
	  for (i = 0; i < request_count; i++) {
	       HIP_DEBUG("service %u", requests[i]);
	       s = hip_get_service(requests[i]);
	       if (s) {
		    if (s->cancel_registration(&entry->hit_peer) >= 0) {      
			 HIP_DEBUG("Accepting cancel request %d.\n", (int)requests[i]); 
			 accepted_requests[accept_count] = (int)requests[i];
			 accept_count++;
		    }
	       }
	       else {
		    HIP_DEBUG("Service inactive \n");
	       }
	  }
	  /* Adding REG_RESPONSE with zero lifetime */   
	  if (accept_count > 0) {
	       lifetime = 0;
	       HIP_DEBUG("Building REG_RESPONSE parameter.\n");
	       HIP_IFEL(hip_build_param_reg_request(msg, lifetime, (uint8_t*)accepted_requests, 
						    accept_count, 0), -1, "Building of REG_RESPONSE failed\n");
	  }
     }
     /* This is a registration message (lifetime != 0) */
     else {
	  HIP_IFEL(!(accepted_requests = HIP_MALLOC((sizeof(int) * request_count), 0)), -1, "alloc\n");
	  HIP_IFEL(!(rejected_requests = HIP_MALLOC((sizeof(int) * request_count), 0)), 
		   -1, "alloc\n");
                
	  HIP_IFEL(hip_check_service_requests(&entry->hit_peer, requests, request_count, 
					      &accepted_requests, &rejected_requests, &accepted_count, &rejected_count), 
		   -1, "check_service_requests failed\n");
                
	  /* Adding REG_RESPONSE and/or REG_FAILED parameter */   
	  HIP_DEBUG("Accepted %d, rejected: %d\n", accepted_count, rejected_count);
	  if (accepted_count > 0) {
	       lifetime = hip_get_acceptable_lifetime(reg_request->lifetime);
	       HIP_DEBUG("Building REG_RESPONSE parameter.\n");
	       HIP_IFEL(hip_build_param_reg_request(msg, lifetime, (uint8_t*)accepted_requests, 
						    accepted_count, 0), -1, "Building of REG_RESPONSE failed\n");
	  }
	  if (rejected_count > 0) {
	       HIP_DEBUG("Building REG_FAILED parameter");
	       /* TODO: Fix failure type to mean something. Now we are using 
		* HIP_REG_TYPE_UNAVAILABLE in any case.*/
	       HIP_IFEL(hip_build_param_reg_failed(msg, HIP_REG_TYPE_UNAVAILABLE,
						   (uint8_t *)rejected_requests, 
						   rejected_count), -1,
			"Building of REG_FAILED failed\n");
	  }
     }
        
 out_err:
     if (accepted_requests)
	  HIP_FREE(accepted_requests);
     if (rejected_requests)
	  HIP_FREE(rejected_requests);        
     return err;        
}

// Default func
int hip_handle_registration(struct in6_addr *hit) 
{
     return 1;
}

// Default func
int hip_cancel_registration(struct in6_addr *hit) 
{
     return 0;
}

// Default func
int hip_cancel_service(void)
{
     // TODO: notify registered clients (REG_RESPONSE with zero lifetime) 
     return 0;
}


/**
 * Check that the requested service lifetime falls within limits.
 * 
 * @param requested_lifetime the lifetime requested.
 * @return                   a lifetime fitting within limits.
 * @todo                     we should have minumum and maximum lifetimes for
 *                           each service. -Lauri 21.09.2007 20:11
 */
uint8_t hip_get_acceptable_lifetime(uint8_t requested_lifetime)
{
     uint8_t time = requested_lifetime;
     if (time > HIP_SERVICE_MAX_LIFETIME)
     {
	  time = HIP_SERVICE_MAX_LIFETIME; 
     } else if (time < HIP_SERVICE_MIN_LIFETIME)
     {
	  time = HIP_SERVICE_MIN_LIFETIME;
     }
     HIP_DEBUG("Requested service lifetime: %d, accepted lifetime: %d\n",
	       requested_lifetime, time);
     return time;
}

uint8_t hip_get_service_min_lifetime()
{
     return HIP_SERVICE_MIN_LIFETIME;
}

uint8_t hip_get_service_max_lifetime()
{
     return HIP_SERVICE_MAX_LIFETIME;
}


/************************/

/* TODO: Move to more appropriate place */
int hip_get_incomplete_registrations(int **types, hip_ha_t *entry, int op, uint8_t srvs[])
{
     int err = 0;
     int type_count = 0, new_count = 0;        
     int request_rvs = 0;
     int request_escrow = 0;
     HIP_KEA *kea = NULL;
     int *reg_type = NULL;

     char local_binstring[20], peer_binstring[20];
     uint16_to_binstring(entry->local_controls, local_binstring);
     uint16_to_binstring(entry->peer_controls, peer_binstring);

     HIP_DEBUG("\nop:%d\nlocal_controls: %s (0x%04x), peer_controls: %s (0x%04x)\n",
	       op,
	       local_binstring, entry->local_controls,
	       peer_binstring, entry->peer_controls);
     
     /* Check which services we have requested, and which services the responder
	offers. Notice, that we do not use the services database here. We just
	check what are the control bit values. The registration database should
	be used here, and is a todo-item for now. Lauri 19.09.2007 19:16 */
#ifdef CONFIG_HIP_RVS   
     if(op &&
	(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_RVS) &&
	(entry->peer_controls & HIP_HA_CTRL_PEER_RVS_CAPABLE))
     {
	  srvs[new_count] = HIP_SERVICE_RENDEZVOUS;
	  new_count ++;
     }
#endif /* CONFIG_HIP_RVS */
//#ifdef CONFIG_HIP_UDPRELAY
     if(op &&
	(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_HIPUDP) &&
	(entry->peer_controls & HIP_HA_CTRL_PEER_HIPUDP_CAPABLE))
     {
	  srvs[new_count] = HIP_SERVICE_RELAY_UDP_HIP;
	  new_count ++;
     }
//#endif /* CONFIG_HIP_UDPRELAY */
#ifdef CONFIG_HIP_ESCROW
     /* This function was designed for just one service (escrow) in the first
	place. I had to do some mods once the RVS and HIPUDPRELAY started to
	use the services database. The escrow part might have become
	nonfunctional as a result. This part is not tested.
	-Lauri 18.09.2007 23:21 */

     /** @todo what if the state is UNREGISTERING? */
     kea = hip_kea_find(&entry->hit_our);
     if(kea)
     {
	  if (op && kea->keastate == HIP_KEASTATE_REGISTERING) {
	       srvs[new_count] = HIP_SERVICE_ESCROW;
	       new_count ++;
	  }
	  else if (!op && kea->keastate == HIP_KEASTATE_UNREGISTERING) {
	       srvs[new_count] = HIP_SERVICE_ESCROW;
	       new_count ++;
	  }
	  hip_keadb_put_entry(kea);
     }
#endif /* CONFIG_HIP_ESCROW */
     
     return new_count;
}


int hip_handle_registration_response(hip_ha_t *entry, struct hip_common *msg)
{
     int err = 0;
     uint8_t lifetime = 0;
     struct hip_reg_request *rresp = NULL;
     struct hip_reg_request *rfail = NULL;
        
     HIP_DEBUG("Checking msg for REG_RESPONSE parameter.\n");
                
     /* Checking REG_RESPONSE */
     rresp = hip_get_param(msg, HIP_PARAM_REG_RESPONSE);
     if (rresp && (rresp->lifetime != 0)) {
	  uint8_t *types = (uint8_t *)
	       (hip_get_param_contents(msg, HIP_PARAM_REG_RESPONSE));
	  int typecnt = hip_get_param_contents_len(rresp);
	  int i;

	  HIP_DEBUG("Found REG_RESPONSE parameter.\n");                        
	  for (i = 1; i < typecnt; i++) {
	       HIP_DEBUG("Service type: %d.\n", types[i]);
	       if (types[i] == HIP_SERVICE_ESCROW) {
		    HIP_KEA *kea = NULL;
		    HIP_DEBUG("Registration to escrow service completed!\n"); 
		    HIP_IFE(!(kea = hip_kea_find(&entry->hit_our)), -1); 
		    HIP_DEBUG("Found kea base entry.\n");
		    kea->keastate = HIP_KEASTATE_VALID;
		    hip_keadb_put_entry(kea);
	       } 
	       if (types[i] == HIP_SERVICE_RENDEZVOUS) {
		    // TODO: RVS
	       }     
	  }       
     }
     else if (rresp && (rresp->lifetime == 0)) {
	  /* Server is cancelling registration or responding to cancellation
	   */
	  // TODO: tell the user!
	  HIP_KEA *kea;
	  HIP_DEBUG("Received cancel-registration message from server\n");
	  HIP_DEBUG("REGISTRATION TO ESCROW SERVICE CANCELLED!\n");
	  HIP_IFEL(hip_remove_escrow_data(entry, NULL), 0, "for_each_hi err.\n");       
	  HIP_IFE(!(kea = hip_kea_find(&entry->hit_our)), -1);
	  HIP_DEBUG("Found kea base entry");
	  hip_keadb_remove_entry(kea);
	  hip_keadb_put_entry(kea); 
     }
     
      /* Checking REG_FAILED */
     rfail = hip_get_param(msg, HIP_PARAM_REG_FAILED);
     HIP_DEBUG("Checking REG_FAILED.\n");
     if (rfail) {
	  uint8_t *types = (uint8_t *)
	       (hip_get_param_contents(msg, HIP_PARAM_REG_FAILED));
	  int typecnt = hip_get_param_contents_len(rfail);
	  int i;
                        
	  if (rfail->type == 0) {
	       HIP_DEBUG("Registration failed: more credentials required.\n");
	  }
	  else {
	       HIP_DEBUG("Registration failed!.\n");
	  }
	  HIP_DEBUG("Found REG_FAILED parameter.\n");                        
	  for (i = 1; i < typecnt; i++) {
	       HIP_DEBUG("Service type: %d.\n", types[i]);
	       if (types[i] == HIP_SERVICE_ESCROW) {
		    /** @todo Should the base entry be removed when registration fails?
			Registration unsuccessful - removing base keas*/
		    hip_kea_remove_base_entries();  
	       } 
	       if (types[i] == HIP_SERVICE_RENDEZVOUS) {
		    // TODO: RVS
	       }     
	  }       
     }
                
     /* We are trying to do registration but server does not respond */
     if (!rfail && !rresp) {
	  HIP_DEBUG("Server not responding to registration attempt.\n");
     }
                
 out_err:
     return err;
}

