/** @file
 * This file defines a registration mechanism for the Host Identity Protocol
 * (HIP) that allows hosts to register with services.
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    05.04.2008
 * @note    Related drafts:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-registration-02.txt">
 *          draft-ietf-hip-registration-02</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @see     registration.h
 * @see     hiprelay.h
 * @see     escrow.h
 */ 
#include "registration.h"

/** An array for storing all existing services. */
hip_srv_t hip_services[HIP_TOTAL_EXISTING_SERVICES];
/** A linked list for storing pending requests on the client side.
 *  @note This assumes a single threded model. We are not using mutexes here.
 */
hip_ll_t pending_requests;
/** A linked list for storing pending responses on the server side.
 *  @note This assumes a single threded model. We are not using mutexes here.
 */
hip_ll_t pending_responses;

void hip_init_xxx_services()
{
	hip_services[0].reg_type     = HIP_SERVICE_RENDEZVOUS;
	hip_services[0].status       = HIP_SERVICE_OFF;
	hip_services[0].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[0].max_lifetime = HIP_RELREC_MAX_LIFETIME;
	hip_services[1].reg_type     = HIP_SERVICE_ESCROW;
	hip_services[1].status       = HIP_SERVICE_OFF;
	hip_services[1].min_lifetime = HIP_ESCROW_MIN_LIFETIME;
	hip_services[1].max_lifetime = HIP_ESCROW_MAX_LIFETIME;
	hip_services[2].reg_type     = HIP_SERVICE_RELAY;
	hip_services[2].status       = HIP_SERVICE_OFF;
	hip_services[2].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[2].max_lifetime = HIP_RELREC_MAX_LIFETIME;

	hip_ll_init(&pending_requests);
	hip_ll_init(&pending_responses);
	
	HIP_DEBUG("NEW SERVICE INITIALIZATION DONE.\n");
}

void hip_uninit_xxx_services()
{
	hip_ll_uninit(&pending_requests, free);
	hip_ll_uninit(&pending_responses, free);
	HIP_DEBUG("NEW SERVICE UNINITIALIZATION DONE.\n");
}

int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status)
{
	int i = 0;
	
	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].reg_type == reg_type) {
			hip_services[i].status = status;
			return 0;
		}
	}
	
	return -1;
}

int hip_set_srv_min_lifetime(uint8_t reg_type, uint8_t lifetime)
{
	if(lifetime = 0) {
		return -1;
	}
	
	int i = 0;
	
	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].reg_type == reg_type) {
			hip_services[i].min_lifetime = lifetime;
			return 0;
		}
	}
	
	return -1;
}

int hip_set_srv_max_lifetime(uint8_t reg_type, uint8_t lifetime)
{
	if(lifetime = 0) {
		return -1;
	}
	
	int i = 0;
	
	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].reg_type == reg_type) {
			hip_services[i].max_lifetime = lifetime;
			return 0;
		}
	}
	
	return -1;
}

int hip_get_active_services(hip_srv_t *active_services,
			    unsigned int *active_service_count)
{
	if(active_services == NULL) {
		return -1;
	}

	int i = 0, j = 0;
	
	memset(active_services, 0, sizeof(hip_services));

	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].status == HIP_SERVICE_ON) {
			memcpy(&active_services[j], &hip_services[i],
			       sizeof(active_services[j]));
			j++;
		}
	}
	
	*active_service_count = j;

	return 0;
} 

void hip_srv_info(const hip_srv_t *srv, char *status)
{
	if(srv == NULL || status == NULL)
		return;
	
	char *cursor = status;
	cursor += sprintf(cursor, "Service info:\n");
	
	cursor += sprintf(cursor, " reg_type: ");
	if(srv->reg_type == HIP_SERVICE_RENDEZVOUS){
		cursor += sprintf(cursor, "rendezvous\n");
	} else if(srv->reg_type == HIP_SERVICE_ESCROW) {
		cursor += sprintf(cursor, "escrow\n");
	} else if(srv->reg_type == HIP_SERVICE_RELAY) {
		cursor += sprintf(cursor, "relay\n");
	} else {
		cursor += sprintf(cursor, "unknown\n");
	}

	cursor += sprintf(cursor, " status: ");
	if(srv->status == HIP_SERVICE_ON) {
		cursor += sprintf(cursor, "on\n");
	}else if(srv->status == HIP_SERVICE_OFF) {
		cursor += sprintf(cursor, "off\n");
	}else{
		cursor += sprintf(cursor, "unknown\n");
	}

	cursor += sprintf(cursor, " minimum lifetime: %u\n", srv->min_lifetime);
	cursor += sprintf(cursor, " maximum lifetime: %u\n", srv->max_lifetime);
}

int hip_add_pending_request(hip_pending_request_t *request)
{
	int err = 0;
	
	HIP_IFEL(hip_ll_add_last(&pending_requests, request), -1,
		 "Failed to add a pending registration request.\n");

 out_err:
	return err;
}

int hip_del_pending_request(hip_ha_t *entry)
{
	int index = 0;
	hip_ll_node_t *iter = NULL;
	
	/* Iterate through the linked list. We're deleting a node from the list
	   even though we use an iterator here, but it's okay, since we do not
	   use the iterator after the deletion. */
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry == entry) {
			
			HIP_DEBUG("Deleting a pending request at index %u.\n", index);
			hip_ll_del(&pending_requests, index, free);
			return 0;
		}
		index++;
	}

	return -1;
}

int hip_get_pending_requests(hip_ha_t *entry, hip_pending_request_t *requests[])
{
	if(requests == NULL) {
		return -1;
	}

	hip_ll_node_t *iter = 0;
	int request_count = 0;
	
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry
		   == entry) {
			requests[request_count] =
				(hip_pending_request_t *)(iter->ptr);
			request_count++;
		}
	}
	
	if(request_count == 0) {
		return -1;
	}
			
	return 0;
}

int hip_get_pending_request_count(hip_ha_t *entry)
{
	hip_ll_node_t *iter = 0;
	int request_count = 0;
	
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry
		   == entry) {
			request_count++;
		}
	}

	return request_count;
}

int hip_handle_param_reg_info(hip_common_t *msg, hip_ha_t *entry)
{
	struct hip_reg_info *reg_info = NULL;
	uint8_t *reg_types = NULL, reg_type = 0;
	unsigned int type_count = 0;
	int i = 0;
	
	reg_info = hip_get_param(msg, HIP_PARAM_REG_INFO);
	
	if(reg_info == NULL) {
#ifdef CONFIG_HIP_ESCROW
		/* The escrow part is just a copy paste from the previous HIPL
		   registration implementation. It is not tested to work.
		   Besides, it makes no sense to do anything except return
		   zero here. Why should we take action if the responder does
		   NOT offer the service? -Lauri. */ 
		HIP_DEBUG("No REG_INFO parameter found. The Responder offers "\
			  "no services.\n");
		HIP_KEA *kea;
		kea = hip_kea_find(&entry->hit_our);
		
		if (kea && (kea->keastate == HIP_KEASTATE_REGISTERING))
			kea->keastate = HIP_KEASTATE_INVALID;
		if (kea)
			hip_keadb_put_entry(kea);	
		/** @todo remove base keas */
#endif /* CONFIG_HIP_ESCROW */		
		return 0;
	}
	
	HIP_DEBUG("REG_INFO parameter found.\n");

	/* Get a pointer registration types and the type count. */
	reg_types  = reg_info->reg_type;
	type_count = hip_get_param_contents_len(reg_info) -
		(sizeof(reg_info->min_lifetime) + sizeof(reg_info->max_lifetime));
	
	/* Check draft-ietf-hip-registration-02 chapter 3.1. */
	if(type_count == 0){
		HIP_INFO("The server is currently unable to provide services "\
			 "due to transient conditions.\n");
		return 0;
	}

	/* Loop through all the registration types found in REG_INFO parameter. */ 
	for(i = 0; i < type_count; i++){
		
		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
			HIP_INFO("Responder offers rendezvous service.\n");
			/* If we have requested for RVS service in I1, we store
			   the information of responder's capability here. */
			if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_RVS) {
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_RVS_CAPABLE);
			}
			break;

#ifdef CONFIG_HIP_ESCROW		
		case HIP_SERVICE_ESCROW:
			/* The escrow part is just a copy paste from the
			   previous HIPL registration implementation. It is not
			   tested to work. -Lauri */
			HIP_INFO("Responder offers escrow service.\n");
			HIP_KEA *kea;
			
			/* If we have requested for escrow service in I1, we
			   store the information of responder's capability
			   here. */
			if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_ESCROW) {
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_ESCROW_CAPABLE);
			}
			
			kea = hip_kea_find(&entry->hit_our);
			if (kea && kea->keastate == HIP_KEASTATE_REGISTERING) {
				HIP_DEBUG("Registering to escrow service.\n");
				hip_keadb_put_entry(kea);
			} else if(kea){
				kea->keastate = HIP_KEASTATE_INVALID;
				HIP_DEBUG("Not doing escrow registration, "\
					  "invalid kea state.\n");
				hip_keadb_put_entry(kea);	  
			} else {
				HIP_DEBUG("Not doing escrow registration.\n");
			}

			break;
#endif /* CONFIG_HIP_ESCROW */				
		case HIP_SERVICE_RELAY:
			HIP_INFO("Responder offers relay service.\n");
			/* If we have requested for relay service in I1, we
			   store the information of responder's capability
			   here. */
			if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_RELAY) {
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_RELAY_CAPABLE);
			}
			break;
			
		default:
			HIP_INFO("Responder offers unsupported service.\n");
		}
	}
	
	return 0;
}

int hip_handle_param_rrq(hip_ha_t *entry, hip_common_t *source_msg,
			 hip_common_t *target_msg)
{
	int err = 0, type_count = 0, accepted_count = 0, refused_count = 0;
	struct hip_reg_request *reg_request = NULL;
	uint8_t *reg_types = NULL;

	reg_request = hip_get_param(source_msg, HIP_PARAM_REG_REQUEST);
	
	if(reg_request == NULL) {
		err = -1;
		_HIP_DEBUG("No REG_REQUEST parameter found.\n");
		/* Have to use return instead of 'goto out_err' because of
		   the arrays initialised later. Otherwise this won't compile:
		   error: jump into scope of identifier with variably modified
		   type. */
		return err;
	}
	
	HIP_DEBUG("REG_REQUEST parameter found.\n");
	
	/* Get the number of registration types. */
	type_count = hip_get_param_contents_len(reg_request) -
		sizeof(reg_request->lifetime);
	/* Get a pointer to the actual registration types. */
	reg_types = hip_get_param_contents_direct(reg_request) +
		sizeof(reg_request->lifetime);

	/* Check that the request has at most one value of each type. */
	if(hip_has_duplicate_services(reg_types, type_count)) {
		err = -1;
		HIP_ERROR("The REG_REQUEST parameter has duplicate services. "\
			  "The whole parameter is omitted.\n");
		/* As above. */
		return err;
	}
	
	/* Arrays for storing the type reg_types of the accepted and refused
	   request types. */
	uint8_t accepted_requests[type_count], accepted_lifetimes[type_count];
	uint8_t refused_requests[type_count], failure_types[type_count];
	
	memset(accepted_requests, '0', sizeof(accepted_requests));
	memset(accepted_lifetimes, '0', sizeof(accepted_lifetimes));
	memset(refused_requests, '0', sizeof(refused_requests));
	memset(failure_types, '0', sizeof(failure_types));
	
	HIP_DEBUG("REG_REQUEST lifetime: 0x%x, number of types: %d.\n",
		  reg_request->lifetime, type_count);

	if(reg_request->lifetime == 0) {
		HIP_DEBUG("Client is cancelling registration.\n");
		hip_cancel_reg(entry, reg_types, type_count,
			       accepted_requests, &accepted_count,
			       refused_requests, &refused_count);
	} else {
		HIP_DEBUG("Client is registrating for new services.\n");
		hip_add_reg(entry, reg_request->lifetime, reg_types, type_count,
			    accepted_requests, accepted_lifetimes,
			    &accepted_count, refused_requests, failure_types,
			    &refused_count);
	}
	
	/* The registration is now done. Next, we build the REG_RESPONSE and
	   REG_FAILED parameters. */
	
	
 out_err:
	return err;
}

int hip_has_duplicate_services(uint8_t *reg_types, int type_count)
{
	if(reg_types == NULL || type_count <= 0) {
		return -1;
	}
	
	int i = 0, j = 0;

	for(; i < type_count; i++) {
		for(j = i + 1; j < type_count; j++) {
			if(reg_types[i] = reg_types[j]) {
				return -1;
			}
		}
	}

	return 0;
}

/**
 * Adds new registrations to services. This function tries to add all new
 * services listed and indentified by @c types. After the function finishes,
 * succesful registrations are listed in @c accepted_requests and unsuccesful
 * registrations in @c refused_requests.
 * 
 * Make sure that you have allocated memory to @c accepted_requests,
 * @c refused_requests and @c failure_types for at least @c type_count elements.
 *
 * @param  entry              a pointer to a host association.
 * @param  lifetime           requested lifetime.
 * @param  reg_types          a pointer to Reg Types found in REG_REQUEST.
 * @param  type_count         number of Reg Types in @c reg_types.
 * @param  accepted_requests  a target buffer that will store the Reg Types of
 *                            the registrations that succeeded.
 * @param  accepted_lifetimes a target buffer that will store the life times of
 *                            the registrations that succeeded. There will be
 *                            @c accepted_count elements in the buffer, and the
 *                            life times will be in matching indexes with
 *                            @c accepted_requests.
 * @param  accepted_count     a target buffer that will store the number of Reg
 *                            Types in @c accepted_requests.
 * @param  refused_requests   a target buffer that will store the Reg Types of
 *                            the registrations that did not succeed.
 * @param  failure_types      a target buffer that will store the Failure Types
 *                            of the refused requests. There will be
 *                            @c refused_count elements in the buffer, and the
 *                            Failure Types will be in matching indexes with
 *                            @c refused_requests.
 * @param  refused_count      a target buffer that will store the number of Reg
 *                            Types in @c refused_requests.
 * @return                    zero on success, -1 otherwise.
 */ 
int hip_add_reg(hip_ha_t *entry, uint8_t lifetime, uint8_t *reg_types,
		int type_count, uint8_t accepted_requests[],
		uint8_t accepted_lifetimes[], int *accepted_count,
		uint8_t refused_requests[], uint8_t failure_types[],
		int *refused_count)
{
	
	int err = 0, i = 0;
	hip_relrec_t dummy, *fetch_record = NULL, *new_record = NULL;
	uint8_t granted_lifetime = 0;

	memcpy(&(dummy.hit_r), &(entry->hit_peer), sizeof(entry->hit_peer));
	
	/* Loop through all registrations types in reg_types. This loop calls
	   the actual registration functions. */
	for(; i < type_count; i++) {

		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
		case HIP_SERVICE_RELAY:
			HIP_DEBUG("Client is registering to rendezvous "\
				 "service or relay service.\n");
			/* Validate lifetime. */
			hip_rvs_validate_lifetime(lifetime, &granted_lifetime);

			fetch_record = hip_relht_get(&dummy);
			/* Check if we already have an relay record for the
			   given HIT. Note that the fetched record type does not
			   matter, since the relay and RVS types cannot co-exist
			   for a single entry. */
			if(fetch_record != NULL) {
				HIP_DEBUG("Cancellation required.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_CANCEL_REQUIRED;
				*refused_count++;
			} else if(hip_relwl_get_status() &&
				  hip_relwl_get(&dummy.hit_r) == NULL) {
				HIP_DEBUG("Client is not whitelisted.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_INSUFFICIENT_CREDENTIALS;
				*refused_count++;
			} else {
				/* Set the type of the relay record. */
				hip_relrec_type_t type =
					(reg_types[i] == HIP_RVSRELAY) ?
					HIP_RVSRELAY : HIP_FULLRELAY;
				
				/* Allocate a new relay record. */
				new_record = hip_relrec_alloc(
					type,granted_lifetime, &(entry->hit_peer),
					&(entry->preferred_address),
					entry->peer_udp_port,
					&(entry->hip_hmac_in),
					entry->hadb_xmit_func->hip_send_pkt);
				
				hip_relht_put(new_record);

				/* Check that the put was succesful. */
				if(hip_relht_get(new_record) != NULL) {
					accepted_requests[*accepted_count] =
						reg_types[i];
					accepted_lifetimes[*accepted_count] =
						granted_lifetime;
					*accepted_count++;
					
					HIP_DEBUG("Registration accepted.\n");
				} /* The put was unsuccessful. */
				else {
					if(new_record != NULL) {
						free(new_record);
					}
					refused_requests[*refused_count] =
						reg_types[i];
					failure_types[*refused_count] =
						HIP_REG_TRANSIENT_CONDITIONS;
					*refused_count++;
					HIP_ERROR("Unable to store new relay "\
						  "record. Registration "\
						  "refused.\n");
				}
			}

			break;
		case HIP_SERVICE_ESCROW:
			HIP_DEBUG("Client is registering to escrow service.\n");
			
			/* Validate lifetime. */
			hip_escrow_validate_lifetime(lifetime,
						     &granted_lifetime);
			
			if(hip_handle_escrow_registration(&entry->hit_peer)
			   == 0) {
				accepted_requests[*accepted_count] =
					reg_types[i];
				accepted_lifetimes[*accepted_count] =
					granted_lifetime;
				*accepted_count++;
				
				HIP_DEBUG("Registration accepted.\n");
			} else {
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_INSUFFICIENT_CREDENTIALS;
				*refused_count++;
				HIP_DEBUG("Registration refused.\n");
			}

			break;
		default:
			HIP_DEBUG("Client is trying to register to an "
				  "unsupported service.\nRegistration "\
				  "refused.\n");
			refused_requests[*refused_count] = reg_types[i];
			failure_types[*refused_count] =
				HIP_REG_TYPE_UNAVAILABLE;
			*refused_count++;
			
			break;
		}
	}

 out_err:

	return err;
}

/**
 * Cancels registrations to services. This function tries to cancel all services
 * listed and indentified by @c types. After the function finishes, succesful
 * cancellations are listed in @c accepted_requests and unsuccesful requests
 * in @c refused_requests.
 * 
 * Make sure that you have allocated memory to both @c accepted_requests and
 * @c refused_requests for at least @c type_count elements.
 *
 * @param  entry             a pointer to a host association.
 * @param  reg_types         a pointer to Reg Types found in REG_REQUEST.
 * @param  type_count        number of Reg Types in @c reg_types.
 * @param  accepted_requests a target buffer that will store the Reg Types of
 *                           the registrations cancellations that succeeded.
 * @param  accepted_count    a target buffer that will store the number of Reg
 *                           Types in @c accepted_requests.
 * @param  refused_requests  a target buffer that will store the Reg Types of
 *                           the registrations cancellations that did not
 *                           succeed.
 * @param  refused_count     a target buffer that will store the number of Reg
 *                           Types in @c refused_requests.
 * @return                   zero on success, -1 otherwise.
 */ 
int hip_cancel_reg(hip_ha_t *entry, uint8_t *reg_types, int type_count,
		   uint8_t accepted_requests[], int *accepted_count,
		   uint8_t refused_requests[], int *refused_count)
{
	return 0;
}
