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
	HIP_DEBUG("NEW SERVICE INITIALIZATION DONE.\n");
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
	}else if(srv->reg_type == HIP_SERVICE_ESCROW) {
		cursor += sprintf(cursor, "escrow\n");
	}else if(srv->reg_type == HIP_SERVICE_RELAY) {
		cursor += sprintf(cursor, "relay\n");
	}else{
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

int hip_handle_param_reg_info(hip_common_t *msg, hip_ha_t *entry)
{
	struct hip_reg_info *reg_info = NULL;
	uint8_t *reg_types = NULL, reg_type = 0;
	unsigned int type_count = 0;
	int i = 0;
	
	HIP_DEBUG("REG_INFO parameter found.\n");

	reg_info = hip_get_param(msg, HIP_PARAM_REG_INFO);
	
	if(reg_info == NULL) {
#ifdef CONFIG_HIP_ESCROW
		/* The escrow part is just a copy paste from the previous HIPL
		   registration implementation. It is not tested to work.
		   Besides, it makes no sense to do anything except return
		   zero here. Why should we take action if the responder does
		   NOT offer the service? -Lauri. */ 
		HIP_DEBUG("No REG_INFO parameter found. The Responder offfers "\
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
	
	/* Get a pointer registration types and the type count. */
	reg_types =
		((uint8_t *) hip_get_param_contents_direct(reg_info)) +
		sizeof(reg_info->min_lifetime) + sizeof(reg_info->max_lifetime);
	
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
		
		case HIP_SERVICE_ESCROW:
			/* The escrow part is just a copy paste from the
			   previous HIPL registration implementation. It is not
			   tested to work. -Lauri */
			HIP_INFO("Responder offers escrow service.\n");
#ifdef CONFIG_HIP_ESCROW
			HIP_KEA *kea;
			
			/* If we have requested for escrow service in I1, we
			   store the information of responder's capability
			   here. */
			if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_ESCROW) {
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_ESCROW_CAPABLE);
			}
			/
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
#endif /* CONFIG_HIP_ESCROW */			
			break;
				
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
