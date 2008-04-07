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
hip_srv_t hip_services[HIP_NUMBER_OF_EXISTING_SERVICES];

void hip_init_xxx_services()
{
	hip_services[0].type         = HIP_SERVICE_RENDEZVOUS;
	hip_services[0].status       = HIP_SERVICE_OFF;
	hip_services[0].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[0].max_lifetime = HIP_RELREC_MAX_LIFETIME;
	hip_services[1].type         = HIP_SERVICE_ESCROW;
	hip_services[1].status       = HIP_SERVICE_OFF;
	hip_services[1].min_lifetime = HIP_ESCROW_MIN_LIFETIME;
	hip_services[1].max_lifetime = HIP_ESCROW_MAX_LIFETIME;
	hip_services[2].type         = HIP_SERVICE_RELAY;
	hip_services[2].status       = HIP_SERVICE_OFF;
	hip_services[2].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[2].max_lifetime = HIP_RELREC_MAX_LIFETIME;
	HIP_DEBUG("NEW SERVICE INITIALIZATION DONE.\n");
}

int hip_set_srv_status(uint8_t type, hip_srv_status_t status)
{
	int i = 0;
	
	for(; i < HIP_NUMBER_OF_EXISTING_SERVICES; i++) {
		if(hip_services[i].type == type) {
			hip_services[i].status = status;
			return 0;
		}
	}
	
	return -1;
}

int hip_set_srv_min_lifetime(uint8_t type, uint8_t lifetime)
{
	if(lifetime = 0) {
		return -1;
	}
	
	int i = 0;
	
	for(; i < HIP_NUMBER_OF_EXISTING_SERVICES; i++) {
		if(hip_services[i].type == type) {
			hip_services[i].min_lifetime = lifetime;
			return 0;
		}
	}
	
	return -1;
}

int hip_set_srv_max_lifetime(uint8_t type, uint8_t lifetime)
{
	if(lifetime = 0) {
		return -1;
	}
	
	int i = 0;
	
	for(; i < HIP_NUMBER_OF_EXISTING_SERVICES; i++) {
		if(hip_services[i].type == type) {
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

	for(; i < HIP_NUMBER_OF_EXISTING_SERVICES; i++) {
		if(hip_services[i].status == HIP_SERVICE_ON) {
			memcpy(&active_services[j], &hip_services[i],
			       sizeof(active_services[j]));
			j++;
		}
	}
	
	*active_service_count = j;

	return 0;
} 

int hip_get_lifetime_value(time_t seconds, uint8_t *lifetime)
{
	/* Check that we get a lifetime value between 1 and 255. The minimum
	   lifetime according to the registration draft is 0.004 seconds, but
	   the reverse formula gives zero for that. 15384774.906 seconds is the
	   maximum value. The boundary checks done here are just curiosities
	   since services are usually granted for minutes to a couple of days,
	   but not for milliseconds and days. However, log() gives a range error
	   if "seconds" is zero. */
	if(seconds == 0) {
		*lifetime = 0;
		return -1;
	}else if(seconds > 15384774) {
		*lifetime = 255;
		return -1;
	}else {
		*lifetime = (8 * (log(seconds) / log(2))) + 64;
		return 0;
	}
}

int hip_get_lifetime_seconds(uint8_t lifetime, time_t *seconds){
	if(lifetime == 0) {
		*seconds = 0;
		return -1;
	}
	/* All values between from 1 to 63 give just fractions of a second. */
	else if(lifetime < 64) {
		*seconds = 1;
		return 0;
	} else {
		*seconds = pow(2, ((double)((lifetime)-64)/8));
		return 0;
	}
}

void hip_srv_info(const hip_srv_t *srv, char *status)
{
	if(srv == NULL || status == NULL)
		return;
	
	char *cursor = status;
	cursor += sprintf(cursor, "Service info:\n");
	
	cursor += sprintf(cursor, " type: ");
	if(srv->type == HIP_SERVICE_RENDEZVOUS){
		cursor += sprintf(cursor, "rendezvous\n");
	}else if(srv->type == HIP_SERVICE_ESCROW){
		cursor += sprintf(cursor, "escrow\n");
	}else if(srv->type == HIP_SERVICE_RELAY){
		cursor += sprintf(cursor, "relay\n");
	}else{
		cursor += sprintf(cursor, "unknown\n");
	}

	cursor += sprintf(cursor, " status: ");
	if(srv->status == HIP_SERVICE_ON){
		cursor += sprintf(cursor, "on\n");
	}else if(srv->status == HIP_SERVICE_OFF){
		cursor += sprintf(cursor, "off\n");
	}else{
		cursor += sprintf(cursor, "unknown\n");
	}

	cursor += sprintf(cursor, " minimum lifetime: %u\n", srv->min_lifetime);
	cursor += sprintf(cursor, " maximum lifetime: %u\n", srv->max_lifetime);
}
