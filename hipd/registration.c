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
hip_service_xxx_t hip_services[HIP_NUMBER_OF_EXISTING_SERVICES];

void hip_reg_init_services()
{
	hip_services[0].service = HIP_SERVICE_RENDEZVOUS;
	hip_services[0].status  = HIP_SERVICE_OFF;
	hip_services[1].service = HIP_SERVICE_ESCROW;
	hip_services[1].status  = HIP_SERVICE_OFF;
	hip_services[2].service = HIP_SERVICE_RELAY;
	hip_services[2].status  = HIP_SERVICE_OFF;
}

int hip_reg_set_srv_status(uint8_t service, hip_service_status_t status)
{
	int i = 0;
	
	for(; i < HIP_NUMBER_OF_EXISTING_SERVICES; i++) {
		if(hip_services[i].service == service) {
			hip_services[i].status = status;
			return 0;
		}
	}
	
	return -1;
}
