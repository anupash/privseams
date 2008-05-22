/** @file
 * A header file for registration.c.
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    20.05.2008
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5203.txt">
 *          Host Identity Protocol (HIP) Registration Extension</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @see     registration.c
 * @see     hiprelay.h
 * @see     escrow.h
 */
#ifndef HIP_REGISTRATION_H
#define HIP_REGISTRATION_H

#include "misc.h"
#include "hiprelay.h" // For relrec lifetimes.
#include "escrow.h" // For escrow lifetimes and other escrow stuff.
#include "builder.h" // For lifetime conversions.
#include "protodefs.h" // For service type values and hip_ha_t
#include "linkedlist.h" // For pending service requests.

/** Possible service states. */
typedef enum{HIP_SERVICE_OFF = 0, HIP_SERVICE_ON = 1}hip_srv_status_t;

/* Need to define a name here too because of a stupid linking error in
   builder.h */
/** HIP service. */
typedef struct hip_srv{
	hip_srv_status_t status; /**< Service status */
	uint8_t reg_type;
	uint8_t min_lifetime;
	uint8_t max_lifetime;
}hip_srv_t;

/** A pending service request coupled with a host association. */
typedef struct{
	hip_ha_t *entry;
	uint8_t reg_type;
	uint8_t lifetime;
}hip_pending_request_t;

void hip_init_xxx_services();
void hip_uninit_xxx_services();
int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status);
int hip_set_srv_min_lifetime(uint8_t reg_type, uint8_t lifetime);
int hip_set_srv_max_lifetime(uint8_t reg_type, uint8_t lifetime);
int hip_get_active_services(hip_srv_t *active_services,
			    unsigned int *active_service_count);
int hip_add_pending_request(hip_pending_request_t *request);
int hip_del_pending_request(hip_ha_t *entry);
int hip_del_pending_request_by_type(hip_ha_t *entry, uint8_t reg_type);
int hip_get_pending_requests(hip_ha_t *entry,
			     hip_pending_request_t *requests[]);
int hip_get_pending_request_count(hip_ha_t *entry);
void hip_srv_info(const hip_srv_t *srv, char *status);
int hip_handle_param_reg_info(hip_common_t *msg, hip_ha_t *entry);
int hip_handle_param_rrq(hip_ha_t *entry, hip_common_t *source_msg,
			 hip_common_t *target_msg);
int hip_has_duplicate_services(uint8_t *values, int type_count);
int hip_add_reg(hip_ha_t *entry, uint8_t lifetime, uint8_t *reg_types,
		int type_count, uint8_t accepted_requests[],
		uint8_t accepted_lifetimes[], int *accepted_count,
		uint8_t refused_requests[], uint8_t failure_types[],
		int *refused_count);
int hip_cancel_reg(hip_ha_t *entry, uint8_t *reg_types, int type_count,
		   uint8_t accepted_requests[], uint8_t accepted_lifetimes[],
		   int *accepted_count, uint8_t refused_requests[],
		   uint8_t failure_types[], int *refused_count);
int hip_handle_param_reg_response(hip_ha_t *entry, hip_common_t *source_msg);

#endif /* HIP_REGISTRATION_H */
