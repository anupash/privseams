/** @file
 * A header file for reg.c
 * 
 * @author  Anu Markkola
 * @date    17.08.2006
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @todo    service_type field should be uint8_t not int. Services range from 0
 *          to 255. Also, when dealing with HIP registration parameters, the values
 *          are of type uint8_t. With int we must do excessive type casting.
 *          -Lauri 20.09.2007 20:55
 */
#ifndef REG_H_
#define REG_H_

#include "hadb.h"
#include "misc.h"
#include "hashtable.h"
#include "escrow.h"
#include "hiprelay.h"

#define HIP_SERVICE_MAX_COUNT 2

/**
 * Lifetime-fields represent lifetime value of 2^((lifetime - 64)/8) seconds.
 * These encoded values can be used directly in lifetime field of the packets.
 *
 * @note We use 91 as the minimum value, because it results to a service
 *       lifetime of ~10 seconds. There's no use to accept values that result to
 *       minuscule service lifetimes as hipd maintenance interval is ~20 seconds.
 */
#define HIP_SERVICE_MIN_LIFETIME 91
#define HIP_SERVICE_MAX_LIFETIME 200

typedef enum { HIP_SERVICE_ACTIVE=0, HIP_SERVICE_INACTIVE=2 } hip_servicestate_t;

typedef struct hip_reg_service{
	char 		   name[20];
	int	 	   service_type;
	hip_servicestate_t state;

	/** @todo Authorization data */
	
	/* accept or reject registration based on the requester hit and do 
	 * service specific initialization */
	/** @todo add local hit */
	int (*handle_registration)(struct in6_addr *hit);
        int (*cancel_registration)(struct in6_addr *hit);
        
        /* Cancel the service offer. This function is called when the service 
         * is removed so all data related to that service should be freed */
        int (*cancel_service)(void);
}hip_service_t;

void hip_init_services(void);
void hip_uninit_services(void);
int hip_services_add(int service_type);
int hip_services_set_active(int service_type);
int hip_services_set_inactive(int service_type);
int hip_services_remove(int service_type);
hip_service_t *hip_get_service(uint8_t service_type);
int hip_get_services_list(int ** service_types);
int hip_get_service_count();
int hip_services_is_active(int service_type);

/**
 * Handles REG_REQUEST parameter. Parses REG_REQUEST parameter from HIP message
 * @c source_msg, registers/cancels to requested services and builds
 * REG_RESPONSE and/or REG_FAILED parameters to HIP message @c target_msg. 
 *
 * @param entry      a pointer to a host association
 * @param source_msg a pointer to source HIP message (I2 / UPDATE)
 * @param target_msg a pointer to target HIP message (R2 / UPDATE)
 * @return           zero if REG_REQUEST was found, non-zero otherwise.
 * @author           Lauri Silvennoinen
 * @date             26.09.2007
 * @note             This function replaces the old registration handlers.
 * @note             Registration cancellation has not been tested.
 */
int hip_handle_regrequest(hip_ha_t *entry, hip_common_t *source_msg,
			  hip_common_t *target_msg);

/**
 * Handles registration attempt.
 * 
 * @param entry a pointer to host association
 * @param msg   a pointer to HIP message
 * @param reg_request a pointer to a REG_REQUEST parameter
 * @param request a pointer to individual requests inside the parameter
 * @param request_count number of requests in the REG_REQUEST parameter
 * @return zero on success, non-zero otherwise
 */
int hip_handle_registration_attempt(hip_ha_t *entry, hip_common_t *msg, 
				    struct hip_reg_request *reg_request,
				    uint8_t *requests, int request_count);
int hip_check_service_requests(struct in6_addr *hit, uint8_t *requests, int request_count, 
	int **accepted_requests, int **rejected_requests, int *accepted_count, int *rejected_count);
int hip_handle_registration(struct in6_addr *hit);
int hip_cancel_registration(struct in6_addr *hit);
int hip_cancel_service(void);

/**
 * Get an array of incompleted registration types. In other words, services
 * that we have requested, but not yet been granted.
 * 
 * @param types pointer to a memory region where incompleted registration types
 *              are to be put.
 * @param entry a pointer to a host association being under registration.
 * @param op    0/1, zero for registrations that are being cancelled 
 * @return      number of incomplete services found
 */
int hip_get_incomplete_registrations(int **types, hip_ha_t *entry, int op, uint8_t services[]);

int hip_handle_registration_response(hip_ha_t *entry, struct hip_common *msg);

#endif /*REG_H_*/
