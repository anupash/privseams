/** @file
 * A header file for reg.c
 * 
 * @author  Anu Markkola
 * @date    17.08.2006
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#ifndef REG_H_
#define REG_H_

#include "hadb.h"
#include "misc.h"
#include "hashtable.h"
#include "escrow.h"
//#include "hiprelay.h"

#define HIP_SERVICE_MAX_COUNT 2

/* Lifetime-fields represent lifetime value of 2^((lifetime - 64)/8) seconds. These 
 * encoded values can be used directly in lifetime field of the packets. */
#define HIP_SERVICE_MIN_LIFETIME 100
#define HIP_SERVICE_MAX_LIFETIME 255

typedef enum { HIP_SERVICE_ACTIVE=0, HIP_SERVICE_INACTIVE=2 } hip_servicestate_t;

struct hip_reg_service {
  //hip_list_t   list;
	char 		   name[20];
	int	 	   service_type;
	hip_servicestate_t state;

	/** @todo Authorization data */
	
	/* accept or reject registration based on the requester hit and do 
	 * service specific initialization */
	// TODO: add local hit
	int (*handle_registration)(struct in6_addr *hit);
        int (*cancel_registration)(struct in6_addr *hit);
        
        /* Cancel the service offer. This function is called when the service 
         * is removed so all data related to that service should be freed */
        int (*cancel_service)(void);
};

typedef struct hip_reg_service HIP_SERVICE;


void hip_init_services(void);

void hip_uninit_services(void);

int hip_services_add(int service_type);

int hip_services_set_active(int service_type);

int hip_services_set_inactive(int service_type);

int hip_services_remove(int service_type);

HIP_SERVICE *hip_get_service(int service_type);

/***/

int hip_get_services_list(int ** service_types);

int hip_get_service_count();

int hip_services_is_active(int service_type);

/* int hip_services_is_authorized(uint8_t service, hip_hit_t *hit);*/

int hip_handle_registration_attempt(hip_ha_t *entry, struct hip_common *msg, struct hip_reg_request *reg_request, 
        uint8_t *requests, int request_count);

int hip_check_service_requests(struct in6_addr *hit, uint8_t *requests, int request_count, 
	int **accepted_requests, int **rejected_requests, int *accepted_count, int *rejected_count);


int hip_handle_registration(struct in6_addr *hit);
int hip_cancel_registration(struct in6_addr *hit);
int hip_cancel_service(void);

/***/

uint8_t hip_get_acceptable_lifetime(uint8_t requested_lifetime);

uint8_t hip_get_service_min_lifetime();
uint8_t hip_get_service_max_lifetime();

/**************/

/* op = 0/1, zero for registrations that are being cancelled */
int hip_get_incomplete_registrations(int **types, hip_ha_t *entry, int op); 

int hip_handle_registration_response(hip_ha_t *entry, struct hip_common *msg);

#endif /*REG_H_*/
