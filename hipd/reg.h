#ifndef REG_H_
#define REG_H_

#include "hadb.h"
#include "misc.h"
#include "hashtable.h"
#include "escrow.h"

#define HIP_SERVICE_MAX_COUNT 2

typedef enum { HIP_SERVICE_ACTIVE=0, HIP_SERVICE_INACTIVE=1 } hip_servicestate_t;

struct hip_reg_service {
	
	struct list_head 		list;
	
	int	 					service_type;
	char 					name[20];
	hip_servicestate_t 		state;

	/*! \todo Authorization data */
	
	/* accept or reject registration based on the requester hit */
	int (*handle_registration)(struct in6_addr *hit);
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

int hip_check_service_requests(struct in6_addr *hit, uint8_t *requests, int request_count, 
	int **accepted_requests, int **rejected_requests);


int hip_handle_registration(struct in6_addr *hit);

#endif /*REG_H_*/
