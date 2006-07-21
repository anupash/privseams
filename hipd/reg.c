/*
 * Registration stuff for HIP.
 *
 * Authors:
 * - Anu Markkola
 *
 * Licence: GNU/GPL
 */

#include "reg.h"

//HIP_SERVICE *services;

static struct list_head services;

void hip_init_services(void)
{
	INIT_LIST_HEAD(&services);
	//services = NULL;
}

void hip_uninit_services(void)
{
	
}

int hip_services_add(int service_type)
{
	
	HIP_DEBUG("Adding service");
	int err = 0;
	HIP_SERVICE *service;
	service = HIP_MALLOC(sizeof(struct hip_reg_service), GFP_KERNEL);
	
	if (!service) {
		HIP_ERROR("service HIP_MALLOC failed");
		err = -ENOMEM;
		goto out_err;
	}
	
	//service->service_type = service_type;
	service->state = HIP_SERVICE_INACTIVE;
	
	if (service_type == HIP_ESCROW_SERVICE) {
		service->service_type = 7;
		HIP_DEBUG("Adding escrow service");
		strncpy(service->name, "ESCROW_SERVICE", 20);
		service->handle_registration = hip_handle_escrow_registration;
		
	}
	else if (service_type == HIP_RVA_RELAY_I1) {
		//TODO: do something about this
		service->service_type = 1;
		HIP_DEBUG("Adding rvs service");
		strncpy(service->name, "HIP_RVS_SERVICE", 20); 
		service->handle_registration = hip_handle_registration;
	}	
	else {
		HIP_DEBUG("Unknown service type");
		err = -1;
		free(service);
		goto out_err;
	}
	
	
	//TODO: check that this service isn't already listed
	
	list_add(&service->list, &services);
	
	return err;

out_err:
	return err;	
}

int hip_services_set_active(int service)
{
	HIP_SERVICE *s, *tmp;
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->service_type == service) {
			HIP_DEBUG("Activating service");
			s->state = HIP_SERVICE_ACTIVE;
		}
	}
}

int hip_services_set_inactive(int service)
{
	HIP_SERVICE *s, *tmp;
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->service_type == service) {
			HIP_DEBUG("Inactivating service");
			s->state = HIP_SERVICE_INACTIVE;
		}
	}
}

int hip_services_remove(int service)
{
	HIP_SERVICE *s, *tmp;
	
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->service_type == service) {
			HIP_DEBUG("Removing service %d", service);
			list_del(&s->list);
			HIP_FREE(s);
		}
	}
}

HIP_SERVICE *hip_get_service(int service_type)
{
	HIP_SERVICE *s, *tmp;
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->service_type == service_type) {
			return s;
		}
	} 
	return NULL;
}

/***/

int hip_get_services_list(int **service_types)
{
	HIP_SERVICE *s, *tmp, *s2, *tmp2;
	int counter1 = 0;
	int counter2 = 0;
	
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->state == HIP_SERVICE_ACTIVE)
			counter1++;
	}

	if (counter1 == 0) {
		return 0;
	}

	*service_types = HIP_MALLOC((counter1 * sizeof(int)), GFP_KERNEL);	
	
	list_for_each_entry_safe(s2, tmp2, &services, list) {
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
	HIP_SERVICE *s, *tmp;
	int count = 0;
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->state == HIP_SERVICE_ACTIVE)
			count++;
	}
	
	return count;
}

int hip_services_is_active(int service)
{
	HIP_SERVICE *s, *tmp;
	list_for_each_entry_safe(s, tmp, &services, list) {
		if (s->service_type == service && s->state == HIP_SERVICE_ACTIVE)
			return 1;
	}
	return 0;
}


int hip_check_service_requests(struct in6_addr *hit, uint8_t *requests, int request_count, 
	int **accepted_requests, int **rejected_requests)
{
	int *tmp_a, *tmp_r;
	int i;
	int accept_count = 0;
	int reject_count = 0;
	int count = 0;
	HIP_SERVICE *s;
	int *a_req, *r_req;
	count = hip_get_service_count();
	tmp_a = HIP_MALLOC((sizeof(int) * count), GFP_KERNEL);
	tmp_r = HIP_MALLOC((sizeof(int) * count), GFP_KERNEL);

	HIP_DEBUG("Service request count: %d", request_count);

	for (i = 0; i < request_count; i++) {
		s = hip_get_service((int)requests[i]);
		if (s) {
			if (s->state == HIP_SERVICE_ACTIVE) {
				if (s->handle_registration(hit)) {	
					HIP_DEBUG("Accepting service request %d", (int)requests[i]);	
					tmp_a[accept_count] = (int)requests[i];
					accept_count++;
				}
				else {
					HIP_DEBUG("Rejecting service request %d", (int)requests[i]);	
					tmp_r[reject_count] = (int)requests[i];
					reject_count++;
				}
			}
			else {
				HIP_DEBUG("Service inactive");
			}
		}
	}
	a_req = HIP_MALLOC((sizeof(int) * accept_count), GFP_KERNEL);	
	r_req = HIP_MALLOC((sizeof(int) * reject_count), GFP_KERNEL);	
		
	for (i = 0; i < accept_count; i++)
		a_req[i] = tmp_a[i];
	for (i = 0; i < reject_count; i++)
		r_req[i] = tmp_r[i];
	
	if ((accept_count + reject_count) != request_count)
		HIP_ERROR("Amount of rejected and accepted services does not match the requests");
	else 
		HIP_DEBUG("Accepted %d and rejected %d service requests", accept_count, reject_count);
	
	HIP_FREE(tmp_a);
	HIP_FREE(tmp_r);
	
	*accepted_requests = a_req;
	*rejected_requests = r_req;
	
	return accept_count;
}

// Default func
int hip_handle_registration(struct in6_addr *hit) 
{
	return 1;
}


