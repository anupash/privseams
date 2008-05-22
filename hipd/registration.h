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

/**
 * Initializes the services. Initializes the @c hip_services array.
 */ 
void hip_init_xxx_services();

/**
 * Uninitializes the services. Removes all pending requests.
 */
void hip_uninit_xxx_services();

/**
 * Sets service status for a given service. Sets service status to value
 * identified by @c status for a service identified by @c reg_type in the
 * @c hip_services array. 
 *
 * @param  reg_type the registration type of the service for which the status
 *                  is to be set.
 * @param  status   the status to set i.e. ON or OFF.
 * @return          zero if the status was set succesfully, -1 otherwise.
 */ 
int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status);

/**
 * Sets the minimum service lifetime for a given service. Sets minimum service
 * lifetype to value identified by @c lifetime for a service identified by
 * @c reg_type in the @c hip_services array. This is the minimum lifetime value
 * that the server is able to grant. According to Chapter 5 of RFC 5203, this
 * value should be at least 10 seconds (note, that the parameter @c lifetime
 * is not in seconds).
 *
 * @param  reg_type the registration type of the service for which the status
 *                  is to be set.
 * @param  lifetime the minimum lifetime to set.
 * @return          zero if the status was set succesfully, -1 otherwise.
 */
int hip_set_srv_min_lifetime(uint8_t reg_type, uint8_t lifetime);

/**
 * Sets the maximum service lifetime for a given service. Sets maximum service
 * lifetype to value identified by @c lifetime for a service identified by
 * @c reg_type in the @c hip_services array. This is the maximum lifetime value
 * that the server is able to grant. According to Chapter 5 of RFC 5203, this
 * value should be at least 120 seconds (note, that the parameter @c lifetime
 * is not in seconds).
 *
 * @param  reg_type the registration type of the service for which the status
 *                  is to be set.
 * @param  lifetime the maximum lifetime to set.
 * @return          zero if the status was set succesfully, -1 otherwise.
 */
int hip_set_srv_max_lifetime(uint8_t reg_type, uint8_t lifetime);

/**
 * Gets the active services. Gets all services from the @c hip_services array
 * whose status is ON.
 *
 * Make sure that the size of the target buffer @c active_services is at least
 * HIP_TOTAL_EXISTING_SERVICES * sizeof(hip_srv_t).
 *
 * @param active_services      a target buffer where to put the active
 *                             services.
 * @param active_service_count a target buffer indefying how many services there
 *                             are in the target buffer @c active_services after
 *                             the function finishes.
 * @return -1 if active_services is NULL, zero otherwise.
 */ 
int hip_get_active_services(hip_srv_t *active_services,
			    unsigned int *active_service_count);

/**
 * Gets service informartion. Gets a string representing the service @c srv.
 *
 * Make sure that the target buffer @c informartion is at least 256 bytes long.
 *
 * @param  srv    the service whose information is to be get.
 * @param  status a target buffer where to store the information string.
 */ 
void hip_get_srv_info(const hip_srv_t *srv, char *information);

/**
 * Adds a pending request. Adds a new pending request to the linked list
 * @c pending_requests storing the pending requests. The pending request will be
 * added as the last element of the list.
 *
 * @param  request the pending request to add.
 * @return         zero if the pending request was added succesfully, -1
 *                 otherwise.
 */ 
int hip_add_pending_request(hip_pending_request_t *request);

/**
 * Deletes a pending request. Deletes a pending request identified by the host
 * association @c entry from the linked list @c pending_requests.
 *
 * @param  entry a host association to which the pending request to be deleted
 *               is bound.
 * @return       zero if the pending request was succesfully deleted, -1
 *               otherwise.
 */ 
int hip_del_pending_request(hip_ha_t *entry);

/**
 * Deletes a pending request of given type. Deletes a pending request identified
 * by the host association @c entry and matching the given type @c reg_type from
 * the linked list @c pending_requests.
 *
 * @param  entry    a host association to which the pending request to be
 *                  deleted is bound.
 * @param  reg_type the type of the pending request to delete.
 * @return          zero if the pending request was succesfully deleted, -1
 *                  otherwise.
 */
int hip_del_pending_request_by_type(hip_ha_t *entry, uint8_t reg_type);
int hip_get_pending_requests(hip_ha_t *entry,
			     hip_pending_request_t *requests[]);
int hip_get_pending_request_count(hip_ha_t *entry);



int hip_handle_param_reg_info(hip_common_t *msg, hip_ha_t *entry);
int hip_handle_param_rrq(hip_ha_t *entry, hip_common_t *source_msg,
			 hip_common_t *target_msg);
int hip_handle_param_reg_response(hip_ha_t *entry, hip_common_t *source_msg);

/**
 * Adds new registrations to services at the server. This function tries to add
 * all new services listed and indentified by @c types. This is server side
 * addition, meaning that the server calls this function to add entries
 * to its served client list. After the function finishes, succesful registrations
 * are listed in @c accepted_requests and unsuccesful registrations in
 * @c refused_requests.
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
 * @see                       hip_add_registration_client().
 */ 
int hip_add_registration_server(hip_ha_t *entry, uint8_t lifetime,
				uint8_t *reg_types, int type_count,
				uint8_t accepted_requests[],
				uint8_t accepted_lifetimes[],
				int *accepted_count, uint8_t refused_requests[],
				uint8_t failure_types[], int *refused_count);
/**
 * Cancels registrations to services at the server. This function tries to
 * cancel all services listed and indentified by @c types. This is server side
 * cancellation, meaning that the server calls this function to remove entries
 * from its served client list. After the function finishes, succesful
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
 * @see                      hip_del_registration_client().
 */ 
int hip_del_registration_server(hip_ha_t *entry, uint8_t *reg_types,
				int type_count, uint8_t accepted_requests[],
				uint8_t accepted_lifetimes[],
				int *accepted_count, uint8_t refused_requests[],
				uint8_t failure_types[], int *refused_count);

/**
 * Adds new registrations to services at the client. This function tries to add
 * all new services listed and indentified by @c types. This is client side
 * addition, meaning that the client calls this function to add entries to the
 * list of services it has been granted.
 *
 * @param  entry              a pointer to a host association.
 * @param  lifetime           granted lifetime.
 * @param  reg_types          a pointer to Reg Types found in REG_REQUEST.
 * @param  type_count         number of Reg Types in @c reg_types.
 * @return                    zero on success, -1 otherwise.
 * @see                       hip_add_registration_server().
 */
int hip_add_registration_client(hip_ha_t *entry, uint8_t lifetime,
				uint8_t *reg_types, int type_count);

/**
 * Cancels registrations to services at the client. This function tries to
 * cancel all services listed and indentified by @c types. This is client side
 * cancellation, meaning that the client calls this function to remove entries
 * from the list of services it has been granted.
 *
 * @param  entry             a pointer to a host association.
 * @param  reg_types         a pointer to Reg Types found in REG_REQUEST.
 * @param  type_count        number of Reg Types in @c reg_types.
 * @return                   zero on success, -1 otherwise.
 * @see                      hip_del_registration_client().
 */
int hip_del_registration_client(hip_ha_t *entry, uint8_t *reg_types,
				int type_count);


/**
 * Checks if the value list has duplicate values. Checks whether the value list
 * @c values has duplicate service values. 
 *
 * @param  values     the value list to check.
 * @param  type_count number of values in the value list.
 * @return            zero if there are no duplicate values, -1 otherwise.
 */ 
int hip_has_duplicate_services(uint8_t *values, int type_count);
#endif /* HIP_REGISTRATION_H */
