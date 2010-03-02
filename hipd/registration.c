/** @file
 * This file defines a registration mechanism for the Host Identity Protocol
 * (HIP) that allows hosts to register with services.
 *
 * @author  Lauri Silvennoinen
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5203.txt">
 *          Host Identity Protocol (HIP) Registration Extension</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     registration.h
 * @see     hiprelay.h
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "registration.h"

/**
 * Pending request lifetime. Pending requests are created when the requester
 * requests a service i.e. sends an I1 packet to the server. Pending requests
 * are normally deleted when the requester receives an REG_RESPONSE or
 * REG_FAILED parameter. Should these parameters never be received, the pending
 * requests can be deleted after the lifetime has expired. This value is in
 * seconds.
 */
#define HIP_PENDING_REQUEST_LIFETIME 120

static int hip_del_pending_request_by_expiration(void);
static int hip_add_registration_server(hip_ha_t *entry, uint8_t lifetime,
                                       uint8_t *reg_types, int type_count,
                                       uint8_t accepted_requests[],
                                       uint8_t accepted_lifetimes[],
                                       int *accepted_count, uint8_t refused_requests[],
                                       uint8_t failure_types[], int *refused_count);
static int hip_del_registration_server(hip_ha_t *entry, uint8_t *reg_types,
                                       int type_count, uint8_t accepted_requests[],
                                       int *accepted_count, uint8_t refused_requests[],
                                       uint8_t failure_types[], int *refused_count);
static int hip_add_registration_client(hip_ha_t *entry, uint8_t lifetime,
                                       uint8_t *reg_types, int type_count);
static int hip_del_registration_client(hip_ha_t *entry, uint8_t *reg_types,
                                       int type_count);
static int hip_has_duplicate_services(uint8_t *values, int type_count);
static int hip_get_registration_failure_string(uint8_t failure_type,
                                               char *type_string);


/** An array for storing all existing services. */
hip_srv_t hip_services[HIP_TOTAL_EXISTING_SERVICES];
/** A linked list for storing pending requests on the client side.
 *  @note This assumes a single threaded model. We are not using mutexes here.
 */
hip_ll_t pending_requests;

void hip_init_services()
{
    hip_services[0].reg_type     = HIP_SERVICE_RENDEZVOUS;
    hip_services[0].status       = HIP_SERVICE_OFF;
    hip_services[0].min_lifetime = HIP_RELREC_MIN_LIFETIME;
    hip_services[0].max_lifetime = HIP_RELREC_MAX_LIFETIME;
    hip_services[1].reg_type     = HIP_SERVICE_RELAY;
    hip_services[1].status       = HIP_SERVICE_OFF;
    hip_services[1].min_lifetime = HIP_RELREC_MIN_LIFETIME;
    hip_services[1].max_lifetime = HIP_RELREC_MAX_LIFETIME;

    hip_ll_init(&pending_requests);
}

void hip_uninit_services()
{
    hip_ll_uninit(&pending_requests, free);
}

/**
 * Periodic maintenance function of the registration extension. This function
 * should be called every now and then. A suitable time between calls could be
 * 10 minutes for example. This function deletes the expired pending requests by
 * calling @c hip_del_pending_request_by_expiration() until there are no expired
 * pending requests left.
 *
 * @note This is by no means time critical operation and is not needed to be
 * done on every maintenance cycle. Once every 10 minutes or so should be enough.
 * Just for the record, if periodic_maintenance() is ever to be optimized.
 *
 * An expired pending requests is one that has not been deleted within
 * @c HIP_PENDING_REQUEST_LIFETIME seconds.
 */
void hip_registration_maintenance()
{
    while (hip_del_pending_request_by_expiration() == 0) {
        ;
    }
}

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
int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status)
{
    int i = 0;

    for (; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
        if (hip_services[i].reg_type == reg_type) {
            hip_services[i].status = status;
            return 0;
        }
    }

    return -1;
}

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

int hip_set_srv_min_lifetime(uint8_t reg_type, uint8_t lifetime)
{
    if (lifetime == 0) {
        return -1;
    }

    int i = 0;

    for (; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
        if (hip_services[i].reg_type == reg_type) {
            hip_services[i].min_lifetime = lifetime;
            return 0;
        }
    }

    return -1;
}

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

int hip_set_srv_max_lifetime(uint8_t reg_type, uint8_t lifetime)
{
    if (lifetime == 0) {
        return -1;
    }

    int i = 0;

    for (; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
        if (hip_services[i].reg_type == reg_type) {
            hip_services[i].max_lifetime = lifetime;
            return 0;
        }
    }

    return -1;
}

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
                            unsigned int *active_service_count)
{
    if (active_services == NULL) {
        return -1;
    }

    int i = 0, j = 0;

    memset(active_services, 0, sizeof(hip_services));

    for (; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
        if (hip_services[i].status == HIP_SERVICE_ON) {
            memcpy(&active_services[j], &hip_services[i],
                   sizeof(active_services[j]));
            j++;
        }
    }

    *active_service_count = j;

    return 0;
}

/**
 * Gets service informartion. Gets a string representing the service @c srv.
 *
 * Make sure that the target buffer @c informartion is at least 256 bytes long.
 *
 * @param  srv    a pointer to the service whose information is to be get.
 * @param  status a target buffer where to store the information string.
 */
void hip_get_srv_info(const hip_srv_t *srv, char *information)
{
    if (srv == NULL || information == NULL) {
        return;
    }

    char *cursor = information;
    cursor += sprintf(cursor, "Service info:\n");

    cursor += sprintf(cursor, " reg_type: ");
    if (srv->reg_type == HIP_SERVICE_RENDEZVOUS) {
        cursor += sprintf(cursor, "rendezvous\n");
    } else if (srv->reg_type == HIP_SERVICE_RELAY) {
        cursor += sprintf(cursor, "relay\n");
    } else if (srv->reg_type == HIP_SERVICE_FULLRELAY) {
        cursor += sprintf(cursor, "fullrelay\n");
    } else {
        cursor += sprintf(cursor, "unknown\n");
    }

    cursor += sprintf(cursor, " status: ");
    if (srv->status == HIP_SERVICE_ON) {
        cursor += sprintf(cursor, "on\n");
    } else if (srv->status == HIP_SERVICE_OFF)   {
        cursor += sprintf(cursor, "off\n");
    } else {
        cursor += sprintf(cursor, "unknown\n");
    }

    cursor += sprintf(cursor, " minimum lifetime: %u\n", srv->min_lifetime);
    cursor += sprintf(cursor, " maximum lifetime: %u\n", srv->max_lifetime);
}

/**
 * Adds a pending request. Adds a new pending request to the linked list
 * @c pending_requests storing the pending requests. The pending request will be
 * added as the last element of the list.
 *
 * @param  request a pointer to the pending request to add.
 * @return         zero if the pending request was added succesfully, -1
 *                 otherwise.
 */

int hip_add_pending_request(hip_pending_request_t *request)
{
    int err = 0;

    /* We don't have to check for NULL request as the linked list does that
     * for us. */
    HIP_IFEL(hip_ll_add_last(&pending_requests, request), -1,
             "Failed to add a pending registration request.\n");

out_err:
    return err;
}

/**
 * Deletes a pending request. Deletes a pending request identified by the host
 * association @c entry from the linked list @c pending_requests.
 *
 * @param  entry a pointer to the host association to which the pending request
 *               to be deleted is bound.
 * @return       zero if the pending request was succesfully deleted, -1
 *               otherwise.
 */
int hip_del_pending_request(hip_ha_t *entry)
{
    int index           = 0;
    hip_ll_node_t *iter = NULL;

    /* Iterate through the linked list. The iterator itself can't be used
     * for deleting nodes from the list. Therefore, we just get the index of
     * the element to be deleted using the iterator and then call
     * hip_ll_del() to do the actual deletion. */
    while ((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
        if (((hip_pending_request_t *) (iter->ptr))->entry == entry) {
            HIP_DEBUG("Deleting and freeing a pending request at " \
                      "index %u.\n", index);
            hip_ll_del(&pending_requests, index, free);
            return 0;
        }
        index++;
    }

    return -1;
}

/**
 * Deletes a pending request of given type. Deletes a pending request identified
 * by the host association @c entry and matching the given type @c reg_type from
 * the linked list @c pending_requests.
 *
 * @param  entry    a pointer to a host association to which the pending request
 *                  to be deleted is bound.
 * @param  reg_type the type of the pending request to delete.
 * @return          zero if the pending request was succesfully deleted, -1
 *                  otherwise.
 */
int hip_del_pending_request_by_type(hip_ha_t *entry, uint8_t reg_type)
{
    int index                      = 0;
    hip_ll_node_t *iter            = NULL;
    hip_pending_request_t *request = NULL;

    /* See hip_del_pending_request() for a comment. */
    while ((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
        request = (hip_pending_request_t *) (iter->ptr);
        if (request->entry == entry && request->reg_type == reg_type) {
            HIP_DEBUG("Deleting and freeing a pending request by " \
                      "type at index %u.\n", index);
            hip_ll_del(&pending_requests, index, free);
            return 0;
        }
        index++;
    }

    return -1;
}

/**
 * Deletes one expired pending request. Deletes the first exipired pending
 * request from the pending request linked list @c pending_requests.
 */
static int hip_del_pending_request_by_expiration(void)
{
    int index                      = 0;
    hip_ll_node_t *iter            = NULL;
    hip_pending_request_t *request = NULL;
    time_t now                     = time(NULL);

    /* See hip_del_pending_request() for a comment. */
    while ((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
        request = (hip_pending_request_t *) (iter->ptr);
        if (now - request->created > HIP_PENDING_REQUEST_LIFETIME) {
            HIP_DEBUG("Deleting and freeing a pending request by " \
                      "expiration (%u seconds) at index %u.\n",
                      now - request->created, index);
            hip_ll_del(&pending_requests, index, free);
            return 0;
        }
        index++;
    }

    return -1;
}

/**
 * Moves a pending request to a new entry. This is handy for opportunistic mode
 *
 * @param  entry_old a pointer to the old  host association from which the pending request
 *                   to be moved is bound.
 * @param  entry_new a pointer to the new  host association to which the pending request
 *                   to be moved
 * @return       zero if the pending request was succesfully moved, -1
 *               otherwise.
 */

int hip_replace_pending_requests(hip_ha_t *entry_old,
                                 hip_ha_t *entry_new)
{
    hip_ll_node_t *iter = 0;

    while ((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
        if (((hip_pending_request_t *) (iter->ptr))->entry
            == entry_old) {
            ((hip_pending_request_t *) (iter->ptr))->entry = entry_new;
            return 0;
        }
    }

    return -1;
}

/**
 * Handles param REG_INFO. Digs out the REG_INFO parameter from the HIP message
 * @c source_msg, sets the peer control bits accordingly and builds REG_REQUEST
 * in response to the HIP message @c target_msg. The peer controls are set to
 * indicate which services the peer offers.
 *
 * REG_REQUEST is build only if the server offers at least one of the services
 * we have requested. Only those services as requested that the server offers.
 *
 * @param source_msg a pointer to HIP message from where to dig out the
 *                   REG_INFO parameter.
 * @param target_msg a pointer to HIP message where to build the REG_REQUEST
 *                   parameter.
 * @param entry      a pointer to a host association for which to set the peer
 *                   control bits.
 * @return           -1 if the message @c msg did not contain a REG_INFO
 *                   parameter zero otherwise.
 * @see              peer_controls
 */
int hip_handle_param_reg_info(hip_ha_t *entry, hip_common_t *source_msg,
                              hip_common_t *target_msg)
{
    struct hip_reg_info *reg_info = NULL;
    uint8_t *reg_types            = NULL;
    unsigned int type_count       = 0;
    int err                       = 0, i = 0;

    reg_info = hip_get_param(source_msg, HIP_PARAM_REG_INFO);

    if (reg_info == NULL) {
        HIP_DEBUG("No REG_INFO parameter found. The server offers " \
                  "no services.\n");

        err = -1;
        goto out_err;
    }

    HIP_DEBUG("REG_INFO parameter found.\n");

    HIP_DEBUG("REG INFO MIN LIFETIME %d\n", reg_info->min_lifetime);
    HIP_DEBUG("REG INFO MAX LIFETIME %d\n", reg_info->max_lifetime);

    /* Get a pointer registration types and the type count. */
    reg_types  = reg_info->reg_type;
    type_count = hip_get_param_contents_len(reg_info) -
                 (sizeof(reg_info->min_lifetime) +
                  sizeof(reg_info->max_lifetime));

    /* Check RFC 5203 Chapter 3.1. */
    if (type_count == 0) {
        HIP_INFO("The server is currently unable to provide services " \
                 "due to transient conditions.\n");
        err = 0;
        goto out_err;
    }

    /* Loop through all the registration types found in REG_INFO parameter
     * and store the information of responder's capability to offer a
     * service. */
    for (i = 0; i < type_count; i++) {
        switch (reg_types[i]) {
        case HIP_SERVICE_RENDEZVOUS:
            HIP_INFO("Responder offers rendezvous service.\n");

            hip_hadb_set_peer_controls(
                entry, HIP_HA_CTRL_PEER_RVS_CAPABLE);

            break;
        case HIP_SERVICE_RELAY:
            HIP_INFO("Responder offers relay service.\n");
            hip_hadb_set_peer_controls(
                entry, HIP_HA_CTRL_PEER_RELAY_CAPABLE);

            break;
        default:
            HIP_INFO("Responder offers unsupported service.\n");
            hip_hadb_set_peer_controls(
                entry, HIP_HA_CTRL_PEER_UNSUP_CAPABLE);
        }
    }

out_err:
    return err;
}

/**
 * Handles param REG_REQUEST. Digs out the REG_REQUEST parameter from the HIP
 * message @c source_msg, takes action based on the contents of the REG_REQUEST
 * parameter and builds parameters in response to the HIP message @c target_msg.
 *
 * First hip_has_duplicate_services() is called to check whether the
 * parameter is malformed in a way that it has the same services listed more
 * than once. If the parameter proves to be malformed, the whole parameter is
 * omitted, none of the Reg Types in the REG_REQUEST are handled, and no
 * parameters are build as response. The initiator might be rogue and trying to
 * stress the server with malformed service requests. This is considered as a
 * protocol error and errno is set to EPROTO.
 *
 * If the parameter passes the hip_has_duplicate_services() test, the parameter
 * lifetime is investigated next. If it is zero i.e. the client is canceling a
 * service, hip_del_registration_server() is called. Otherwise the client is
 * registering to new services and hip_add_registration_server() is called.
 *
 * Once the aforementioned functions return, a REG_RESPONSE and/or a required
 * number of REG_FAILED parameters are built to
 *
 * @param entry      a pointer to a host association which is registering.
 * @param source_msg a pointer to HIP message from where to dig out the
 *                   REG_INFO parameter.
 * @param target_msg a pointer to HIP message where to build the REG_RESPONSE
 *                   and/or REG_FAILED parameters.
 * @return           -1 if the message @c source_msg did not contain a
 *                   REG_REQUEST parameter or the parameter had duplicate
 *                   services, zero otherwise.
 * @see              hip_has_duplicate_services().
 * @see              hip_add_registration_server().
 * @see              hip_del_registration_server().
 */

int hip_handle_param_reg_request(hip_ha_t *entry, hip_common_t *source_msg,
                                 hip_common_t *target_msg)
{
    int err                             = 0, type_count = 0, accepted_count = 0, refused_count = 0;
    struct hip_reg_request *reg_request = NULL;
    uint8_t *reg_types                  = NULL;
    /* Arrays for storing the type reg_types of the accepted and refused
     * request types. */
    uint8_t *accepted_requests          = NULL, *accepted_lifetimes = NULL;
    uint8_t *refused_requests           = NULL, *failure_types = NULL;

    reg_request = hip_get_param(source_msg, HIP_PARAM_REG_REQUEST);

    if (reg_request == NULL) {
        err = -1;
        /* Have to use return instead of 'goto out_err' because of
         * the arrays initialised later. Otherwise this won't compile:
         * error: jump into scope of identifier with variably modified
         * type. */
        return err;
    }

    /* Get the number of registration types. */
    type_count         = hip_get_param_contents_len(reg_request) -
                         sizeof(reg_request->lifetime);
    accepted_requests  = malloc(sizeof(uint8_t) * type_count);
    accepted_lifetimes = malloc(sizeof(uint8_t) * type_count);
    refused_requests   = malloc(sizeof(uint8_t) * type_count);
    failure_types      = malloc(sizeof(uint8_t) * type_count);

    /* Allocate memory for types */

    /* Get a pointer to the actual registration types. */
    reg_types = hip_get_param_contents_direct(reg_request) +
                sizeof(reg_request->lifetime);

    HIP_DEBUG("REG_REQUEST parameter found. Requested lifetime: 0x%x, " \
              "number of service types requested: %d.\n",
              reg_request->lifetime, type_count);

    /* Check that the request has at most one value of each type. */
    if (hip_has_duplicate_services(reg_types, type_count)) {
        /* We consider this as a protocol error, and do not build
         * REG_FAILED parameters. The initiator may be rogue and
         * trying to stress the server with malformed service
         * requests. */
        err   = -1;
        errno = EPROTO;
        HIP_ERROR("The REG_REQUEST parameter has duplicate services. " \
                  "The whole parameter is omitted.\n");
        /* As above. */
        return err;
    }

    memset(accepted_requests,  0, sizeof(uint8_t) * type_count);
    memset(accepted_lifetimes, 0, sizeof(uint8_t) * type_count);
    memset(refused_requests,   0, sizeof(uint8_t) * type_count);
    memset(failure_types,      0, sizeof(uint8_t) * type_count);

    if (reg_request->lifetime == 0) {
        hip_del_registration_server(
            entry, reg_types, type_count, accepted_requests,
            &accepted_count, refused_requests, failure_types,
            &refused_count);
    } else {
        hip_add_registration_server(
            entry, reg_request->lifetime, reg_types, type_count,
            accepted_requests, accepted_lifetimes, &accepted_count,
            refused_requests, failure_types, &refused_count);
    }

    HIP_DEBUG("Number of accepted service requests: %d, number of refused " \
              "service requests: %d.\n", accepted_count, refused_count);

    /* The registration is now done. Next, we build the REG_RESPONSE and
     * REG_FAILED parameters. */
    if (accepted_count > 0) {
        /* There is an issue related to the building of REG_RESPONSE
         * parameters in RFC 5203. In Section 4.4 it is said: "The
         * registrar MUST NOT include more than one REG_RESPONSE
         * parameter in its R2 or UPDATE packets..." Now, how can we
         * inform the requester that it has been granted two or more
         * services with different lifetimes? We cannot. Therefore we
         * just take the first accepted lifetime and use that with all
         * services. -Lauri 20.05.2008 */
        hip_build_param_reg_response(target_msg, accepted_lifetimes[0],
                                     accepted_requests, accepted_count);
    }
    if (refused_count > 0) {
        /* We must add as many REG_FAILED parameters as there are
         * different failure types. */
        int i, j, to_be_build_count;
        uint8_t reg_types_to_build[refused_count];
        uint8_t type_to_check[HIP_TOTAL_EXISTING_FAILURE_TYPES] =
            HIP_ARRAY_INIT_REG_FAILURES;

        /* We have to get an continuous memory region holding all the
         * registration types having the same failure type. This memory
         * region is the 'reg_types_to_build' array and it will hold
         * 'to_be_build_count' elements in it. This is done for each
         * existing failure type. After each failure type check, we
         * build a REG_FAILED parameter. */
        for (i = 0; i < HIP_TOTAL_EXISTING_FAILURE_TYPES; i++) {
            to_be_build_count = 0;
            for (j = 0; j < refused_count; j++) {
                if (failure_types[j] == type_to_check[i]) {
                    reg_types_to_build[to_be_build_count] =
                        refused_requests[j];
                    to_be_build_count++;
                }
            }
            if (to_be_build_count > 0) {
                hip_build_param_reg_failed(
                    target_msg, type_to_check[i],
                    reg_types_to_build, to_be_build_count);
            }
        }
    }

    free(accepted_requests);
    free(accepted_lifetimes);
    free(refused_requests);
    free(failure_types);

    return err;
}

/**
 * Handles param REG_RESPONSE. Digs out the REG_RESPONSE parameter from the HIP
 * message @c msg and takes action based on the contents of the
 * REG_RESPONSE parameter.
 *
 * Unlike the REG_REQUEST parameter, the REG_RESPONSE parameter is allowed to
 * have duplicate services listed. This is because the initiator has the option
 * not to contact the server in the first place. If the server sends
 * REG_RESPONSE parameters that contain duplicate services, we just handle each
 * duplicate Reg Type one after the other.
 *
 * The parameter lifetime is investigated first. If it is zero i.e. the server
 * has canceled a service and hip_del_registration_client() is called. Otherwise
 * the server has granted us the services we requested and
 * hip_add_registration_client() is called.
 *
 * @parameter entry a pointer to a host association which is registering.
 * @param     msg   a pointer to HIP message from where to dig out the
 *                  REG_RESPONSE parameter.
 * @return          -1 if the message @c msg did not contain a
 *                  REG_RESPONSE parameter, zero otherwise.
 * @see             hip_add_registration_client().
 * @see             hip_del_registration_client().
 */
int hip_handle_param_reg_response(hip_ha_t *entry, hip_common_t *msg)
{
    int err                               = 0, type_count = 0;
    struct hip_reg_response *reg_response = NULL;
    uint8_t *reg_types                    = NULL;

    reg_response = hip_get_param(msg, HIP_PARAM_REG_RESPONSE);

    if (reg_response == NULL) {
        err = -1;
        goto out_err;
    }

    HIP_DEBUG("REG_RESPONSE parameter found.\n");
    HIP_DEBUG("Lifetime %d \n", reg_response->lifetime);

    type_count = hip_get_param_contents_len(reg_response) -
                 sizeof(reg_response->lifetime);
    reg_types  = hip_get_param_contents_direct(reg_response) +
                 sizeof(reg_response->lifetime);

    if (reg_response->lifetime == 0) {
        hip_del_registration_client(entry, reg_types, type_count);
    } else {
        hip_add_registration_client(entry, reg_response->lifetime,
                                    reg_types, type_count);
    }

out_err:
    return err;
}

/**
 * Handles all REG_FAILED parameters. Digs out the REG_FAILED parameters one
 * after other from the HIP message @c msg and takes action based on the
 * contents of the current REG_FAILED parameter. The function first cancels the
 * 'request' bit and then removes the corresponding pending request.
 *
 * @parameter entry a pointer to a host association which is registering.
 * @param  msg      a pointer to HIP message from where to dig out the
 *                  REG_FAILED parameters.
 * @return          -1 if the message @c msg did not contain a REG_FAILED
 *                  parameter, zero otherwise.
 */
int hip_handle_param_reg_failed(hip_ha_t *entry, hip_common_t *msg)
{
    int err                           = 0, type_count = 0, i = 0;
    struct hip_reg_failed *reg_failed = NULL;
    uint8_t *reg_types                = NULL;
    char reason[256];

    reg_failed = hip_get_param(msg, HIP_PARAM_REG_FAILED);

    if (reg_failed == NULL) {
        err = -1;
        goto out_err;
    }

    HIP_DEBUG("REG_FAILED parameter found.\n");

    /* There can be more than one REG_FAILED parameters in the message. We
     * have to loop through every one. */
    while (hip_get_param_type(reg_failed) == HIP_PARAM_REG_FAILED) {
        type_count = hip_get_param_contents_len(reg_failed) -
                     sizeof(reg_failed->failure_type);
        reg_types  = hip_get_param_contents_direct(reg_failed) +
                     sizeof(reg_failed->failure_type);
        hip_get_registration_failure_string(reg_failed->failure_type,
                                            reason);

        for (; i < type_count; i++) {
            switch (reg_types[i]) {
            case HIP_SERVICE_RENDEZVOUS:
            {
                HIP_DEBUG("The server has refused to grant us " \
                          "rendezvous service.\n%s\n", reason);
                hip_hadb_cancel_local_controls(
                    entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
                hip_del_pending_request_by_type(
                    entry, HIP_SERVICE_RENDEZVOUS);
                hip_hadb_set_peer_controls(
                    entry, HIP_HA_CTRL_PEER_REFUSED_RVS);
                break;
            }
            case HIP_SERVICE_RELAY:
            {
                HIP_DEBUG("The server has refused to grant us " \
                          "relay service.\n%s\n", reason);
                hip_hadb_cancel_local_controls(
                    entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);
                hip_del_pending_request_by_type(
                    entry, HIP_SERVICE_RELAY);
                hip_hadb_set_peer_controls(
                    entry, HIP_HA_CTRL_PEER_REFUSED_RELAY);
                break;
            }
            default:
                HIP_DEBUG("The server has refused to grant us " \
                          "an unknown service (%u).\n%s\n",
                          reg_types[i], reason);
                hip_del_pending_request_by_type(
                    entry, reg_types[i]);
                hip_hadb_set_peer_controls(
                    entry, HIP_HA_CTRL_PEER_REFUSED_UNSUP);
                break;
            }
        }

        /* Iterate to the next parameter and break the loop if there are
         * no more parameters left. */
        i          = 0;
        reg_failed = (struct hip_reg_failed *)
                     hip_get_next_param(msg, (hip_tlv_common_t *) reg_failed);

        if (reg_failed == NULL) {
            break;
        }
    }

out_err:

    return err;
}

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

static int hip_add_registration_server(hip_ha_t *entry, uint8_t lifetime,
                                       uint8_t *reg_types, int type_count,
                                       uint8_t accepted_requests[],
                                       uint8_t accepted_lifetimes[],
                                       int *accepted_count, uint8_t refused_requests[],
                                       uint8_t failure_types[], int *refused_count)
{
    int err                  = 0, i = 0;
    hip_relrec_t dummy, *fetch_record = NULL, *new_record = NULL;
    uint8_t granted_lifetime = 0;

    memcpy(&(dummy.hit_r), &(entry->hit_peer), sizeof(entry->hit_peer));

    /* Loop through all registrations types in reg_types. This loop calls
     * the actual registration functions. */
    for (; i < type_count; i++) {
        switch (reg_types[i]) {
        case HIP_SERVICE_RENDEZVOUS:
        case HIP_SERVICE_RELAY:
        case HIP_SERVICE_FULLRELAY:
            HIP_DEBUG("Client is registering to rendezvous " \
                      "service or relay service.\n");
            /* Validate lifetime. */
            hip_rvs_validate_lifetime(lifetime, &granted_lifetime);

            fetch_record = hip_relht_get(&dummy);
            /* Check that
             * a) the rvs/relay is ON;
             * b) there already is no relay record for the given
             * HIT. Note that the fetched record type does not
             * matter, since the relay and RVS types cannot co-exist
             * for a single entry;
             * c) the client is whitelisted if the whitelist is on. */
            if (hip_relay_get_status() == HIP_RELAY_OFF) {
                HIP_DEBUG("RVS/Relay is OFF.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_TYPE_UNAVAILABLE;
                (*refused_count)++;
#if 0
                /* Commented this part of the code out to
                 * allow consequtive registration without
                 * service cancellation to support host reboots
                 * -miika */
            } else if (fetch_record != NULL) {
                HIP_DEBUG("Cancellation required.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_CANCEL_REQUIRED;
                (*refused_count)++;
#endif
            } else if (hip_relwl_get_status() ==  HIP_RELAY_WL_ON &&
                       hip_relwl_get(&dummy.hit_r) == NULL) {
                HIP_DEBUG("Client is not whitelisted.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_INSUFFICIENT_CREDENTIALS;
                (*refused_count)++;
            } else {
                /* Set the type of the relay record. */
                hip_relrec_type_t type;
                switch (reg_types[i]) {
                case HIP_SERVICE_RELAY:
                    type = HIP_RELAY;
                    break;
                case HIP_SERVICE_RENDEZVOUS:
                default:
                    type = HIP_RVSRELAY;
                    break;
                }

                /* Allow consequtive registration without
                 * service cancellation to support host
                 * reboots */
                if (fetch_record != NULL) {
                    HIP_DEBUG("Warning: registration exists. Overwriting old one\n");
                }

                /* Allocate a new relay record. */
                new_record = hip_relrec_alloc(
                    type, granted_lifetime, &(entry->hit_peer),
                    &(entry->peer_addr),
                    entry->peer_udp_port,
                    &(entry->hip_hmac_in));

                hip_relht_put(new_record);

                /* Check that the put was succesful. */
                if (hip_relht_get(new_record) != NULL) {
                    accepted_requests[*accepted_count]  =
                        reg_types[i];
                    accepted_lifetimes[*accepted_count] =
                        granted_lifetime;
                    (*accepted_count)++;

                    /* SAs with the registrant were causing
                     * problems with ESP relay.
                     * HIP_HA_CTRL_LOCAL_GRANTED_FULLRELAY
                     * disables heartbeats to prevent
                     * creation of new SAs. */
                    if (reg_types[i] == HIP_SERVICE_FULLRELAY) {
                        entry->disable_sas = 1;
                        /* SAs are added before registration completes*/
                        hip_delete_security_associations_and_sp(entry);

                        hip_hadb_set_local_controls(entry,
                                                    HIP_HA_CTRL_LOCAL_GRANTED_FULLRELAY);
                    }

                    HIP_DEBUG("Registration accepted.\n");
                } else {               /* The put was unsuccessful. */
                    if (new_record != NULL) {
                        free(new_record);
                    }
                    refused_requests[*refused_count] =
                        reg_types[i];
                    failure_types[*refused_count]    =
                        HIP_REG_TRANSIENT_CONDITIONS;
                    (*refused_count)++;
                    HIP_ERROR("Unable to store new relay " \
                              "record. Registration " \
                              "refused.\n");
                }
            }

            break;
        default:
            HIP_DEBUG("Client is trying to register to an "
                      "unsupported service.\nRegistration " \
                      "refused.\n");
            refused_requests[*refused_count] = reg_types[i];
            failure_types[*refused_count]    =
                HIP_REG_TYPE_UNAVAILABLE;
            (*refused_count)++;

            break;
        }
    }

    return err;
}

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
static int hip_del_registration_server(hip_ha_t *entry, uint8_t *reg_types,
                                       int type_count, uint8_t accepted_requests[],
                                       int *accepted_count, uint8_t refused_requests[],
                                       uint8_t failure_types[], int *refused_count)
{
    int err = 0, i = 0;
    hip_relrec_t dummy, *fetch_record = NULL;

    memcpy(&(dummy.hit_r), &(entry->hit_peer), sizeof(entry->hit_peer));

    /* Loop through all registrations types in reg_types. This loop calls
     * the actual registration functions. */
    for (; i < type_count; i++) {
        switch (reg_types[i]) {
        case HIP_SERVICE_RENDEZVOUS:
        case HIP_SERVICE_RELAY:
        case HIP_SERVICE_FULLRELAY: {
            /* Set the type of the relay record. */
            hip_relrec_type_t type_to_delete = 0;

            /* RVS and relay deletions are identical except the
             * relay record type. */
            if (reg_types[i] == HIP_SERVICE_RENDEZVOUS) {
                HIP_DEBUG("Client is cancelling registration " \
                          "to rendezvous service.\n");
                type_to_delete = HIP_RVSRELAY;
            } else if (reg_types[i] == HIP_SERVICE_RELAY) {
                HIP_DEBUG("Client is cancelling registration " \
                          "to relay service.\n");
                type_to_delete = HIP_RELAY;
            } else {
                HIP_DEBUG("Client is cancelling registration " \
                          "to full relay service.\n");
                type_to_delete = HIP_FULLRELAY;
            }

            fetch_record = hip_relht_get(&dummy);
            /* Check that
             * a) the rvs/relay is ON;
             * b) there is an relay record to delete for the given
             * HIT.
             * c) the fetched record type is correct.
             * d) the client is whitelisted if the whitelist is on. */

            if (hip_relay_get_status() == HIP_RELAY_OFF) {
                HIP_DEBUG("RVS/Relay is OFF.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_TYPE_UNAVAILABLE;
                (*refused_count)++;
            } else if (fetch_record == NULL) {
                HIP_DEBUG("There is no relay record to " \
                          "cancel.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_TYPE_UNAVAILABLE;
                (*refused_count)++;
            } else if (fetch_record->type != type_to_delete) {
                HIP_DEBUG("The relay record to be cancelled " \
                          "is of wrong type.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_TYPE_UNAVAILABLE;
                (*refused_count)++;
            } else if (hip_relwl_get_status() &&
                       hip_relwl_get(&dummy.hit_r) == NULL) {
                HIP_DEBUG("Client is not whitelisted.\n");
                refused_requests[*refused_count] = reg_types[i];
                failure_types[*refused_count]    =
                    HIP_REG_INSUFFICIENT_CREDENTIALS;
                (*refused_count)++;
            } else {
                /* Delete the relay record. */
                hip_relht_rec_free_doall(&dummy);
                /* Check that the relay record really got deleted. */
                if (hip_relht_get(&dummy) == NULL) {
                    accepted_requests[*accepted_count] =
                        reg_types[i];
                    (*accepted_count)++;
                    HIP_DEBUG("Cancellation accepted.\n");
                } else {
                    refused_requests[*refused_count] =
                        reg_types[i];
                    failure_types[*refused_count]    =
                        HIP_REG_TRANSIENT_CONDITIONS;
                    (*refused_count)++;
                    HIP_ERROR("Cancellation refused.\n");
                }
            }

            break;
        }
        default:
            HIP_DEBUG("Client is trying to cancel an unsupported " \
                      "service.\nCancellation refused.\n");
            refused_requests[*refused_count] = reg_types[i];
            failure_types[*refused_count]    =
                HIP_REG_TYPE_UNAVAILABLE;
            (*refused_count)++;

            break;
        }
    }

    return err;
}

/**
 * Adds new registrations to services at the client. This function tries to add
 * all new services listed and indentified by @c types. This is client side
 * addition, meaning that the client calls this function to add entries to the
 * list of services it has been granted. It first cancels the 'request' bit,
 * then sets the 'granted' bit and finally removes the corresponding pending
 * request.
 *
 * @param  entry              a pointer to a host association.
 * @param  lifetime           granted lifetime.
 * @param  reg_types          a pointer to Reg Types found in REG_REQUEST.
 * @param  type_count         number of Reg Types in @c reg_types.
 * @return                    zero on success, -1 otherwise.
 * @see                       hip_add_registration_server().
 */
static int hip_add_registration_client(hip_ha_t *entry, uint8_t lifetime,
                                       uint8_t *reg_types, int type_count)
{
    int i          = 0;
    time_t seconds = 0;

    /* 'seconds' is just just for debug prints. */
    hip_get_lifetime_seconds(lifetime, &seconds);

    /* Check what services we have been granted. Cancel the local requests
     * bit, set the peer granted bit and delete the pending request. */
    /** @todo We are not storing the granted lifetime anywhere as we
     *  obviously should. */
    for (; i < type_count; i++) {
        switch (reg_types[i]) {
        case HIP_SERVICE_RENDEZVOUS:
        {
            HIP_DEBUG("The server has granted us rendezvous " \
                      "service for %u seconds (lifetime 0x%x.)\n",
                      seconds, lifetime);
            hip_hadb_cancel_local_controls(
                entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
            hip_hadb_set_peer_controls(
                entry, HIP_HA_CTRL_PEER_GRANTED_RVS);
            hip_del_pending_request_by_type(
                entry, HIP_SERVICE_RENDEZVOUS);
            break;
        }
        case HIP_SERVICE_RELAY:
        {
            HIP_DEBUG("The server has granted us relay " \
                      "service for %u seconds (lifetime 0x%x.)\n",
                      seconds, lifetime);
            hip_hadb_cancel_local_controls(
                entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);
            hip_hadb_set_peer_controls(
                entry, HIP_HA_CTRL_PEER_GRANTED_RELAY);
            hip_del_pending_request_by_type(
                entry, HIP_SERVICE_RELAY);
            break;
        }
        default:
        {
            HIP_DEBUG("The server has granted us an unknown " \
                      "service for %u seconds (lifetime 0x%x.)\n",
                      seconds, lifetime);
            hip_hadb_cancel_local_controls(
                entry, HIP_HA_CTRL_LOCAL_REQ_UNSUP);
            hip_hadb_set_peer_controls(
                entry, HIP_HA_CTRL_PEER_GRANTED_UNSUP);
            hip_del_pending_request_by_type(
                entry, reg_types[i]);
            break;
        }
        }
    }

    return 0;
}

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
static int hip_del_registration_client(hip_ha_t *entry, uint8_t *reg_types,
                                       int type_count)
{
    int i = 0;

    /* Check what service registration cancellations we have been granted.
     * Cancel the local requests and delete the pending request. */
    /** @todo We are not storing information about cancellation anywhere. */
    for (; i < type_count; i++) {
        switch (reg_types[i]) {
        case HIP_SERVICE_RENDEZVOUS:
        {
            HIP_DEBUG("The server has cancelled our rendezvous " \
                      "service.\n");
            hip_hadb_cancel_local_controls(
                entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
            hip_del_pending_request_by_type(
                entry, HIP_SERVICE_RENDEZVOUS);
            break;
        }
        case HIP_SERVICE_RELAY:
        {
            HIP_DEBUG("The server has cancelled our relay " \
                      "service.\n");
            hip_hadb_cancel_local_controls(
                entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);
            hip_del_pending_request_by_type(
                entry, HIP_SERVICE_RELAY);

            break;
        }
        default:
        {
            HIP_DEBUG("The server has cancelled our registration " \
                      "to an unknown service.\n");
            break;
        }
        }
    }

    return 0;
}

/**
 * Checks if the value list has duplicate values. Checks whether the value list
 * @c values has duplicate service values.
 *
 * @param  values     the value list to check.
 * @param  type_count number of values in the value list.
 * @return            zero if there are no duplicate values, -1 otherwise.
 */

static int hip_has_duplicate_services(uint8_t *reg_types, int type_count)
{
    if (reg_types == NULL || type_count <= 0) {
        return -1;
    }

    int i = 0, j = 0;

    for (; i < type_count; i++) {
        for (j = i + 1; j < type_count; j++) {
            if (reg_types[i] == reg_types[j]) {
                return -1;
            }
        }
    }

    return 0;
}

/**
 * Gets a string representation related to a registration failure type.
 *
 * @param  failure_type the Failure Type of a REG_FAILED parameter.
 * @param  type_string  a target buffer where to store the string
 *                      representation. This should be at least 256 bytes long.
 * @return              -1 if @c type_string is NULL, zero otherwise.
 */
static int hip_get_registration_failure_string(uint8_t failure_type,
                                               char *type_string)
{
    if (type_string == NULL) {
        return -1;
    }

    switch (failure_type) {
    case HIP_REG_INSUFFICIENT_CREDENTIALS:
        memcpy(type_string,
               "Registration requires additional credentials.",
               sizeof("Registration requires additional credentials."));
        break;
    case HIP_REG_TYPE_UNAVAILABLE:
        memcpy(type_string, "Registration type unavailable.",
               sizeof("Registration type unavailable."));
        break;
    case HIP_REG_CANCEL_REQUIRED:
        memcpy(type_string,
               "Cancellation of a previously granted service is " \
               "required.",
               sizeof("Cancellation of a previously granted service " \
                      "is required."));
        break;
    case HIP_REG_TRANSIENT_CONDITIONS:
        memcpy(type_string,
               "The server is currently unable to provide services " \
               "due to transient conditions.",
               sizeof("The server is currently unable to provide services " \
                      "due to transient conditions."));
        break;
    default:
        memcpy(type_string, "Unknown failure type.",
               sizeof("Unknown failure type."));
        break;
    }

    return 0;
}

// add by santtu from here
/*
 * Why is this not named consistelty with other parameterhandlers? Why is it not
 * hip_handle_param_reg_from? We have a naming convetion in use...
 * -Lauri 22.07.2008
 */
int hip_handle_reg_from(hip_ha_t *entry, struct hip_common *msg)
{
    int err                    = 0;
    struct hip_reg_from *rfrom = NULL;

    HIP_DEBUG("Checking msg for REG_FROM parameter.\n");
    rfrom = hip_get_param(msg, HIP_PARAM_REG_FROM);

    if (rfrom != NULL) {
        HIP_DEBUG("received a for REG_FROM parameter \n");
        HIP_DEBUG_IN6ADDR("the received reg_from address is ",
                          &rfrom->address);
        HIP_DEBUG_IN6ADDR("the local address is ", &entry->our_addr);
        //check if it is a local address
        if (!ipv6_addr_cmp(&rfrom->address, &entry->our_addr)) {
            HIP_DEBUG("the host is not behind nat \n");
        } else {
            _HIP_DEBUG("found a nat @port %d \n ",
                       ntohs(rfrom->port));
            memcpy(&entry->local_reflexive_address,
                   &rfrom->address, sizeof(struct in6_addr));
            entry->local_reflexive_udp_port = ntohs(rfrom->port);
            HIP_DEBUG_HIT("set reflexive address:",
                          &entry->local_reflexive_address);
            HIP_DEBUG("set reflexive port: %d \n",
                      entry->local_reflexive_udp_port);
            _HIP_DEBUG("the entry address is %d \n", entry);
        }
    } else {
        err = 1;
    }

    return err;
}
