/** @file
 * A header file for registration.c.
 *
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    20.05.2008
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5203.txt">
 *          Host Identity Protocol (HIP) Registration Extension</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     registration.c
 * @see     hiprelay.h
 * @see     escrow.h
 */
#ifndef HIP_HIPD_REGISTRATION_H
#define HIP_HIPD_REGISTRATION_H

#include "lib/core/builder.h" // For lifetime conversions.
#include "lib/core/protodefs.h" // For service type values and hip_ha_t
#include "hiprelay.h" // For relrec lifetimes.
#include "lib/core/linkedlist.h" // For pending service requests.

/** Possible service states. */
typedef enum { HIP_SERVICE_OFF = 0, HIP_SERVICE_ON = 1 } hip_srv_status_t;

/* Need to define a name here too because of a stupid linking error in
 * builder.h */
/** HIP service. */
typedef struct hip_srv {
    hip_srv_status_t status;     /**< Service status */
    uint8_t          reg_type;
    uint8_t          min_lifetime;
    uint8_t          max_lifetime;
} hip_srv_t;

/** A pending service request coupled with a host association. */
typedef struct {
    hip_ha_t *entry;
    uint8_t   reg_type;
    uint8_t   lifetime;
    /** Time when this record was created, seconds since epoch. */
    time_t    created;
} hip_pending_request_t;

/**
 * Initializes the services. Initializes the @c hip_services array.
 */
void hip_init_services(void);

/**
 * Uninitializes the services. Removes all pending requests.
 */
void hip_uninit_services(void);
void hip_registration_maintenance(void);
int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status);
int hip_set_srv_min_lifetime(uint8_t reg_type, uint8_t lifetime);
int hip_set_srv_max_lifetime(uint8_t reg_type, uint8_t lifetime);
void hip_get_srv_info(const hip_srv_t *srv, char *information);
int hip_get_active_services(hip_srv_t *active_services,
                            unsigned int *active_service_count);
int hip_add_pending_request(hip_pending_request_t *request);
int hip_del_pending_request(hip_ha_t *entry);
int hip_replace_pending_requests(hip_ha_t *entry_old,
                                 hip_ha_t *entry_new);
int hip_del_pending_request_by_type(hip_ha_t *entry, uint8_t reg_type);
int hip_handle_param_reg_info(hip_ha_t *entry, hip_common_t *source_msg,
                              hip_common_t *target_msg);
int hip_handle_param_reg_request(hip_ha_t *entry, hip_common_t *source_msg,
                                 hip_common_t *target_msg);
int hip_handle_param_reg_response(hip_ha_t *entry, hip_common_t *msg);
int hip_handle_param_reg_failed(hip_ha_t *entry, hip_common_t *msg);

int hip_handle_reg_from(hip_ha_t *entry, struct hip_common *msg);

#endif /* HIP_HIPD_REGISTRATION_H */
