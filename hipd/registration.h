/** @file
 * A header file for registration.c.
 *
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    20.05.2008
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5203.txt">
 *          Host Identity Protocol (HIP) Registration Extension</a>
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * @see     registration.c
 * @see     hiprelay.h
 * @see     escrow.h
 */

#ifndef HIP_HIPD_REGISTRATION_H
#define HIP_HIPD_REGISTRATION_H

#include <stdint.h>
#include <sys/types.h>

#include "lib/core/builder.h"
#include "lib/core/protodefs.h"


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
int hip_registration_maintenance(void);
int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status);
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
