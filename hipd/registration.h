/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

/**
 * @file
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    20.05.2008
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5203.txt">
 *          Host Identity Protocol (HIP) Registration Extension</a>
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
struct hip_pending_request {
    struct hip_hadb_state *entry;
    uint8_t                reg_type;
    uint8_t                lifetime;
    /** Time when this record was created, seconds since epoch. */
    time_t created;
};

/**
 * Initializes the services. Initializes the @c hip_services array.
 */
void hip_init_services(void);

/**
 * Uninitializes the services. Removes all pending requests.
 */
void hip_uninit_services(void);
int hip_registration_maintenance(void);
int hip_set_srv_status(uint8_t reg_type, enum hip_srv_status status);
int hip_get_active_services(struct hip_srv *active_services,
                            unsigned int *active_service_count);
int hip_add_pending_request(struct hip_pending_request *request);
int hip_del_pending_request(struct hip_hadb_state *entry);
int hip_replace_pending_requests(struct hip_hadb_state *entry_old,
                                 struct hip_hadb_state *entry_new);
int hip_del_pending_request_by_type(struct hip_hadb_state *entry,
                                    uint8_t reg_type);
int hip_handle_param_reg_info(struct hip_hadb_state *entry,
                              struct hip_common *source_msg,
                              struct hip_common *target_msg);
int hip_handle_param_reg_request(struct hip_hadb_state *entry,
                                 struct hip_common *source_msg,
                                 struct hip_common *target_msg);
int hip_handle_param_reg_response(struct hip_hadb_state *entry,
                                  struct hip_common *msg);
int hip_handle_param_reg_failed(struct hip_hadb_state *entry,
                                struct hip_common *msg);

int hip_handle_reg_from(struct hip_hadb_state *entry, struct hip_common *msg);

#endif /* HIP_HIPD_REGISTRATION_H */
