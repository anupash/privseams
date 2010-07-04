/**
 * @file
 *
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
 *
 * This is the main source file of the module HEARTBEAT-UPDATE. Its core
 * functionality is UPDATE triggering if HEARTBEATS fail. You can adjust the
 * threshold which has to be reached before an UPDATE is triggered.
 *
 * During module initialization an maintenance function is registered. This
 * checks if the threshold value is reached and triggers the UPDATE if needed.
 *
 * The heartbeat counter is set to 0, if an UPDATE was triggered.
 *
 * @author Tim Just
 */

#include "hb_update.h"
#include "hipd/maintenance.h"
#include "lib/core/common.h"
#include "modules/update/hipd/update.h"

static const int hip_heartbeat_trigger_update_threshold = 5;

static int hip_hb_update_trigger(hip_ha_t *hadb_entry, UNUSED void *opaque)
{
    int err                                     = 0;
    uint8_t *heartbeat_counter                  = NULL;
    hip_common_t *locator_msg                   = NULL;
    struct hip_locator_info_addr_item *locators = NULL;

    if ((hadb_entry->state == HIP_STATE_ESTABLISHED) &&
        (hadb_entry->outbound_sa_count > 0)) {

        heartbeat_counter = lmod_get_state_item(hadb_entry->hip_modular_state,
                                                "heartbeat_update");

        if (*heartbeat_counter >= hip_heartbeat_trigger_update_threshold) {
            HIP_DEBUG("HEARTBEAT counter reached threshold, trigger UPDATE\n");

            HIP_IFEL(!(locator_msg = hip_msg_alloc()), -ENOMEM,
                     "Out of memory while allocation memory for the packet\n");
            HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

            HIP_IFEL(hip_send_update_to_one_peer(NULL,
                                                 hadb_entry,
                                                 &hadb_entry->our_addr,
                                                 &hadb_entry->peer_addr,
                                                 locators,
                                                 HIP_UPDATE_LOCATOR),
                     -1, "Failed to trigger update\n");

            *heartbeat_counter = 0;
        }
    }

out_err:
    if (locator_msg) {
        free(locator_msg);
    }

    return err;
}

static int hip_hb_update_maintenance(void)
{
    hip_for_each_ha(hip_hb_update_trigger, NULL);

    return 0;
}

int hip_hb_update_init(void)
{
    int err = 0;

    HIP_IFEL(hip_register_maint_function(&hip_hb_update_maintenance, 50000),
             -1,
             "Error on registration of hip_hb_update_maintenance().\n");
out_err:
    return err;
}
