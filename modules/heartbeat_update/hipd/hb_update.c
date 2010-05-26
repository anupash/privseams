/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
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
#include "modules/update/hipd/update.h"

static const int hip_heartbeat_trigger_update_threshold = 5;

static int hip_hb_update_trigger(hip_ha_t *hadb_entry, void *unused)
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
