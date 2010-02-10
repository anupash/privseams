/**
 * @file agent/gui_interface.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 *
 * This file contains a function that checks if the HIT is already in the database
 * for HITs (local/remote) and if not it calls the GUI to open a dialog to ask
 * the user if the remote HIT should be accepted (and added to the db)
 * or dropped
 *
 * @brief Functionality that checks the HIT and prompts the user if the HIT is unknown.
 *
 * @author Antti Partanen <aehparta@cc.hut.fi>
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools.h"
#include "gui_interface.h"
#include "lib/gui/hipgui.h"
#include "lib/core/debug.h"

/**
 * check_hit - This function checks if the incoming HIT is already in the database
 *             for remote HITs and if not it calls the GUI to open a dialog to ask
 *             the user if the remote HIT should be accepted (and added to the db)
 *             or dropped
 *
 * @param hit Pointer to hit that should be accepted
 * @param inout Decides if this is input or output @see gui_hit_remote_ask
 * @return 0 if accept, -1 on other cases
 **/
int check_hit(HIT_Remote *hit, int inout)
{
    HIT_Remote *fhit;
    int err = 0;
    char str[128];
    HIT_Group *rgroup;

    fhit = hit_db_find(NULL, &hit->hit);

    if (fhit) {
        HIP_DEBUG("Found HIT from database.\n");
        rgroup = hit_db_find_rgroup(fhit->g->name);
        HIP_DEBUG("Accepted: %d (should be 1 drop 2)\n",
                  rgroup->accept);
        if (rgroup->accept == HIT_ACCEPT) {
            /*
             * Changing this to 1 here for letting the callee know that hit
             * already exist and is accepted this is again changed to zero in
             * callee for this case.
             */
            err = 1;
        } else {
            err = -1;
        }
        memcpy(hit, fhit, sizeof(HIT_Remote));

        goto out_err;
    } else {
        HIP_DEBUG("Did not find HIT from database.\n");
    }

    HIP_DEBUG("Calling GUI for accepting new HIT.\n");
    err = gui_hit_remote_ask(hit, inout);

    /* Add hit info to database, if answer was yes. */
    if (err == 0) {
        HIP_DEBUG("Adding new remote HIT to database with type %s.\n",
                  hit->g->accept == HIT_ACCEPT ? "accept" : "deny");
        hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->g, 0);
        if (hit->g->accept == HIT_ACCEPT) {
            err = 0;
        } else {    err = -1;
        }
    } else {
        HIP_DEBUG("User dropped new HIT, not adding to database, denie the packet.\n");
        print_hit_to_buffer(str, &hit->hit);
        hit->g = hit_db_find_rgroup(" deny");
        if (hit->g) {
            hit_db_add(str, &hit->hit, "none", "0", hit->g, 0);
        }
        err    = -1;
    }

out_err:
    return err;
}
