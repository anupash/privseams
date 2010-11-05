/*
 * signaling_common_builder.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#include "lib/core/builder.h"
#include "lib/core/ife.h"
#include "signaling_common_builder.h"


int signaling_build_param_portinfo(struct hip_common *msg, uint16_t src_port, uint16_t dest_port) {
    struct signaling_param_portinfo pi;
    int err = 0;

    hip_set_param_type((struct hip_tlv_common *) &pi, HIP_PARAM_SIGNALING_PORTINFO);
    hip_set_param_contents_len((struct hip_tlv_common *) &pi, 2*sizeof(uint16_t));

    pi.srcport = htons(src_port);
    pi.destport = htons(dest_port);

    if(src_port || dest_port) {
        HIP_DEBUG("Signaling port information to hipd (src = %d, dest = %d)\n", src_port, dest_port);
        HIP_IFEL(hip_build_param(msg, &pi),
                            -1, "Appending port information param failed\n");
    } else {
        HIP_DEBUG("No port information given. Omitting building parameter HIP_PARAM_SIGNALING_PORTINFO. \n");
    }

out_err:
    return err;
}
