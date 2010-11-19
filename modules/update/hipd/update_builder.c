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
 *
 * This file facilitates buiding of mobility and multi-homing-specific
 * parameters.
 *
 * @author Rene Hummen
 */

#include "lib/core/builder.h"
#include "update_builder.h"


/**
 * build and append a HIP SEQ parameter to a message
 *
 * @param msg the message where the parameter will be appended
 * @param update_id Update ID
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_seq(struct hip_common *msg, uint32_t update_id)
{
    int err = 0;
    struct hip_seq seq;

    hip_set_param_type((struct hip_tlv_common *) &seq, HIP_PARAM_SEQ);
    hip_calc_param_len((struct hip_tlv_common *) &seq,
                       sizeof(struct hip_seq));
    seq.update_id = htonl(update_id);
    err = hip_build_param(msg, &seq);
    return err;
}

/**
 * build and append a HIP ACK parameter to a message
 *
 * @param msg the message where the parameter will be appended
 * @param peer_update_id peer Update ID
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_ack(struct hip_common *msg, uint32_t peer_update_id)
{
    int err = 0;
    struct hip_ack ack;

    hip_set_param_type((struct hip_tlv_common *) &ack, HIP_PARAM_ACK);
    hip_calc_param_len((struct hip_tlv_common *) &ack,
                               sizeof(struct hip_ack));
    ack.peer_update_id = htonl(peer_update_id);
    err = hip_build_param(msg, &ack);
    return err;
}
